//! Core diagnostic types for GoGuard.
//!
//! All analysis passes produce `Diagnostic` values, and all formatters
//! (human, agent JSON, SARIF) consume them.

use serde::{Deserialize, Serialize};

/// A diagnostic produced by an analysis pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Unique ID: RULE_CODE-file:line (e.g., "NIL001-handler.go:18").
    pub id: String,
    /// Rule code (e.g., "NIL001", "ERR001", "RACE001").
    pub rule: String,
    /// Severity level.
    pub severity: Severity,
    /// Analysis confidence (0.0 to 1.0). Below 0.7 may be false positive.
    pub confidence: f64,
    /// One-line summary.
    pub title: String,
    /// Detailed explanation of why this is a bug.
    pub explanation: String,
    /// Where the issue manifests.
    pub location: Location,
    /// Where the bug originates (often different from where it manifests).
    pub root_cause: Option<RootCause>,
    /// Auto-fix suggestion.
    pub fix: Option<Fix>,
    /// IDs of related diagnostics. Fixing this may resolve them.
    pub related: Vec<String>,
    /// Impact assessment.
    pub blast_radius: Option<BlastRadius>,
    /// Pattern information for agent learning.
    pub pattern: Option<Pattern>,
    /// The analysis pass that produced this diagnostic.
    pub source: DiagnosticSource,
    /// Optional callee key for elicitation (e.g., "db.Find#0").
    /// Set when confidence is low due to unknown external call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_key: Option<String>,
}

/// Severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding.
    Info,
    /// Potential issue that should be addressed.
    Warning,
    /// Definite bug or serious issue.
    Error,
    /// Critical safety issue (nil deref, data race, etc.).
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl Severity {
    /// Check if this severity is at or above a threshold.
    pub fn is_at_least(&self, threshold: Severity) -> bool {
        *self >= threshold
    }
}

/// Source code location.
///
/// Lines and columns are 1-based (matching Go's `token.Position`).
/// Consumers that need 0-based positions (e.g., LSP) must subtract 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    /// Line number (1-based).
    pub line: u32,
    /// Column offset (1-based), from Go's `token.Position.Column`.
    pub column: u32,
    /// End line number (1-based).
    pub end_line: u32,
    /// End column offset (1-based).
    pub end_column: u32,
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// Root cause information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RootCause {
    pub file: String,
    pub line: u32,
    pub description: String,
}

/// Auto-fix suggestion with exact text edits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    /// Human-readable description of the fix.
    pub description: String,
    /// Text edits to apply.
    pub edits: Vec<Edit>,
}

/// A text edit for an auto-fix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edit {
    pub file: String,
    pub range: EditRange,
    /// The original text (for verification).
    pub old_text: Option<String>,
    /// The replacement text.
    pub new_text: String,
}

/// A range of lines for an edit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditRange {
    pub start_line: u32,
    pub end_line: u32,
}

/// Blast radius assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Number of callers affected.
    pub affects_callers: u32,
    /// Whether this is in a hot code path.
    pub in_hot_path: bool,
    /// Production risk level.
    pub production_risk: Risk,
}

/// Risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Pattern information for agent learning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pattern {
    /// Name of the pattern.
    pub name: String,
    /// How frequently this pattern occurs.
    pub frequency: Frequency,
    /// The correct Go idiom to use instead.
    pub go_idiom: String,
}

/// How common a pattern is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    VeryCommon,
    Common,
    Uncommon,
    Rare,
}

/// Which analysis pass produced the diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSource {
    Nil,
    Errcheck,
    Concurrency,
    Ownership,
    Exhaustive,
    Taint,
}

impl std::fmt::Display for DiagnosticSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Errcheck => write!(f, "errcheck"),
            Self::Concurrency => write!(f, "concurrency"),
            Self::Ownership => write!(f, "ownership"),
            Self::Exhaustive => write!(f, "exhaustive"),
            Self::Taint => write!(f, "taint"),
        }
    }
}

/// Builder for creating diagnostics conveniently.
pub struct DiagnosticBuilder {
    rule: String,
    severity: Severity,
    title: String,
    file: String,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    source: DiagnosticSource,
    confidence: f64,
    explanation: String,
    root_cause: Option<RootCause>,
    fix: Option<Fix>,
    related: Vec<String>,
    blast_radius: Option<BlastRadius>,
    pattern: Option<Pattern>,
    callee_key: Option<String>,
}

impl DiagnosticBuilder {
    /// Create a new diagnostic builder.
    pub fn new(
        rule: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        source: DiagnosticSource,
    ) -> Self {
        Self {
            rule: rule.into(),
            severity,
            title: title.into(),
            file: String::new(),
            line: 0,
            column: 0,
            end_line: 0,
            end_column: 0,
            source,
            confidence: 0.9,
            explanation: String::new(),
            root_cause: None,
            fix: None,
            related: Vec::new(),
            blast_radius: None,
            pattern: None,
            callee_key: None,
        }
    }

    /// Set the location.
    pub fn location(mut self, file: impl Into<String>, line: u32, column: u32) -> Self {
        self.file = file.into();
        self.line = line;
        self.column = column;
        self.end_line = line;
        self.end_column = column;
        self
    }

    /// Set the end location.
    pub fn end_location(mut self, end_line: u32, end_column: u32) -> Self {
        self.end_line = end_line;
        self.end_column = end_column;
        self
    }

    /// Set the confidence level.
    pub fn confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set the explanation.
    pub fn explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = explanation.into();
        self
    }

    /// Set the root cause.
    pub fn root_cause(
        mut self,
        file: impl Into<String>,
        line: u32,
        description: impl Into<String>,
    ) -> Self {
        self.root_cause = Some(RootCause {
            file: file.into(),
            line,
            description: description.into(),
        });
        self
    }

    /// Set a fix.
    pub fn fix(mut self, description: impl Into<String>, edits: Vec<Edit>) -> Self {
        self.fix = Some(Fix {
            description: description.into(),
            edits,
        });
        self
    }

    /// Add a related diagnostic ID.
    pub fn related(mut self, id: impl Into<String>) -> Self {
        self.related.push(id.into());
        self
    }

    /// Set the blast radius.
    pub fn blast_radius(
        mut self,
        affects_callers: u32,
        in_hot_path: bool,
        production_risk: Risk,
    ) -> Self {
        self.blast_radius = Some(BlastRadius {
            affects_callers,
            in_hot_path,
            production_risk,
        });
        self
    }

    /// Set the pattern.
    pub fn pattern(
        mut self,
        name: impl Into<String>,
        frequency: Frequency,
        go_idiom: impl Into<String>,
    ) -> Self {
        self.pattern = Some(Pattern {
            name: name.into(),
            frequency,
            go_idiom: go_idiom.into(),
        });
        self
    }

    /// Set the callee key for elicitation linking.
    pub fn callee_key(mut self, key: impl Into<String>) -> Self {
        self.callee_key = Some(key.into());
        self
    }

    /// Build the diagnostic.
    pub fn build(self) -> Diagnostic {
        let id = format!("{}-{}:{}", self.rule, self.file, self.line);
        Diagnostic {
            id,
            rule: self.rule,
            severity: self.severity,
            confidence: self.confidence,
            title: self.title,
            explanation: self.explanation,
            location: Location {
                file: self.file,
                line: self.line,
                column: self.column,
                end_line: self.end_line,
                end_column: self.end_column,
            },
            root_cause: self.root_cause,
            fix: self.fix,
            related: self.related,
            blast_radius: self.blast_radius,
            pattern: self.pattern,
            source: self.source,
            callee_key: self.callee_key,
        }
    }
}

/// Summary of analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    pub fix_available: usize,
    pub analysis_time_ms: u64,
}

impl AnalysisSummary {
    /// Create a summary from a list of diagnostics.
    pub fn from_diagnostics(diagnostics: &[Diagnostic], analysis_time_ms: u64) -> Self {
        let mut summary = Self {
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
            fix_available: 0,
            analysis_time_ms,
        };

        for diag in diagnostics {
            match diag.severity {
                Severity::Critical => summary.critical += 1,
                Severity::Error => summary.error += 1,
                Severity::Warning => summary.warning += 1,
                Severity::Info => summary.info += 1,
            }
            if diag.fix.is_some() {
                summary.fix_available += 1;
            }
        }

        summary
    }

    /// Total number of diagnostics.
    pub fn total(&self) -> usize {
        self.critical + self.error + self.warning + self.info
    }

    /// Whether there are any issues at or above a severity threshold.
    pub fn has_issues_above(&self, threshold: Severity) -> bool {
        match threshold {
            Severity::Info => self.total() > 0,
            Severity::Warning => self.warning + self.error + self.critical > 0,
            Severity::Error => self.error + self.critical > 0,
            Severity::Critical => self.critical > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_builder() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .confidence(0.95)
        .explanation("Variable 'user' may be nil because error was not checked")
        .root_cause("handler.go", 15, "missing return after error handling")
        .pattern(
            "missing-return-after-error",
            Frequency::VeryCommon,
            "Always add return after writing HTTP error response",
        )
        .build();

        assert_eq!(diag.id, "NIL001-handler.go:18");
        assert_eq!(diag.rule, "NIL001");
        assert_eq!(diag.severity, Severity::Critical);
        assert_eq!(diag.confidence, 0.95);
        assert_eq!(diag.location.file, "handler.go");
        assert_eq!(diag.location.line, 18);
        assert!(diag.root_cause.is_some());
        assert!(diag.pattern.is_some());
    }

    #[test]
    fn test_diagnostic_with_fix() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add return after error log",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 15,
                    end_line: 15,
                },
                old_text: Some("\t\tlog.Printf(\"error: %v\", err)".into()),
                new_text: "\t\tlog.Printf(\"error: %v\", err)\n\t\treturn".into(),
            }],
        )
        .build();

        assert!(diag.fix.is_some());
        let fix = diag.fix.unwrap();
        assert_eq!(fix.edits.len(), 1);
        assert!(fix.edits[0].new_text.contains("return"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn test_severity_threshold() {
        assert!(Severity::Critical.is_at_least(Severity::Warning));
        assert!(Severity::Warning.is_at_least(Severity::Warning));
        assert!(!Severity::Info.is_at_least(Severity::Warning));
    }

    #[test]
    fn test_analysis_summary() {
        let diagnostics = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 1, 0)
            .fix("fix", vec![])
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "error ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 2, 0)
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("c.go", 3, 0)
            .build(),
        ];

        let summary = AnalysisSummary::from_diagnostics(&diagnostics, 150);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.error, 1);
        assert_eq!(summary.warning, 1);
        assert_eq!(summary.info, 0);
        assert_eq!(summary.fix_available, 1);
        assert_eq!(summary.total(), 3);
        assert!(summary.has_issues_above(Severity::Warning));
        assert!(summary.has_issues_above(Severity::Critical));
    }

    #[test]
    fn test_diagnostic_json_roundtrip() {
        let diag = DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 42, 10)
        .explanation("The error return from os.Open is discarded")
        .build();

        let json = serde_json::to_string_pretty(&diag).unwrap();
        let parsed: Diagnostic = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.rule, "ERR001");
        assert_eq!(parsed.severity, Severity::Error);
        assert_eq!(parsed.location.line, 42);
    }

    #[test]
    fn test_location_display() {
        let loc = Location {
            file: "handler.go".into(),
            line: 18,
            column: 5,
            end_line: 18,
            end_column: 20,
        };
        assert_eq!(loc.to_string(), "handler.go:18:5");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Warning.to_string(), "warning");
    }

    #[test]
    fn test_diagnostic_source_display() {
        assert_eq!(DiagnosticSource::Nil.to_string(), "nil");
        assert_eq!(DiagnosticSource::Errcheck.to_string(), "errcheck");
    }

    #[test]
    fn test_risk_display() {
        assert_eq!(Risk::Low.to_string(), "low");
        assert_eq!(Risk::Medium.to_string(), "medium");
        assert_eq!(Risk::High.to_string(), "high");
    }

    #[test]
    fn test_diagnostic_with_callee_key() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .confidence(0.55)
        .callee_key("db.Find#0")
        .build();

        assert_eq!(diag.callee_key.as_deref(), Some("db.Find#0"));

        // Verify JSON roundtrip with callee_key
        let json = serde_json::to_string(&diag).unwrap();
        assert!(json.contains("callee_key"));
        let parsed: Diagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.callee_key.as_deref(), Some("db.Find#0"));
    }

    #[test]
    fn test_diagnostic_without_callee_key_omits_from_json() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .build();

        assert!(diag.callee_key.is_none());
        let json = serde_json::to_string(&diag).unwrap();
        assert!(!json.contains("callee_key"));
    }
}
