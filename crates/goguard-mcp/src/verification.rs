//! Verification and batch result types for CodeAct-enhanced MCP tools.

use goguard_diagnostics::diagnostic::Diagnostic;
use serde::Serialize;

/// Result of auto-verification after a fix.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    pub status: String,
    pub remaining_in_file: usize,
    pub new_issues_introduced: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub new_issues: Vec<NewIssueSkeleton>,
    pub affected_packages: Vec<String>,
}

/// Compact representation of a newly introduced issue.
#[derive(Debug, Clone, Serialize)]
pub struct NewIssueSkeleton {
    pub id: String,
    pub rule: String,
    pub title: String,
    pub severity: String,
}

/// Result of a batch fix operation.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub applied: Vec<BatchFixStatus>,
    pub verification: BatchVerification,
    pub remaining_diagnostics: Vec<NewIssueSkeleton>,
}

/// Status of a single fix in a batch.
#[derive(Debug, Clone, Serialize)]
pub struct BatchFixStatus {
    pub diagnostic_id: String,
    pub status: String,
}

/// Verification summary for batch operations.
#[derive(Debug, Clone, Serialize)]
pub struct BatchVerification {
    pub before: SeverityCounts,
    pub after: SeverityCounts,
    pub resolved: usize,
    pub new_issues_introduced: usize,
}

/// Severity counts used in verification summaries.
#[derive(Debug, Clone, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn from_diagnostics(diagnostics: &[Diagnostic]) -> Self {
        use goguard_diagnostics::diagnostic::Severity;
        let mut counts = Self {
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
        };
        for d in diagnostics {
            match d.severity {
                Severity::Critical => counts.critical += 1,
                Severity::Error => counts.error += 1,
                Severity::Warning => counts.warning += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

/// Diff between two snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotDiff {
    pub resolved: Vec<NewIssueSkeleton>,
    pub new: Vec<NewIssueSkeleton>,
    pub unchanged: usize,
    pub summary: SnapshotDiffSummary,
}

/// Summary section of a snapshot diff.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotDiffSummary {
    pub before: SeverityCounts,
    pub after: SeverityCounts,
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

    #[test]
    fn test_severity_counts_from_diagnostics() {
        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("c.go", 30, 1)
            .build(),
        ];
        let counts = SeverityCounts::from_diagnostics(&diags);
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.error, 1);
        assert_eq!(counts.warning, 1);
        assert_eq!(counts.info, 0);
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            status: "resolved".to_string(),
            remaining_in_file: 2,
            new_issues_introduced: 0,
            new_issues: vec![],
            affected_packages: vec!["example.com/app/handler".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("resolved"));
        assert!(json.contains("remaining_in_file"));
        // "new_issues" array should be skipped when empty (skip_serializing_if)
        // but "new_issues_introduced" should still be present
        assert!(json.contains("new_issues_introduced"));
        assert!(!json.contains("\"new_issues\":"));
    }

    #[test]
    fn test_snapshot_diff_serialization() {
        let diff = SnapshotDiff {
            resolved: vec![NewIssueSkeleton {
                id: "NIL001-a.go:10".to_string(),
                rule: "NIL001".to_string(),
                title: "nil deref".to_string(),
                severity: "critical".to_string(),
            }],
            new: vec![],
            unchanged: 5,
            summary: SnapshotDiffSummary {
                before: SeverityCounts {
                    critical: 2,
                    error: 1,
                    warning: 3,
                    info: 0,
                },
                after: SeverityCounts {
                    critical: 1,
                    error: 1,
                    warning: 3,
                    info: 0,
                },
            },
        };
        let json = serde_json::to_string_pretty(&diff).unwrap();
        assert!(json.contains("resolved"));
        assert!(json.contains("unchanged"));
        assert!(json.contains("\"critical\": 2"));
    }
}
