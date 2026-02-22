//! Skeleton diagnostic format — compact output for AI agents.
//!
//! Skeleton diagnostics contain only essential information (~50 tokens each):
//! - Rule ID, severity, title
//! - File, line, column
//! - Root cause line number
//! - Whether a fix is available
//!
//! The agent requests full details via goguard_explain or goguard_fix
//! only for diagnostics it wants to investigate — lazy fetching.

use crate::diagnostic::{Diagnostic, Severity};
use serde::{Deserialize, Serialize};

/// Compact diagnostic skeleton for agent output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticSkeleton {
    /// Unique ID: "{rule}-{file}:{line}" e.g. "NIL001-handler.go:18"
    pub id: String,
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub location: SkeletonLocation,
    /// Line where the root cause is (for quick navigation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause_line: Option<u32>,
    pub fix_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Summary with skeleton diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonOutput {
    pub summary: SkeletonSummary,
    pub diagnostics: Vec<DiagnosticSkeleton>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_plan: Option<FixPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonSummary {
    pub critical: u32,
    pub warning: u32,
    pub info: u32,
    pub fix_available: u32,
    pub analysis_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPlan {
    pub order: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cascading: Option<String>,
}

impl DiagnosticSkeleton {
    /// Convert a core Diagnostic to a compact skeleton.
    pub fn from_diagnostic(diag: &Diagnostic) -> Self {
        Self {
            id: diag.id.clone(),
            rule: diag.rule.clone(),
            severity: diag.severity.to_string(),
            title: diag.title.clone(),
            location: SkeletonLocation {
                file: diag.location.file.clone(),
                line: diag.location.line,
                column: diag.location.column,
            },
            root_cause_line: diag.root_cause.as_ref().map(|rc| rc.line),
            fix_available: diag.fix.is_some(),
        }
    }
}

impl SkeletonOutput {
    /// Convert a slice of core Diagnostics to a SkeletonOutput with summary.
    pub fn from_diagnostics(diagnostics: &[Diagnostic], analysis_time_ms: u64) -> Self {
        let skeletons: Vec<DiagnosticSkeleton> = diagnostics
            .iter()
            .map(DiagnosticSkeleton::from_diagnostic)
            .collect();

        let mut critical = 0u32;
        let mut warning = 0u32;
        let mut info = 0u32;
        let mut fix_available = 0u32;

        for diag in diagnostics {
            match diag.severity {
                Severity::Critical | Severity::Error => critical += 1,
                Severity::Warning => warning += 1,
                Severity::Info => info += 1,
            }
            if diag.fix.is_some() {
                fix_available += 1;
            }
        }

        Self {
            summary: SkeletonSummary {
                critical,
                warning,
                info,
                fix_available,
                analysis_time_ms,
            },
            diagnostics: skeletons,
            fix_plan: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

    #[test]
    fn test_skeleton_from_diagnostic() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .root_cause("handler.go", 15, "missing return after error handling")
        .fix("Add return", vec![])
        .build();

        let skeleton = DiagnosticSkeleton::from_diagnostic(&diag);
        assert_eq!(skeleton.id, "NIL001-handler.go:18");
        assert_eq!(skeleton.rule, "NIL001");
        assert_eq!(skeleton.severity, "critical");
        assert_eq!(skeleton.title, "nil pointer dereference");
        assert_eq!(skeleton.location.file, "handler.go");
        assert_eq!(skeleton.location.line, 18);
        assert_eq!(skeleton.location.column, 5);
        assert_eq!(skeleton.root_cause_line, Some(15));
        assert!(skeleton.fix_available);
    }

    #[test]
    fn test_skeleton_output_from_diagnostics() {
        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .fix("fix", vec![])
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Warning,
                "error ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 20, 1)
            .build(),
        ];

        let output = SkeletonOutput::from_diagnostics(&diags, 142);
        assert_eq!(output.summary.critical, 1);
        assert_eq!(output.summary.warning, 1);
        assert_eq!(output.summary.info, 0);
        assert_eq!(output.summary.fix_available, 1);
        assert_eq!(output.summary.analysis_time_ms, 142);
        assert_eq!(output.diagnostics.len(), 2);
        assert!(output.fix_plan.is_none());
    }

    #[test]
    fn test_skeleton_serialization() {
        let skeleton = DiagnosticSkeleton {
            id: "NIL001-handler.go:18".into(),
            rule: "NIL001".into(),
            severity: "critical".into(),
            title: "nil pointer dereference".into(),
            location: SkeletonLocation {
                file: "handler.go".into(),
                line: 18,
                column: 22,
            },
            root_cause_line: Some(15),
            fix_available: true,
        };

        let json = serde_json::to_string(&skeleton).unwrap();
        assert!(json.contains("NIL001"));
        assert!(json.contains("handler.go"));
        assert!(!json.contains("explanation")); // no explanation in skeleton!
        assert!(!json.contains("blast_radius")); // no blast radius in skeleton!
    }

    #[test]
    fn test_skeleton_output_compact() {
        let output = SkeletonOutput {
            summary: SkeletonSummary {
                critical: 2,
                warning: 5,
                info: 1,
                fix_available: 6,
                analysis_time_ms: 142,
            },
            diagnostics: vec![DiagnosticSkeleton {
                id: "NIL001-handler.go:18".into(),
                rule: "NIL001".into(),
                severity: "critical".into(),
                title: "nil pointer dereference".into(),
                location: SkeletonLocation {
                    file: "handler.go".into(),
                    line: 18,
                    column: 22,
                },
                root_cause_line: Some(15),
                fix_available: true,
            }],
            fix_plan: Some(FixPlan {
                order: vec!["NIL001-handler.go:18".into()],
                cascading: Some("Fixing NIL001 will likely resolve NIL003".into()),
            }),
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        // Estimate tokens: ~4 chars per token
        let estimated_tokens = json.len() / 4;
        assert!(
            estimated_tokens < 200,
            "Single skeleton should be well under 200 tokens, got {}",
            estimated_tokens
        );
    }

    #[test]
    fn test_50_skeletons_under_3000_tokens() {
        let diags: Vec<DiagnosticSkeleton> = (0..50)
            .map(|i| DiagnosticSkeleton {
                id: format!("NIL{:03}-file{}.go:{}", i % 6 + 1, i / 6, 10 + i),
                rule: format!("NIL{:03}", i % 6 + 1),
                severity: if i % 3 == 0 { "critical" } else { "warning" }.into(),
                title: "nil pointer dereference".into(),
                location: SkeletonLocation {
                    file: format!("file{}.go", i / 6),
                    line: 10 + i as u32,
                    column: 5,
                },
                root_cause_line: Some(8 + i as u32),
                fix_available: i % 2 == 0,
            })
            .collect();

        let output = SkeletonOutput {
            summary: SkeletonSummary {
                critical: 17,
                warning: 33,
                info: 0,
                fix_available: 25,
                analysis_time_ms: 350,
            },
            diagnostics: diags,
            fix_plan: None,
        };

        let json = serde_json::to_string(&output).unwrap();
        let estimated_tokens = json.len() / 4;
        assert!(
            estimated_tokens < 3000,
            "50 skeletons should be under 3000 tokens, got {}",
            estimated_tokens
        );
    }
}
