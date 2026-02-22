//! Full diagnostic format — detailed output with explanations, fixes, blast radius.
//!
//! Returned by goguard_explain and goguard_fix tools (~300 tokens per diagnostic).
//! Only requested by the agent for specific diagnostics — lazy fetching pattern.

use crate::diagnostic::Diagnostic;
use serde::{Deserialize, Serialize};

/// Full diagnostic detail — returned by goguard_explain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticFull {
    pub id: String,
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub explanation: String,
    pub location: FullLocation,
    pub root_cause: RootCause,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blast_radius: Option<BlastRadius>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<Pattern>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub file: String,
    pub line: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    pub affects_callers: u32,
    pub in_hot_path: bool,
    pub production_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub frequency: String,
    pub go_idiom: String,
}

/// Fix output — returned by goguard_fix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixOutput {
    pub diagnostic_id: String,
    pub description: String,
    pub edits: Vec<TextEdit>,
    /// Ready-to-exec shell commands for CodeAct agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    /// Combined bash script that applies all edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_script: Option<String>,
    pub verify_after_fix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEdit {
    pub file: String,
    pub range: EditRange,
    pub old_text: String,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRange {
    pub start_line: u32,
    pub end_line: u32,
}

impl DiagnosticFull {
    /// Convert a core Diagnostic to a full detail view.
    pub fn from_diagnostic(diag: &Diagnostic) -> Self {
        Self {
            id: diag.id.clone(),
            rule: diag.rule.clone(),
            severity: diag.severity.to_string(),
            title: diag.title.clone(),
            explanation: diag.explanation.clone(),
            location: FullLocation {
                file: diag.location.file.clone(),
                line: diag.location.line,
                column: diag.location.column,
                end_line: diag.location.end_line,
                end_column: diag.location.end_column,
            },
            root_cause: match &diag.root_cause {
                Some(rc) => RootCause {
                    file: rc.file.clone(),
                    line: rc.line,
                    description: rc.description.clone(),
                },
                None => RootCause {
                    file: diag.location.file.clone(),
                    line: diag.location.line,
                    description: diag.title.clone(),
                },
            },
            blast_radius: diag.blast_radius.as_ref().map(|br| BlastRadius {
                affects_callers: br.affects_callers,
                in_hot_path: br.in_hot_path,
                production_risk: br.production_risk.to_string(),
            }),
            pattern: diag.pattern.as_ref().map(|p| Pattern {
                name: p.name.clone(),
                frequency: serde_json::to_value(p.frequency)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| format!("{:?}", p.frequency)),
                go_idiom: p.go_idiom.clone(),
            }),
            related: diag.related.clone(),
        }
    }
}

impl FixOutput {
    /// Convert a core Diagnostic to a fix output. Returns None if no fix available.
    ///
    /// Generates both JSON text edits and executable shell commands for CodeAct agents.
    pub fn from_diagnostic(diag: &Diagnostic) -> Option<Self> {
        let fix = diag.fix.as_ref()?;
        let edits: Vec<TextEdit> = fix
            .edits
            .iter()
            .map(|e| TextEdit {
                file: e.file.clone(),
                range: EditRange {
                    start_line: e.range.start_line,
                    end_line: e.range.end_line,
                },
                old_text: e.old_text.clone().unwrap_or_default(),
                new_text: e.new_text.clone(),
            })
            .collect();

        // Generate executable shell commands for CodeAct agents
        let exec_edits = crate::executable::generate_shell_commands(&edits);
        let commands: Vec<String> = exec_edits.iter().map(|e| e.command.clone()).collect();
        let apply_script = if edits.is_empty() {
            None
        } else {
            Some(crate::executable::generate_apply_script(&edits))
        };

        Some(Self {
            diagnostic_id: diag.id.clone(),
            description: fix.description.clone(),
            edits,
            commands,
            apply_script,
            verify_after_fix: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{
        DiagnosticBuilder, DiagnosticSource, Edit, EditRange as CoreEditRange, Frequency, Risk,
        Severity,
    };

    #[test]
    fn test_full_from_diagnostic() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 22)
        .end_location(18, 31)
        .explanation("Variable 'user' may be nil")
        .root_cause("handler.go", 15, "missing return after error handling")
        .blast_radius(3, true, Risk::High)
        .pattern(
            "missing-return-after-error",
            Frequency::VeryCommon,
            "Always return after error response",
        )
        .related("NIL003-handler.go:42")
        .build();

        let full = DiagnosticFull::from_diagnostic(&diag);
        assert_eq!(full.id, "NIL001-handler.go:18");
        assert_eq!(full.severity, "critical");
        assert_eq!(full.explanation, "Variable 'user' may be nil");
        assert_eq!(full.root_cause.line, 15);
        assert!(full.blast_radius.is_some());
        let br = full.blast_radius.unwrap();
        assert_eq!(br.affects_callers, 3);
        assert!(br.in_hot_path);
        assert_eq!(br.production_risk, "high");
        assert!(full.pattern.is_some());
        assert_eq!(full.related, vec!["NIL003-handler.go:42"]);
    }

    #[test]
    fn test_full_no_optional_fields() {
        let diag = DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 10, 5)
        .explanation("The error from Open is discarded")
        .build();

        let full = DiagnosticFull::from_diagnostic(&diag);
        assert_eq!(full.id, "ERR001-main.go:10");
        assert!(full.blast_radius.is_none());
        assert!(full.pattern.is_none());
        assert!(full.related.is_empty());
        // root_cause defaults to location when None
        assert_eq!(full.root_cause.file, "main.go");
        assert_eq!(full.root_cause.line, 10);
    }

    #[test]
    fn test_fix_output_from_diagnostic() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add return after error",
            vec![Edit {
                file: "handler.go".into(),
                range: CoreEditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: Some("http.Error(w, \"not found\", 404)".into()),
                new_text: "http.Error(w, \"not found\", 404)\n\t\treturn".into(),
            }],
        )
        .build();

        let fix = FixOutput::from_diagnostic(&diag);
        assert!(fix.is_some());
        let fix = fix.unwrap();
        assert_eq!(fix.diagnostic_id, "NIL001-handler.go:18");
        assert_eq!(fix.description, "Add return after error");
        assert_eq!(fix.edits.len(), 1);
        assert!(fix.edits[0].new_text.contains("return"));
        assert!(fix.verify_after_fix);
    }

    #[test]
    fn test_fix_output_no_fix() {
        let diag = DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 10, 5)
        .build();

        let fix = FixOutput::from_diagnostic(&diag);
        assert!(fix.is_none());
    }

    #[test]
    fn test_full_diagnostic_serialization() {
        let full = DiagnosticFull {
            id: "NIL001-handler.go:18".into(),
            rule: "NIL001".into(),
            severity: "critical".into(),
            title: "nil pointer dereference".into(),
            explanation: "GetUser() returns (nil, error) on failure. After the error check on line 15, there is no return statement, so execution falls through to line 18 where user.Name dereferences a nil pointer.".into(),
            location: FullLocation {
                file: "handler.go".into(),
                line: 18, column: 22,
                end_line: 18, end_column: 31,
            },
            root_cause: RootCause {
                file: "handler.go".into(),
                line: 15,
                description: "missing return after error handling".into(),
            },
            blast_radius: Some(BlastRadius {
                affects_callers: 3,
                in_hot_path: true,
                production_risk: "high".into(),
            }),
            pattern: Some(Pattern {
                name: "missing-return-after-error-write".into(),
                frequency: "very_common".into(),
                go_idiom: "Always return after writing an HTTP error response".into(),
            }),
            related: vec!["NIL003-handler.go:42".into()],
        };

        let json = serde_json::to_string_pretty(&full).unwrap();
        assert!(json.contains("explanation"));
        assert!(json.contains("blast_radius"));
        assert!(json.contains("pattern"));
        assert!(json.contains("go_idiom"));

        // Full diagnostic should be around 300 tokens
        let estimated_tokens = json.len() / 4;
        assert!(
            estimated_tokens < 500,
            "Full diagnostic should be under 500 tokens, got {}",
            estimated_tokens
        );
    }

    #[test]
    fn test_fix_output_serialization() {
        let fix = FixOutput {
            diagnostic_id: "NIL001-handler.go:18".into(),
            description: "Add return after error response".into(),
            edits: vec![TextEdit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: "\t\thttp.Error(w, \"not found\", 404)".into(),
                new_text: "\t\thttp.Error(w, \"not found\", 404)\n\t\treturn".into(),
            }],
            commands: vec!["sed -i '' '16d' 'handler.go'".into()],
            apply_script: Some("#!/bin/bash\nset -e\nsed ...".into()),
            verify_after_fix: true,
        };

        let json = serde_json::to_string(&fix).unwrap();
        assert!(json.contains("return"));
        assert!(json.contains("verify_after_fix"));
        assert!(json.contains("commands"));
        assert!(json.contains("apply_script"));
    }

    #[test]
    fn test_fix_output_from_diagnostic_has_commands() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add return after error",
            vec![Edit {
                file: "handler.go".into(),
                range: CoreEditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: Some("http.Error(w, \"not found\", 404)".into()),
                new_text: "http.Error(w, \"not found\", 404)\n\t\treturn".into(),
            }],
        )
        .build();

        let fix = FixOutput::from_diagnostic(&diag).unwrap();
        // Should have executable commands
        assert!(
            !fix.commands.is_empty(),
            "from_diagnostic should generate commands"
        );
        assert!(
            fix.commands[0].contains("sed"),
            "command should be a sed command: {}",
            fix.commands[0]
        );
        // Should have apply script
        assert!(fix.apply_script.is_some(), "should have apply_script");
        let script = fix.apply_script.unwrap();
        assert!(
            script.starts_with("#!/bin/bash"),
            "script should start with shebang"
        );
        assert!(script.contains("set -e"), "script should have fail-fast");
    }

    #[test]
    fn test_fix_output_no_commands_when_empty() {
        let json =
            r#"{"diagnostic_id":"X","description":"test","edits":[],"verify_after_fix":false}"#;
        let fix: FixOutput = serde_json::from_str(json).unwrap();
        assert!(fix.commands.is_empty());
        assert!(fix.apply_script.is_none());
    }
}
