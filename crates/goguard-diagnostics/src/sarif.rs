//! SARIF v2.1.0 output formatter for CI/CD integration.
//!
//! Produces SARIF JSON compatible with GitHub Security tab,
//! Azure DevOps, and other SARIF consumers.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::diagnostic::{Diagnostic, Severity};

// ---------------------------------------------------------------------------
// SARIF v2.1.0 data model
// ---------------------------------------------------------------------------

/// SARIF v2.1.0 root object.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run (one tool execution).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

/// Tool information.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// Tool driver with rules.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

/// A SARIF rule definition.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub short_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    pub default_configuration: SarifRuleConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

/// Default configuration for a rule (severity level).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleConfig {
    pub level: String,
}

/// A SARIF result (one diagnostic finding).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixes: Option<Vec<SarifFix>>,
}

/// A text message.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

/// A SARIF location (physical file + optional annotation message).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// Physical file location with artifact URI and region.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

/// Artifact (file) location.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

/// A region within a file (line/column ranges, 1-based).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: u32,
    pub start_column: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub end_line: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub end_column: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

/// A proposed fix.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifFix {
    pub description: SarifMessage,
    pub artifact_changes: Vec<SarifArtifactChange>,
}

/// Changes to a single artifact (file) within a fix.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactChange {
    pub artifact_location: SarifArtifactLocation,
    pub replacements: Vec<SarifReplacement>,
}

/// A single text replacement within a fix.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReplacement {
    pub deleted_region: SarifRegion,
    pub inserted_content: SarifInsertedContent,
}

/// Inserted text content.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInsertedContent {
    pub text: String,
}

// ---------------------------------------------------------------------------
// Conversion functions
// ---------------------------------------------------------------------------

/// Convert GoGuard diagnostics to a pretty-printed SARIF JSON string.
pub fn to_sarif(diagnostics: &[Diagnostic], version: &str) -> String {
    let log = to_sarif_log(diagnostics, version);
    serde_json::to_string_pretty(&log).expect("SARIF serialization should not fail")
}

/// Convert GoGuard diagnostics to a [`SarifLog`] struct.
pub fn to_sarif_log(diagnostics: &[Diagnostic], version: &str) -> SarifLog {
    let rules = collect_rules(diagnostics);
    let results: Vec<SarifResult> = diagnostics.iter().map(diagnostic_to_sarif_result).collect();

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "GoGuard".into(),
                    version: version.into(),
                    information_uri: "https://github.com/aspect-build/goguard".into(),
                    rules,
                },
            },
            results,
        }],
    }
}

/// Map GoGuard [`Severity`] to SARIF level string.
fn severity_to_sarif_level(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::Error => "error".into(),
        Severity::Warning => "warning".into(),
        Severity::Info => "note".into(),
    }
}

/// Convert a single [`Diagnostic`] to a [`SarifResult`].
fn diagnostic_to_sarif_result(diag: &Diagnostic) -> SarifResult {
    let primary_location = SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: diag.location.file.clone(),
            },
            region: SarifRegion {
                start_line: diag.location.line,
                start_column: diag.location.column,
                end_line: diag.location.end_line,
                end_column: diag.location.end_column,
            },
        },
        message: None,
    };

    let related_locations: Vec<SarifLocation> = diag
        .root_cause
        .as_ref()
        .map(|rc| {
            vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: rc.file.clone(),
                    },
                    region: SarifRegion {
                        start_line: rc.line,
                        start_column: 1,
                        end_line: 0,
                        end_column: 0,
                    },
                },
                message: Some(SarifMessage {
                    text: rc.description.clone(),
                }),
            }]
        })
        .unwrap_or_default();

    let fixes = diag.fix.as_ref().map(|fix| {
        vec![SarifFix {
            description: SarifMessage {
                text: fix.description.clone(),
            },
            artifact_changes: fix
                .edits
                .iter()
                .map(|edit| SarifArtifactChange {
                    artifact_location: SarifArtifactLocation {
                        uri: edit.file.clone(),
                    },
                    replacements: vec![SarifReplacement {
                        deleted_region: SarifRegion {
                            start_line: edit.range.start_line,
                            start_column: 1,
                            end_line: edit.range.end_line,
                            end_column: 0,
                        },
                        inserted_content: SarifInsertedContent {
                            text: edit.new_text.clone(),
                        },
                    }],
                })
                .collect(),
        }]
    });

    // Build the message: use explanation if non-empty, otherwise fall back to title.
    let message_text = if diag.explanation.is_empty() {
        diag.title.clone()
    } else {
        diag.explanation.clone()
    };

    SarifResult {
        rule_id: diag.rule.clone(),
        level: severity_to_sarif_level(diag.severity),
        message: SarifMessage { text: message_text },
        locations: vec![primary_location],
        related_locations,
        fixes,
    }
}

/// Collect unique rule definitions from diagnostics, deduplicated by rule code.
///
/// When the same rule appears with different severities across diagnostics,
/// the first occurrence's severity wins (stable ordering).
fn collect_rules(diagnostics: &[Diagnostic]) -> Vec<SarifRule> {
    let mut seen: BTreeMap<String, SarifRule> = BTreeMap::new();

    for diag in diagnostics {
        seen.entry(diag.rule.clone()).or_insert_with(|| SarifRule {
            id: diag.rule.clone(),
            short_description: SarifMessage {
                text: diag.title.clone(),
            },
            full_description: if diag.explanation.is_empty() {
                None
            } else {
                Some(SarifMessage {
                    text: diag.explanation.clone(),
                })
            },
            default_configuration: SarifRuleConfig {
                level: severity_to_sarif_level(diag.severity),
            },
            help_uri: None,
        });
    }

    seen.into_values().collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity};

    fn make_test_diag(rule: &str, severity: Severity, file: &str, line: u32) -> Diagnostic {
        DiagnosticBuilder::new(
            rule,
            severity,
            format!("{} issue", rule),
            DiagnosticSource::Nil,
        )
        .location(file, line, 5)
        .explanation(format!("Explanation for {}", rule))
        .confidence(0.9)
        .build()
    }

    #[test]
    fn test_sarif_schema_and_version() {
        let diags = vec![make_test_diag("NIL001", Severity::Critical, "main.go", 10)];
        let log = to_sarif_log(&diags, "0.1.0");
        assert_eq!(log.version, "2.1.0");
        assert!(log.schema.contains("sarif"));
    }

    #[test]
    fn test_sarif_tool_info() {
        let log = to_sarif_log(&[], "0.1.0");
        assert_eq!(log.runs.len(), 1);
        assert_eq!(log.runs[0].tool.driver.name, "GoGuard");
        assert_eq!(log.runs[0].tool.driver.version, "0.1.0");
    }

    #[test]
    fn test_sarif_result_mapping() {
        let diags = vec![make_test_diag(
            "NIL001",
            Severity::Critical,
            "handler.go",
            18,
        )];
        let log = to_sarif_log(&diags, "0.1.0");
        assert_eq!(log.runs[0].results.len(), 1);
        let result = &log.runs[0].results[0];
        assert_eq!(result.rule_id, "NIL001");
        assert_eq!(result.level, "error");
        assert_eq!(result.locations[0].physical_location.region.start_line, 18);
    }

    #[test]
    fn test_sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(Severity::Error), "error");
        assert_eq!(severity_to_sarif_level(Severity::Warning), "warning");
        assert_eq!(severity_to_sarif_level(Severity::Info), "note");
    }

    #[test]
    fn test_sarif_rules_deduplication() {
        let diags = vec![
            make_test_diag("NIL001", Severity::Critical, "a.go", 1),
            make_test_diag("NIL001", Severity::Critical, "b.go", 2),
            make_test_diag("ERR001", Severity::Error, "c.go", 3),
        ];
        let log = to_sarif_log(&diags, "0.1.0");
        assert_eq!(log.runs[0].tool.driver.rules.len(), 2); // NIL001 + ERR001
    }

    #[test]
    fn test_sarif_empty_diagnostics() {
        let log = to_sarif_log(&[], "0.1.0");
        assert!(log.runs[0].results.is_empty());
    }

    #[test]
    fn test_sarif_json_valid() {
        let diags = vec![make_test_diag("NIL001", Severity::Critical, "main.go", 10)];
        let json = to_sarif(&diags, "0.1.0");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["$schema"].as_str().unwrap().contains("sarif"));
    }

    #[test]
    fn test_sarif_with_root_cause_as_related_location() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .root_cause("handler.go", 12, "Error not checked here")
        .build();
        let log = to_sarif_log(&[diag], "0.1.0");
        let result = &log.runs[0].results[0];
        assert_eq!(result.related_locations.len(), 1);
        assert_eq!(
            result.related_locations[0].message.as_ref().unwrap().text,
            "Error not checked here"
        );
    }

    #[test]
    fn test_sarif_with_fix() {
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
                range: EditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: Some("http.Error(w, \"not found\", 404)".into()),
                new_text: "http.Error(w, \"not found\", 404)\n\t\treturn".into(),
            }],
        )
        .build();

        let log = to_sarif_log(&[diag], "0.1.0");
        let result = &log.runs[0].results[0];
        assert!(result.fixes.is_some());
        let fixes = result.fixes.as_ref().unwrap();
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].description.text, "Add return after error");
        assert_eq!(fixes[0].artifact_changes.len(), 1);
        assert!(fixes[0].artifact_changes[0].replacements[0]
            .inserted_content
            .text
            .contains("return"));
    }

    #[test]
    fn test_sarif_no_related_locations_when_no_root_cause() {
        let diag = DiagnosticBuilder::new(
            "ERR001",
            Severity::Warning,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 10, 3)
        .build();

        let log = to_sarif_log(&[diag], "0.1.0");
        let result = &log.runs[0].results[0];
        assert!(result.related_locations.is_empty());
    }

    #[test]
    fn test_sarif_message_uses_explanation() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .explanation("Detailed explanation of the issue")
        .build();

        let log = to_sarif_log(&[diag], "0.1.0");
        let result = &log.runs[0].results[0];
        assert_eq!(result.message.text, "Detailed explanation of the issue");
    }

    #[test]
    fn test_sarif_message_falls_back_to_title() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .build();

        let log = to_sarif_log(&[diag], "0.1.0");
        let result = &log.runs[0].results[0];
        assert_eq!(result.message.text, "nil deref");
    }
}
