//! MCP tool parameter definitions for GoGuard analysis operations.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for the goguard_analyze tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AnalyzeParams {
    /// Go packages or files to analyze (default: ./...)
    #[serde(default)]
    pub files: Vec<String>,
    /// Minimum severity threshold: info, warning, error, critical
    #[serde(default)]
    pub severity_threshold: Option<String>,
    /// Maximum number of diagnostics to return
    #[serde(default)]
    pub max_diagnostics: Option<u32>,
}

/// Parameters for the goguard_explain tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExplainParams {
    /// Diagnostic ID to explain (e.g., "NIL001-handler.go:18")
    pub diagnostic_id: String,
}

/// Parameters for the goguard_fix tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FixParams {
    /// Diagnostic ID to get fix for (e.g., "NIL001-handler.go:18")
    pub diagnostic_id: String,
    /// Auto-verify: re-analyze after fix, return verification result (default: true)
    #[serde(default = "default_true")]
    pub auto_verify: bool,
}

fn default_true() -> bool {
    true
}

/// Parameters for the goguard_verify tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct VerifyParams {
    /// Go packages or files to re-analyze for verification
    #[serde(default)]
    pub files: Vec<String>,
}

/// Parameters for the goguard_rules tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RulesParams {
    /// Filter by category: nil, errcheck (optional, returns all if omitted)
    #[serde(default)]
    pub category: Option<String>,
}

/// Parameters for the goguard_batch tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BatchParams {
    /// Specific diagnostic IDs to fix
    #[serde(default)]
    pub diagnostic_ids: Vec<String>,
    /// Filter: fix all matching diagnostics (alternative to diagnostic_ids)
    #[serde(default)]
    pub filter: Option<BatchFilter>,
    /// Preview fixes without applying
    #[serde(default)]
    pub dry_run: bool,
}

/// Filter criteria for batch operations.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct BatchFilter {
    /// Filter by severity
    #[serde(default)]
    pub severity: Option<String>,
    /// Filter by rule prefix (e.g., "NIL" for all nil rules)
    #[serde(default)]
    pub rule_prefix: Option<String>,
    /// Filter by file path
    #[serde(default)]
    pub file: Option<String>,
}

/// Parameters for the goguard_query tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct QueryParams {
    /// GoGuard QL expression (e.g., "diagnostics where severity == \"critical\"")
    pub expression: String,
}

/// Parameters for the goguard_search tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// JavaScript code. The 'spec' and 'goguard' globals are available.
    pub code: String,
}

/// Parameters for the goguard_execute tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExecuteParams {
    /// JavaScript code. The 'goguard' global provides: .diagnostics(), .packages(), .callGraph(), .functions(), .rules(), .taintFlows(), .config
    pub code: String,
    /// Execution timeout in milliseconds (default: 5000)
    #[serde(default = "default_execute_timeout")]
    pub timeout_ms: u64,
}

fn default_execute_timeout() -> u64 {
    5000
}

/// Parameters for the goguard_snapshot tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SnapshotParams {
    /// Action: save, diff, list, restore
    pub action: String,
    /// Snapshot name (for save/restore/diff)
    #[serde(default)]
    pub name: Option<String>,
    /// Second snapshot name (for diff, compared against `name`)
    #[serde(default)]
    pub compare_to: Option<String>,
}

/// Parameters for the goguard_autofix tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AutofixParams {
    /// Go packages or files to analyze (default: ./...)
    #[serde(default)]
    pub packages: Vec<String>,
    /// Minimum severity threshold: info, warning, error, critical
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Maximum number of fixes to apply per run
    #[serde(default = "default_max_fixes")]
    pub max_fixes: usize,
    /// Maximum number of analysis iterations
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
    /// Run unit tests after each fix batch to verify
    #[serde(default)]
    pub test: bool,
    /// Only propose fixes, don't write to disk
    #[serde(default)]
    pub dry_run: bool,
}

/// Parameters for the goguard_teach tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct TeachParams {
    /// Pattern key from the elicitation request (e.g., "nil_return:db.Find#0").
    pub pattern_key: String,
    /// User's answer (e.g., "always_nil_on_error", "nonnull", "nilable", "partial_result_possible").
    pub answer: String,
}

fn default_severity() -> String {
    "error".to_string()
}

fn default_max_fixes() -> usize {
    50
}

fn default_max_iterations() -> usize {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_params_deserialize() {
        let json = r#"{"files": ["./cmd/..."], "severity_threshold": "error"}"#;
        let params: AnalyzeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.files, vec!["./cmd/..."]);
        assert_eq!(params.severity_threshold.as_deref(), Some("error"));
        assert!(params.max_diagnostics.is_none());
    }

    #[test]
    fn test_analyze_params_defaults() {
        let json = r#"{}"#;
        let params: AnalyzeParams = serde_json::from_str(json).unwrap();
        assert!(params.files.is_empty());
        assert!(params.severity_threshold.is_none());
    }

    #[test]
    fn test_explain_params_deserialize() {
        let json = r#"{"diagnostic_id": "NIL001-handler.go:18"}"#;
        let params: ExplainParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.diagnostic_id, "NIL001-handler.go:18");
    }

    #[test]
    fn test_fix_params_deserialize() {
        let json = r#"{"diagnostic_id": "ERR001-main.go:42"}"#;
        let params: FixParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.diagnostic_id, "ERR001-main.go:42");
    }

    #[test]
    fn test_rules_params_with_category() {
        let json = r#"{"category": "nil"}"#;
        let params: RulesParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.category.as_deref(), Some("nil"));
    }

    #[test]
    fn test_rules_params_no_category() {
        let json = r#"{}"#;
        let params: RulesParams = serde_json::from_str(json).unwrap();
        assert!(params.category.is_none());
    }

    #[test]
    fn test_fix_params_with_auto_verify_default() {
        let json = r#"{"diagnostic_id": "NIL001-handler.go:18"}"#;
        let params: FixParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.diagnostic_id, "NIL001-handler.go:18");
        assert!(params.auto_verify, "auto_verify should default to true");
    }

    #[test]
    fn test_fix_params_auto_verify_false() {
        let json = r#"{"diagnostic_id": "NIL001-handler.go:18", "auto_verify": false}"#;
        let params: FixParams = serde_json::from_str(json).unwrap();
        assert!(!params.auto_verify);
    }

    #[test]
    fn test_batch_params_with_ids() {
        let json = r#"{"diagnostic_ids": ["NIL001-a.go:1", "ERR001-b.go:2"]}"#;
        let params: BatchParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.diagnostic_ids.len(), 2);
        assert!(!params.dry_run);
        assert!(params.filter.is_none());
    }

    #[test]
    fn test_batch_params_with_filter() {
        let json = r#"{"filter": {"severity": "critical", "rule_prefix": "NIL"}}"#;
        let params: BatchParams = serde_json::from_str(json).unwrap();
        assert!(params.diagnostic_ids.is_empty());
        let filter = params.filter.unwrap();
        assert_eq!(filter.severity.as_deref(), Some("critical"));
        assert_eq!(filter.rule_prefix.as_deref(), Some("NIL"));
        assert!(filter.file.is_none());
    }

    #[test]
    fn test_query_params_deserialize() {
        let json = r#"{"expression": "diagnostics where severity == \"critical\""}"#;
        let params: QueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(
            params.expression,
            r#"diagnostics where severity == "critical""#
        );
    }

    #[test]
    fn test_snapshot_params_save() {
        let json = r#"{"action": "save", "name": "before_fixes"}"#;
        let params: SnapshotParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.action, "save");
        assert_eq!(params.name.as_deref(), Some("before_fixes"));
        assert!(params.compare_to.is_none());
    }

    #[test]
    fn test_search_params_deserialize() {
        let json = r#"{"code": "Object.keys(spec.api)"}"#;
        let params: SearchParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.code, "Object.keys(spec.api)");
    }

    #[test]
    fn test_execute_params_deserialize() {
        let json = r#"{"code": "goguard.diagnostics().length"}"#;
        let params: ExecuteParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.code, "goguard.diagnostics().length");
        assert_eq!(params.timeout_ms, 5000, "default timeout should be 5000ms");
    }

    #[test]
    fn test_execute_params_custom_timeout() {
        let json = r#"{"code": "goguard.diagnostics()", "timeout_ms": 10000}"#;
        let params: ExecuteParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.code, "goguard.diagnostics()");
        assert_eq!(params.timeout_ms, 10000);
    }

    #[test]
    fn test_teach_params_deserialize() {
        let json = r#"{"pattern_key": "nil_return:db.Find#0", "answer": "always_nil_on_error"}"#;
        let params: TeachParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.pattern_key, "nil_return:db.Find#0");
        assert_eq!(params.answer, "always_nil_on_error");
    }
}
