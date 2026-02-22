//! Salsa input types for incremental analysis.

/// Per-package IR stored as Salsa input.
/// Uses JSON serialization + content hash for change detection.
/// Package has f64 fields (Diagnostic.confidence), so we can't derive Eq directly.
/// Instead we use content_hash for Salsa's change detection.
#[salsa::input]
pub struct PackageInput {
    /// The Go import path for this package.
    pub import_path: String,

    /// JSON-serialized package IR.
    pub ir_json: String,

    /// Hash of ir_json for fast change detection.
    pub content_hash: u64,
}

/// Analysis configuration. Set with Durability::HIGH (rarely changes).
#[salsa::input]
pub struct AnalysisConfigInput {
    /// Whether nil analysis is enabled.
    pub nil_enabled: bool,
    /// Whether nil analysis uses strict parameter semantics.
    pub nil_strict_params: bool,
    /// User-provided nil return models: (key, value) pairs.
    pub nil_models: Vec<(String, String)>,

    /// Whether errcheck analysis is enabled.
    pub errcheck_enabled: bool,

    /// Whether concurrency analysis is enabled.
    pub concurrency_enabled: bool,

    /// Whether ownership analysis is enabled.
    pub ownership_enabled: bool,

    /// Whether exhaustive analysis is enabled.
    pub exhaustive_enabled: bool,

    /// Whether taint analysis is enabled.
    pub taint_enabled: bool,

    /// Severity threshold (e.g. "warning", "error").
    pub severity_threshold: String,

    /// Maximum diagnostics to return.
    pub max_diagnostics: usize,

    /// Errcheck ignore patterns.
    pub errcheck_ignore: Vec<String>,
}

/// Global analysis context (interface table, enum groups).
/// Shared across all packages for exhaustive analysis.
#[salsa::input]
pub struct GlobalContextInput {
    /// JSON-serialized interface table.
    pub interface_table_json: String,

    /// JSON-serialized enum groups.
    pub enum_groups_json: String,

    /// Hash for change detection.
    pub content_hash: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::GoGuardDatabase;

    #[test]
    fn test_package_input_roundtrip() {
        let db = GoGuardDatabase::default();
        let pkg = PackageInput::new(
            &db,
            "example.com/test".to_string(),
            r#"{"functions":[]}"#.to_string(),
            12345u64,
        );
        assert_eq!(pkg.import_path(&db), "example.com/test");
        assert_eq!(pkg.ir_json(&db), r#"{"functions":[]}"#);
        assert_eq!(pkg.content_hash(&db), 12345);
    }

    #[test]
    fn test_config_input_roundtrip() {
        let db = GoGuardDatabase::default();
        let config = AnalysisConfigInput::new(
            &db,
            true,
            false,
            vec![("x.F".to_string(), "nonnull".to_string())],
            true,
            true,
            true,
            true,
            true,
            "warning".to_string(),
            100usize,
            vec!["fmt.Print*".to_string()],
        );
        assert!(config.nil_enabled(&db));
        assert!(!config.nil_strict_params(&db));
        assert_eq!(
            config.nil_models(&db),
            vec![("x.F".to_string(), "nonnull".to_string())]
        );
        assert!(config.errcheck_enabled(&db));
        assert!(config.concurrency_enabled(&db));
        assert!(config.ownership_enabled(&db));
        assert!(config.exhaustive_enabled(&db));
        assert!(config.taint_enabled(&db));
        assert_eq!(config.severity_threshold(&db), "warning");
        assert_eq!(config.max_diagnostics(&db), 100);
        assert_eq!(config.errcheck_ignore(&db), vec!["fmt.Print*".to_string()]);
    }
}
