//! Analysis orchestrator — coordinates bridge, analysis passes, and output.

use crate::bridge_manager::{BridgeError, GoBridge};
use crate::config::Config;
use goguard_db::cache::IrCache;
use goguard_db::db::GoGuardDatabase;
use goguard_db::queries;
use goguard_diagnostics::diagnostic::{Diagnostic, Severity};
use goguard_ir::ir::AnalysisInput;
use std::path::Path;

/// Complete output from an analysis run.
#[derive(Debug, Clone)]
pub struct AnalysisOutput {
    pub diagnostics: Vec<Diagnostic>,
    pub summary: AnalysisSummary,
    pub bridge_errors: Vec<String>,
}

/// Summary statistics for the analysis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisSummary {
    pub total: usize,
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    pub packages_analyzed: usize,
    pub functions_analyzed: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("bridge error: {0}")]
    Bridge(#[from] BridgeError),
}

/// Run full analysis pipeline: spawn bridge -> get IR -> run passes -> merge.
pub fn analyze_project(
    dir: &Path,
    packages: &[String],
    config: &Config,
) -> Result<AnalysisOutput, OrchestratorError> {
    let bridge = GoBridge::new()?;
    let cache_dir = crate::config::resolve_bridge_cache_dir(&config.goguard);
    let ir = bridge.analyze_packages_sync_with_cache(
        dir,
        packages,
        cache_dir.as_deref(),
        config.goguard.max_cache_entries,
    )?;
    Ok(analyze_ir(&ir, config))
}

/// Run analysis passes on already-loaded IR.
/// Used by both the CLI (after bridge) and tests (from fixtures).
pub fn analyze_ir(ir: &AnalysisInput, config: &Config) -> AnalysisOutput {
    let mut all_diags = Vec::new();

    // Run nil analysis
    if config.rules.nil.enabled {
        let mut nil_models: Vec<(String, String)> = config
            .rules
            .nil
            .models
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        nil_models.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let nil_options = goguard_nil::analysis::NilOptions {
            strict_params: config.rules.nil.strict_params,
            user_models: goguard_nil::analysis::parse_user_models(&nil_models),
        };

        let nil_diags = goguard_nil::analysis::NilAnalyzer::analyze_with_options(ir, &nil_options);
        all_diags.extend(nil_diags);
    }

    // Run errcheck analysis
    if config.rules.errcheck.enabled {
        let ignore_refs: Vec<&str> = config
            .rules
            .errcheck
            .ignore
            .iter()
            .map(|s| s.as_str())
            .collect();
        let err_diags =
            goguard_errcheck::analysis::ErrcheckAnalyzer::analyze_with_ignore(ir, &ignore_refs);
        all_diags.extend(err_diags);
    }

    // Run concurrency analysis
    if config.rules.concurrency.enabled {
        let conc_diags = goguard_concurrency::analysis::ConcurrencyAnalyzer::analyze(ir);
        all_diags.extend(conc_diags);
    }

    // Run ownership analysis
    if config.rules.ownership.enabled {
        let own_diags = goguard_ownership::analysis::OwnershipAnalyzer::analyze(ir);
        all_diags.extend(own_diags);
    }

    // Run exhaustive analysis
    if config.rules.exhaustive.enabled {
        let exh_diags = goguard_exhaustive::analysis::ExhaustiveAnalyzer::analyze(ir);
        all_diags.extend(exh_diags);
    }

    // Run taint analysis
    if config.rules.taint.enabled {
        let taint_diags = goguard_taint::analysis::TaintAnalyzer::analyze(ir);
        all_diags.extend(taint_diags);
    }

    postprocess_diagnostics(all_diags, config, ir)
}

/// Shared post-processing: severity filter, sort, truncate, build summary.
/// Used by both `analyze_ir` (non-incremental) and `IncrementalAnalyzer::analyze`.
fn postprocess_diagnostics(
    mut diags: Vec<Diagnostic>,
    config: &Config,
    ir: &AnalysisInput,
) -> AnalysisOutput {
    let threshold = parse_severity(&config.goguard.severity_threshold);
    diags.retain(|d| d.severity.is_at_least(threshold));

    diags.sort_by(|a, b| {
        a.location
            .file
            .cmp(&b.location.file)
            .then(a.location.line.cmp(&b.location.line))
            .then(b.severity.cmp(&a.severity))
    });

    if config.goguard.max_diagnostics > 0 && diags.len() > config.goguard.max_diagnostics {
        diags.truncate(config.goguard.max_diagnostics);
    }

    let summary = AnalysisSummary {
        total: diags.len(),
        critical: diags
            .iter()
            .filter(|d| d.severity == Severity::Critical)
            .count(),
        error: diags
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count(),
        warning: diags
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count(),
        info: diags
            .iter()
            .filter(|d| d.severity == Severity::Info)
            .count(),
        packages_analyzed: ir.packages.len(),
        functions_analyzed: ir.packages.iter().map(|p| p.functions.len()).sum(),
    };

    AnalysisOutput {
        diagnostics: diags,
        summary,
        bridge_errors: Vec::new(),
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        _ => Severity::Warning,
    }
}

/// Incremental analyzer for long-running processes (MCP, LSP).
/// Holds a Salsa DB that persists across analysis runs, enabling
/// memoization of unchanged packages.
#[derive(Clone)]
pub struct IncrementalAnalyzer {
    db: GoGuardDatabase,
    cache: IrCache,
}

impl IncrementalAnalyzer {
    /// Create a new incremental analyzer with an empty Salsa DB.
    pub fn new() -> Self {
        Self {
            db: GoGuardDatabase::default(),
            cache: IrCache::new(),
        }
    }

    /// Run incremental analysis. Only re-analyzes packages whose IR changed.
    /// Returns the same `AnalysisOutput` as `analyze_ir` for compatibility.
    pub fn analyze(&mut self, ir: &AnalysisInput, config: &Config) -> AnalysisOutput {
        // Update config in Salsa DB
        let ignore: Vec<String> = config.rules.errcheck.ignore.clone();
        let mut nil_models: Vec<(String, String)> = config
            .rules
            .nil
            .models
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        nil_models.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        self.cache.update_config(
            &mut self.db,
            config.rules.nil.enabled,
            config.rules.nil.strict_params,
            &nil_models,
            config.rules.errcheck.enabled,
            config.rules.concurrency.enabled,
            config.rules.ownership.enabled,
            config.rules.exhaustive.enabled,
            config.rules.taint.enabled,
            &config.goguard.severity_threshold,
            config.goguard.max_diagnostics,
            &ignore,
        );

        // Update IR packages — only changed packages get new Salsa inputs
        let updated = self.cache.update_ir(&mut self.db, ir);

        // Update global context for exhaustive analysis
        self.cache.update_global_context(&mut self.db, ir);

        tracing::info!(
            total = ir.packages.len(),
            updated = updated,
            "incremental analysis"
        );

        // Collect diagnostics from all packages using Salsa queries
        let mut all_diags: Vec<Diagnostic> = Vec::new();
        let salsa_config = self
            .cache
            .config()
            .expect("config must be set after update_config");

        for pkg_input in self.cache.all_packages() {
            if config.rules.nil.enabled {
                all_diags.extend(queries::nil_diagnostics(&self.db, pkg_input, salsa_config));
            }
            if config.rules.errcheck.enabled {
                all_diags.extend(queries::errcheck_diagnostics(
                    &self.db,
                    pkg_input,
                    salsa_config,
                ));
            }
            if config.rules.concurrency.enabled {
                all_diags.extend(queries::concurrency_diagnostics(&self.db, pkg_input));
            }
            if config.rules.ownership.enabled {
                all_diags.extend(queries::ownership_diagnostics(&self.db, pkg_input));
            }
            if config.rules.exhaustive.enabled {
                if let Some(global_ctx) = self.cache.global_context() {
                    all_diags.extend(queries::exhaustive_diagnostics(
                        &self.db, pkg_input, global_ctx,
                    ));
                }
            }
            if config.rules.taint.enabled {
                all_diags.extend(queries::taint_diagnostics(&self.db, pkg_input));
            }
        }

        postprocess_diagnostics(all_diags, config, ir)
    }
}

impl Default for IncrementalAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_analyze_ir_nil_fixture() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let config = Config::default();
        let output = analyze_ir(&ir, &config);
        assert!(
            !output.diagnostics.is_empty(),
            "basic_nil_deref should produce diagnostics"
        );
        assert!(output.summary.total > 0);
    }

    #[test]
    fn test_analyze_ir_errcheck_fixture() {
        let ir = goguard_ir::load_bridge_fixture("errcheck/ignored_error");
        let config = Config::default();
        let output = analyze_ir(&ir, &config);
        assert!(
            output.diagnostics.iter().any(|d| d.rule.starts_with("ERR")),
            "should detect errcheck issues"
        );
    }

    #[test]
    fn test_analyze_ir_disabled_nil() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let mut config = Config::default();
        config.rules.nil.enabled = false;
        let output = analyze_ir(&ir, &config);
        assert!(
            !output.diagnostics.iter().any(|d| d.rule.starts_with("NIL")),
            "nil analysis should be disabled"
        );
    }

    #[test]
    fn test_analyze_ir_severity_filter() {
        let ir = goguard_ir::load_bridge_fixture("errcheck/ignored_error");
        let mut config = Config::default();
        config.goguard.severity_threshold = "error".to_string();
        let output = analyze_ir(&ir, &config);
        for d in &output.diagnostics {
            assert!(
                d.severity.is_at_least(Severity::Error),
                "all diagnostics should be at least error severity"
            );
        }
    }

    #[test]
    fn test_analyze_ir_sorted_output() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let config = Config::default();
        let output = analyze_ir(&ir, &config);
        for w in output.diagnostics.windows(2) {
            let cmp = w[0]
                .location
                .file
                .cmp(&w[1].location.file)
                .then(w[0].location.line.cmp(&w[1].location.line));
            assert!(
                cmp != std::cmp::Ordering::Greater,
                "diagnostics should be sorted by file then line"
            );
        }
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("error"), Severity::Error);
        assert_eq!(parse_severity("warning"), Severity::Warning);
        assert_eq!(parse_severity("info"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Warning);
    }

    // --- IncrementalAnalyzer tests ---

    #[test]
    fn test_incremental_matches_non_incremental() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let config = Config::default();

        let non_inc = analyze_ir(&ir, &config);
        let mut inc = IncrementalAnalyzer::new();
        let inc_output = inc.analyze(&ir, &config);

        // Both should produce the same diagnostic IDs and rules
        assert_eq!(
            non_inc.diagnostics.len(),
            inc_output.diagnostics.len(),
            "incremental and non-incremental should produce same number of diagnostics"
        );
        for (a, b) in non_inc
            .diagnostics
            .iter()
            .zip(inc_output.diagnostics.iter())
        {
            assert_eq!(a.id, b.id);
            assert_eq!(a.rule, b.rule);
        }
    }

    #[test]
    fn test_incremental_second_run_zero_updates() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let config = Config::default();
        let mut inc = IncrementalAnalyzer::new();

        let output1 = inc.analyze(&ir, &config);
        let output2 = inc.analyze(&ir, &config);

        // Same input -> same output
        assert_eq!(output1.diagnostics.len(), output2.diagnostics.len());
    }

    #[test]
    fn test_incremental_detects_package_change() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let config = Config::default();
        let mut inc = IncrementalAnalyzer::new();

        let output1 = inc.analyze(&ir, &config);

        // Now use safe_patterns (should produce different diagnostics)
        let ir2 = goguard_ir::load_bridge_fixture("nil/safe_patterns");
        let output2 = inc.analyze(&ir2, &config);

        // The outputs should differ since the packages are different
        // We just verify the analyzer doesn't crash and returns valid output
        let _ = output2.summary.total; // proves no panic
                                       // Also verify that at least something changed in the output
        let different = output1.diagnostics.len() != output2.diagnostics.len()
            || output1
                .diagnostics
                .iter()
                .zip(output2.diagnostics.iter())
                .any(|(a, b)| a.id != b.id);
        assert!(
            different,
            "switching fixtures should produce different diagnostics"
        );
    }

    #[test]
    fn test_orchestrator_uses_cache_config() {
        // Verify that resolve_bridge_cache_dir returns expected values for
        // various config states — this is what analyze_project now uses.
        use crate::config::{resolve_bridge_cache_dir, GoguardConfig};

        // Default config: cache enabled, platform default dir
        let default_cfg = GoguardConfig::default();
        let resolved = resolve_bridge_cache_dir(&default_cfg);
        assert!(
            resolved.is_some(),
            "default config should resolve a cache dir"
        );

        // no_cache = true: cache disabled
        let no_cache_cfg = GoguardConfig {
            no_cache: true,
            ..Default::default()
        };
        assert!(resolve_bridge_cache_dir(&no_cache_cfg).is_none());

        // Explicit cache_dir overrides platform default
        let explicit_cfg = GoguardConfig {
            cache_dir: Some("/tmp/goguard-test-cache".to_string()),
            ..Default::default()
        };
        let resolved = resolve_bridge_cache_dir(&explicit_cfg);
        assert_eq!(
            resolved,
            Some(std::path::PathBuf::from("/tmp/goguard-test-cache"))
        );

        // max_cache_entries is passed through to bridge (default 20)
        assert_eq!(default_cfg.max_cache_entries, 20);
    }

    #[test]
    fn test_incremental_config_disable_nil() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");

        let config_on = Config::default(); // nil enabled by default
        let mut config_off = Config::default();
        config_off.rules.nil.enabled = false;

        let mut inc = IncrementalAnalyzer::new();

        let with_nil = inc.analyze(&ir, &config_on);
        let nil_count = with_nil
            .diagnostics
            .iter()
            .filter(|d| d.rule.starts_with("NIL"))
            .count();

        let without_nil = inc.analyze(&ir, &config_off);
        let nil_count_off = without_nil
            .diagnostics
            .iter()
            .filter(|d| d.rule.starts_with("NIL"))
            .count();

        assert!(nil_count > 0, "should have nil diagnostics when enabled");
        assert_eq!(
            nil_count_off, 0,
            "should have no nil diagnostics when disabled"
        );
    }
}
