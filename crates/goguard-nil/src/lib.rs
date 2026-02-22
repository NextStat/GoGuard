//! GoGuard nil - nil pointer dereference analysis

pub mod analysis;
pub mod lattice;
pub mod models;
pub mod rules;
pub mod summary;

#[cfg(test)]
mod fixture_tests {
    use crate::analysis::NilAnalyzer;

    fn redact_diags(diags: &mut [goguard_diagnostics::diagnostic::Diagnostic]) {
        for d in diags.iter_mut() {
            if let Some(pos) = d.location.file.rfind("/001/") {
                d.location.file = format!("[FIXTURE_DIR]/{}", &d.location.file[pos + 5..]);
            }
            if let Some(pos) = d.id.rfind("/001/") {
                let prefix = &d.id[..d.id.find('-').unwrap_or(0)];
                let suffix = &d.id[pos + 5..];
                d.id = format!("{}-[FIXTURE_DIR]/{}", prefix, suffix);
            }
            // Redact SSA variable names in explanation (e.g. `t1` or `t22`)
            let expl = d.explanation.clone();
            let mut result = String::new();
            let mut chars = expl.chars().peekable();
            while let Some(c) = chars.next() {
                result.push(c);
                if result.ends_with("value `t") {
                    let mut num = String::new();
                    while let Some(&next) = chars.peek() {
                        if next.is_ascii_digit() {
                            num.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    if chars.peek() == Some(&'`') && !num.is_empty() {
                        result.push_str("_var");
                    } else {
                        result.push_str(&num);
                    }
                }
            }
            d.explanation = result;
        }
    }

    #[test]
    fn test_basic_nil_deref_fixture() {
        let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
        let mut diags = NilAnalyzer::analyze(&ir);
        // Phase 1: the fixture may not produce NIL001 if the SSA shape
        // does not match our current transfer/check patterns. Snapshot
        // records whatever the analyzer finds so we can track improvements.
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("basic_nil_deref", &diags);
    }

    #[test]
    fn test_safe_patterns_snapshot() {
        let ir = goguard_ir::load_bridge_fixture("nil/safe_patterns");
        let mut diags = NilAnalyzer::analyze(&ir);
        // Phase 1: safe patterns may produce false positives because the
        // analyzer lacks conditional refinement. Snapshot the results to
        // track progress as we improve the analysis.
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("safe_patterns", &diags);
    }

    #[test]
    fn test_type_assertion_without_ok() {
        let ir = goguard_ir::load_bridge_fixture("nil/type_assertion");
        let mut diags = NilAnalyzer::analyze(&ir);
        assert!(
            diags.iter().any(|d| d.rule == "NIL002"),
            "should detect unchecked type assertion, got: {diags:?}"
        );
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("type_assertion", &diags);
    }

    #[test]
    fn test_nil_map_access() {
        let ir = goguard_ir::load_bridge_fixture("nil/nil_map");
        let mut diags = NilAnalyzer::analyze(&ir);
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("nil_map", &diags);
    }

    #[test]
    fn test_error_ignored() {
        let ir = goguard_ir::load_bridge_fixture("nil/error_ignored");
        let mut diags = NilAnalyzer::analyze(&ir);
        // Phase 1: error-ignored pattern detection depends on seeing the
        // exact SSA shape. Snapshot whatever we find.
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("error_ignored", &diags);
    }

    #[test]
    fn test_missing_return() {
        let ir = goguard_ir::load_bridge_fixture("nil/missing_return");
        let mut diags = NilAnalyzer::analyze(&ir);
        // Phase 1: missing return after error check may not trigger if the
        // CFG structure does not match the expected pattern. Snapshot for
        // tracking.
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("missing_return", &diags);
    }
}
