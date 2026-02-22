//! GoGuard errcheck - unchecked error analysis

pub mod analysis;
pub mod rules;

#[cfg(test)]
mod fixture_tests {
    use crate::analysis::ErrcheckAnalyzer;

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
        }
    }

    #[test]
    fn test_error_ignored_fixture() {
        let ir = goguard_ir::load_bridge_fixture("errcheck/ignored_error");
        let mut diags = ErrcheckAnalyzer::analyze(&ir);
        assert!(
            !diags.is_empty(),
            "should detect errcheck issues in ignored_error fixture, got empty"
        );
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("error_ignored", &diags);
    }

    #[test]
    fn test_safe_error_handling() {
        let ir = goguard_ir::load_bridge_fixture("errcheck/safe_error_handling");
        let mut diags = ErrcheckAnalyzer::analyze(&ir);
        redact_diags(&mut diags);
        insta::assert_yaml_snapshot!("safe_error_handling", &diags);
    }
}
