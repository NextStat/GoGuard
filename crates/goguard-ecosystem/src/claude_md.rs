//! CLAUDE.md generation from GoGuard config.
//!
//! Generates GoGuard sections for CLAUDE.md files with round-trip safe
//! `<!-- goguard:begin -->` / `<!-- goguard:end -->` markers. Existing
//! content outside the markers is preserved during updates.

use goguard_core::config::Config;

/// Generate GoGuard section for CLAUDE.md from config.
pub fn generate_section(config: &Config) -> String {
    let mut s = String::new();
    s.push_str("## GoGuard Configuration\n\n");
    s.push_str("### Build & Test\n\n");
    s.push_str("- Build: `cargo build`\n");
    s.push_str("- Test: `cargo test`\n");
    s.push_str("- Lint: `cargo clippy -- -W clippy::all`\n");
    s.push_str("\n### Enabled Rules\n\n");
    s.push_str(&format!(
        "- nil analysis: {}\n",
        if config.rules.nil.enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    s.push_str(&format!(
        "- errcheck analysis: {}\n",
        if config.rules.errcheck.enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    s.push_str("\n### Settings\n\n");
    s.push_str(&format!(
        "- Severity threshold: {}\n",
        config.goguard.severity_threshold
    ));
    s.push_str(&format!(
        "- Skip generated files: {}\n",
        config.goguard.skip_generated
    ));
    s.push_str(&format!(
        "- Max diagnostics: {}\n",
        config.goguard.max_diagnostics
    ));

    if !config.rules.errcheck.ignore.is_empty() {
        s.push_str("\n### Ignore Patterns (errcheck)\n\n");
        for pattern in &config.rules.errcheck.ignore {
            s.push_str(&format!("- `{}`\n", pattern));
        }
    }
    s
}

/// Merge GoGuard section into existing CLAUDE.md content.
/// Replaces content between markers. If no markers found, appends at end.
pub fn merge_into_existing(existing: &str, section: &str) -> String {
    crate::markers::merge_with_markers(existing, section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_core::config::Config;

    #[test]
    fn test_generate_section_default_config() {
        let config = Config::default();
        let section = generate_section(&config);
        assert!(section.contains("nil analysis: enabled"));
        assert!(section.contains("errcheck analysis: enabled"));
        assert!(section.contains("Severity threshold: warning"));
        assert!(section.contains("`cargo test`"));
    }

    #[test]
    fn test_generate_section_disabled_rules() {
        let mut config = Config::default();
        config.rules.nil.enabled = false;
        let section = generate_section(&config);
        assert!(section.contains("nil analysis: disabled"));
        assert!(section.contains("errcheck analysis: enabled"));
    }

    #[test]
    fn test_generate_section_with_ignore_patterns() {
        let config = Config::default();
        let section = generate_section(&config);
        // Default config has ignore patterns for errcheck
        assert!(section.contains("### Ignore Patterns (errcheck)"));
        assert!(section.contains("`fmt.Print*`"));
        assert!(section.contains("`fmt.Fprint*`"));
    }

    #[test]
    fn test_generate_section_no_ignore_patterns() {
        let mut config = Config::default();
        config.rules.errcheck.ignore.clear();
        let section = generate_section(&config);
        assert!(!section.contains("### Ignore Patterns (errcheck)"));
    }

    #[test]
    fn test_generate_section_settings() {
        let mut config = Config::default();
        config.goguard.severity_threshold = "error".to_string();
        config.goguard.skip_generated = false;
        config.goguard.max_diagnostics = 50;
        let section = generate_section(&config);
        assert!(section.contains("Severity threshold: error"));
        assert!(section.contains("Skip generated files: false"));
        assert!(section.contains("Max diagnostics: 50"));
    }

    #[test]
    fn test_merge_replaces_existing() {
        let existing =
            "# My CLAUDE.md\n\n<!-- goguard:begin -->\nOLD\n<!-- goguard:end -->\n\nOther stuff\n";
        let section = "NEW SECTION\n";
        let result = merge_into_existing(existing, section);
        assert!(result.contains("# My CLAUDE.md"));
        assert!(result.contains("NEW SECTION"));
        assert!(!result.contains("OLD"));
        assert!(result.contains("Other stuff"));
    }

    #[test]
    fn test_merge_appends_if_no_markers() {
        let existing = "# CLAUDE.md\n\nExisting content.\n";
        let section = "NEW SECTION\n";
        let result = merge_into_existing(existing, section);
        assert!(result.contains("# CLAUDE.md"));
        assert!(result.contains("<!-- goguard:begin -->"));
        assert!(result.contains("NEW SECTION"));
        assert!(result.contains("<!-- goguard:end -->"));
    }

    #[test]
    fn test_merge_preserves_content_before_and_after_markers() {
        let existing = "BEFORE\n\n<!-- goguard:begin -->\nOLD\n<!-- goguard:end -->\n\nAFTER\n";
        let section = "UPDATED\n";
        let result = merge_into_existing(existing, section);
        assert!(result.starts_with("BEFORE"));
        assert!(result.contains("UPDATED"));
        assert!(result.contains("AFTER"));
        assert!(!result.contains("OLD"));
    }

    #[test]
    fn test_merge_appends_newline_if_missing() {
        let existing = "# CLAUDE.md\n\nNo trailing newline";
        let section = "SECTION\n";
        let result = merge_into_existing(existing, section);
        assert!(result.contains("No trailing newline\n\n<!-- goguard:begin -->"));
    }
}
