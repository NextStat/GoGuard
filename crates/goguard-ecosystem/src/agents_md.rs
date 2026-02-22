//! AGENTS.md file generation and management.
//!
//! Generates GoGuard sections for AGENTS.md files with round-trip safe
//! `<!-- goguard:begin -->` / `<!-- goguard:end -->` markers. Existing
//! content outside the markers is preserved during updates.

use goguard_diagnostics::rules::get_all_rules;

use crate::markers::{MARKER_BEGIN, MARKER_END};

/// Statistics from analysis (optional, for hybrid generation).
pub struct ProjectStats {
    pub total_issues: usize,
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    /// (file, count), sorted descending by count, max 5.
    pub top_files: Vec<(String, usize)>,
}

/// Generate the GoGuard section content (between markers).
/// If `stats` is `Some`, appends project statistics.
pub fn generate_section(stats: Option<&ProjectStats>) -> String {
    let rules = get_all_rules();
    let mut s = String::new();
    s.push_str("## GoGuard Static Analysis\n\n");
    s.push_str("### Rules\n\n");
    s.push_str("| Code | Name | Severity | Category |\n");
    s.push_str("|------|------|----------|----------|\n");
    for r in &rules {
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            r.code, r.name, r.severity, r.category
        ));
    }
    s.push_str("\n### Commands\n\n");
    s.push_str("- Analyze: `goguard check ./...`\n");
    s.push_str("- Explain rule: `goguard explain <RULE_CODE>`\n");
    s.push_str("- MCP server: `goguard serve --mcp`\n");
    s.push_str("- LSP server: `goguard serve --lsp`\n");
    s.push_str("\n### Key Constraint\n\n");
    s.push_str("Go bridge handles parse/type/SSA/CFG. Rust handles analysis/diagnostics/tooling. Never cross this boundary.\n");

    if let Some(stats) = stats {
        s.push_str("\n### Project Statistics\n\n");
        s.push_str(&format!("- Total issues: {}\n", stats.total_issues));
        s.push_str(&format!(
            "- Critical: {}, Error: {}, Warning: {}, Info: {}\n",
            stats.critical, stats.error, stats.warning, stats.info
        ));
        if !stats.top_files.is_empty() {
            s.push_str("- Top affected files:\n");
            for (file, count) in &stats.top_files {
                s.push_str(&format!("  - {} ({} issues)\n", file, count));
            }
        }
    }
    s
}

/// Merge GoGuard section into existing markdown content.
/// Replaces content between markers. If no markers found, appends at end.
pub fn merge_into_existing(existing: &str, section: &str) -> String {
    crate::markers::merge_with_markers(existing, section)
}

/// Generate a complete AGENTS.md from scratch.
pub fn generate_full(stats: Option<&ProjectStats>) -> String {
    let mut s = String::new();
    s.push_str("# AGENTS.md\n\n");
    s.push_str(MARKER_BEGIN);
    s.push('\n');
    s.push_str(&generate_section(stats));
    s.push_str(MARKER_END);
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_section_no_stats() {
        let section = generate_section(None);
        assert!(section.contains("## GoGuard Static Analysis"));
        assert!(section.contains("NIL001"));
        assert!(section.contains("ERR001"));
        assert!(section.contains("`goguard check ./...`"));
        assert!(!section.contains("### Project Statistics"));
    }

    #[test]
    fn test_generate_section_with_stats() {
        let stats = ProjectStats {
            total_issues: 42,
            critical: 5,
            error: 10,
            warning: 20,
            info: 7,
            top_files: vec![("handler.go".to_string(), 8), ("main.go".to_string(), 3)],
        };
        let section = generate_section(Some(&stats));
        assert!(section.contains("### Project Statistics"));
        assert!(section.contains("Total issues: 42"));
        assert!(section.contains("handler.go (8 issues)"));
    }

    #[test]
    fn test_merge_into_existing_with_markers() {
        let existing = "# My Project\n\nSome content.\n\n<!-- goguard:begin -->\nOLD STUFF\n<!-- goguard:end -->\n\nMore content.\n";
        let section = "NEW SECTION\n";
        let result = merge_into_existing(existing, section);
        assert!(result.contains("# My Project"));
        assert!(result.contains("NEW SECTION"));
        assert!(!result.contains("OLD STUFF"));
        assert!(result.contains("More content."));
    }

    #[test]
    fn test_merge_into_existing_no_markers() {
        let existing = "# My Project\n\nSome content.\n";
        let section = "NEW SECTION\n";
        let result = merge_into_existing(existing, section);
        assert!(result.contains("# My Project"));
        assert!(result.contains("<!-- goguard:begin -->"));
        assert!(result.contains("NEW SECTION"));
        assert!(result.contains("<!-- goguard:end -->"));
    }

    #[test]
    fn test_generate_full() {
        let content = generate_full(None);
        assert!(content.starts_with("# AGENTS.md"));
        assert!(content.contains("<!-- goguard:begin -->"));
        assert!(content.contains("<!-- goguard:end -->"));
        assert!(content.contains("NIL001"));
    }
}
