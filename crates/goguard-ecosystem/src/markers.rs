//! Shared marker-based section merge for markdown files.
//!
//! Both `agents_md` and `claude_md` use HTML comment markers to delimit
//! the GoGuard-managed section.  This module provides the shared constants
//! and merge logic so neither module duplicates it.

pub const MARKER_BEGIN: &str = "<!-- goguard:begin -->";
pub const MARKER_END: &str = "<!-- goguard:end -->";

/// Merge a section into existing content between markers.
///
/// If markers exist, replaces content between them.
/// If no markers found, appends at end with markers.
pub fn merge_with_markers(existing: &str, section: &str) -> String {
    let begin_idx = existing.find(MARKER_BEGIN);
    let end_idx = existing.find(MARKER_END);

    match (begin_idx, end_idx) {
        (Some(begin), Some(end)) if end > begin => {
            let after_end = end + MARKER_END.len();
            let mut result = String::new();
            result.push_str(&existing[..begin]);
            result.push_str(MARKER_BEGIN);
            result.push('\n');
            result.push_str(section);
            result.push_str(MARKER_END);
            result.push_str(&existing[after_end..]);
            result
        }
        _ => {
            // No valid markers -- append at end
            let mut result = existing.to_string();
            if !result.ends_with('\n') {
                result.push('\n');
            }
            result.push('\n');
            result.push_str(MARKER_BEGIN);
            result.push('\n');
            result.push_str(section);
            result.push_str(MARKER_END);
            result.push('\n');
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_replaces_existing_markers() {
        let existing = "# My Project\n\nSome content.\n\n<!-- goguard:begin -->\nOLD STUFF\n<!-- goguard:end -->\n\nMore content.\n";
        let section = "NEW SECTION\n";
        let result = merge_with_markers(existing, section);
        assert!(result.contains("# My Project"));
        assert!(result.contains("NEW SECTION"));
        assert!(!result.contains("OLD STUFF"));
        assert!(result.contains("More content."));
    }

    #[test]
    fn test_merge_appends_if_no_markers() {
        let existing = "# My Project\n\nSome content.\n";
        let section = "NEW SECTION\n";
        let result = merge_with_markers(existing, section);
        assert!(result.contains("# My Project"));
        assert!(result.contains("<!-- goguard:begin -->"));
        assert!(result.contains("NEW SECTION"));
        assert!(result.contains("<!-- goguard:end -->"));
    }

    #[test]
    fn test_merge_preserves_content_before_and_after() {
        let existing = "BEFORE\n\n<!-- goguard:begin -->\nOLD\n<!-- goguard:end -->\n\nAFTER\n";
        let section = "UPDATED\n";
        let result = merge_with_markers(existing, section);
        assert!(result.starts_with("BEFORE"));
        assert!(result.contains("UPDATED"));
        assert!(result.contains("AFTER"));
        assert!(!result.contains("OLD"));
    }

    #[test]
    fn test_merge_appends_newline_if_missing() {
        let existing = "# Title\n\nNo trailing newline";
        let section = "SECTION\n";
        let result = merge_with_markers(existing, section);
        assert!(result.contains("No trailing newline\n\n<!-- goguard:begin -->"));
    }

    #[test]
    fn test_merge_inverted_markers_appends() {
        // If markers are in wrong order, treat as no markers.
        let existing = "<!-- goguard:end -->\nstuff\n<!-- goguard:begin -->\n";
        let section = "CONTENT\n";
        let result = merge_with_markers(existing, section);
        // Should append at end since markers are inverted
        assert!(result.ends_with("<!-- goguard:end -->\n"));
        assert!(result.contains("CONTENT"));
    }
}
