//! Hover information for LSP.
//!
//! Provides hover content when the user hovers over a GoGuard diagnostic
//! in their editor. Shows rule, severity, explanation, root cause, and fix.

use goguard_diagnostics::diagnostic::Diagnostic;
use tower_lsp_server::ls_types;

/// Find diagnostic at position and return hover content.
pub fn hover_for_position(
    diags: &[Diagnostic],
    file: &str,
    position: &ls_types::Position,
) -> Option<ls_types::Hover> {
    let diag = diags
        .iter()
        .find(|d| d.location.file == file && position_in_diagnostic(d, position))?;

    let content = format_diagnostic_hover(diag);

    Some(ls_types::Hover {
        contents: ls_types::HoverContents::Markup(ls_types::MarkupContent {
            kind: ls_types::MarkupKind::Markdown,
            value: content,
        }),
        range: Some(super::diagnostics::to_lsp_range(&diag.location)),
    })
}

/// Check whether a 0-based LSP position falls within a diagnostic's range.
fn position_in_diagnostic(diag: &Diagnostic, pos: &ls_types::Position) -> bool {
    let range = super::diagnostics::to_lsp_range(&diag.location);
    pos.line >= range.start.line
        && pos.line <= range.end.line
        && (pos.line > range.start.line || pos.character >= range.start.character)
        && (pos.line < range.end.line || pos.character <= range.end.character)
}

/// Format a GoGuard Diagnostic as markdown for hover display.
fn format_diagnostic_hover(diag: &Diagnostic) -> String {
    let mut md = String::new();
    md.push_str(&format!("### {} — {}\n\n", diag.rule, diag.title));
    md.push_str(&format!("**Severity:** {}\n\n", diag.severity));

    if !diag.explanation.is_empty() {
        md.push_str(&format!("{}\n\n", diag.explanation));
    }

    if let Some(rc) = &diag.root_cause {
        md.push_str(&format!(
            "**Root cause:** {}:{} — {}\n\n",
            rc.file, rc.line, rc.description
        ));
    }

    if let Some(fix) = &diag.fix {
        md.push_str(&format!("**Fix:** {}\n", fix.description));
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

    fn make_diag(file: &str, line: u32) -> Diagnostic {
        DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location(file, line, 5)
        .end_location(line, 20)
        .explanation("Variable 'user' may be nil")
        .root_cause(file, line - 3, "error not checked on line above")
        .fix("Add nil check", vec![])
        .build()
    }

    #[test]
    fn test_hover_at_diagnostic_position() {
        let diags = vec![make_diag("handler.go", 18)];
        // Position at line 17 (0-based), char 10 — inside diagnostic range
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_some());
    }

    #[test]
    fn test_hover_outside_diagnostic() {
        let diags = vec![make_diag("handler.go", 18)];
        // Position at line 0 — far from diagnostic
        let pos = ls_types::Position::new(0, 0);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_none());
    }

    #[test]
    fn test_hover_wrong_file() {
        let diags = vec![make_diag("handler.go", 18)];
        // Correct line but wrong file
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "other.go", &pos);
        assert!(hover.is_none());
    }

    #[test]
    fn test_hover_content_includes_rule() {
        let diags = vec![make_diag("handler.go", 18)];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos).unwrap();
        if let ls_types::HoverContents::Markup(content) = &hover.contents {
            assert!(content.value.contains("NIL001"));
            assert!(content.value.contains("nil pointer dereference"));
            assert!(content.value.contains("critical"));
        } else {
            panic!("expected Markup hover contents");
        }
    }

    #[test]
    fn test_hover_content_includes_fix() {
        let diags = vec![make_diag("handler.go", 18)];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos).unwrap();
        if let ls_types::HoverContents::Markup(content) = &hover.contents {
            assert!(content.value.contains("Add nil check"));
            assert!(content.value.contains("Root cause"));
        } else {
            panic!("expected Markup hover contents");
        }
    }

    #[test]
    fn test_hover_content_includes_explanation() {
        let diags = vec![make_diag("handler.go", 18)];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos).unwrap();
        if let ls_types::HoverContents::Markup(content) = &hover.contents {
            assert!(content.value.contains("Variable 'user' may be nil"));
        } else {
            panic!("expected Markup hover contents");
        }
    }

    #[test]
    fn test_hover_range_matches_diagnostic() {
        let diags = vec![make_diag("handler.go", 18)];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos).unwrap();
        let range = hover.range.unwrap();
        // Line 18 (1-based) -> 17 (0-based), column 5 -> 4, end_column 20 -> 19
        assert_eq!(range.start.line, 17);
        assert_eq!(range.start.character, 4);
        assert_eq!(range.end.line, 17);
        assert_eq!(range.end.character, 19);
    }

    #[test]
    fn test_hover_at_range_start_boundary() {
        let diags = vec![make_diag("handler.go", 18)];
        // Exactly at start: line 17 (0-based), char 4 (column 5 -> 4 after 1-based -> 0-based)
        let pos = ls_types::Position::new(17, 4);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_some());
    }

    #[test]
    fn test_hover_at_range_end_boundary() {
        let diags = vec![make_diag("handler.go", 18)];
        // Exactly at end: line 17 (0-based), char 19 (end_column 20 -> 19 after 1-based -> 0-based)
        let pos = ls_types::Position::new(17, 19);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_some());
    }

    #[test]
    fn test_hover_just_before_range() {
        let diags = vec![make_diag("handler.go", 18)];
        // One character before start: char 3 (start is char 4)
        let pos = ls_types::Position::new(17, 3);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_none());
    }

    #[test]
    fn test_hover_just_after_range() {
        let diags = vec![make_diag("handler.go", 18)];
        // One character after end: char 20 (end is char 19)
        let pos = ls_types::Position::new(17, 20);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_none());
    }

    #[test]
    fn test_hover_multiple_diagnostics_finds_first() {
        let diags = vec![make_diag("handler.go", 10), make_diag("handler.go", 18)];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos).unwrap();
        if let ls_types::HoverContents::Markup(content) = &hover.contents {
            assert!(content.value.contains("NIL001"));
        } else {
            panic!("expected Markup hover contents");
        }
    }

    #[test]
    fn test_hover_empty_diagnostics() {
        let diags: Vec<Diagnostic> = vec![];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos);
        assert!(hover.is_none());
    }

    #[test]
    fn test_format_diagnostic_hover_without_optional_fields() {
        let diag = DiagnosticBuilder::new(
            "ERR001",
            Severity::Warning,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 42, 10)
        .end_location(42, 30)
        .build();

        let md = format_diagnostic_hover(&diag);
        assert!(md.contains("### ERR001 — error ignored"));
        assert!(md.contains("**Severity:** warning"));
        // Should NOT contain root cause or fix sections
        assert!(!md.contains("Root cause"));
        assert!(!md.contains("Fix:"));
    }

    #[test]
    fn test_hover_markdown_kind() {
        let diags = vec![make_diag("handler.go", 18)];
        let pos = ls_types::Position::new(17, 10);
        let hover = hover_for_position(&diags, "handler.go", &pos).unwrap();
        if let ls_types::HoverContents::Markup(content) = &hover.contents {
            assert_eq!(content.kind, ls_types::MarkupKind::Markdown);
        } else {
            panic!("expected Markup hover contents");
        }
    }
}
