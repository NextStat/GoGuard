//! LSP code action provider for quick fixes.
//!
//! Converts GoGuard [`Fix`] suggestions into LSP [`CodeAction`] values
//! with [`WorkspaceEdit`] payloads that editors can apply automatically.

use goguard_diagnostics::diagnostic::{Diagnostic, Edit};
use std::collections::HashMap;
use tower_lsp_server::ls_types;

/// Convert a GoGuard [`Fix`] (attached to a diagnostic) into an LSP [`CodeAction`].
///
/// Returns `None` if the diagnostic has no fix or if all edits target
/// cross-file locations (cross-file edits are deferred to a future phase).
pub fn fix_to_code_action(diag: &Diagnostic, uri: &ls_types::Uri) -> Option<ls_types::CodeAction> {
    let fix = diag.fix.as_ref()?;

    let mut changes: HashMap<ls_types::Uri, Vec<ls_types::TextEdit>> = HashMap::new();
    for edit in &fix.edits {
        // Only handle same-file edits (cross-file deferred).
        if edit.file != diag.location.file {
            continue;
        }
        let text_edit = edit_to_text_edit(edit);
        changes.entry(uri.clone()).or_default().push(text_edit);
    }

    if changes.is_empty() {
        return None;
    }

    Some(ls_types::CodeAction {
        title: format!("GoGuard: {}", fix.description),
        kind: Some(ls_types::CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![super::diagnostics::to_lsp_diagnostic(diag)]),
        edit: Some(ls_types::WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Convert a GoGuard [`Edit`] to an LSP [`TextEdit`].
///
/// GoGuard uses 1-based line numbers; LSP uses 0-based.
fn edit_to_text_edit(edit: &Edit) -> ls_types::TextEdit {
    ls_types::TextEdit {
        range: ls_types::Range::new(
            ls_types::Position::new(edit.range.start_line.saturating_sub(1), 0),
            ls_types::Position::new(edit.range.end_line.saturating_sub(1), u32::MAX),
        ),
        new_text: edit.new_text.clone(),
    }
}

/// Get all code actions for diagnostics whose locations overlap a given LSP range.
///
/// Only diagnostics that (a) refer to `file` and (b) carry a [`Fix`] are included.
pub fn code_actions_for_range(
    diags: &[Diagnostic],
    file: &str,
    range: &ls_types::Range,
    uri: &ls_types::Uri,
) -> Vec<ls_types::CodeAction> {
    diags
        .iter()
        .filter(|d| d.location.file == file && d.fix.is_some())
        .filter(|d| {
            let diag_range = super::diagnostics::to_lsp_range(&d.location);
            ranges_overlap(&diag_range, range)
        })
        .filter_map(|d| fix_to_code_action(d, uri))
        .collect()
}

/// Check whether two LSP ranges overlap (inclusive on both endpoints).
fn ranges_overlap(a: &ls_types::Range, b: &ls_types::Range) -> bool {
    a.start <= b.end && b.start <= a.end
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::{
        DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
    };
    use std::str::FromStr;

    fn make_diag_with_fix(file: &str, line: u32) -> Diagnostic {
        DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location(file, line, 5)
        .end_location(line, 20)
        .fix(
            "Add nil check",
            vec![Edit {
                file: file.to_string(),
                range: EditRange {
                    start_line: line,
                    end_line: line,
                },
                old_text: Some("user.Name".to_string()),
                new_text: "if user != nil {\n\tuser.Name\n}".to_string(),
            }],
        )
        .build()
    }

    fn test_uri() -> ls_types::Uri {
        ls_types::Uri::from_str("file:///project/handler.go").unwrap()
    }

    #[test]
    fn test_fix_to_code_action() {
        let diag = make_diag_with_fix("handler.go", 18);
        let uri = test_uri();
        let action = fix_to_code_action(&diag, &uri).unwrap();

        assert!(action.title.contains("GoGuard:"));
        assert!(action.title.contains("Add nil check"));
        assert_eq!(action.kind, Some(ls_types::CodeActionKind::QUICKFIX));
        assert!(action.edit.is_some());

        let edit = action.edit.unwrap();
        let changes = edit.changes.unwrap();
        assert!(changes.contains_key(&uri));

        let text_edits = &changes[&uri];
        assert_eq!(text_edits.len(), 1);
        assert!(text_edits[0].new_text.contains("if user != nil"));
    }

    #[test]
    fn test_fix_to_code_action_no_fix() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .build();

        let action = fix_to_code_action(&diag, &test_uri());
        assert!(action.is_none());
    }

    #[test]
    fn test_fix_to_code_action_cross_file_edit_skipped() {
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add nil check",
            vec![Edit {
                file: "other_file.go".to_string(),
                range: EditRange {
                    start_line: 10,
                    end_line: 10,
                },
                old_text: None,
                new_text: "fixed".to_string(),
            }],
        )
        .build();

        // Cross-file edit means no same-file changes, so None.
        let action = fix_to_code_action(&diag, &test_uri());
        assert!(action.is_none());
    }

    #[test]
    fn test_edit_to_text_edit_1_based_to_0_based() {
        let edit = Edit {
            file: "handler.go".to_string(),
            range: EditRange {
                start_line: 18,
                end_line: 18,
            },
            old_text: None,
            new_text: "fixed code".to_string(),
        };
        let te = edit_to_text_edit(&edit);
        // 1-based line 18 -> 0-based line 17
        assert_eq!(te.range.start.line, 17);
        assert_eq!(te.range.start.character, 0);
        assert_eq!(te.range.end.line, 17);
        assert_eq!(te.range.end.character, u32::MAX);
        assert_eq!(te.new_text, "fixed code");
    }

    #[test]
    fn test_edit_to_text_edit_line_1() {
        let edit = Edit {
            file: "main.go".to_string(),
            range: EditRange {
                start_line: 1,
                end_line: 1,
            },
            old_text: None,
            new_text: "package main".to_string(),
        };
        let te = edit_to_text_edit(&edit);
        assert_eq!(te.range.start.line, 0);
        assert_eq!(te.range.end.line, 0);
    }

    #[test]
    fn test_edit_to_text_edit_multi_line() {
        let edit = Edit {
            file: "handler.go".to_string(),
            range: EditRange {
                start_line: 5,
                end_line: 8,
            },
            old_text: None,
            new_text: "replacement block".to_string(),
        };
        let te = edit_to_text_edit(&edit);
        assert_eq!(te.range.start.line, 4);
        assert_eq!(te.range.end.line, 7);
    }

    #[test]
    fn test_code_actions_for_range_overlapping() {
        let diags = vec![
            make_diag_with_fix("handler.go", 18),
            make_diag_with_fix("handler.go", 30),
        ];

        // Request range covers 0-based lines 16..18, which overlaps
        // with diag at line 18 (0-based 17).
        let range = ls_types::Range::new(
            ls_types::Position::new(16, 0),
            ls_types::Position::new(18, 0),
        );

        let actions = code_actions_for_range(&diags, "handler.go", &range, &test_uri());
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_code_actions_for_range_no_overlap() {
        let diags = vec![make_diag_with_fix("handler.go", 18)];

        // Request range is 0-based lines 0..5, diag is at 0-based line 17.
        let range =
            ls_types::Range::new(ls_types::Position::new(0, 0), ls_types::Position::new(5, 0));

        let actions = code_actions_for_range(&diags, "handler.go", &range, &test_uri());
        assert_eq!(actions.len(), 0);
    }

    #[test]
    fn test_code_actions_for_range_wrong_file() {
        let diags = vec![make_diag_with_fix("handler.go", 18)];

        let range = ls_types::Range::new(
            ls_types::Position::new(16, 0),
            ls_types::Position::new(18, 0),
        );

        // Query for a different file.
        let actions = code_actions_for_range(&diags, "other.go", &range, &test_uri());
        assert_eq!(actions.len(), 0);
    }

    #[test]
    fn test_code_actions_for_range_no_fix() {
        let diag_no_fix = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .build();

        let diags = vec![diag_no_fix];

        let range = ls_types::Range::new(
            ls_types::Position::new(16, 0),
            ls_types::Position::new(18, 0),
        );

        let actions = code_actions_for_range(&diags, "handler.go", &range, &test_uri());
        assert_eq!(actions.len(), 0);
    }

    #[test]
    fn test_ranges_overlap_identical() {
        let r = ls_types::Range::new(
            ls_types::Position::new(5, 0),
            ls_types::Position::new(10, 0),
        );
        assert!(ranges_overlap(&r, &r));
    }

    #[test]
    fn test_ranges_overlap_adjacent() {
        let a = ls_types::Range::new(
            ls_types::Position::new(5, 0),
            ls_types::Position::new(10, 0),
        );
        let b = ls_types::Range::new(
            ls_types::Position::new(10, 0),
            ls_types::Position::new(15, 0),
        );
        // Touching at the boundary counts as overlapping.
        assert!(ranges_overlap(&a, &b));
    }

    #[test]
    fn test_ranges_no_overlap() {
        let a = ls_types::Range::new(
            ls_types::Position::new(5, 0),
            ls_types::Position::new(10, 0),
        );
        let b = ls_types::Range::new(
            ls_types::Position::new(11, 0),
            ls_types::Position::new(15, 0),
        );
        assert!(!ranges_overlap(&a, &b));
    }

    #[test]
    fn test_code_action_diagnostics_field() {
        let diag = make_diag_with_fix("handler.go", 18);
        let action = fix_to_code_action(&diag, &test_uri()).unwrap();

        let lsp_diags = action.diagnostics.unwrap();
        assert_eq!(lsp_diags.len(), 1);
        assert_eq!(lsp_diags[0].source.as_deref(), Some("goguard"));
        assert_eq!(
            lsp_diags[0].code,
            Some(ls_types::NumberOrString::String("NIL001".into()))
        );
    }
}
