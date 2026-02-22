//! Diagnostic conversion for LSP output.

use goguard_diagnostics::diagnostic::{Diagnostic, Location, Severity};
use tower_lsp_server::ls_types;

/// Convert GoGuard Severity to LSP DiagnosticSeverity.
pub fn to_lsp_severity(severity: Severity) -> ls_types::DiagnosticSeverity {
    match severity {
        Severity::Critical | Severity::Error => ls_types::DiagnosticSeverity::ERROR,
        Severity::Warning => ls_types::DiagnosticSeverity::WARNING,
        Severity::Info => ls_types::DiagnosticSeverity::INFORMATION,
    }
}

/// Convert GoGuard Location to LSP Range (1-based -> 0-based).
///
/// GoGuard locations use 1-based lines and columns (from Go's
/// `token.Position`). LSP expects 0-based positions for both.
pub fn to_lsp_range(loc: &Location) -> ls_types::Range {
    ls_types::Range::new(
        ls_types::Position::new(loc.line.saturating_sub(1), loc.column.saturating_sub(1)),
        ls_types::Position::new(
            loc.end_line.saturating_sub(1),
            loc.end_column.saturating_sub(1),
        ),
    )
}

/// Convert a single GoGuard Diagnostic to LSP Diagnostic.
pub fn to_lsp_diagnostic(diag: &Diagnostic) -> ls_types::Diagnostic {
    ls_types::Diagnostic {
        range: to_lsp_range(&diag.location),
        severity: Some(to_lsp_severity(diag.severity)),
        code: Some(ls_types::NumberOrString::String(diag.rule.clone())),
        source: Some("goguard".to_string()),
        message: format!("{}: {}", diag.rule, diag.title),
        related_information: None,
        ..Default::default()
    }
}

/// Convert GoGuard diagnostics to LSP diagnostics, filtered by file path.
pub fn to_lsp_diagnostics(diags: &[Diagnostic], file: &str) -> Vec<ls_types::Diagnostic> {
    diags
        .iter()
        .filter(|d| d.location.file == file)
        .map(to_lsp_diagnostic)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

    fn make_diag(rule: &str, severity: Severity, file: &str, line: u32) -> Diagnostic {
        DiagnosticBuilder::new(rule, severity, "test title", DiagnosticSource::Nil)
            .location(file, line, 5)
            .end_location(line, 20)
            .build()
    }

    #[test]
    fn test_severity_mapping_critical() {
        assert_eq!(
            to_lsp_severity(Severity::Critical),
            ls_types::DiagnosticSeverity::ERROR
        );
    }

    #[test]
    fn test_severity_mapping_error() {
        assert_eq!(
            to_lsp_severity(Severity::Error),
            ls_types::DiagnosticSeverity::ERROR
        );
    }

    #[test]
    fn test_severity_mapping_warning() {
        assert_eq!(
            to_lsp_severity(Severity::Warning),
            ls_types::DiagnosticSeverity::WARNING
        );
    }

    #[test]
    fn test_severity_mapping_info() {
        assert_eq!(
            to_lsp_severity(Severity::Info),
            ls_types::DiagnosticSeverity::INFORMATION
        );
    }

    #[test]
    fn test_range_converts_1based_to_0based() {
        let loc = Location {
            file: "test.go".to_string(),
            line: 10,
            column: 5,
            end_line: 10,
            end_column: 20,
        };
        let range = to_lsp_range(&loc);
        assert_eq!(range.start.line, 9); // 10 - 1
        assert_eq!(range.start.character, 4); // 5 - 1 (1-based -> 0-based)
        assert_eq!(range.end.line, 9); // 10 - 1
        assert_eq!(range.end.character, 19); // 20 - 1 (1-based -> 0-based)
    }

    #[test]
    fn test_range_saturating_sub_at_zero() {
        let loc = Location {
            file: "test.go".to_string(),
            line: 0,
            column: 0,
            end_line: 0,
            end_column: 0,
        };
        let range = to_lsp_range(&loc);
        assert_eq!(range.start.line, 0); // saturating_sub prevents underflow
        assert_eq!(range.end.line, 0);
    }

    #[test]
    fn test_to_lsp_diagnostic() {
        let diag = make_diag("NIL001", Severity::Critical, "handler.go", 18);
        let lsp = to_lsp_diagnostic(&diag);
        assert_eq!(lsp.range.start.line, 17); // 1-based -> 0-based
        assert_eq!(lsp.range.start.character, 4); // 5 - 1 (1-based -> 0-based)
        assert_eq!(lsp.severity, Some(ls_types::DiagnosticSeverity::ERROR));
        assert_eq!(
            lsp.code,
            Some(ls_types::NumberOrString::String("NIL001".to_string()))
        );
        assert_eq!(lsp.source, Some("goguard".to_string()));
        assert!(lsp.message.contains("NIL001"));
        assert!(lsp.message.contains("test title"));
    }

    #[test]
    fn test_to_lsp_diagnostic_message_format() {
        let diag = DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 42, 10)
        .build();

        let lsp = to_lsp_diagnostic(&diag);
        assert_eq!(lsp.message, "ERR001: error ignored");
    }

    #[test]
    fn test_to_lsp_diagnostics_filters_by_file() {
        let diags = vec![
            make_diag("NIL001", Severity::Critical, "handler.go", 18),
            make_diag("ERR001", Severity::Error, "main.go", 5),
            make_diag("NIL002", Severity::Critical, "handler.go", 25),
        ];
        let lsp = to_lsp_diagnostics(&diags, "handler.go");
        assert_eq!(lsp.len(), 2);
    }

    #[test]
    fn test_to_lsp_diagnostics_empty_when_no_match() {
        let diags = vec![make_diag("NIL001", Severity::Critical, "handler.go", 18)];
        let lsp = to_lsp_diagnostics(&diags, "other.go");
        assert!(lsp.is_empty());
    }

    #[test]
    fn test_to_lsp_diagnostics_empty_input() {
        let diags: Vec<Diagnostic> = vec![];
        let lsp = to_lsp_diagnostics(&diags, "handler.go");
        assert!(lsp.is_empty());
    }
}
