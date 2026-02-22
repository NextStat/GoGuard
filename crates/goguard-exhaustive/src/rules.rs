//! Exhaustiveness rules (EXH001, EXH002, EXH003).
//!
//! Each rule builds a `Diagnostic` from the discovered switch information.

use goguard_diagnostics::diagnostic::*;
use goguard_ir::ir::Span;

/// EXH001: Type switch missing interface implementor.
///
/// Fires when a type switch on a known interface does not cover all
/// concrete implementors and has no default case.
pub fn build_exh001(
    span: &Option<Span>,
    interface_name: &str,
    missing: &[&str],
    func_name: &str,
) -> Diagnostic {
    let (file, line, col) = extract_span(span);
    let missing_list = missing.join(", ");
    DiagnosticBuilder::new(
        "EXH001",
        Severity::Error,
        "Type switch missing interface implementor",
        DiagnosticSource::Exhaustive,
    )
    .location(&file, line, col)
    .explanation(format!(
        "In function `{func_name}`, type switch on `{interface_name}` is missing cases for: {missing_list}"
    ))
    .confidence(0.9)
    .pattern(
        "non-exhaustive-type-switch",
        Frequency::Common,
        "Add cases for all known implementors or add a default case",
    )
    .build()
}

/// EXH002: Const/iota enum switch missing value.
///
/// Fires when a switch on an enum-like type does not cover all known
/// constant values and has no default case.
pub fn build_exh002(
    span: &Option<Span>,
    enum_type_name: &str,
    missing: &[&str],
    func_name: &str,
) -> Diagnostic {
    let (file, line, col) = extract_span(span);
    let missing_list = missing.join(", ");
    DiagnosticBuilder::new(
        "EXH002",
        Severity::Error,
        "Enum switch missing constant value",
        DiagnosticSource::Exhaustive,
    )
    .location(&file, line, col)
    .explanation(format!(
        "In function `{func_name}`, switch on `{enum_type_name}` is missing cases for: {missing_list}"
    ))
    .confidence(0.9)
    .pattern(
        "non-exhaustive-enum-switch",
        Frequency::Common,
        "Add cases for all enum values or add a default case",
    )
    .build()
}

/// EXH003: Missing default case in non-exhaustive switch.
///
/// Informational: fires when a switch does not cover all possible values
/// and also lacks a default case. This is a softer version of EXH001/EXH002.
pub fn build_exh003(span: &Option<Span>, switch_description: &str, func_name: &str) -> Diagnostic {
    let (file, line, col) = extract_span(span);
    DiagnosticBuilder::new(
        "EXH003",
        Severity::Info,
        "Missing default case in non-exhaustive switch",
        DiagnosticSource::Exhaustive,
    )
    .location(&file, line, col)
    .explanation(format!(
        "In function `{func_name}`, {switch_description} does not cover all cases and has no default"
    ))
    .confidence(0.8)
    .pattern(
        "missing-default-case",
        Frequency::VeryCommon,
        "Add a default case to handle unexpected values",
    )
    .build()
}

fn extract_span(span: &Option<Span>) -> (String, u32, u32) {
    match span {
        Some(s) => (s.file.clone(), s.start_line, s.start_col),
        None => ("unknown".into(), 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::Span;

    #[test]
    fn test_exh001_diagnostic() {
        let span = Some(Span::new("handler.go", 25, 5));
        let diag = build_exh001(&span, "Animal", &["*Bird", "*Fish"], "HandleAnimal");

        assert_eq!(diag.rule, "EXH001");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.source, DiagnosticSource::Exhaustive);
        assert_eq!(diag.location.file, "handler.go");
        assert_eq!(diag.location.line, 25);
        assert!(diag.explanation.contains("Animal"));
        assert!(diag.explanation.contains("*Bird"));
        assert!(diag.explanation.contains("*Fish"));
        assert!(diag.explanation.contains("HandleAnimal"));
        assert!(diag.pattern.is_some());
    }

    #[test]
    fn test_exh001_no_span() {
        let diag = build_exh001(&None, "Shape", &["*Hexagon"], "DrawShape");
        assert_eq!(diag.location.file, "unknown");
        assert_eq!(diag.location.line, 0);
    }

    #[test]
    fn test_exh002_diagnostic() {
        let span = Some(Span::new("color.go", 42, 10));
        let diag = build_exh002(&span, "Color", &["Blue"], "ApplyColor");

        assert_eq!(diag.rule, "EXH002");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.source, DiagnosticSource::Exhaustive);
        assert_eq!(diag.location.file, "color.go");
        assert_eq!(diag.location.line, 42);
        assert!(diag.explanation.contains("Color"));
        assert!(diag.explanation.contains("Blue"));
        assert!(diag.explanation.contains("ApplyColor"));
    }

    #[test]
    fn test_exh003_diagnostic() {
        let span = Some(Span::new("main.go", 15, 3));
        let diag = build_exh003(&span, "type switch on `io.Reader`", "ProcessReader");

        assert_eq!(diag.rule, "EXH003");
        assert_eq!(diag.severity, Severity::Info);
        assert_eq!(diag.source, DiagnosticSource::Exhaustive);
        assert_eq!(diag.location.file, "main.go");
        assert!(diag.explanation.contains("ProcessReader"));
        assert!(diag.explanation.contains("io.Reader"));
    }

    #[test]
    fn test_exh001_id_format() {
        let span = Some(Span::new("handler.go", 25, 5));
        let diag = build_exh001(&span, "Animal", &["*Bird"], "HandleAnimal");
        assert_eq!(diag.id, "EXH001-handler.go:25");
    }

    #[test]
    fn test_exh002_id_format() {
        let span = Some(Span::new("color.go", 42, 10));
        let diag = build_exh002(&span, "Color", &["Blue"], "ApplyColor");
        assert_eq!(diag.id, "EXH002-color.go:42");
    }

    #[test]
    fn test_exh003_confidence() {
        let diag = build_exh003(&None, "switch", "Func");
        assert_eq!(diag.confidence, 0.8);
    }
}
