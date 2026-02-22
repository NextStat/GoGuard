//! Error checking rules (ERR001, ERR002, etc.).

use goguard_diagnostics::diagnostic::{Diagnostic, DiagnosticSource, Location, Severity};
use goguard_ir::ir::{Instruction, Span};

/// ERR001: error return value not used
pub fn build_err001(instr: &Instruction, func_name: &str, callee_name: &str) -> Diagnostic {
    let (file, line, col, end_line, end_col) = extract_span(&instr.span);
    Diagnostic {
        id: format!("ERR001-{file}:{line}"),
        rule: "ERR001".to_string(),
        severity: Severity::Error,
        confidence: 0.95,
        title: "error return value not checked".to_string(),
        explanation: format!(
            "In function `{func_name}`, error returned by `{callee_name}` is not checked"
        ),
        location: Location {
            file,
            line,
            column: col,
            end_line,
            end_column: end_col,
        },
        root_cause: None,
        fix: None,
        related: vec![],
        blast_radius: None,
        pattern: None,
        source: DiagnosticSource::Errcheck,
        callee_key: None,
    }
}

/// ERR002: error assigned to blank identifier
pub fn build_err002(instr: &Instruction, func_name: &str, callee_name: &str) -> Diagnostic {
    let (file, line, col, end_line, end_col) = extract_span(&instr.span);
    Diagnostic {
        id: format!("ERR002-{file}:{line}"),
        rule: "ERR002".to_string(),
        severity: Severity::Warning,
        confidence: 0.95,
        title: "error assigned to blank identifier".to_string(),
        explanation: format!(
            "In function `{func_name}`, error from `{callee_name}` explicitly discarded with `_`"
        ),
        location: Location {
            file,
            line,
            column: col,
            end_line,
            end_column: end_col,
        },
        root_cause: None,
        fix: None,
        related: vec![],
        blast_radius: None,
        pattern: None,
        source: DiagnosticSource::Errcheck,
        callee_key: None,
    }
}

fn extract_span(span: &Option<Span>) -> (String, u32, u32, u32, u32) {
    match span {
        Some(s) => (
            s.file.clone(),
            s.start_line,
            s.start_col,
            s.end_line,
            s.end_col,
        ),
        None => (String::new(), 0, 0, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::{Span, ValueKind};

    fn make_call_instr(id: u32, callee: &str) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Call,
            name: format!("t{id}"),
            type_id: 0,
            span: Some(Span {
                file: "main.go".into(),
                start_line: 10,
                start_col: 5,
                end_line: 10,
                end_col: 25,
            }),
            operands: vec![],
            extract_index: 0,
            callee: Some(callee.to_string()),
            callee_is_interface: false,
            assert_type_id: 0,
            comma_ok: false,
            const_value: None,
            is_nil: false,
            bin_op: None,
            nil_operand_indices: vec![],
            select_cases: vec![],
            channel_dir: None,
        }
    }

    #[test]
    fn test_err001() {
        let instr = make_call_instr(1, "os.Remove");
        let diag = build_err001(&instr, "DoStuff", "os.Remove");
        assert_eq!(diag.rule, "ERR001");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.confidence, 0.95);
        assert!(diag.explanation.contains("os.Remove"));
        assert!(diag.explanation.contains("DoStuff"));
        assert_eq!(diag.location.file, "main.go");
        assert_eq!(diag.location.line, 10);
        assert_eq!(diag.source, DiagnosticSource::Errcheck);
    }

    #[test]
    fn test_err002() {
        let instr = make_call_instr(2, "os.Open");
        let diag = build_err002(&instr, "DoStuff", "os.Open");
        assert_eq!(diag.rule, "ERR002");
        assert_eq!(diag.severity, Severity::Warning);
        assert!(diag.explanation.contains("os.Open"));
        assert!(diag.explanation.contains("discarded"));
    }

    #[test]
    fn test_extract_span_none() {
        let (file, line, col, end_line, end_col) = extract_span(&None);
        assert_eq!(file, "");
        assert_eq!(line, 0);
        assert_eq!(col, 0);
        assert_eq!(end_line, 0);
        assert_eq!(end_col, 0);
    }

    #[test]
    fn test_extract_span_some() {
        let span = Some(Span {
            file: "handler.go".into(),
            start_line: 42,
            start_col: 3,
            end_line: 42,
            end_col: 30,
        });
        let (file, line, col, end_line, end_col) = extract_span(&span);
        assert_eq!(file, "handler.go");
        assert_eq!(line, 42);
        assert_eq!(col, 3);
        assert_eq!(end_line, 42);
        assert_eq!(end_col, 30);
    }
}
