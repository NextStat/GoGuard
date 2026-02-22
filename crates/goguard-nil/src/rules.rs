//! Nil safety rules (NIL001, NIL002, etc.).

use goguard_diagnostics::diagnostic::*;
use goguard_ir::ir::{Instruction, ValueKind};

use crate::lattice::Nilability;

/// NIL001: nil pointer dereference
pub fn build_nil001(
    instr: &Instruction,
    func_name: &str,
    confidence: f64,
    callee_key: Option<String>,
) -> Diagnostic {
    let (file, line, col) = extract_span(instr);
    let mut builder = DiagnosticBuilder::new(
        "NIL001",
        Severity::Critical,
        "nil pointer dereference",
        DiagnosticSource::Nil,
    )
    .location(&file, line, col)
    .explanation(format!(
        "In function `{func_name}`, value `{}` may be nil when dereferenced",
        instr.name
    ))
    .confidence(confidence);
    if let Some(key) = callee_key {
        builder = builder.callee_key(key);
    }
    builder.build()
}

/// NIL002: unchecked type assertion
pub fn build_nil002(instr: &Instruction, func_name: &str) -> Diagnostic {
    let (file, line, col) = extract_span(instr);
    DiagnosticBuilder::new(
        "NIL002",
        Severity::Critical,
        "unchecked type assertion",
        DiagnosticSource::Nil,
    )
    .location(&file, line, col)
    .explanation(format!(
        "In function `{func_name}`, type assertion without comma-ok pattern. Use `v, ok := x.(T)`"
    ))
    .confidence(1.0)
    .build()
}

/// NIL004: nil map access or write
pub fn build_nil004(instr: &Instruction, func_name: &str, nilability: Nilability) -> Diagnostic {
    let (file, line, col) = extract_span(instr);
    let (sev, title) = match instr.kind {
        ValueKind::MapUpdate => (Severity::Critical, "nil map write — runtime panic"),
        _ => (Severity::Warning, "nil map access"),
    };
    DiagnosticBuilder::new("NIL004", sev, title, DiagnosticSource::Nil)
        .location(&file, line, col)
        .explanation(format!(
            "In function `{func_name}`, map is {} when accessed",
            if nilability == Nilability::Nil {
                "nil"
            } else {
                "possibly nil"
            }
        ))
        .confidence(0.95)
        .build()
}

/// NIL006: nil channel operation
pub fn build_nil006(instr: &Instruction, func_name: &str) -> Diagnostic {
    let (file, line, col) = extract_span(instr);
    DiagnosticBuilder::new(
        "NIL006",
        Severity::Critical,
        "nil channel operation",
        DiagnosticSource::Nil,
    )
    .location(&file, line, col)
    .explanation(format!(
        "In function `{func_name}`, channel may be nil when used"
    ))
    .confidence(0.95)
    .build()
}

fn extract_span(instr: &Instruction) -> (String, u32, u32) {
    match &instr.span {
        Some(s) => (s.file.clone(), s.start_line, s.start_col),
        None => ("unknown".into(), 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::*;

    fn make_instr(kind: ValueKind, name: &str, line: u32) -> Instruction {
        Instruction {
            id: 0,
            kind,
            name: name.into(),
            type_id: 0,
            span: Some(Span::new("test.go", line, 5)),
            operands: vec![],
            extract_index: 0,
            callee: None,
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
    fn test_nil001() {
        let instr = make_instr(ValueKind::FieldAddr, "t4", 18);
        let diag = build_nil001(&instr, "HandleRequest", 0.9, None);
        assert_eq!(diag.rule, "NIL001");
        assert_eq!(diag.severity, Severity::Critical);
        assert_eq!(diag.location.line, 18);
        assert!(diag.explanation.contains("t4"));
        assert!(diag.explanation.contains("HandleRequest"));
    }

    #[test]
    fn test_nil002() {
        let instr = make_instr(ValueKind::TypeAssert, "t3", 8);
        let diag = build_nil002(&instr, "ProcessValue");
        assert_eq!(diag.rule, "NIL002");
        assert_eq!(diag.severity, Severity::Critical);
        assert!(diag.explanation.contains("comma-ok"));
    }

    #[test]
    fn test_nil004_write() {
        let instr = make_instr(ValueKind::MapUpdate, "t5", 17);
        let diag = build_nil004(&instr, "WriteData", Nilability::Nil);
        assert_eq!(diag.rule, "NIL004");
        assert_eq!(diag.severity, Severity::Critical);
        assert!(diag.explanation.contains("nil"));
    }

    #[test]
    fn test_nil004_read() {
        let instr = make_instr(ValueKind::Lookup, "t5", 10);
        let diag = build_nil004(&instr, "ReadData", Nilability::MaybeNil);
        assert_eq!(diag.rule, "NIL004");
        assert_eq!(diag.severity, Severity::Warning);
        assert!(diag.explanation.contains("possibly nil"));
    }

    #[test]
    fn test_nil006() {
        let instr = make_instr(ValueKind::Send, "t6", 25);
        let diag = build_nil006(&instr, "SendMsg");
        assert_eq!(diag.rule, "NIL006");
        assert_eq!(diag.severity, Severity::Critical);
        assert!(diag.explanation.contains("channel"));
    }

    #[test]
    fn test_extract_span_none() {
        let mut instr = make_instr(ValueKind::FieldAddr, "t0", 1);
        instr.span = None;
        let (file, line, col) = extract_span(&instr);
        assert_eq!(file, "unknown");
        assert_eq!(line, 0);
        assert_eq!(col, 0);
    }
}
