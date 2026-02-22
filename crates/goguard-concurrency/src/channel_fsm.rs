//! Finite state machine modeling for Go channel operations.
//!
//! Implements CHAN001 (send on possibly closed channel) and
//! CHAN002 (unbuffered channel in select without default).

use std::collections::{HashMap, HashSet};

use goguard_diagnostics::diagnostic::{
    Diagnostic, DiagnosticBuilder, DiagnosticSource, Frequency, Severity,
};
use goguard_ir::ir::*;

/// Detect CHAN001: send on possibly closed channel.
///
/// Track channel state across the function. If a channel is closed
/// (via a Call to "close" builtin), flag any subsequent Send on the same channel.
pub fn detect_send_on_closed(pkg: &Package) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for func in &pkg.functions {
        // Track which instruction IDs represent channels that have been closed.
        let mut closed_channels: HashSet<u32> = HashSet::new();

        // Collect all "close" calls and the channels they close.
        // Also collect all Send instructions.
        // We process blocks in order (a simple approximation of control flow).
        let mut close_sites: HashMap<u32, (String, u32)> = HashMap::new(); // channel_id -> (file, line)
        let mut send_sites: Vec<(u32, &Instruction)> = Vec::new(); // (channel_id, instruction)

        for block in &func.blocks {
            for instr in &block.instructions {
                match instr.kind {
                    ValueKind::Call => {
                        if let Some(ref callee) = instr.callee {
                            if callee == "close" || callee == "builtin.close" {
                                // The first operand of close() is the channel.
                                if let Some(&ch_id) = instr.operands.first() {
                                    closed_channels.insert(ch_id);
                                    let (file, line) = instr
                                        .span
                                        .as_ref()
                                        .map(|s| (s.file.clone(), s.start_line))
                                        .unwrap_or_else(|| ("unknown".into(), 0));
                                    close_sites.insert(ch_id, (file, line));
                                }
                            }
                        }
                    }
                    ValueKind::Send => {
                        if let Some(&ch_id) = instr.operands.first() {
                            send_sites.push((ch_id, instr));
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check if any send targets a closed channel.
        // This is a simple intra-function check: if close(ch) appears anywhere
        // in the function and send(ch) also appears, flag it.
        // A more precise analysis would check block ordering / dominance.
        for (ch_id, send_instr) in &send_sites {
            if closed_channels.contains(ch_id) {
                let (file, line, col) = send_instr
                    .span
                    .as_ref()
                    .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                    .unwrap_or(("unknown", 0, 1));

                let close_info = close_sites
                    .get(ch_id)
                    .map(|(f, l)| format!(" (closed at {}:{})", f, l))
                    .unwrap_or_default();

                diagnostics.push(
                    DiagnosticBuilder::new(
                        "CHAN001",
                        Severity::Critical,
                        "Send on possibly closed channel".to_string(),
                        DiagnosticSource::Concurrency,
                    )
                    .location(file, line, col)
                    .confidence(0.85)
                    .explanation(format!(
                        "Channel is sent to at {}:{} but is also closed in function '{}'{}.  \
                         Sending on a closed channel causes a runtime panic.",
                        file, line, func.short_name, close_info
                    ))
                    .pattern(
                        "send-on-closed-channel",
                        Frequency::Common,
                        "Ensure the channel is not closed before sending, or use a sync mechanism",
                    )
                    .build(),
                );
            }
        }
    }

    diagnostics
}

/// Detect CHAN002: unbuffered channel in select without default case.
///
/// Find Select instructions that have no default case. This can cause blocking
/// if no channel operation is ready.
pub fn detect_select_without_default(pkg: &Package) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for func in &pkg.functions {
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind != ValueKind::Select {
                    continue;
                }

                // Check if any select case is the default case.
                let has_default = instr.select_cases.iter().any(|c| c.is_default);

                if !has_default && !instr.select_cases.is_empty() {
                    let (file, line, col) = instr
                        .span
                        .as_ref()
                        .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                        .unwrap_or(("unknown", 0, 1));

                    diagnostics.push(
                        DiagnosticBuilder::new(
                            "CHAN002",
                            Severity::Info,
                            "Select statement without default case".to_string(),
                            DiagnosticSource::Concurrency,
                        )
                        .location(file, line, col)
                        .confidence(0.6)
                        .explanation(format!(
                            "Select at {}:{} in '{}' has no default case. If no channel \
                             operation is ready, this select will block indefinitely. \
                             Consider adding a default case or a timeout.",
                            file, line, func.short_name
                        ))
                        .pattern(
                            "select-without-default",
                            Frequency::Common,
                            "Add a default case or use time.After for timeout",
                        )
                        .build(),
                    );
                }
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_span(file: &str, line: u32) -> Option<Span> {
        Some(Span::new(file, line, 1))
    }

    fn make_close_call(id: u32, channel_id: u32, span_line: u32) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Call,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", span_line),
            operands: vec![channel_id],
            extract_index: 0,
            callee: Some("close".into()),
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

    fn make_send_instr(id: u32, channel_id: u32, span_line: u32) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Send,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", span_line),
            operands: vec![channel_id],
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

    fn make_makechan_instr(id: u32, span_line: u32) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::MakeChan,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", span_line),
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

    fn make_select_instr(id: u32, span_line: u32, cases: Vec<SelectCase>) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Select,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", span_line),
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
            select_cases: cases,
            channel_dir: None,
        }
    }

    /// CHAN001: send on closed channel.
    #[test]
    fn test_chan001_send_on_closed() {
        let func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_makechan_instr(0, 10),
                    make_close_call(1, 0, 12),
                    make_send_instr(2, 0, 14),
                ],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_send_on_closed(&pkg);
        assert!(!diags.is_empty(), "should detect CHAN001");
        assert_eq!(diags[0].rule, "CHAN001");
        assert_eq!(diags[0].severity, Severity::Critical);
    }

    /// CHAN001 safe: channel is not closed.
    #[test]
    fn test_chan001_safe_no_close() {
        let func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_makechan_instr(0, 10), make_send_instr(1, 0, 12)],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_send_on_closed(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag CHAN001 when channel is not closed"
        );
    }

    /// CHAN002: select without default case.
    #[test]
    fn test_chan002_select_without_default() {
        let select = make_select_instr(
            0,
            10,
            vec![
                SelectCase {
                    dir: "recv".into(),
                    channel: "ch1".into(),
                    is_default: false,
                },
                SelectCase {
                    dir: "send".into(),
                    channel: "ch2".into(),
                    is_default: false,
                },
            ],
        );

        let func = Function {
            name: "pkg.handler".into(),
            short_name: "handler".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![select],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_select_without_default(&pkg);
        assert!(!diags.is_empty(), "should detect CHAN002");
        assert_eq!(diags[0].rule, "CHAN002");
        assert_eq!(diags[0].severity, Severity::Info);
    }

    /// CHAN002 safe: select with default case.
    #[test]
    fn test_chan002_safe_with_default() {
        let select = make_select_instr(
            0,
            10,
            vec![
                SelectCase {
                    dir: "recv".into(),
                    channel: "ch1".into(),
                    is_default: false,
                },
                SelectCase {
                    dir: "default".into(),
                    channel: String::new(),
                    is_default: true,
                },
            ],
        );

        let func = Function {
            name: "pkg.handler".into(),
            short_name: "handler".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![select],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_select_without_default(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag CHAN002 when select has default case"
        );
    }

    /// CHAN001: different channels - close one, send on another.
    #[test]
    fn test_chan001_different_channels_safe() {
        let func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_makechan_instr(0, 10), // ch1
                    make_makechan_instr(1, 11), // ch2
                    make_close_call(2, 0, 12),  // close(ch1)
                    make_send_instr(3, 1, 14),  // ch2 <- val (safe, ch2 not closed)
                ],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_send_on_closed(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag CHAN001 when send is on a different channel than the closed one"
        );
    }

    /// CHAN002: empty select_cases should not trigger.
    #[test]
    fn test_chan002_empty_select_no_diagnostic() {
        let select = make_select_instr(0, 10, vec![]);

        let func = Function {
            name: "pkg.handler".into(),
            short_name: "handler".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![select],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_select_without_default(&pkg);
        assert!(
            diags.is_empty(),
            "empty select_cases should not trigger CHAN002"
        );
    }
}
