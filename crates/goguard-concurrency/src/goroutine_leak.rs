//! Goroutine leak detection analysis.
//!
//! Implements LEAK001 (goroutine may never terminate) and
//! LEAK002 (channel created but never used).

use std::collections::{HashMap, HashSet};

use goguard_diagnostics::diagnostic::{
    Diagnostic, DiagnosticBuilder, DiagnosticSource, Frequency, Severity,
};
use goguard_ir::ir::*;

/// Check if a function has a termination signal: context.Context parameter,
/// channel receive, or select with a done case.
fn has_termination_signal(func: &Function) -> bool {
    // Check function parameters for context.Context.
    for block in &func.blocks {
        for instr in &block.instructions {
            if instr.kind == ValueKind::Parameter
                && (instr.name.contains("ctx") || instr.name.contains("context"))
            {
                return true;
            }
        }
    }

    // Check free_vars for context.Context or termination-related variables.
    for free_var in &func.free_vars {
        if free_var.type_name.contains("context.Context") || free_var.name.contains("ctx") {
            return true;
        }
        // Quit/stop/done/signal channels are termination signals.
        let name_lower = free_var.name.to_lowercase();
        if name_lower.contains("quit")
            || name_lower.contains("stop")
            || name_lower.contains("done")
            || name_lower.contains("shutdown")
            || name_lower.contains("sig")
        {
            return true;
        }
    }

    // Check for channel receive operations, select statements, or context calls.
    for block in &func.blocks {
        for instr in &block.instructions {
            match instr.kind {
                ValueKind::Select => return true,
                ValueKind::Call => {
                    if let Some(ref callee) = instr.callee {
                        if callee.contains("context.")
                            || callee.contains(".Done")
                            || callee.contains("signal)")  // os/signal package
                            || callee.contains("signal.Notify")
                            || callee.contains("signal.NotifyContext")
                            || callee.contains(".Shutdown")
                            || callee.contains(".GracefulStop")
                        {
                            return true;
                        }
                    }
                }
                // UnOp with channel_dir "recv" indicates a channel receive.
                ValueKind::UnOp => {
                    if instr.channel_dir.as_deref() == Some("recv") {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }

    // Check if the function has any return block (it terminates naturally).
    let has_return = func.blocks.iter().any(|b| b.is_return);
    // A function with only a single return block at the end is fine;
    // we only flag infinite loops (no return path with a termination signal).
    // If the function has a return, it's likely fine.
    if has_return && func.blocks.len() <= 2 {
        return true;
    }

    false
}

/// Detect LEAK001: goroutine may never terminate.
///
/// For each Go instruction, find the callee function. Check if the callee
/// has any termination path involving context.Context or channel receive.
/// If not, it may be an infinite goroutine leak.
pub fn detect_goroutine_leaks(pkg: &Package) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    let func_map: HashMap<&str, &Function> =
        pkg.functions.iter().map(|f| (f.name.as_str(), f)).collect();

    for func in &pkg.functions {
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind != ValueKind::Go {
                    continue;
                }

                let callee_name = match &instr.callee {
                    Some(name) => name.as_str(),
                    None => continue,
                };

                let callee_func = match func_map.get(callee_name) {
                    Some(f) => f,
                    None => continue,
                };

                if !has_termination_signal(callee_func) {
                    let (file, line, col) = instr
                        .span
                        .as_ref()
                        .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                        .unwrap_or(("unknown", 0, 1));

                    diagnostics.push(
                        DiagnosticBuilder::new(
                            "LEAK001",
                            Severity::Warning,
                            format!("Goroutine '{}' may never terminate", callee_func.short_name),
                            DiagnosticSource::Concurrency,
                        )
                        .location(file, line, col)
                        .confidence(0.7)
                        .explanation(format!(
                            "Goroutine '{}' launched at {}:{} has no visible termination \
                             signal. It does not accept context.Context, receive from a channel, \
                             or use select. This goroutine may leak and consume resources \
                             indefinitely.",
                            callee_func.short_name, file, line
                        ))
                        .pattern(
                            "goroutine-leak",
                            Frequency::Common,
                            "Pass context.Context and select on ctx.Done() for cancellation",
                        )
                        .build(),
                    );
                }
            }
        }
    }

    diagnostics
}

/// Detect LEAK002: channel created but never used in send, receive, or select.
///
/// Find MakeChan instructions. Track if the resulting channel ID appears
/// as an operand in any Send, Select, or UnOp (recv) instruction across
/// all functions in the package.
pub fn detect_unused_channels(pkg: &Package) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    // Collect all channel instruction IDs from MakeChan.
    let mut channel_defs: Vec<(u32, &str, &str, u32, u32)> = Vec::new(); // (id, func_name, file, line, col)

    for func in &pkg.functions {
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind == ValueKind::MakeChan {
                    let (file, line, col) = instr
                        .span
                        .as_ref()
                        .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                        .unwrap_or(("unknown", 0, 1));
                    channel_defs.push((instr.id, &func.short_name, file, line, col));
                }
            }
        }
    }

    if channel_defs.is_empty() {
        return diagnostics;
    }

    // Collect all instruction IDs used as operands in Send, Select, and
    // channel-related operations.
    let mut used_channel_ids: HashSet<u32> = HashSet::new();

    for func in &pkg.functions {
        for block in &func.blocks {
            for instr in &block.instructions {
                match instr.kind {
                    ValueKind::Send => {
                        // First operand of Send is typically the channel.
                        if let Some(&ch_id) = instr.operands.first() {
                            used_channel_ids.insert(ch_id);
                        }
                    }
                    ValueKind::Select => {
                        // All operands of select may be channels.
                        for &op in &instr.operands {
                            used_channel_ids.insert(op);
                        }
                        // Also check select_cases for channel references.
                        for case in &instr.select_cases {
                            // The channel field is a name, not an ID, so we need
                            // to also check by name matching below.
                            let _ = case;
                        }
                    }
                    ValueKind::UnOp => {
                        // Channel receive: operand is the channel.
                        if instr.channel_dir.as_deref() == Some("recv") {
                            if let Some(&ch_id) = instr.operands.first() {
                                used_channel_ids.insert(ch_id);
                            }
                        }
                    }
                    ValueKind::Call => {
                        // close(ch) — the channel is an operand.
                        if let Some(ref callee) = instr.callee {
                            if callee == "close" || callee.ends_with(".close") {
                                for &op in &instr.operands {
                                    used_channel_ids.insert(op);
                                }
                            }
                        }
                        // Channel used as argument to any function.
                        for &op in &instr.operands {
                            used_channel_ids.insert(op);
                        }
                    }
                    ValueKind::Go => {
                        // Channel passed to goroutine.
                        for &op in &instr.operands {
                            used_channel_ids.insert(op);
                        }
                    }
                    ValueKind::Store => {
                        // Channel stored somewhere.
                        for &op in &instr.operands {
                            used_channel_ids.insert(op);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    for (ch_id, func_name, file, line, col) in channel_defs {
        if !used_channel_ids.contains(&ch_id) {
            diagnostics.push(
                DiagnosticBuilder::new(
                    "LEAK002",
                    Severity::Warning,
                    "Channel created but never used".to_string(),
                    DiagnosticSource::Concurrency,
                )
                .location(file, line, col)
                .confidence(0.85)
                .explanation(format!(
                    "Channel created in '{}' at {}:{} is never sent to, received from, \
                     or used in a select statement. This is likely dead code or a bug.",
                    func_name, file, line
                ))
                .pattern(
                    "unused-channel",
                    Frequency::Uncommon,
                    "Remove unused channels or use them for synchronization",
                )
                .build(),
            );
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

    fn make_go_instr(id: u32, callee: &str, span_line: u32) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Go,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", span_line),
            operands: vec![],
            extract_index: 0,
            callee: Some(callee.into()),
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

    fn make_send_instr(id: u32, channel_op: u32) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Send,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", id + 10),
            operands: vec![channel_op],
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

    /// LEAK001: goroutine with no termination signal.
    #[test]
    fn test_leak001_goroutine_no_termination() {
        let caller = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_go_instr(0, "pkg.worker", 10)],
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

        // Worker is a long-running goroutine with no context or channel receive.
        // It has a loop (multiple blocks, no return in the loop body).
        let worker = Function {
            name: "pkg.worker".into(),
            short_name: "worker".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "loop.header".into(),
                    instructions: vec![Instruction {
                        id: 10,
                        kind: ValueKind::Call,
                        name: "t10".into(),
                        type_id: 0,
                        span: make_span("main.go", 20),
                        operands: vec![],
                        extract_index: 0,
                        callee: Some("time.Sleep".into()),
                        callee_is_interface: false,
                        assert_type_id: 0,
                        comma_ok: false,
                        const_value: None,
                        is_nil: false,
                        bin_op: None,
                        nil_operand_indices: vec![],
                        select_cases: vec![],
                        channel_dir: None,
                    }],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "loop.body".into(),
                    instructions: vec![Instruction {
                        id: 11,
                        kind: ValueKind::Call,
                        name: "t11".into(),
                        type_id: 0,
                        span: make_span("main.go", 21),
                        operands: vec![],
                        extract_index: 0,
                        callee: Some("fmt.Println".into()),
                        callee_is_interface: false,
                        assert_type_id: 0,
                        comma_ok: false,
                        const_value: None,
                        is_nil: false,
                        bin_op: None,
                        nil_operand_indices: vec![],
                        select_cases: vec![],
                        channel_dir: None,
                    }],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "loop.exit".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::Unconditional,
                },
                CfgEdge {
                    from_block: 1,
                    to_block: 0,
                    kind: EdgeKind::Unconditional,
                },
            ],
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
            functions: vec![caller, worker],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_goroutine_leaks(&pkg);
        assert!(!diags.is_empty(), "should detect LEAK001");
        assert_eq!(diags[0].rule, "LEAK001");
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    /// LEAK001 safe: goroutine uses context.Context.
    #[test]
    fn test_leak001_safe_with_context() {
        let caller = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_go_instr(0, "pkg.worker", 10)],
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

        // Worker receives a context.Context as free var.
        let worker = Function {
            name: "pkg.worker".into(),
            short_name: "worker".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "loop.header".into(),
                    instructions: vec![Instruction {
                        id: 10,
                        kind: ValueKind::Select,
                        name: "t10".into(),
                        type_id: 0,
                        span: make_span("main.go", 20),
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
                    }],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "done".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![CfgEdge {
                from_block: 0,
                to_block: 1,
                kind: EdgeKind::Unconditional,
            }],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![Variable {
                name: "ctx".into(),
                type_name: "context.Context".into(),
                span: None,
            }],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![caller, worker],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_goroutine_leaks(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag LEAK001 when context/select is used"
        );
    }

    /// LEAK001 safe: goroutine captures a quit channel (common server pattern).
    #[test]
    fn test_leak001_safe_with_quit_channel() {
        let caller = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_go_instr(0, "pkg.main$1", 10)],
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

        // Anonymous goroutine captures a "quit" channel — this is a shutdown handler.
        let worker = Function {
            name: "pkg.main$1".into(),
            short_name: "main$1".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "body".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "done".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::Unconditional,
                },
                CfgEdge {
                    from_block: 1,
                    to_block: 2,
                    kind: EdgeKind::Unconditional,
                },
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![Variable {
                name: "quit".into(),
                type_name: "chan os.Signal".into(),
                span: None,
            }],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![caller, worker],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_goroutine_leaks(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag LEAK001 when goroutine captures a quit channel"
        );
    }

    /// LEAK001 safe: goroutine calls signal.Notify (shutdown handler).
    #[test]
    fn test_leak001_safe_with_signal_notify() {
        let caller = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_go_instr(0, "pkg.main$2", 10)],
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

        let worker = Function {
            name: "pkg.main$2".into(),
            short_name: "main$2".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![Instruction {
                        id: 10,
                        kind: ValueKind::Call,
                        name: "t10".into(),
                        type_id: 0,
                        span: make_span("main.go", 20),
                        operands: vec![],
                        extract_index: 0,
                        callee: Some("(os/signal).Notify".into()),
                        callee_is_interface: false,
                        assert_type_id: 0,
                        comma_ok: false,
                        const_value: None,
                        is_nil: false,
                        bin_op: None,
                        nil_operand_indices: vec![],
                        select_cases: vec![],
                        channel_dir: None,
                    }],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "body".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "done".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::Unconditional,
                },
                CfgEdge {
                    from_block: 1,
                    to_block: 2,
                    kind: EdgeKind::Unconditional,
                },
            ],
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
            functions: vec![caller, worker],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_goroutine_leaks(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag LEAK001 when goroutine calls signal.Notify"
        );
    }

    /// LEAK002: channel created but never used.
    #[test]
    fn test_leak002_unused_channel() {
        let func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_makechan_instr(0, 10),
                    // Channel 0 is never used.
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

        let diags = detect_unused_channels(&pkg);
        assert!(!diags.is_empty(), "should detect LEAK002");
        assert_eq!(diags[0].rule, "LEAK002");
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    /// LEAK002 safe: channel is used in send.
    #[test]
    fn test_leak002_safe_channel_used() {
        let func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_makechan_instr(0, 10),
                    make_send_instr(1, 0), // Send on channel 0.
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

        let diags = detect_unused_channels(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag LEAK002 when channel is used in Send"
        );
    }
}
