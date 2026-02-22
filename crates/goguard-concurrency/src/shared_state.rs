//! Shared state analysis for detecting unsynchronized access.
//!
//! Implements RACE001 (shared variable in goroutine without sync) and
//! RACE002 (goroutine captures loop variable).

use std::collections::{HashMap, HashSet};

use goguard_diagnostics::diagnostic::{
    Diagnostic, DiagnosticBuilder, DiagnosticSource, Frequency, Severity,
};
use goguard_ir::ir::*;

/// Sync primitive type name prefixes that indicate synchronization.
const SYNC_PREFIXES: &[&str] = &[
    "sync.Mutex",
    "sync.RWMutex",
    "sync.WaitGroup",
    "sync.Once",
    "sync.Map",
    "sync/atomic",
    "atomic.",
];

/// Check if a callee name indicates a sync primitive usage.
fn is_sync_call(callee: &str) -> bool {
    SYNC_PREFIXES.iter().any(|prefix| callee.contains(prefix))
}

/// Check if a function uses sync primitives anywhere in its body.
fn function_uses_sync(func: &Function) -> bool {
    for block in &func.blocks {
        for instr in &block.instructions {
            if instr.kind == ValueKind::Call || instr.kind == ValueKind::Defer {
                if let Some(ref callee) = instr.callee {
                    if is_sync_call(callee) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Collect all variable names that are written (Store) in a function.
fn collect_written_vars(func: &Function) -> HashSet<String> {
    let mut written = HashSet::new();
    for block in &func.blocks {
        for instr in &block.instructions {
            if instr.kind == ValueKind::Store {
                // The name of a Store instruction often refers to the target variable.
                // Also check if operands reference FreeVar instructions.
                if !instr.name.is_empty() {
                    written.insert(instr.name.clone());
                }
            }
        }
    }
    written
}

/// Detect RACE001: shared variable accessed in goroutine without synchronization.
///
/// For each Go instruction in each function, find the callee function in the package.
/// Check if the callee has FreeVar entries that are also written (Store) in the caller,
/// and neither the caller nor the callee uses sync primitives.
pub fn detect_shared_state_races(pkg: &Package) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    // Build a map from function name to function for callee lookup.
    let func_map: HashMap<&str, &Function> =
        pkg.functions.iter().map(|f| (f.name.as_str(), f)).collect();

    for func in &pkg.functions {
        let caller_writes = collect_written_vars(func);
        let caller_uses_sync = function_uses_sync(func);

        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind != ValueKind::Go {
                    continue;
                }

                // The Go instruction's callee is the goroutine function.
                let callee_name = match &instr.callee {
                    Some(name) => name.as_str(),
                    None => continue,
                };

                let callee_func = match func_map.get(callee_name) {
                    Some(f) => f,
                    None => continue,
                };

                // Skip if either side uses sync primitives.
                if caller_uses_sync || function_uses_sync(callee_func) {
                    continue;
                }

                // Check if any of the callee's free variables overlap with
                // variables written in the caller.
                for free_var in &callee_func.free_vars {
                    if caller_writes.contains(&free_var.name) {
                        let (file, line, col) = instr
                            .span
                            .as_ref()
                            .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                            .unwrap_or(("unknown", 0, 1));

                        diagnostics.push(
                            DiagnosticBuilder::new(
                                "RACE001",
                                Severity::Warning,
                                format!(
                                    "Shared variable '{}' accessed in goroutine without synchronization",
                                    free_var.name
                                ),
                                DiagnosticSource::Concurrency,
                            )
                            .location(file, line, col)
                            .confidence(0.8)
                            .explanation(format!(
                                "Variable '{}' is written in '{}' and captured as a free variable \
                                 by goroutine '{}' without any sync.Mutex, sync.RWMutex, or atomic \
                                 protection. This is a data race.",
                                free_var.name, func.short_name, callee_func.short_name
                            ))
                            .pattern(
                                "unsynchronized-goroutine-access",
                                Frequency::VeryCommon,
                                "Protect shared variables with sync.Mutex or use channels",
                            )
                            .build(),
                        );
                    }
                }

                // Also check if the callee writes to free variables that the caller reads.
                let callee_writes = collect_written_vars(callee_func);
                for free_var in &callee_func.free_vars {
                    // If the callee writes to a free var (shared state), and the
                    // caller also accesses it (it's a free var so caller owns it).
                    if callee_writes.contains(&free_var.name)
                        && !caller_writes.contains(&free_var.name)
                    {
                        let (file, line, col) = instr
                            .span
                            .as_ref()
                            .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                            .unwrap_or(("unknown", 0, 1));

                        diagnostics.push(
                            DiagnosticBuilder::new(
                                "RACE001",
                                Severity::Warning,
                                format!(
                                    "Shared variable '{}' accessed in goroutine without synchronization",
                                    free_var.name
                                ),
                                DiagnosticSource::Concurrency,
                            )
                            .location(file, line, col)
                            .confidence(0.75)
                            .explanation(format!(
                                "Variable '{}' is written in goroutine '{}' and accessible from \
                                 '{}' without any sync.Mutex, sync.RWMutex, or atomic protection. \
                                 This is a data race.",
                                free_var.name, callee_func.short_name, func.short_name
                            ))
                            .pattern(
                                "unsynchronized-goroutine-access",
                                Frequency::VeryCommon,
                                "Protect shared variables with sync.Mutex or use channels",
                            )
                            .build(),
                        );
                    }
                }
            }
        }
    }

    diagnostics
}

/// Detect RACE002: goroutine captures loop variable.
///
/// Find Go instructions inside loop blocks (blocks reachable from Range/Next blocks).
/// Check if the callee captures a loop iterator variable as a free variable.
pub fn detect_loop_var_capture(pkg: &Package) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    let func_map: HashMap<&str, &Function> =
        pkg.functions.iter().map(|f| (f.name.as_str(), f)).collect();

    for func in &pkg.functions {
        // Find blocks that are part of a loop by looking for blocks containing
        // Range or Next instructions (the iterator blocks of for-range loops).
        let mut loop_var_names: HashSet<String> = HashSet::new();
        let mut loop_block_ids: HashSet<u32> = HashSet::new();

        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind == ValueKind::Range || instr.kind == ValueKind::Next {
                    loop_block_ids.insert(block.id);
                    // The Range/Next instruction name is the loop iterator variable.
                    if !instr.name.is_empty() {
                        loop_var_names.insert(instr.name.clone());
                    }
                }
            }
        }

        if loop_block_ids.is_empty() {
            continue;
        }

        // Also consider blocks reachable from loop blocks within the loop body.
        // Simple heuristic: include successors of loop blocks.
        let mut body_block_ids = loop_block_ids.clone();
        for edge in &func.cfg_edges {
            if loop_block_ids.contains(&edge.from_block) {
                body_block_ids.insert(edge.to_block);
            }
        }
        // Also add blocks that flow back to loop blocks (loop body proper).
        for edge in &func.cfg_edges {
            if loop_block_ids.contains(&edge.to_block) && !loop_block_ids.contains(&edge.from_block)
            {
                body_block_ids.insert(edge.from_block);
            }
        }

        // Now scan for Go instructions in body blocks.
        for block in &func.blocks {
            if !body_block_ids.contains(&block.id) {
                continue;
            }

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

                // Check if any of the callee's free variables match loop iterator names.
                for free_var in &callee_func.free_vars {
                    if loop_var_names.contains(&free_var.name) {
                        let (file, line, col) = instr
                            .span
                            .as_ref()
                            .map(|s| (s.file.as_str(), s.start_line, s.start_col))
                            .unwrap_or(("unknown", 0, 1));

                        diagnostics.push(
                            DiagnosticBuilder::new(
                                "RACE002",
                                Severity::Critical,
                                format!("Goroutine captures loop variable '{}'", free_var.name),
                                DiagnosticSource::Concurrency,
                            )
                            .location(file, line, col)
                            .confidence(0.95)
                            .explanation(format!(
                                "The goroutine launched at {}:{} captures loop variable '{}' \
                                 by reference. By the time the goroutine executes, the variable \
                                 will have been mutated by the loop iterator. All goroutines \
                                 will see the final value of the loop variable.",
                                file, line, free_var.name
                            ))
                            .pattern(
                                "loop-variable-capture",
                                Frequency::VeryCommon,
                                "Pass the loop variable as a parameter: go func(v Type) { ... }(v)",
                            )
                            .build(),
                        );
                    }
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

    fn make_instr(id: u32, kind: ValueKind, name: &str) -> Instruction {
        Instruction {
            id,
            kind,
            name: name.into(),
            type_id: 0,
            span: make_span("main.go", id + 10),
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

    fn make_store_instr(id: u32, name: &str) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Store,
            name: name.into(),
            type_id: 0,
            span: make_span("main.go", id + 10),
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

    fn make_call_instr(id: u32, callee: &str) -> Instruction {
        Instruction {
            id,
            kind: ValueKind::Call,
            name: format!("t{id}"),
            type_id: 0,
            span: make_span("main.go", id + 10),
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

    /// RACE001: goroutine captures variable written by caller without sync.
    #[test]
    fn test_race001_shared_var_in_goroutine() {
        // Caller writes to "counter", goroutine closure captures "counter" as free var.
        let caller_func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_store_instr(0, "counter"),
                    make_go_instr(1, "pkg.main$1", 15),
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

        let closure_func = Function {
            name: "pkg.main$1".into(),
            short_name: "main$1".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_store_instr(10, "counter")],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![Variable {
                name: "counter".into(),
                type_name: "int".into(),
                span: None,
            }],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![caller_func, closure_func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_shared_state_races(&pkg);
        assert!(!diags.is_empty(), "should detect RACE001");
        assert_eq!(diags[0].rule, "RACE001");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert!(diags[0].title.contains("counter"));
    }

    /// RACE001 safe: goroutine uses sync.Mutex for protection.
    #[test]
    fn test_race001_safe_with_mutex() {
        let caller_func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_store_instr(0, "counter"),
                    make_call_instr(1, "(*sync.Mutex).Lock"),
                    make_go_instr(2, "pkg.main$1", 15),
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

        let closure_func = Function {
            name: "pkg.main$1".into(),
            short_name: "main$1".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    make_call_instr(10, "(*sync.Mutex).Lock"),
                    make_store_instr(11, "counter"),
                    make_call_instr(12, "(*sync.Mutex).Unlock"),
                ],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![Variable {
                name: "counter".into(),
                type_name: "int".into(),
                span: None,
            }],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![caller_func, closure_func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_shared_state_races(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag RACE001 when sync.Mutex is used"
        );
    }

    /// RACE002: goroutine captures loop variable.
    #[test]
    fn test_race002_loop_var_capture() {
        // Outer function has a for-range loop with a Go inside the body.
        let range_instr = Instruction {
            id: 0,
            kind: ValueKind::Range,
            name: "i".into(),
            type_id: 0,
            span: make_span("main.go", 10),
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
        };

        let go_instr = make_go_instr(1, "pkg.process$1", 12);

        let outer_func = Function {
            name: "pkg.process".into(),
            short_name: "process".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "loop.header".into(),
                    instructions: vec![range_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "loop.body".into(),
                    instructions: vec![go_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "loop.done".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 0,
                    to_block: 2,
                    kind: EdgeKind::CondFalse,
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

        let closure_func = Function {
            name: "pkg.process$1".into(),
            short_name: "process$1".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_instr(10, ValueKind::Call, "t10")],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![Variable {
                name: "i".into(),
                type_name: "int".into(),
                span: None,
            }],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![outer_func, closure_func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_loop_var_capture(&pkg);
        assert!(!diags.is_empty(), "should detect RACE002");
        assert_eq!(diags[0].rule, "RACE002");
        assert_eq!(diags[0].severity, Severity::Critical);
        assert!(diags[0].title.contains("'i'"));
    }

    /// RACE002 safe: goroutine does not capture loop variable.
    #[test]
    fn test_race002_safe_no_loop_var() {
        let range_instr = Instruction {
            id: 0,
            kind: ValueKind::Range,
            name: "i".into(),
            type_id: 0,
            span: make_span("main.go", 10),
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
        };

        let go_instr = make_go_instr(1, "pkg.process$1", 12);

        let outer_func = Function {
            name: "pkg.process".into(),
            short_name: "process".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "loop.header".into(),
                    instructions: vec![range_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "loop.body".into(),
                    instructions: vec![go_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "loop.done".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 0,
                    to_block: 2,
                    kind: EdgeKind::CondFalse,
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

        // Closure does NOT capture "i" — it captures "data" instead.
        let closure_func = Function {
            name: "pkg.process$1".into(),
            short_name: "process$1".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_instr(10, ValueKind::Call, "t10")],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![Variable {
                name: "data".into(),
                type_name: "[]string".into(),
                span: None,
            }],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![outer_func, closure_func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = detect_loop_var_capture(&pkg);
        assert!(
            diags.is_empty(),
            "should not flag RACE002 when closure does not capture loop var"
        );
    }

    /// RACE001: no diagnostic when no Go instructions exist.
    #[test]
    fn test_race001_no_goroutines() {
        let func = Function {
            name: "pkg.simple".into(),
            short_name: "simple".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_store_instr(0, "x")],
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

        let diags = detect_shared_state_races(&pkg);
        assert!(diags.is_empty());
    }
}
