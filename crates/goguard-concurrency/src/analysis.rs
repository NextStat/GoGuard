//! Core concurrency analysis engine.
//!
//! Combines all sub-analyzers (shared state, goroutine leaks, channel FSM)
//! into a single `ConcurrencyAnalyzer` entry point.

use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::ir::{AnalysisInput, Package};

use crate::channel_fsm;
use crate::goroutine_leak;
use crate::shared_state;

/// Top-level concurrency analyzer combining all sub-analyzers.
///
/// Produces diagnostics for:
/// - RACE001: shared variable access in goroutine without sync
/// - RACE002: goroutine captures loop variable
/// - LEAK001: goroutine may never terminate
/// - LEAK002: channel created but never used
/// - CHAN001: send on possibly closed channel
/// - CHAN002: select without default case
pub struct ConcurrencyAnalyzer;

impl ConcurrencyAnalyzer {
    /// Analyze all packages in an `AnalysisInput` and return diagnostics.
    pub fn analyze(input: &AnalysisInput) -> Vec<Diagnostic> {
        input
            .packages
            .iter()
            .flat_map(Self::analyze_package)
            .collect()
    }

    /// Analyze a single package for concurrency issues.
    pub fn analyze_package(pkg: &Package) -> Vec<Diagnostic> {
        let mut diags = Vec::new();
        diags.extend(shared_state::detect_shared_state_races(pkg));
        diags.extend(shared_state::detect_loop_var_capture(pkg));
        diags.extend(goroutine_leak::detect_goroutine_leaks(pkg));
        diags.extend(goroutine_leak::detect_unused_channels(pkg));
        diags.extend(channel_fsm::detect_send_on_closed(pkg));
        diags.extend(channel_fsm::detect_select_without_default(pkg));
        diags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::Severity;
    use goguard_ir::ir::*;

    fn make_span(file: &str, line: u32) -> Option<Span> {
        Some(Span::new(file, line, 1))
    }

    /// Integration test: ConcurrencyAnalyzer catches multiple issues.
    #[test]
    fn test_analyzer_catches_race001_and_chan001() {
        // Build a package with:
        // 1. A RACE001 pattern (shared var in goroutine)
        // 2. A CHAN001 pattern (send on closed channel)

        let caller_func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    Instruction {
                        id: 0,
                        kind: ValueKind::Store,
                        name: "counter".into(),
                        type_id: 0,
                        span: make_span("main.go", 5),
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
                    },
                    Instruction {
                        id: 1,
                        kind: ValueKind::Go,
                        name: "t1".into(),
                        type_id: 0,
                        span: make_span("main.go", 7),
                        operands: vec![],
                        extract_index: 0,
                        callee: Some("pkg.main$1".into()),
                        callee_is_interface: false,
                        assert_type_id: 0,
                        comma_ok: false,
                        const_value: None,
                        is_nil: false,
                        bin_op: None,
                        nil_operand_indices: vec![],
                        select_cases: vec![],
                        channel_dir: None,
                    },
                    Instruction {
                        id: 2,
                        kind: ValueKind::MakeChan,
                        name: "t2".into(),
                        type_id: 0,
                        span: make_span("main.go", 9),
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
                    },
                    Instruction {
                        id: 3,
                        kind: ValueKind::Call,
                        name: "t3".into(),
                        type_id: 0,
                        span: make_span("main.go", 10),
                        operands: vec![2],
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
                    },
                    Instruction {
                        id: 4,
                        kind: ValueKind::Send,
                        name: "t4".into(),
                        type_id: 0,
                        span: make_span("main.go", 11),
                        operands: vec![2],
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
                    },
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
                instructions: vec![Instruction {
                    id: 10,
                    kind: ValueKind::Store,
                    name: "counter".into(),
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

        let input = AnalysisInput {
            packages: vec![pkg],
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        };

        let diags = ConcurrencyAnalyzer::analyze(&input);

        let has_race001 = diags.iter().any(|d| d.rule == "RACE001");
        let has_chan001 = diags.iter().any(|d| d.rule == "CHAN001");

        assert!(has_race001, "should detect RACE001");
        assert!(has_chan001, "should detect CHAN001");
    }

    /// Integration test: empty package produces zero diagnostics.
    #[test]
    fn test_analyzer_empty_package() {
        let pkg = Package {
            import_path: "example.com/empty".into(),
            name: "empty".into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = ConcurrencyAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "empty package should produce zero diagnostics"
        );
    }

    /// Integration test: analyze_package matches analyze for single-package input.
    #[test]
    fn test_analyzer_package_vs_analyze_consistency() {
        // A safe package with no issues.
        let func = Function {
            name: "pkg.hello".into(),
            short_name: "hello".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![Instruction {
                    id: 0,
                    kind: ValueKind::Call,
                    name: "t0".into(),
                    type_id: 0,
                    span: make_span("main.go", 5),
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
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
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

        let input = AnalysisInput {
            packages: vec![pkg.clone()],
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        };

        let from_analyze = ConcurrencyAnalyzer::analyze(&input);
        let from_package = ConcurrencyAnalyzer::analyze_package(&input.packages[0]);

        assert_eq!(
            from_analyze.len(),
            from_package.len(),
            "analyze and analyze_package should produce same count"
        );
    }

    /// Integration test: all 6 rules can fire from a single package.
    #[test]
    fn test_analyzer_all_rules() {
        // Build a complex package that triggers all 6 rules.

        // Function with RACE001 + LEAK001 (Go launches worker without sync, no termination)
        let main_func = Function {
            name: "pkg.main".into(),
            short_name: "main".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "loop.header".into(),
                    instructions: vec![
                        Instruction {
                            id: 100,
                            kind: ValueKind::Range,
                            name: "i".into(),
                            type_id: 0,
                            span: make_span("main.go", 5),
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
                        },
                        Instruction {
                            id: 101,
                            kind: ValueKind::Store,
                            name: "counter".into(),
                            type_id: 0,
                            span: make_span("main.go", 6),
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
                        },
                    ],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "loop.body".into(),
                    instructions: vec![
                        // RACE002: Go inside loop capturing loop var
                        Instruction {
                            id: 102,
                            kind: ValueKind::Go,
                            name: "t102".into(),
                            type_id: 0,
                            span: make_span("main.go", 8),
                            operands: vec![],
                            extract_index: 0,
                            callee: Some("pkg.main$loop".into()),
                            callee_is_interface: false,
                            assert_type_id: 0,
                            comma_ok: false,
                            const_value: None,
                            is_nil: false,
                            bin_op: None,
                            nil_operand_indices: vec![],
                            select_cases: vec![],
                            channel_dir: None,
                        },
                        // RACE001 + LEAK001: Go launching worker without sync
                        Instruction {
                            id: 103,
                            kind: ValueKind::Go,
                            name: "t103".into(),
                            type_id: 0,
                            span: make_span("main.go", 10),
                            operands: vec![],
                            extract_index: 0,
                            callee: Some("pkg.worker".into()),
                            callee_is_interface: false,
                            assert_type_id: 0,
                            comma_ok: false,
                            const_value: None,
                            is_nil: false,
                            bin_op: None,
                            nil_operand_indices: vec![],
                            select_cases: vec![],
                            channel_dir: None,
                        },
                    ],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "after_loop".into(),
                    instructions: vec![
                        // LEAK002: unused channel
                        Instruction {
                            id: 200,
                            kind: ValueKind::MakeChan,
                            name: "t200".into(),
                            type_id: 0,
                            span: make_span("main.go", 15),
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
                        },
                        // CHAN001: close + send on same channel
                        Instruction {
                            id: 201,
                            kind: ValueKind::MakeChan,
                            name: "t201".into(),
                            type_id: 0,
                            span: make_span("main.go", 16),
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
                        },
                        Instruction {
                            id: 202,
                            kind: ValueKind::Call,
                            name: "t202".into(),
                            type_id: 0,
                            span: make_span("main.go", 17),
                            operands: vec![201],
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
                        },
                        Instruction {
                            id: 203,
                            kind: ValueKind::Send,
                            name: "t203".into(),
                            type_id: 0,
                            span: make_span("main.go", 18),
                            operands: vec![201],
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
                        },
                        // CHAN002: select without default
                        Instruction {
                            id: 204,
                            kind: ValueKind::Select,
                            name: "t204".into(),
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
                            select_cases: vec![SelectCase {
                                dir: "recv".into(),
                                channel: "ch".into(),
                                is_default: false,
                            }],
                            channel_dir: None,
                        },
                    ],
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

        // Closure that captures loop variable (RACE002).
        let loop_closure = Function {
            name: "pkg.main$loop".into(),
            short_name: "main$loop".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![],
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

        // Worker: captures "counter" without sync, has 3+ blocks (LEAK001 fires).
        let worker = Function {
            name: "pkg.worker".into(),
            short_name: "worker".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![Instruction {
                        id: 300,
                        kind: ValueKind::Store,
                        name: "counter".into(),
                        type_id: 0,
                        span: make_span("main.go", 30),
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
                    name: "loop".into(),
                    instructions: vec![Instruction {
                        id: 301,
                        kind: ValueKind::Call,
                        name: "t301".into(),
                        type_id: 0,
                        span: make_span("main.go", 31),
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
                    name: "exit".into(),
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
            functions: vec![main_func, loop_closure, worker],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = ConcurrencyAnalyzer::analyze_package(&pkg);

        let rules: Vec<&str> = diags.iter().map(|d| d.rule.as_str()).collect();

        assert!(
            rules.contains(&"RACE001"),
            "missing RACE001, got: {:?}",
            rules
        );
        assert!(
            rules.contains(&"RACE002"),
            "missing RACE002, got: {:?}",
            rules
        );
        assert!(
            rules.contains(&"LEAK001"),
            "missing LEAK001, got: {:?}",
            rules
        );
        assert!(
            rules.contains(&"LEAK002"),
            "missing LEAK002, got: {:?}",
            rules
        );
        assert!(
            rules.contains(&"CHAN001"),
            "missing CHAN001, got: {:?}",
            rules
        );
        assert!(
            rules.contains(&"CHAN002"),
            "missing CHAN002, got: {:?}",
            rules
        );

        // Verify severities.
        for d in &diags {
            match d.rule.as_str() {
                "RACE001" => assert_eq!(d.severity, Severity::Warning),
                "RACE002" => assert_eq!(d.severity, Severity::Critical),
                "LEAK001" => assert_eq!(d.severity, Severity::Warning),
                "LEAK002" => assert_eq!(d.severity, Severity::Warning),
                "CHAN001" => assert_eq!(d.severity, Severity::Critical),
                "CHAN002" => assert_eq!(d.severity, Severity::Info),
                _ => panic!("unexpected rule: {}", d.rule),
            }
        }
    }
}
