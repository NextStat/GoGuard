//! Exhaustiveness analysis engine for switch and type-switch statements.
//!
//! Detects non-exhaustive type switches (EXH001), enum switches (EXH002),
//! and missing default cases (EXH003) by scanning Go SSA IR for switch
//! patterns and comparing covered cases against known interface implementors
//! and enum constant groups.

use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::ir::{AnalysisInput, EnumGroup, Function, InterfaceEntry, Package, TypeRef};

use crate::enum_discovery;
use crate::rules;

/// Exhaustiveness analyzer for Go switch statements.
pub struct ExhaustiveAnalyzer;

impl ExhaustiveAnalyzer {
    /// Analyze all packages in the input for exhaustiveness issues.
    ///
    /// This is the primary entry point. It uses `interface_table` and
    /// `enum_groups` from the `AnalysisInput` to check coverage.
    pub fn analyze(input: &AnalysisInput) -> Vec<Diagnostic> {
        input
            .packages
            .iter()
            .flat_map(|pkg| Self::analyze_package(pkg, &input.interface_table, &input.enum_groups))
            .collect()
    }

    /// Analyze a single package for exhaustiveness issues.
    ///
    /// Used by the Salsa incremental computation path, where interface_table
    /// and enum_groups are passed separately from the package.
    pub fn analyze_package(
        pkg: &Package,
        interface_table: &[InterfaceEntry],
        enum_groups: &[EnumGroup],
    ) -> Vec<Diagnostic> {
        let mut diags = Vec::new();
        for func in &pkg.functions {
            diags.extend(Self::check_type_switches(func, &pkg.types, interface_table));
            diags.extend(Self::check_enum_switches(func, &pkg.types, enum_groups));
        }
        diags
    }

    /// Check type switches in a function against the interface table.
    fn check_type_switches(
        func: &Function,
        types: &[TypeRef],
        ifaces: &[InterfaceEntry],
    ) -> Vec<Diagnostic> {
        let switches = enum_discovery::find_type_switches(func, types);
        let mut diags = Vec::new();

        for sw in &switches {
            // Try to find this interface in the interface table.
            let iface = ifaces
                .iter()
                .find(|i| i.interface_name == sw.interface_type_name);

            if let Some(iface) = iface {
                // Compute missing implementors
                let missing: Vec<&str> = iface
                    .implementors
                    .iter()
                    .filter(|imp| !sw.tested_types.iter().any(|t| t == *imp))
                    .map(|s| s.as_str())
                    .collect();

                if !missing.is_empty() && !sw.has_default {
                    // EXH001: missing implementor without default
                    diags.push(rules::build_exh001(
                        &sw.span,
                        &sw.interface_type_name,
                        &missing,
                        &func.short_name,
                    ));
                }
            }

            // EXH003: non-exhaustive switch without default (even when no
            // interface table entry exists, we can still flag the missing default
            // if the switch is known to be incomplete).
            if !sw.has_default {
                let is_fully_covered = ifaces
                    .iter()
                    .find(|i| i.interface_name == sw.interface_type_name)
                    .map(|i| {
                        i.implementors
                            .iter()
                            .all(|imp| sw.tested_types.contains(imp))
                    })
                    .unwrap_or(false);

                if !is_fully_covered {
                    diags.push(rules::build_exh003(
                        &sw.span,
                        &format!("type switch on `{}`", sw.interface_type_name),
                        &func.short_name,
                    ));
                }
            }
        }

        diags
    }

    /// Check enum switches in a function against the enum groups.
    fn check_enum_switches(
        func: &Function,
        types: &[TypeRef],
        enum_groups: &[EnumGroup],
    ) -> Vec<Diagnostic> {
        let switches = enum_discovery::find_enum_switches(func, types);
        let mut diags = Vec::new();

        for sw in &switches {
            // Try to find this enum type in the enum groups.
            let group = enum_groups
                .iter()
                .find(|g| g.type_name == sw.enum_type_name);

            if let Some(group) = group {
                // Compute missing constants
                let missing: Vec<&str> = group
                    .constants
                    .iter()
                    .filter(|c| !sw.tested_values.contains(&c.name))
                    .map(|c| c.name.as_str())
                    .collect();

                if !missing.is_empty() && !sw.has_default {
                    // EXH002: missing enum value without default
                    diags.push(rules::build_exh002(
                        &sw.span,
                        &sw.enum_type_name,
                        &missing,
                        &func.short_name,
                    ));
                }
            }

            // EXH003: non-exhaustive enum switch without default
            if !sw.has_default {
                let is_fully_covered = enum_groups
                    .iter()
                    .find(|g| g.type_name == sw.enum_type_name)
                    .map(|g| {
                        g.constants
                            .iter()
                            .all(|c| sw.tested_values.contains(&c.name))
                    })
                    .unwrap_or(false);

                if !is_fully_covered {
                    diags.push(rules::build_exh003(
                        &sw.span,
                        &format!("switch on `{}`", sw.enum_type_name),
                        &func.short_name,
                    ));
                }
            }
        }

        diags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::Severity;
    use goguard_ir::ir::*;

    fn make_animal_types() -> Vec<TypeRef> {
        vec![
            TypeRef {
                id: 10,
                kind: TypeKind::Interface,
                name: "Animal".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
            TypeRef {
                id: 11,
                kind: TypeKind::Pointer,
                name: "*Dog".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
            TypeRef {
                id: 12,
                kind: TypeKind::Pointer,
                name: "*Cat".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
            TypeRef {
                id: 13,
                kind: TypeKind::Pointer,
                name: "*Bird".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
            TypeRef {
                id: 20,
                kind: TypeKind::Basic,
                name: "bool".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
        ]
    }

    fn make_color_types() -> Vec<TypeRef> {
        vec![
            TypeRef {
                id: 10,
                kind: TypeKind::Named,
                name: "Color".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
            TypeRef {
                id: 20,
                kind: TypeKind::Basic,
                name: "bool".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
        ]
    }

    /// Build a type switch function that tests the given types.
    /// `tested_type_ids` are the assert_type_ids for each case.
    /// `has_default_block` controls whether the fallthrough block has instructions.
    fn make_type_switch_func(
        name: &str,
        base_type_id: u32,
        tested_type_ids: &[u32],
        has_default_block: bool,
    ) -> Function {
        let mut blocks = Vec::new();
        let mut edges = Vec::new();
        let mut instr_id: u32 = 0;

        // Block 0: param
        let param = Instruction {
            id: instr_id,
            kind: ValueKind::Parameter,
            name: "x".into(),
            type_id: base_type_id,
            span: Some(Span::new("test.go", 10, 1)),
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
        let param_id = instr_id;
        instr_id += 1;

        // Build the chain of TypeAssert -> Extract -> If
        let mut first_block_instrs = vec![param];
        let mut block_id: u32 = 0;
        let case_start_block: u32 = 100; // case blocks start at high IDs

        for (i, &assert_type_id) in tested_type_ids.iter().enumerate() {
            let ta_id = instr_id;
            let ta = Instruction {
                id: ta_id,
                kind: ValueKind::TypeAssert,
                name: format!("ta{i}"),
                type_id: assert_type_id,
                span: Some(Span::new("test.go", 10 + (i as u32) * 3, 5)),
                operands: vec![param_id],
                extract_index: 0,
                callee: None,
                callee_is_interface: false,
                assert_type_id,
                comma_ok: true,
                const_value: None,
                is_nil: false,
                bin_op: None,
                nil_operand_indices: vec![],
                select_cases: vec![],
                channel_dir: None,
            };
            instr_id += 1;

            let extract_id = instr_id;
            let extract = Instruction {
                id: extract_id,
                kind: ValueKind::Extract,
                name: format!("ext{i}"),
                type_id: 20, // bool
                span: None,
                operands: vec![ta_id],
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
            instr_id += 1;

            let if_id = instr_id;
            let if_instr = Instruction {
                id: if_id,
                kind: ValueKind::If,
                name: format!("if{i}"),
                type_id: 0,
                span: None,
                operands: vec![extract_id],
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
            instr_id += 1;

            let case_block_id = case_start_block + i as u32;
            let next_block_id = block_id + 1;

            if i == 0 {
                // First case goes in the entry block
                first_block_instrs.push(ta);
                first_block_instrs.push(extract);
                first_block_instrs.push(if_instr);
            } else {
                // Subsequent cases go in their own block
                blocks.push(BasicBlock {
                    id: block_id,
                    name: format!("check{i}"),
                    instructions: vec![ta, extract, if_instr],
                    is_return: false,
                    is_panic: false,
                });
            }

            // Edge from current block to case (CondTrue) and next check (CondFalse)
            edges.push(CfgEdge {
                from_block: block_id,
                to_block: case_block_id,
                kind: EdgeKind::CondTrue,
            });

            if i < tested_type_ids.len() - 1 {
                edges.push(CfgEdge {
                    from_block: block_id,
                    to_block: next_block_id,
                    kind: EdgeKind::CondFalse,
                });
            } else {
                // Last case: CondFalse goes to default/fallthrough
                let default_block_id = case_start_block + tested_type_ids.len() as u32;
                edges.push(CfgEdge {
                    from_block: block_id,
                    to_block: default_block_id,
                    kind: EdgeKind::CondFalse,
                });

                // Default/fallthrough block
                let default_instrs = if has_default_block {
                    vec![Instruction {
                        id: instr_id,
                        kind: ValueKind::Return,
                        name: "ret_default".into(),
                        type_id: 0,
                        span: None,
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
                    }]
                } else {
                    vec![]
                };
                instr_id += 1;

                blocks.push(BasicBlock {
                    id: default_block_id,
                    name: "default".into(),
                    instructions: default_instrs,
                    is_return: has_default_block,
                    is_panic: false,
                });
            }

            // Case block (just a return)
            blocks.push(BasicBlock {
                id: case_block_id,
                name: format!("case{i}"),
                instructions: vec![Instruction {
                    id: instr_id,
                    kind: ValueKind::Return,
                    name: format!("ret{i}"),
                    type_id: 0,
                    span: None,
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
            });
            instr_id += 1;

            if i == 0 {
                // After filling the first block, move to block_id 1
                blocks.push(BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: first_block_instrs.clone(),
                    is_return: false,
                    is_panic: false,
                });
                block_id = 1;
            } else {
                block_id += 1;
            }
        }

        // Handle edge case: single tested type, first_block_instrs not yet pushed
        if tested_type_ids.len() == 1 && blocks.iter().all(|b| b.id != 0) {
            // Already pushed above
        }

        Function {
            name: format!("test.{name}"),
            short_name: name.into(),
            span: None,
            blocks,
            cfg_edges: edges,
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    /// Build an enum switch function that tests the given constant values.
    fn make_enum_switch_func(
        name: &str,
        enum_type_id: u32,
        const_names: &[&str],
        has_default_block: bool,
    ) -> Function {
        let mut blocks = Vec::new();
        let mut edges = Vec::new();
        let mut instr_id: u32 = 0;

        // Block 0: param
        let param = Instruction {
            id: instr_id,
            kind: ValueKind::Parameter,
            name: "val".into(),
            type_id: enum_type_id,
            span: Some(Span::new("test.go", 10, 1)),
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
        let param_id = instr_id;
        instr_id += 1;

        let case_start_block: u32 = 100;
        let mut block_id: u32 = 0;
        let mut first_block_instrs = vec![param];

        for (i, const_name) in const_names.iter().enumerate() {
            let const_id = instr_id;
            let const_instr = Instruction {
                id: const_id,
                kind: ValueKind::Const,
                name: const_name.to_string(),
                type_id: enum_type_id,
                span: None,
                operands: vec![],
                extract_index: 0,
                callee: None,
                callee_is_interface: false,
                assert_type_id: 0,
                comma_ok: false,
                const_value: Some(const_name.to_string()),
                is_nil: false,
                bin_op: None,
                nil_operand_indices: vec![],
                select_cases: vec![],
                channel_dir: None,
            };
            instr_id += 1;

            let binop_id = instr_id;
            let binop = Instruction {
                id: binop_id,
                kind: ValueKind::BinOp,
                name: format!("cmp{i}"),
                type_id: 20, // bool
                span: Some(Span::new("test.go", 12 + (i as u32) * 3, 5)),
                operands: vec![param_id, const_id],
                extract_index: 0,
                callee: None,
                callee_is_interface: false,
                assert_type_id: 0,
                comma_ok: false,
                const_value: None,
                is_nil: false,
                bin_op: Some("==".into()),
                nil_operand_indices: vec![],
                select_cases: vec![],
                channel_dir: None,
            };
            instr_id += 1;

            let if_id = instr_id;
            let if_instr = Instruction {
                id: if_id,
                kind: ValueKind::If,
                name: format!("if{i}"),
                type_id: 0,
                span: None,
                operands: vec![binop_id],
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
            instr_id += 1;

            let case_block_id = case_start_block + i as u32;
            let next_block_id = block_id + 1;

            if i == 0 {
                first_block_instrs.push(const_instr);
                first_block_instrs.push(binop);
                first_block_instrs.push(if_instr);
            } else {
                blocks.push(BasicBlock {
                    id: block_id,
                    name: format!("check{i}"),
                    instructions: vec![const_instr, binop, if_instr],
                    is_return: false,
                    is_panic: false,
                });
            }

            edges.push(CfgEdge {
                from_block: block_id,
                to_block: case_block_id,
                kind: EdgeKind::CondTrue,
            });

            if i < const_names.len() - 1 {
                edges.push(CfgEdge {
                    from_block: block_id,
                    to_block: next_block_id,
                    kind: EdgeKind::CondFalse,
                });
            } else {
                let default_block_id = case_start_block + const_names.len() as u32;
                edges.push(CfgEdge {
                    from_block: block_id,
                    to_block: default_block_id,
                    kind: EdgeKind::CondFalse,
                });

                let default_instrs = if has_default_block {
                    vec![Instruction {
                        id: instr_id,
                        kind: ValueKind::Return,
                        name: "ret_default".into(),
                        type_id: 0,
                        span: None,
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
                    }]
                } else {
                    vec![]
                };
                instr_id += 1;

                blocks.push(BasicBlock {
                    id: default_block_id,
                    name: "default".into(),
                    instructions: default_instrs,
                    is_return: has_default_block,
                    is_panic: false,
                });
            }

            // Case block
            blocks.push(BasicBlock {
                id: case_block_id,
                name: format!("case{i}"),
                instructions: vec![Instruction {
                    id: instr_id,
                    kind: ValueKind::Return,
                    name: format!("ret{i}"),
                    type_id: 0,
                    span: None,
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
            });
            instr_id += 1;

            if i == 0 {
                blocks.push(BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: first_block_instrs.clone(),
                    is_return: false,
                    is_panic: false,
                });
                block_id = 1;
            } else {
                block_id += 1;
            }
        }

        Function {
            name: format!("test.{name}"),
            short_name: name.into(),
            span: None,
            blocks,
            cfg_edges: edges,
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn make_analysis_input(
        functions: Vec<Function>,
        types: Vec<TypeRef>,
        interface_table: Vec<InterfaceEntry>,
        enum_groups: Vec<EnumGroup>,
    ) -> AnalysisInput {
        AnalysisInput {
            packages: vec![Package {
                import_path: "example.com/test".into(),
                name: "test".into(),
                files: vec![],
                types,
                functions,
                interface_satisfactions: vec![],
                call_edges: vec![],
                global_vars: vec![],
            }],
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table,
            enum_groups,
        }
    }

    // -----------------------------------------------------------------------
    // EXH001 Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_exh001_missing_implementor() {
        // Interface Animal has Dog, Cat, Bird implementors.
        // Type switch only handles Dog and Cat.
        // Should flag EXH001 with "missing: *Bird"
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11, 12], false);
        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into(), "*Bird".into()],
            methods: vec!["Speak".into()],
        }];

        let input = make_analysis_input(vec![func], types, ifaces, vec![]);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh001s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH001").collect();
        assert!(
            !exh001s.is_empty(),
            "should detect EXH001 for missing *Bird"
        );
        assert!(exh001s[0].explanation.contains("*Bird"));
        assert_eq!(exh001s[0].severity, Severity::Error);
    }

    #[test]
    fn test_exh001_safe_all_covered() {
        // Type switch handles all three implementors -> no EXH001.
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11, 12, 13], false);
        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into(), "*Bird".into()],
            methods: vec!["Speak".into()],
        }];

        let input = make_analysis_input(vec![func], types, ifaces, vec![]);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh001s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH001").collect();
        assert!(
            exh001s.is_empty(),
            "all implementors covered, no EXH001 expected"
        );
    }

    #[test]
    fn test_exh001_safe_has_default() {
        // Type switch missing Bird but has default case -> no EXH001.
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11, 12], true);
        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into(), "*Bird".into()],
            methods: vec!["Speak".into()],
        }];

        let input = make_analysis_input(vec![func], types, ifaces, vec![]);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh001s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH001").collect();
        assert!(exh001s.is_empty(), "has default case, no EXH001 expected");
    }

    // -----------------------------------------------------------------------
    // EXH002 Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_exh002_missing_enum_value() {
        // Enum Color with Red, Green, Blue.
        // Switch only handles Red and Green -> EXH002.
        let types = make_color_types();
        let func = make_enum_switch_func("HandleColor", 10, &["Red", "Green"], false);
        let groups = vec![EnumGroup {
            type_name: "Color".into(),
            constants: vec![
                EnumConstant {
                    name: "Red".into(),
                    value: "0".into(),
                },
                EnumConstant {
                    name: "Green".into(),
                    value: "1".into(),
                },
                EnumConstant {
                    name: "Blue".into(),
                    value: "2".into(),
                },
            ],
        }];

        let input = make_analysis_input(vec![func], types, vec![], groups);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh002s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH002").collect();
        assert!(!exh002s.is_empty(), "should detect EXH002 for missing Blue");
        assert!(exh002s[0].explanation.contains("Blue"));
        assert_eq!(exh002s[0].severity, Severity::Error);
    }

    #[test]
    fn test_exh002_safe_all_values() {
        // Switch handles all three enum values -> no EXH002.
        let types = make_color_types();
        let func = make_enum_switch_func("HandleColor", 10, &["Red", "Green", "Blue"], false);
        let groups = vec![EnumGroup {
            type_name: "Color".into(),
            constants: vec![
                EnumConstant {
                    name: "Red".into(),
                    value: "0".into(),
                },
                EnumConstant {
                    name: "Green".into(),
                    value: "1".into(),
                },
                EnumConstant {
                    name: "Blue".into(),
                    value: "2".into(),
                },
            ],
        }];

        let input = make_analysis_input(vec![func], types, vec![], groups);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh002s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH002").collect();
        assert!(exh002s.is_empty(), "all values covered, no EXH002 expected");
    }

    #[test]
    fn test_exh002_safe_has_default() {
        // Switch missing Blue but has default -> no EXH002.
        let types = make_color_types();
        let func = make_enum_switch_func("HandleColor", 10, &["Red", "Green"], true);
        let groups = vec![EnumGroup {
            type_name: "Color".into(),
            constants: vec![
                EnumConstant {
                    name: "Red".into(),
                    value: "0".into(),
                },
                EnumConstant {
                    name: "Green".into(),
                    value: "1".into(),
                },
                EnumConstant {
                    name: "Blue".into(),
                    value: "2".into(),
                },
            ],
        }];

        let input = make_analysis_input(vec![func], types, vec![], groups);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh002s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH002").collect();
        assert!(exh002s.is_empty(), "has default, no EXH002 expected");
    }

    // -----------------------------------------------------------------------
    // EXH003 Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_exh003_no_default() {
        // Non-exhaustive type switch without default -> EXH003.
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11], false);
        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into()],
            methods: vec!["Speak".into()],
        }];

        let input = make_analysis_input(vec![func], types, ifaces, vec![]);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh003s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH003").collect();
        assert!(
            !exh003s.is_empty(),
            "should detect EXH003 for missing default"
        );
        assert_eq!(exh003s[0].severity, Severity::Info);
    }

    #[test]
    fn test_exh003_safe_with_default() {
        // Non-exhaustive switch but with default -> no EXH003.
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11], true);
        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into()],
            methods: vec!["Speak".into()],
        }];

        let input = make_analysis_input(vec![func], types, ifaces, vec![]);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh003s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH003").collect();
        assert!(exh003s.is_empty(), "has default, no EXH003 expected");
    }

    #[test]
    fn test_exh003_enum_no_default() {
        // Non-exhaustive enum switch without default -> EXH003.
        let types = make_color_types();
        let func = make_enum_switch_func("HandleColor", 10, &["Red"], false);
        let groups = vec![EnumGroup {
            type_name: "Color".into(),
            constants: vec![
                EnumConstant {
                    name: "Red".into(),
                    value: "0".into(),
                },
                EnumConstant {
                    name: "Green".into(),
                    value: "1".into(),
                },
            ],
        }];

        let input = make_analysis_input(vec![func], types, vec![], groups);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh003s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH003").collect();
        assert!(
            !exh003s.is_empty(),
            "should detect EXH003 for missing default in enum switch"
        );
    }

    // -----------------------------------------------------------------------
    // Integration Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_analyze_empty_input() {
        let input = AnalysisInput {
            packages: vec![],
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        };
        let diags = ExhaustiveAnalyzer::analyze(&input);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_analyze_package_matches_analyze() {
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11, 12], false);
        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into(), "*Bird".into()],
            methods: vec!["Speak".into()],
        }];

        let input = make_analysis_input(vec![func], types, ifaces, vec![]);

        let from_analyze = ExhaustiveAnalyzer::analyze(&input);
        let from_package = ExhaustiveAnalyzer::analyze_package(
            &input.packages[0],
            &input.interface_table,
            &input.enum_groups,
        );

        assert_eq!(
            from_analyze.len(),
            from_package.len(),
            "analyze and analyze_package should produce same results"
        );
        for (a, b) in from_analyze.iter().zip(from_package.iter()) {
            assert_eq!(a.rule, b.rule);
            assert_eq!(a.title, b.title);
        }
    }

    #[test]
    fn test_no_interface_table_entry() {
        // Type switch on unknown interface (not in interface_table).
        // Should not produce EXH001 but may produce EXH003.
        let types = make_animal_types();
        let func = make_type_switch_func("HandleAnimal", 10, &[11], false);

        // Empty interface table - Animal not known
        let input = make_analysis_input(vec![func], types, vec![], vec![]);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh001s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH001").collect();
        assert!(
            exh001s.is_empty(),
            "unknown interface should not produce EXH001"
        );

        // But EXH003 can still fire (missing default on non-exhaustive switch)
        let exh003s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH003").collect();
        assert!(
            !exh003s.is_empty(),
            "should produce EXH003 for missing default"
        );
    }

    #[test]
    fn test_empty_package() {
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

        let diags = ExhaustiveAnalyzer::analyze_package(&pkg, &[], &[]);
        assert!(
            diags.is_empty(),
            "empty package should produce zero diagnostics"
        );
    }

    #[test]
    fn test_multiple_switches_in_one_function() {
        // A function with both a type switch and enum switch
        let mut types = make_animal_types();
        types.extend(make_color_types().into_iter().map(|mut t| {
            t.id += 100; // offset to avoid collisions
            t
        }));
        // We need Color type at ID 110
        let color_type_id = 110;

        // For simplicity, test with separate functions
        let func1 = make_type_switch_func("HandleAnimal", 10, &[11], false);
        let func2 = make_enum_switch_func("HandleColor", color_type_id, &["Red"], false);

        let ifaces = vec![InterfaceEntry {
            interface_name: "Animal".into(),
            implementors: vec!["*Dog".into(), "*Cat".into()],
            methods: vec!["Speak".into()],
        }];
        let groups = vec![EnumGroup {
            type_name: "Color".into(),
            constants: vec![
                EnumConstant {
                    name: "Red".into(),
                    value: "0".into(),
                },
                EnumConstant {
                    name: "Green".into(),
                    value: "1".into(),
                },
            ],
        }];

        let input = make_analysis_input(vec![func1, func2], types, ifaces, groups);
        let diags = ExhaustiveAnalyzer::analyze(&input);

        let exh001s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH001").collect();
        let exh002s: Vec<_> = diags.iter().filter(|d| d.rule == "EXH002").collect();
        assert!(!exh001s.is_empty(), "should detect EXH001");
        assert!(!exh002s.is_empty(), "should detect EXH002");
    }
}
