//! Discovery of type switches and enum/const switches in Go SSA IR.
//!
//! In Go SSA, type switches are compiled to chains of `TypeAssert(comma_ok=true)` ->
//! `Extract` -> `If` instructions. Enum switches become `BinOp(==)` -> `If` chains.
//! This module scans function blocks for these patterns and extracts the
//! tested types/values so that exhaustiveness rules can check coverage.

use std::collections::HashMap;

use goguard_ir::ir::{
    BasicBlock, CfgEdge, EdgeKind, Function, Instruction, Span, TypeRef, ValueKind,
};

/// A discovered type switch pattern in SSA.
#[derive(Debug, Clone)]
pub struct TypeSwitchInfo {
    /// Source location of the first TypeAssert in the chain.
    pub span: Option<Span>,
    /// The name of the interface type being switched on.
    pub interface_type_name: String,
    /// The concrete type names that are tested in the switch cases.
    pub tested_types: Vec<String>,
    /// Whether the switch has a default case (a block reachable when all
    /// type assertions fail).
    pub has_default: bool,
}

/// A discovered enum/const switch pattern in SSA.
#[derive(Debug, Clone)]
pub struct EnumSwitchInfo {
    /// Source location of the first BinOp comparison in the chain.
    pub span: Option<Span>,
    /// The name of the enum type being switched on.
    pub enum_type_name: String,
    /// The constant names that are tested in the switch cases.
    pub tested_values: Vec<String>,
    /// Whether the switch has a default case.
    pub has_default: bool,
}

/// Find type switch patterns in a function's blocks.
///
/// A type switch in Go SSA looks like a chain of:
/// ```text
/// block N:
///   tX = TypeAssert(base_val, ConcreteType) comma_ok=true
///   tY = Extract(tX, 1)  // the ok bool
///   If tY -> block_case, block_next
/// ```
///
/// We detect these by scanning for `TypeAssert(comma_ok=true)` instructions
/// and following the `If` chain to determine which types are tested.
pub fn find_type_switches(func: &Function, types: &[TypeRef]) -> Vec<TypeSwitchInfo> {
    if func.blocks.is_empty() {
        return Vec::new();
    }

    // Build instruction map: id -> &Instruction
    let instr_map: HashMap<u32, &Instruction> = func
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter())
        .map(|i| (i.id, i))
        .collect();

    // Build type map: id -> &TypeRef
    let type_map: HashMap<u32, &TypeRef> = types.iter().map(|t| (t.id, t)).collect();

    // Build block map: id -> &BasicBlock
    let block_map: HashMap<u32, &BasicBlock> = func.blocks.iter().map(|b| (b.id, b)).collect();

    // Build edge map: from_block -> Vec<(to_block, kind)>
    let mut edges_from: HashMap<u32, Vec<(u32, &EdgeKind)>> = HashMap::new();
    for edge in &func.cfg_edges {
        edges_from
            .entry(edge.from_block)
            .or_default()
            .push((edge.to_block, &edge.kind));
    }

    // Track which TypeAssert instructions we've already grouped into a switch.
    let mut visited_type_asserts: std::collections::HashSet<u32> = std::collections::HashSet::new();

    let mut switches = Vec::new();

    // Scan blocks for TypeAssert patterns
    for block in &func.blocks {
        // Look for a TypeAssert(comma_ok=true) that starts a chain
        for instr in &block.instructions {
            if instr.kind != ValueKind::TypeAssert || !instr.comma_ok {
                continue;
            }
            if visited_type_asserts.contains(&instr.id) {
                continue;
            }

            // Found a potential type switch start. Walk the chain.
            let mut tested_types = Vec::new();
            let mut first_span = instr.span.clone();
            let mut current_block_id = block.id;
            let mut interface_type_name = String::new();

            // Determine the interface type from the first TypeAssert's operand.
            // The operand of the TypeAssert is the value being switched on.
            if let Some(&base_val_id) = instr.operands.first() {
                if let Some(base_instr) = instr_map.get(&base_val_id) {
                    if let Some(tr) = type_map.get(&base_instr.type_id) {
                        interface_type_name = tr.name.clone();
                    }
                }
            }

            // Collect the asserted type name from this first TypeAssert
            if let Some(tr) = type_map.get(&instr.assert_type_id) {
                tested_types.push(tr.name.clone());
            }
            visited_type_asserts.insert(instr.id);

            // Follow the chain: the CondFalse successor of this block should
            // contain the next TypeAssert in the chain.
            let mut has_default = false;
            loop {
                let edges = match edges_from.get(&current_block_id) {
                    Some(e) => e,
                    None => {
                        // No outgoing edges means the chain ends here.
                        // If we haven't found all cases, there's an implicit default.
                        has_default = false;
                        break;
                    }
                };

                // Find the CondFalse successor (the "else" branch = next case or default)
                let next_block_id = edges
                    .iter()
                    .find(|(_, k)| **k == EdgeKind::CondFalse)
                    .map(|(to, _)| *to);

                let next_block_id = match next_block_id {
                    Some(id) => id,
                    None => {
                        // No CondFalse edge means this is not a conditional branch.
                        break;
                    }
                };

                let next_block = match block_map.get(&next_block_id) {
                    Some(b) => b,
                    None => break,
                };

                // Look for another TypeAssert(comma_ok=true) in the next block
                let next_ta = next_block
                    .instructions
                    .iter()
                    .find(|i| i.kind == ValueKind::TypeAssert && i.comma_ok);

                match next_ta {
                    Some(ta) => {
                        if let Some(tr) = type_map.get(&ta.assert_type_id) {
                            tested_types.push(tr.name.clone());
                        }
                        visited_type_asserts.insert(ta.id);
                        current_block_id = next_block_id;
                    }
                    None => {
                        // No more TypeAsserts in the next block.
                        // This block is the default case (or there is no default).
                        // If the block has instructions (non-empty), it's a default case.
                        // A truly "no default" situation would be when the fallthrough
                        // block is empty or unreachable.
                        has_default = !next_block.instructions.is_empty()
                            || next_block.is_return
                            || next_block.is_panic;
                        break;
                    }
                }
            }

            if first_span.is_none() {
                first_span = instr.span.clone();
            }

            switches.push(TypeSwitchInfo {
                span: first_span,
                interface_type_name,
                tested_types,
                has_default,
            });
        }
    }

    switches
}

/// Find enum/const switch patterns in a function's blocks.
///
/// An enum switch in Go SSA looks like a chain of:
/// ```text
/// block N:
///   tX = BinOp(==, val, const_A)
///   If tX -> block_case_A, block_next
///
/// block_next:
///   tY = BinOp(==, val, const_B)
///   If tY -> block_case_B, block_default
/// ```
///
/// We detect these by scanning for `BinOp(==)` instructions where one
/// operand is a constant with a known name.
pub fn find_enum_switches(func: &Function, types: &[TypeRef]) -> Vec<EnumSwitchInfo> {
    if func.blocks.is_empty() {
        return Vec::new();
    }

    // Build instruction map: id -> &Instruction
    let instr_map: HashMap<u32, &Instruction> = func
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter())
        .map(|i| (i.id, i))
        .collect();

    // Build type map: id -> &TypeRef
    let type_map: HashMap<u32, &TypeRef> = types.iter().map(|t| (t.id, t)).collect();

    // Build block map: id -> &BasicBlock
    let block_map: HashMap<u32, &BasicBlock> = func.blocks.iter().map(|b| (b.id, b)).collect();

    // Build edge map: from_block -> Vec<(to_block, kind)>
    let mut edges_from: HashMap<u32, Vec<(u32, &EdgeKind)>> = HashMap::new();
    for edge in &func.cfg_edges {
        edges_from
            .entry(edge.from_block)
            .or_default()
            .push((edge.to_block, &edge.kind));
    }

    // Track which BinOp instructions we've already grouped into a switch.
    let mut visited_binops: std::collections::HashSet<u32> = std::collections::HashSet::new();

    let mut switches = Vec::new();

    for block in &func.blocks {
        // Look for an enum comparison pattern: BinOp(==) -> If at end of block
        let binop_if = find_enum_comparison(block, &instr_map);
        let (binop_instr, _base_val_id, const_instr) = match binop_if {
            Some(x) => x,
            None => continue,
        };

        if visited_binops.contains(&binop_instr.id) {
            continue;
        }

        // Determine the enum type from the constant's type
        let enum_type_name = type_map
            .get(&const_instr.type_id)
            .map(|t| t.name.clone())
            .unwrap_or_default();

        if enum_type_name.is_empty() {
            continue;
        }

        let first_span = binop_instr.span.clone();
        let mut tested_values = Vec::new();

        // Collect the constant name from const_value or instruction name
        let const_name = const_instr
            .const_value
            .as_deref()
            .unwrap_or(&const_instr.name);
        tested_values.push(const_name.to_string());
        visited_binops.insert(binop_instr.id);

        // Follow the chain via CondFalse edges
        let mut current_block_id = block.id;
        let mut has_default = false;

        while let Some(edges) = edges_from.get(&current_block_id) {
            let next_block_id = edges
                .iter()
                .find(|(_, k)| **k == EdgeKind::CondFalse)
                .map(|(to, _)| *to);

            let next_block_id = match next_block_id {
                Some(id) => id,
                None => break,
            };

            let next_block = match block_map.get(&next_block_id) {
                Some(b) => b,
                None => break,
            };

            // Look for another enum comparison in this block
            let next_cmp = find_enum_comparison(next_block, &instr_map);
            match next_cmp {
                Some((next_binop, _, next_const)) => {
                    let cname = next_const
                        .const_value
                        .as_deref()
                        .unwrap_or(&next_const.name);
                    tested_values.push(cname.to_string());
                    visited_binops.insert(next_binop.id);
                    current_block_id = next_block_id;
                }
                None => {
                    // No more comparisons. Check if this is a default block.
                    has_default = !next_block.instructions.is_empty()
                        || next_block.is_return
                        || next_block.is_panic;
                    break;
                }
            }
        }

        switches.push(EnumSwitchInfo {
            span: first_span,
            enum_type_name,
            tested_values,
            has_default,
        });
    }

    switches
}

/// Look for a pattern: `BinOp(==, val, const) -> If` at the end of a block.
/// Returns (binop_instr, base_value_id, const_instr) if found.
fn find_enum_comparison<'a>(
    block: &'a BasicBlock,
    instr_map: &'a HashMap<u32, &'a Instruction>,
) -> Option<(&'a Instruction, u32, &'a Instruction)> {
    let instrs = &block.instructions;
    if instrs.len() < 2 {
        return None;
    }

    // Last instruction should be If
    let last = instrs.last()?;
    if last.kind != ValueKind::If {
        return None;
    }

    // The If operand should be a BinOp(==)
    let if_operand = *last.operands.first()?;
    let binop = instr_map.get(&if_operand)?;
    if binop.kind != ValueKind::BinOp || binop.bin_op.as_deref() != Some("==") {
        return None;
    }

    if binop.operands.len() != 2 {
        return None;
    }

    // One operand should be a Const (the enum value), the other is the
    // switched-on value
    let op0 = instr_map.get(&binop.operands[0]);
    let op1 = instr_map.get(&binop.operands[1]);

    let (base_val_id, const_instr) = match (op0, op1) {
        (Some(a), Some(b)) if b.kind == ValueKind::Const && !b.is_nil => (binop.operands[0], *b),
        (Some(a), Some(b)) if a.kind == ValueKind::Const && !a.is_nil => (binop.operands[1], *a),
        _ => return None,
    };

    Some((*binop, base_val_id, const_instr))
}

/// Check if any CFG edge from a block has a DefaultCase kind.
pub fn has_default_edge(block_id: u32, edges: &[CfgEdge]) -> bool {
    edges
        .iter()
        .any(|e| e.from_block == block_id && e.kind == EdgeKind::DefaultCase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::*;

    fn make_instr(id: u32, kind: ValueKind, name: &str, type_id: u32) -> Instruction {
        Instruction {
            id,
            kind,
            name: name.into(),
            type_id,
            span: Some(Span::new("test.go", 10 + id, 1)),
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
    fn test_find_type_switches_basic() {
        // Simulate a type switch on interface Animal with cases Dog, Cat
        // Block 0: TypeAssert(comma_ok) for Dog -> Extract -> If
        // Block 2: TypeAssert(comma_ok) for Cat -> Extract -> If
        // Block 4: default

        let types = vec![
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
                id: 20,
                kind: TypeKind::Basic,
                name: "bool".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
        ];

        // Block 0: param x (interface Animal), TypeAssert x.(*Dog) comma_ok, Extract, If
        let param = make_instr(0, ValueKind::Parameter, "x", 10);
        let mut ta_dog = make_instr(1, ValueKind::TypeAssert, "t1", 11);
        ta_dog.comma_ok = true;
        ta_dog.assert_type_id = 11;
        ta_dog.operands = vec![0]; // asserts on param x

        let mut extract = make_instr(2, ValueKind::Extract, "t2", 20);
        extract.operands = vec![1];

        let mut if_instr = make_instr(3, ValueKind::If, "t3", 0);
        if_instr.operands = vec![2];

        // Block 2: TypeAssert x.(*Cat) comma_ok, Extract, If
        let mut ta_cat = make_instr(4, ValueKind::TypeAssert, "t4", 12);
        ta_cat.comma_ok = true;
        ta_cat.assert_type_id = 12;
        ta_cat.operands = vec![0];

        let mut extract2 = make_instr(5, ValueKind::Extract, "t5", 20);
        extract2.operands = vec![4];

        let mut if_instr2 = make_instr(6, ValueKind::If, "t6", 0);
        if_instr2.operands = vec![5];

        // Block 4: default (non-empty)
        let default_instr = make_instr(7, ValueKind::Return, "t7", 0);

        let func = Function {
            name: "test.HandleAnimal".into(),
            short_name: "HandleAnimal".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![param, ta_dog, extract, if_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "case.Dog".into(),
                    instructions: vec![make_instr(100, ValueKind::Return, "ret1", 0)],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "next".into(),
                    instructions: vec![ta_cat, extract2, if_instr2],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 3,
                    name: "case.Cat".into(),
                    instructions: vec![make_instr(101, ValueKind::Return, "ret2", 0)],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 4,
                    name: "default".into(),
                    instructions: vec![default_instr],
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
                    from_block: 2,
                    to_block: 3,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 2,
                    to_block: 4,
                    kind: EdgeKind::CondFalse,
                },
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let switches = find_type_switches(&func, &types);
        assert_eq!(switches.len(), 1);
        assert_eq!(switches[0].interface_type_name, "Animal");
        assert_eq!(switches[0].tested_types, vec!["*Dog", "*Cat"]);
        assert!(switches[0].has_default, "should detect default block");
    }

    #[test]
    fn test_find_type_switches_no_default() {
        // Same as above but the CondFalse from the last type assert goes to an empty block
        let types = vec![
            TypeRef {
                id: 10,
                kind: TypeKind::Interface,
                name: "Shape".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
            TypeRef {
                id: 11,
                kind: TypeKind::Pointer,
                name: "*Circle".into(),
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
        ];

        let param = make_instr(0, ValueKind::Parameter, "x", 10);
        let mut ta = make_instr(1, ValueKind::TypeAssert, "t1", 11);
        ta.comma_ok = true;
        ta.assert_type_id = 11;
        ta.operands = vec![0];

        let mut extract = make_instr(2, ValueKind::Extract, "t2", 20);
        extract.operands = vec![1];

        let mut if_instr = make_instr(3, ValueKind::If, "t3", 0);
        if_instr.operands = vec![2];

        let func = Function {
            name: "test.HandleShape".into(),
            short_name: "HandleShape".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![param, ta, extract, if_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "case".into(),
                    instructions: vec![make_instr(10, ValueKind::Return, "ret", 0)],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "fallthrough".into(),
                    instructions: vec![],
                    is_return: false,
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
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let switches = find_type_switches(&func, &types);
        assert_eq!(switches.len(), 1);
        assert_eq!(switches[0].tested_types, vec!["*Circle"]);
        assert!(
            !switches[0].has_default,
            "empty fallthrough block should not be considered default"
        );
    }

    #[test]
    fn test_find_type_switches_empty_function() {
        let func = Function {
            name: "test.Empty".into(),
            short_name: "Empty".into(),
            span: None,
            blocks: vec![],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };
        let switches = find_type_switches(&func, &[]);
        assert!(switches.is_empty());
    }

    #[test]
    fn test_find_enum_switches_basic() {
        // Simulate: switch color { case Red: ... case Green: ... }
        let types = vec![
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
        ];

        // Block 0: param color, const Red, BinOp(==), If
        let param = make_instr(0, ValueKind::Parameter, "color", 10);
        let mut const_red = make_instr(1, ValueKind::Const, "Red", 10);
        const_red.const_value = Some("Red".into());

        let mut binop = make_instr(2, ValueKind::BinOp, "t2", 20);
        binop.bin_op = Some("==".into());
        binop.operands = vec![0, 1]; // color == Red

        let mut if_instr = make_instr(3, ValueKind::If, "t3", 0);
        if_instr.operands = vec![2];

        // Block 2 (next case): const Green, BinOp(==), If
        let mut const_green = make_instr(4, ValueKind::Const, "Green", 10);
        const_green.const_value = Some("Green".into());

        let mut binop2 = make_instr(5, ValueKind::BinOp, "t5", 20);
        binop2.bin_op = Some("==".into());
        binop2.operands = vec![0, 4]; // color == Green

        let mut if_instr2 = make_instr(6, ValueKind::If, "t6", 0);
        if_instr2.operands = vec![5];

        // Block 4: default
        let default_ret = make_instr(7, ValueKind::Return, "t7", 0);

        let func = Function {
            name: "test.HandleColor".into(),
            short_name: "HandleColor".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![param, const_red, binop, if_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "case.Red".into(),
                    instructions: vec![make_instr(100, ValueKind::Return, "ret1", 0)],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "next".into(),
                    instructions: vec![const_green, binop2, if_instr2],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 3,
                    name: "case.Green".into(),
                    instructions: vec![make_instr(101, ValueKind::Return, "ret2", 0)],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 4,
                    name: "default".into(),
                    instructions: vec![default_ret],
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
                    from_block: 2,
                    to_block: 3,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 2,
                    to_block: 4,
                    kind: EdgeKind::CondFalse,
                },
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let switches = find_enum_switches(&func, &types);
        assert_eq!(switches.len(), 1);
        assert_eq!(switches[0].enum_type_name, "Color");
        assert_eq!(switches[0].tested_values, vec!["Red", "Green"]);
        assert!(switches[0].has_default);
    }

    #[test]
    fn test_find_enum_switches_empty_function() {
        let func = Function {
            name: "test.Empty".into(),
            short_name: "Empty".into(),
            span: None,
            blocks: vec![],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };
        let switches = find_enum_switches(&func, &[]);
        assert!(switches.is_empty());
    }

    #[test]
    fn test_has_default_edge() {
        let edges = vec![
            CfgEdge {
                from_block: 0,
                to_block: 1,
                kind: EdgeKind::SwitchCase,
            },
            CfgEdge {
                from_block: 0,
                to_block: 2,
                kind: EdgeKind::DefaultCase,
            },
        ];
        assert!(has_default_edge(0, &edges));
        assert!(!has_default_edge(1, &edges));
    }
}
