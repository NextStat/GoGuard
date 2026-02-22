//! Inter-procedural summaries for nil analysis.
//!
//! Per-return-position summaries: for a function returning `(*T, error)`,
//! position 0 may be `Unconditional` while position 1 is `CanBeNil`.
//! Single-return functions use position 0.

use std::collections::HashMap;

use goguard_ir::ir::{Function, Instruction, Package, ValueKind};

/// Nilness summary for a function's return value at a specific position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnNilness {
    /// All return paths produce a proven non-nil value.
    Unconditional,
    /// At least one return path can return nil (explicit nil or proven-nilable).
    CanBeNil,
    /// Cannot determine (includes returns derived from parameters/fields/unknown calls).
    Indeterminate,
}

/// Per-function return summaries: maps return position → nilness.
pub type FunctionSummary = HashMap<u32, ReturnNilness>;

/// All summaries for a package: function name → per-position summaries.
pub type PackageSummaries = HashMap<String, FunctionSummary>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueNilness {
    NeverNil,
    CanBeNil,
    Indeterminate,
}

/// Compute per-function, per-return-position summaries for a package (bottom-up, fixpoint).
///
/// Supports both single-return and multi-return functions.
/// Only proves `Unconditional` when the returned value is a fresh allocation-like value
/// (or a call to another `Unconditional` function at the same return position).
pub fn compute_package_return_nilness(pkg: &Package) -> PackageSummaries {
    let mut summaries: PackageSummaries = HashMap::new();

    for func in &pkg.functions {
        let instr_map = build_instr_map(func);
        summaries.insert(
            func.name.clone(),
            classify_function_returns(func, &instr_map, &HashMap::new()),
        );
    }

    // Fixpoint: allow Unconditional/CanBeNil to propagate through return-of-call.
    let mut changed = true;
    let mut iteration = 0;
    while changed && iteration < 20 {
        changed = false;
        iteration += 1;

        for func in &pkg.functions {
            let instr_map = build_instr_map(func);
            let new = classify_function_returns(func, &instr_map, &summaries);
            if summaries.get(&func.name) != Some(&new) {
                summaries.insert(func.name.clone(), new);
                changed = true;
            }
        }
    }

    summaries
}

fn build_instr_map(func: &Function) -> HashMap<u32, &Instruction> {
    func.blocks
        .iter()
        .flat_map(|b| b.instructions.iter())
        .map(|i| (i.id, i))
        .collect()
}

/// Classify each return position independently.
/// For `func F() (*T, error)` with `return alloc, nil` → `{0: Unconditional, 1: CanBeNil}`.
fn classify_function_returns(
    func: &Function,
    instr_map: &HashMap<u32, &Instruction>,
    summaries: &PackageSummaries,
) -> FunctionSummary {
    // Collect all Return instructions.
    let return_instrs: Vec<&Instruction> = func
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter())
        .filter(|i| i.kind == ValueKind::Return)
        .collect();

    if return_instrs.is_empty() {
        return HashMap::new();
    }

    // All Return instructions must have the same number of operands.
    let num_positions = return_instrs[0].operands.len();
    if num_positions == 0 {
        return HashMap::new();
    }
    // Bail if any return has a different operand count (shouldn't happen in valid SSA).
    if return_instrs
        .iter()
        .any(|r| r.operands.len() != num_positions)
    {
        return (0..num_positions as u32)
            .map(|i| (i, ReturnNilness::Indeterminate))
            .collect();
    }

    let mut memo: HashMap<u32, ValueNilness> = HashMap::new();
    let mut results: FunctionSummary = HashMap::new();

    for pos in 0..num_positions {
        let mut any_can_be_nil = false;
        let mut all_determined = true;

        for ret in &return_instrs {
            let value_id = ret.operands[pos];
            match value_nilness(value_id, instr_map, summaries, &mut memo) {
                ValueNilness::NeverNil => {}
                ValueNilness::CanBeNil => any_can_be_nil = true,
                ValueNilness::Indeterminate => {
                    all_determined = false;
                    break;
                }
            }
        }

        let nilness = if !all_determined {
            ReturnNilness::Indeterminate
        } else if any_can_be_nil {
            ReturnNilness::CanBeNil
        } else {
            ReturnNilness::Unconditional
        };
        results.insert(pos as u32, nilness);
    }

    results
}

fn value_nilness(
    value_id: u32,
    instr_map: &HashMap<u32, &Instruction>,
    summaries: &PackageSummaries,
    memo: &mut HashMap<u32, ValueNilness>,
) -> ValueNilness {
    if let Some(cached) = memo.get(&value_id).copied() {
        return cached;
    }

    // Insert Indeterminate first to break cycles.
    memo.insert(value_id, ValueNilness::Indeterminate);

    let result = match instr_map.get(&value_id) {
        None => ValueNilness::Indeterminate,
        Some(instr) => match instr.kind {
            // Fresh allocations are never nil.
            ValueKind::Alloc
            | ValueKind::MakeMap
            | ValueKind::MakeChan
            | ValueKind::MakeSlice
            | ValueKind::MakeClosure
            | ValueKind::MakeInterface => ValueNilness::NeverNil,

            // Const(nil) is can-be-nil; other constants are never nil.
            ValueKind::Const if instr.is_nil => ValueNilness::CanBeNil,
            ValueKind::Const => ValueNilness::NeverNil,

            // Conversions propagate.
            ValueKind::Convert | ValueKind::ChangeType | ValueKind::ChangeInterface => instr
                .operands
                .first()
                .map(|&op| value_nilness(op, instr_map, summaries, memo))
                .unwrap_or(ValueNilness::Indeterminate),

            // Phi: only prove never-nil when all inputs are never-nil.
            ValueKind::Phi => {
                if instr.operands.is_empty() {
                    ValueNilness::Indeterminate
                } else {
                    let mut saw_indeterminate = false;
                    let mut saw_can_be_nil = false;
                    for &op in &instr.operands {
                        match value_nilness(op, instr_map, summaries, memo) {
                            ValueNilness::NeverNil => {}
                            ValueNilness::CanBeNil => saw_can_be_nil = true,
                            ValueNilness::Indeterminate => saw_indeterminate = true,
                        }
                    }
                    if saw_indeterminate {
                        ValueNilness::Indeterminate
                    } else if saw_can_be_nil {
                        ValueNilness::CanBeNil
                    } else {
                        ValueNilness::NeverNil
                    }
                }
            }

            // Calls (single-return): use position 0 from summary.
            ValueKind::Call if !instr.callee_is_interface => {
                summary_to_value_nilness(instr.callee.as_deref(), 0, summaries)
            }

            // Extract: use the extracted position from the call's summary.
            ValueKind::Extract => instr
                .operands
                .first()
                .and_then(|&call_id| instr_map.get(&call_id))
                .filter(|call| call.kind == ValueKind::Call && !call.callee_is_interface)
                .map(|call| {
                    summary_to_value_nilness(call.callee.as_deref(), instr.extract_index, summaries)
                })
                .unwrap_or(ValueNilness::Indeterminate),

            _ => ValueNilness::Indeterminate,
        },
    };

    memo.insert(value_id, result);
    result
}

/// Look up a callee's summary at a specific return position.
fn summary_to_value_nilness(
    callee: Option<&str>,
    position: u32,
    summaries: &PackageSummaries,
) -> ValueNilness {
    callee
        .and_then(|c| summaries.get(c))
        .and_then(|m| m.get(&position).copied())
        .map(|s| match s {
            ReturnNilness::Unconditional => ValueNilness::NeverNil,
            ReturnNilness::CanBeNil => ValueNilness::CanBeNil,
            ReturnNilness::Indeterminate => ValueNilness::Indeterminate,
        })
        .unwrap_or(ValueNilness::Indeterminate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::{BasicBlock, Span, TypeKind, TypeRef};

    fn make_instr(id: u32, kind: ValueKind) -> Instruction {
        Instruction {
            id,
            kind,
            name: format!("t{id}"),
            type_id: 0,
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

    fn make_func(name: &str, instructions: Vec<Instruction>) -> Function {
        Function {
            name: name.into(),
            short_name: name.rsplit('.').next().unwrap_or(name).into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions,
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn make_pkg(functions: Vec<Function>) -> Package {
        Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![TypeRef {
                id: 0,
                kind: TypeKind::Basic,
                name: "void".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            }],
            functions,
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        }
    }

    #[test]
    fn test_summary_unconditional_alloc_return() {
        let alloc = make_instr(0, ValueKind::Alloc);
        let mut ret = make_instr(1, ValueKind::Return);
        ret.operands = vec![0];

        let pkg = make_pkg(vec![make_func("pkg.NewUser", vec![alloc, ret])]);
        let summaries = compute_package_return_nilness(&pkg);
        let func_summary = summaries.get("pkg.NewUser").unwrap();
        assert_eq!(func_summary.get(&0), Some(&ReturnNilness::Unconditional));
    }

    #[test]
    fn test_summary_multi_return_alloc_and_nil() {
        // func Load() (*User, error) { return &User{}, nil }
        let alloc = make_instr(0, ValueKind::Alloc); // &User{}
        let mut nil_const = make_instr(1, ValueKind::Const);
        nil_const.is_nil = true; // nil (for error)
        let mut ret = make_instr(2, ValueKind::Return);
        ret.operands = vec![0, 1]; // return alloc, nil

        let pkg = make_pkg(vec![make_func("pkg.Load", vec![alloc, nil_const, ret])]);
        let summaries = compute_package_return_nilness(&pkg);
        let func_summary = summaries.get("pkg.Load").unwrap();
        assert_eq!(
            func_summary.get(&0),
            Some(&ReturnNilness::Unconditional),
            "position 0 (*User) should be Unconditional (alloc)"
        );
        assert_eq!(
            func_summary.get(&1),
            Some(&ReturnNilness::CanBeNil),
            "position 1 (error) should be CanBeNil (nil const)"
        );
    }

    #[test]
    fn test_summary_multi_return_both_alloc() {
        // func NewPair() (*A, *B) { return &A{}, &B{} }
        let alloc_a = make_instr(0, ValueKind::Alloc);
        let alloc_b = make_instr(1, ValueKind::Alloc);
        let mut ret = make_instr(2, ValueKind::Return);
        ret.operands = vec![0, 1];

        let pkg = make_pkg(vec![make_func("pkg.NewPair", vec![alloc_a, alloc_b, ret])]);
        let summaries = compute_package_return_nilness(&pkg);
        let func_summary = summaries.get("pkg.NewPair").unwrap();
        assert_eq!(func_summary.get(&0), Some(&ReturnNilness::Unconditional));
        assert_eq!(func_summary.get(&1), Some(&ReturnNilness::Unconditional));
    }

    #[test]
    fn test_summary_multi_return_extract_propagates() {
        // func Inner() (*T, error) { return &T{}, nil }
        // func Outer() (*T, error) { return Inner() }
        // (Outer calls Inner, extracts both positions)
        let alloc = make_instr(0, ValueKind::Alloc);
        let mut nil_const = make_instr(1, ValueKind::Const);
        nil_const.is_nil = true;
        let mut inner_ret = make_instr(2, ValueKind::Return);
        inner_ret.operands = vec![0, 1];
        let inner = make_func("pkg.Inner", vec![alloc, nil_const, inner_ret]);

        // Outer: t0 = Call Inner; t1 = Extract(t0, 0); t2 = Extract(t0, 1); return t1, t2
        let mut call = make_instr(10, ValueKind::Call);
        call.callee = Some("pkg.Inner".into());
        let mut ext0 = make_instr(11, ValueKind::Extract);
        ext0.operands = vec![10];
        ext0.extract_index = 0;
        let mut ext1 = make_instr(12, ValueKind::Extract);
        ext1.operands = vec![10];
        ext1.extract_index = 1;
        let mut outer_ret = make_instr(13, ValueKind::Return);
        outer_ret.operands = vec![11, 12];
        let outer = make_func("pkg.Outer", vec![call, ext0, ext1, outer_ret]);

        let pkg = make_pkg(vec![inner, outer]);
        let summaries = compute_package_return_nilness(&pkg);

        // Inner: pos 0 = Unconditional, pos 1 = CanBeNil
        let inner_s = summaries.get("pkg.Inner").unwrap();
        assert_eq!(inner_s.get(&0), Some(&ReturnNilness::Unconditional));
        assert_eq!(inner_s.get(&1), Some(&ReturnNilness::CanBeNil));

        // Outer propagates from Inner via Extract
        let outer_s = summaries.get("pkg.Outer").unwrap();
        assert_eq!(
            outer_s.get(&0),
            Some(&ReturnNilness::Unconditional),
            "Outer pos 0 should propagate Inner's Unconditional"
        );
        assert_eq!(
            outer_s.get(&1),
            Some(&ReturnNilness::CanBeNil),
            "Outer pos 1 should propagate Inner's CanBeNil"
        );
    }

    #[test]
    fn test_summary_can_be_nil_const() {
        let mut nil_const = make_instr(0, ValueKind::Const);
        nil_const.is_nil = true;
        let mut ret = make_instr(1, ValueKind::Return);
        ret.operands = vec![0];

        let pkg = make_pkg(vec![make_func("pkg.Nil", vec![nil_const, ret])]);
        let summaries = compute_package_return_nilness(&pkg);
        let func_summary = summaries.get("pkg.Nil").unwrap();
        assert_eq!(func_summary.get(&0), Some(&ReturnNilness::CanBeNil));
    }
}
