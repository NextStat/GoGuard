//! Taint propagation rules through function calls and data flow.
//!
//! Implements forward taint propagation through SSA instructions within
//! a function, and inter-procedural taint tracking across call edges.

use std::collections::{HashMap, HashSet};

use goguard_ir::ir::{Function, Instruction, Package, Span, ValueKind};

use crate::sinks::{self, SinkKind};
use crate::sources::{self, TaintSource};

/// Taint state for a single SSA value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintState {
    /// Not tainted.
    Clean,
    /// Tainted by a known source.
    Tainted {
        source: TaintSource,
        /// The instruction ID that introduced the taint.
        source_instruction_id: u32,
    },
    /// Was tainted but has been sanitized.
    Sanitized,
}

impl TaintState {
    /// Returns true if this state represents tainted data.
    pub fn is_tainted(&self) -> bool {
        matches!(self, TaintState::Tainted { .. })
    }
}

/// A detected taint flow from source to sink.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink_kind: SinkKind,
    /// The sink instruction (call to dangerous function).
    pub sink_instruction_id: u32,
    /// The source instruction (where taint originated).
    pub source_instruction_id: u32,
    /// Function name where the sink was found.
    pub function_name: String,
    /// Span of the sink call.
    pub sink_span: Option<Span>,
    /// Span of the source.
    pub source_span: Option<Span>,
}

/// Forward taint propagation through a function's SSA IR.
///
/// Returns all detected taint flows (source-to-sink paths) within the function.
pub fn propagate_taint(func: &Function, pkg: &Package) -> Vec<TaintFlow> {
    propagate_taint_inner(func, pkg, None)
}

/// Like `propagate_taint`, but additionally marks function parameters as tainted
/// if their sequential index is in `tainted_param_indices`.
///
/// This is used for inter-procedural analysis: when a caller passes tainted data
/// as an argument to this function, the corresponding parameter is pre-marked
/// as tainted with `TaintSource::CrossFunction`.
pub fn propagate_taint_with_params(
    func: &Function,
    pkg: &Package,
    tainted_param_indices: &HashSet<u32>,
) -> Vec<TaintFlow> {
    propagate_taint_inner(func, pkg, Some(tainted_param_indices))
}

/// Inner implementation shared by `propagate_taint` and `propagate_taint_with_params`.
fn propagate_taint_inner(
    func: &Function,
    _pkg: &Package,
    tainted_params: Option<&HashSet<u32>>,
) -> Vec<TaintFlow> {
    if func.blocks.is_empty() {
        return Vec::new();
    }

    // Build instruction lookup map for span resolution.
    let mut instr_map: HashMap<u32, &Instruction> = HashMap::new();
    for block in &func.blocks {
        for instr in &block.instructions {
            instr_map.insert(instr.id, instr);
        }
    }

    // Step 1: Initialize taint map.
    let mut taint: HashMap<u32, TaintState> = HashMap::new();

    // Step 2: Mark source instructions and cross-function tainted parameters.
    let mut param_idx: u32 = 0;
    for block in &func.blocks {
        for instr in &block.instructions {
            // Check if the instruction itself is a source (Global, Parameter).
            if let Some(source) = sources::is_source_instruction(instr) {
                taint.insert(
                    instr.id,
                    TaintState::Tainted {
                        source,
                        source_instruction_id: instr.id,
                    },
                );
            }

            // Check if this parameter is tainted by a caller (inter-procedural).
            if instr.kind == ValueKind::Parameter {
                if let Some(params) = tainted_params {
                    if params.contains(&param_idx) && !taint.contains_key(&instr.id) {
                        taint.insert(
                            instr.id,
                            TaintState::Tainted {
                                source: TaintSource::CrossFunction,
                                source_instruction_id: instr.id,
                            },
                        );
                    }
                }
                param_idx += 1;
            }
        }
    }

    // Step 3: Forward propagation — iterate blocks in order.
    // We do multiple passes until no changes occur (for Phi convergence).
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 50 {
        changed = false;
        iterations += 1;

        for block in &func.blocks {
            for instr in &block.instructions {
                let new_state = transfer(instr, &taint);
                if let Some(state) = new_state {
                    let existing = taint.get(&instr.id);
                    if existing != Some(&state) {
                        taint.insert(instr.id, state);
                        changed = true;
                    }
                }
            }
        }
    }

    // Step 4: Detect flows — check calls to known sinks.
    let mut flows = Vec::new();
    for block in &func.blocks {
        for instr in &block.instructions {
            if instr.kind != ValueKind::Call {
                continue;
            }
            let callee = match &instr.callee {
                Some(c) => c.as_str(),
                None => continue,
            };
            let (sink_kind, dangerous_args) = match sinks::classify_sink(callee) {
                Some(s) => s,
                None => continue,
            };

            // Check if any argument is tainted.
            //
            // We check ALL operands rather than only specific indices because
            // real Go SSA bridge IR includes the function value or receiver as
            // the first operand(s), shifting argument positions compared to the
            // logical argument indices returned by classify_sink.
            //
            // First try the exact dangerous_args indices. If that doesn't find
            // taint, fall back to checking all operands. This preserves
            // precision for synthetic IR in unit tests while handling the
            // offset in real bridge IR.
            let mut found = false;
            for &arg_idx in &dangerous_args {
                if let Some(&operand_id) = instr.operands.get(arg_idx) {
                    if let Some(TaintState::Tainted {
                        ref source,
                        source_instruction_id,
                    }) = taint.get(&operand_id)
                    {
                        let src_id = *source_instruction_id;
                        let source_span = instr_map.get(&src_id).and_then(|i| i.span.clone());
                        flows.push(TaintFlow {
                            source: source.clone(),
                            sink_kind: sink_kind.clone(),
                            sink_instruction_id: instr.id,
                            source_instruction_id: src_id,
                            function_name: func.short_name.clone(),
                            sink_span: instr.span.clone(),
                            source_span,
                        });
                        found = true;
                        break;
                    }
                }
            }
            // Fallback: scan all operands for taint.
            // In bridge IR, the receiver/func-value shifts argument positions,
            // so the dangerous_args indices may not match.
            if !found {
                for &operand_id in &instr.operands {
                    if let Some(TaintState::Tainted {
                        ref source,
                        source_instruction_id,
                    }) = taint.get(&operand_id)
                    {
                        let src_id = *source_instruction_id;
                        let source_span = instr_map.get(&src_id).and_then(|i| i.span.clone());
                        flows.push(TaintFlow {
                            source: source.clone(),
                            sink_kind: sink_kind.clone(),
                            sink_instruction_id: instr.id,
                            source_instruction_id: src_id,
                            function_name: func.short_name.clone(),
                            sink_span: instr.span.clone(),
                            source_span,
                        });
                        break;
                    }
                }
            }
        }
    }

    flows
}

/// Transfer function: compute the taint state produced by an instruction.
fn transfer(instr: &Instruction, taint: &HashMap<u32, TaintState>) -> Option<TaintState> {
    match instr.kind {
        // Constants are always clean.
        ValueKind::Const => Some(TaintState::Clean),

        // Allocations produce clean values.
        ValueKind::Alloc => Some(TaintState::Clean),

        // Globals and Parameters are handled in the initialization phase;
        // if not already marked, they are clean.
        ValueKind::Global | ValueKind::Parameter => {
            if taint.contains_key(&instr.id) {
                None // Already handled.
            } else {
                Some(TaintState::Clean)
            }
        }

        // Call instructions: check source, sanitizer, or propagate.
        ValueKind::Call => {
            if let Some(callee) = &instr.callee {
                // Check if this call is a known source.
                if let Some(source) = sources::classify_source(callee) {
                    return Some(TaintState::Tainted {
                        source,
                        source_instruction_id: instr.id,
                    });
                }

                // Check if this call is a sanitizer.
                if sinks::is_any_sanitizer(callee) {
                    // If any argument is tainted, the result is sanitized.
                    let any_tainted = instr
                        .operands
                        .iter()
                        .any(|op| taint.get(op).is_some_and(|s| s.is_tainted()));
                    if any_tainted {
                        return Some(TaintState::Sanitized);
                    }
                }

                // Otherwise, propagate taint from arguments.
                propagate_from_operands(instr, taint)
            } else {
                propagate_from_operands(instr, taint)
            }
        }

        // Phi: union of inputs' taint — if ANY input is tainted, result is tainted.
        ValueKind::Phi => {
            for &op_id in &instr.operands {
                if let Some(TaintState::Tainted {
                    ref source,
                    source_instruction_id,
                }) = taint.get(&op_id)
                {
                    return Some(TaintState::Tainted {
                        source: source.clone(),
                        source_instruction_id: *source_instruction_id,
                    });
                }
            }
            // If no operand is tainted, check if any is sanitized.
            for &op_id in &instr.operands {
                if let Some(TaintState::Sanitized) = taint.get(&op_id) {
                    return Some(TaintState::Sanitized);
                }
            }
            None
        }

        // BinOp: string concatenation and other binary ops preserve taint.
        ValueKind::BinOp => propagate_from_operands(instr, taint),

        // Extract: inherits taint from the tuple operand.
        ValueKind::Extract => propagate_from_operands(instr, taint),

        // Store: we propagate taint to the store target.
        // In SSA, Store takes (addr, value) — taint flows from value.
        ValueKind::Store => {
            if instr.operands.len() >= 2 {
                let value_op = instr.operands[1];
                taint.get(&value_op).cloned()
            } else {
                propagate_from_operands(instr, taint)
            }
        }

        // FieldAddr/IndexAddr: result inherits taint from base pointer.
        ValueKind::FieldAddr | ValueKind::IndexAddr => propagate_from_operands(instr, taint),

        // Convert/ChangeType/ChangeInterface/MakeInterface: preserve taint.
        ValueKind::Convert
        | ValueKind::ChangeType
        | ValueKind::ChangeInterface
        | ValueKind::MakeInterface => propagate_from_operands(instr, taint),

        // Slice: propagate from base.
        ValueKind::Slice => propagate_from_operands(instr, taint),

        // Lookup (map lookup): propagate from map.
        ValueKind::Lookup => propagate_from_operands(instr, taint),

        // Load: propagate from the address operand.
        ValueKind::Load => propagate_from_operands(instr, taint),

        // UnOp: propagate from operand.
        ValueKind::UnOp => propagate_from_operands(instr, taint),

        // TypeAssert: propagate from operand.
        ValueKind::TypeAssert => propagate_from_operands(instr, taint),

        // All other instructions (Return, If, Jump, Go, Defer, etc.)
        // do not produce tracked taint values.
        _ => None,
    }
}

/// Propagate taint from any tainted operand.
/// Returns `Some(Tainted)` if any operand is tainted,
/// `Some(Sanitized)` if any operand is sanitized (and none tainted),
/// `None` if no operand carries taint.
fn propagate_from_operands(
    instr: &Instruction,
    taint: &HashMap<u32, TaintState>,
) -> Option<TaintState> {
    // First check for tainted operands (takes priority over sanitized).
    for &op_id in &instr.operands {
        if let Some(TaintState::Tainted {
            ref source,
            source_instruction_id,
        }) = taint.get(&op_id)
        {
            return Some(TaintState::Tainted {
                source: source.clone(),
                source_instruction_id: *source_instruction_id,
            });
        }
    }
    None
}

/// Inter-procedural taint: determine which function parameters receive tainted
/// data via call edges from other functions in the package.
///
/// Takes a map of `function_name -> set of tainted value IDs` and the package's
/// call edges, and returns an updated map of `function_name -> set of tainted
/// parameter indices`.
pub fn propagate_interprocedural(
    pkg: &Package,
    function_taints: &HashMap<String, HashMap<u32, TaintState>>,
) -> HashMap<String, HashSet<u32>> {
    let mut tainted_params: HashMap<String, HashSet<u32>> = HashMap::new();

    // Build a lookup from function name to its parameter instruction IDs.
    let mut func_params: HashMap<&str, Vec<u32>> = HashMap::new();
    for func in &pkg.functions {
        let mut params = Vec::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind == ValueKind::Parameter {
                    params.push(instr.id);
                }
            }
        }
        func_params.insert(&func.name, params);
    }

    // For each call edge, check if the caller passes tainted values as arguments.
    // Build a map from callee instructions to their taint state by examining
    // calls in each function.
    for func in &pkg.functions {
        let func_taint = match function_taints.get(&func.name) {
            Some(t) => t,
            None => continue,
        };

        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind != ValueKind::Call && instr.kind != ValueKind::Go {
                    continue;
                }
                let callee_name = match &instr.callee {
                    Some(c) => c.as_str(),
                    None => continue,
                };

                // Check each argument passed to the callee.
                for (arg_idx, &operand_id) in instr.operands.iter().enumerate() {
                    if let Some(TaintState::Tainted { .. }) = func_taint.get(&operand_id) {
                        tainted_params
                            .entry(callee_name.to_owned())
                            .or_default()
                            .insert(arg_idx as u32);
                    }
                }
            }
        }
    }

    tainted_params
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::{BasicBlock, Function, Package, Span};

    fn make_instr(id: u32, kind: ValueKind, name: &str, type_id: u32) -> Instruction {
        Instruction {
            id,
            kind,
            name: name.into(),
            type_id,
            span: Some(Span::new("test.go", id + 10, 1)),
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

    fn make_call(id: u32, callee: &str, operands: Vec<u32>, type_id: u32) -> Instruction {
        let mut instr = make_instr(id, ValueKind::Call, &format!("t{}", id), type_id);
        instr.callee = Some(callee.into());
        instr.operands = operands;
        instr
    }

    fn make_package(import_path: &str, functions: Vec<Function>) -> Package {
        Package {
            import_path: import_path.into(),
            name: import_path.split('/').next_back().unwrap_or("main").into(),
            files: vec![],
            types: vec![],
            functions,
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        }
    }

    fn make_func(name: &str, blocks: Vec<BasicBlock>) -> Function {
        Function {
            name: name.into(),
            short_name: name.split('.').next_back().unwrap_or(name).into(),
            span: None,
            blocks,
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn make_block(id: u32, instructions: Vec<Instruction>) -> BasicBlock {
        BasicBlock {
            id,
            name: format!("b{}", id),
            instructions,
            is_return: true,
            is_panic: false,
        }
    }

    #[test]
    fn test_taint_through_binop() {
        // source_call (tainted) -> BinOp(source, const) -> result should be tainted
        let source_call = make_call(0, "os.Getenv", vec![], 0);

        let mut const_instr = make_instr(1, ValueKind::Const, "t1", 0);
        const_instr.const_value = Some("prefix_".into());

        let mut binop = make_instr(2, ValueKind::BinOp, "t2", 0);
        binop.bin_op = Some("+".into());
        binop.operands = vec![1, 0]; // const + tainted

        let func = make_func(
            "main.handler",
            vec![make_block(0, vec![source_call, const_instr, binop])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        // No sink, so no flows. But let's verify taint propagation via the taint map.
        // We can verify by adding a sink after the binop.
        assert!(flows.is_empty(), "no sink, no flow expected");

        // Now add a sink consuming the binop result.
        let source_call2 = make_call(10, "os.Getenv", vec![], 0);
        let mut const_instr2 = make_instr(11, ValueKind::Const, "t11", 0);
        const_instr2.const_value = Some("SELECT * FROM ".into());
        let mut binop2 = make_instr(12, ValueKind::BinOp, "t12", 0);
        binop2.bin_op = Some("+".into());
        binop2.operands = vec![11, 10]; // const + tainted env var
        let sink_call = make_call(13, "(*database/sql.DB).Query", vec![12], 0);

        let func2 = make_func(
            "main.handler",
            vec![make_block(
                0,
                vec![source_call2, const_instr2, binop2, sink_call],
            )],
        );
        let pkg2 = make_package("example.com/test", vec![func2.clone()]);

        let flows2 = propagate_taint(&func2, &pkg2);
        assert_eq!(flows2.len(), 1, "should detect taint flow through BinOp");
        assert_eq!(flows2[0].source, TaintSource::EnvironmentVar);
        assert_eq!(flows2[0].sink_kind, SinkKind::SqlQuery);
    }

    #[test]
    fn test_taint_through_phi() {
        // Two blocks: one with a tainted value, one with a clean value.
        // Phi merges them -> result should be tainted.
        let source_call = make_call(0, "os.Getenv", vec![], 0);

        let mut const_clean = make_instr(1, ValueKind::Const, "t1", 0);
        const_clean.const_value = Some("safe".into());

        let mut phi = make_instr(2, ValueKind::Phi, "t2", 0);
        phi.operands = vec![0, 1]; // tainted + clean

        let sink = make_call(3, "os/exec.Command", vec![2], 0);

        let func = make_func(
            "main.handler",
            vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![source_call],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "else".into(),
                    instructions: vec![const_clean],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "merge".into(),
                    instructions: vec![phi, sink],
                    is_return: true,
                    is_panic: false,
                },
            ],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert_eq!(flows.len(), 1, "phi with tainted input should propagate");
        assert_eq!(flows[0].sink_kind, SinkKind::CommandExec);
    }

    #[test]
    fn test_sanitizer_breaks_taint() {
        // source -> sanitizer -> sink: no flow should be detected.
        let source_call = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sanitizer = make_call(1, "path/filepath.Clean", vec![0], 0);
        let sink = make_call(2, "os.Open", vec![1], 0);

        let func = make_func(
            "main.handler",
            vec![make_block(0, vec![source_call, sanitizer, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert!(
            flows.is_empty(),
            "sanitizer should break taint chain, got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_clean_const_not_tainted() {
        // A constant string fed directly into a sink should not produce a flow.
        let mut const_instr = make_instr(0, ValueKind::Const, "t0", 0);
        const_instr.const_value = Some("SELECT 1".into());

        let sink = make_call(1, "(*database/sql.DB).Query", vec![0], 0);

        let func = make_func("main.handler", vec![make_block(0, vec![const_instr, sink])]);
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert!(
            flows.is_empty(),
            "constant values should not trigger taint flows"
        );
    }

    #[test]
    fn test_taint_source_to_sink_detected() {
        // Direct flow: HTTP request -> SQL query
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sink = make_call(1, "(*database/sql.DB).Query", vec![0], 0);

        let func = make_func("main.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].source, TaintSource::HttpRequest);
        assert_eq!(flows[0].sink_kind, SinkKind::SqlQuery);
        assert_eq!(flows[0].function_name, "handler");
    }

    #[test]
    fn test_no_flow_when_sanitized() {
        // HTTP request -> html.EscapeString -> html/template.HTML: safe
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sanitizer = make_call(1, "html.EscapeString", vec![0], 0);
        let sink = make_call(2, "html/template.HTML", vec![1], 0);

        let func = make_func(
            "main.handler",
            vec![make_block(0, vec![source, sanitizer, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert!(flows.is_empty(), "sanitized taint should not reach sink");
    }

    #[test]
    fn test_taint_through_extract() {
        // Call returning tuple -> Extract -> sink: taint should propagate.
        let source = make_call(0, "os.LookupEnv", vec![], 0);

        let mut extract = make_instr(1, ValueKind::Extract, "t1", 0);
        extract.operands = vec![0]; // Extract from tuple

        let sink = make_call(2, "os/exec.Command", vec![1], 0);

        let func = make_func(
            "main.handler",
            vec![make_block(0, vec![source, extract, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert_eq!(flows.len(), 1, "taint should propagate through Extract");
        assert_eq!(flows[0].source, TaintSource::EnvironmentVar);
        assert_eq!(flows[0].sink_kind, SinkKind::CommandExec);
    }

    #[test]
    fn test_interprocedural_basic() {
        // Caller passes tainted argument to callee.
        let source = make_call(0, "os.Getenv", vec![], 0);
        let call_callee = make_call(1, "example.com/test.process", vec![0], 0);

        let caller_func = make_func(
            "example.com/test.main",
            vec![make_block(0, vec![source, call_callee])],
        );

        let param = make_instr(10, ValueKind::Parameter, "input", 0);
        let sink = make_call(11, "(*database/sql.DB).Query", vec![10], 0);

        let callee_func = make_func(
            "example.com/test.process",
            vec![make_block(0, vec![param, sink])],
        );

        let pkg = make_package(
            "example.com/test",
            vec![caller_func.clone(), callee_func.clone()],
        );

        // First, get intra-procedural taint for the caller.
        let mut function_taints: HashMap<String, HashMap<u32, TaintState>> = HashMap::new();

        // Build taint map for caller.
        let caller_taint = {
            let mut taint = HashMap::new();
            taint.insert(
                0,
                TaintState::Tainted {
                    source: TaintSource::EnvironmentVar,
                    source_instruction_id: 0,
                },
            );
            taint
        };
        function_taints.insert("example.com/test.main".into(), caller_taint);

        let result = propagate_interprocedural(&pkg, &function_taints);

        assert!(
            result.contains_key("example.com/test.process"),
            "callee should have tainted params"
        );
        let tainted_params = result.get("example.com/test.process").unwrap();
        assert!(tainted_params.contains(&0), "parameter 0 should be tainted");
    }

    #[test]
    fn test_empty_function_no_flows() {
        let func = make_func("main.empty", vec![]);
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert!(flows.is_empty());
    }

    #[test]
    fn test_taint_through_convert() {
        // source -> Convert -> sink: taint should propagate through Convert.
        let source = make_call(0, "os.Getenv", vec![], 0);

        let mut convert = make_instr(1, ValueKind::Convert, "t1", 0);
        convert.operands = vec![0];

        let sink = make_call(2, "os/exec.Command", vec![1], 0);

        let func = make_func(
            "main.handler",
            vec![make_block(0, vec![source, convert, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert_eq!(flows.len(), 1, "taint should propagate through Convert");
    }

    #[test]
    fn test_taint_through_slice() {
        // source -> Slice -> sink: taint should propagate through Slice.
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);

        let mut slice_instr = make_instr(1, ValueKind::Slice, "t1", 0);
        slice_instr.operands = vec![0];

        let sink = make_call(2, "os.Open", vec![1], 0);

        let func = make_func(
            "main.handler",
            vec![make_block(0, vec![source, slice_instr, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let flows = propagate_taint(&func, &pkg);
        assert_eq!(flows.len(), 1, "taint should propagate through Slice");
    }

    #[test]
    fn test_propagate_taint_with_params_marks_parameter() {
        // A function with a Parameter that receives tainted data from caller.
        // param (index 0) -> db.Query(param): should detect flow via CrossFunction.
        let param = make_instr(10, ValueKind::Parameter, "input", 0);
        let sink = make_call(11, "(*database/sql.DB).Query", vec![10], 0);

        let func = make_func(
            "example.com/test.process",
            vec![make_block(0, vec![param, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let mut tainted_indices = HashSet::new();
        tainted_indices.insert(0u32);

        let flows = propagate_taint_with_params(&func, &pkg, &tainted_indices);
        assert_eq!(
            flows.len(),
            1,
            "should detect taint flow via cross-function param"
        );
        assert_eq!(flows[0].source, TaintSource::CrossFunction);
        assert_eq!(flows[0].sink_kind, SinkKind::SqlQuery);
    }

    #[test]
    fn test_propagate_taint_with_params_no_false_positive() {
        // A function with a Parameter NOT in the tainted set.
        // param (index 0) -> db.Query(param): no flow because param is clean.
        let param = make_instr(10, ValueKind::Parameter, "input", 0);
        let sink = make_call(11, "(*database/sql.DB).Query", vec![10], 0);

        let func = make_func(
            "example.com/test.process",
            vec![make_block(0, vec![param, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        // Empty set — no parameter is tainted.
        let tainted_indices = HashSet::new();

        let flows = propagate_taint_with_params(&func, &pkg, &tainted_indices);
        assert!(
            flows.is_empty(),
            "should not detect flow when parameter is not tainted, got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_propagate_taint_with_params_second_param() {
        // Function with two parameters; only the second (index 1) is tainted.
        let param0 = make_instr(10, ValueKind::Parameter, "safe", 0);
        let param1 = make_instr(11, ValueKind::Parameter, "tainted_input", 0);
        let sink = make_call(12, "(*database/sql.DB).Query", vec![11], 0);

        let func = make_func(
            "example.com/test.process",
            vec![make_block(0, vec![param0, param1, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let mut tainted_indices = HashSet::new();
        tainted_indices.insert(1u32); // Only second param is tainted.

        let flows = propagate_taint_with_params(&func, &pkg, &tainted_indices);
        assert_eq!(
            flows.len(),
            1,
            "should detect flow from second tainted param"
        );
        assert_eq!(flows[0].source, TaintSource::CrossFunction);
    }

    #[test]
    fn test_propagate_taint_with_params_does_not_override_http_source() {
        // If a parameter is already an HTTP request source, the CrossFunction
        // taint should NOT override it (the existing source takes priority).
        let param = make_instr(10, ValueKind::Parameter, "*net/http.Request", 0);
        let sink = make_call(11, "(*database/sql.DB).Query", vec![10], 0);

        let func = make_func(
            "example.com/test.handler",
            vec![make_block(0, vec![param, sink])],
        );
        let pkg = make_package("example.com/test", vec![func.clone()]);

        let mut tainted_indices = HashSet::new();
        tainted_indices.insert(0u32);

        let flows = propagate_taint_with_params(&func, &pkg, &tainted_indices);
        assert_eq!(flows.len(), 1);
        // Should keep the more specific HttpRequest source, not CrossFunction.
        assert_eq!(flows[0].source, TaintSource::HttpRequest);
    }
}
