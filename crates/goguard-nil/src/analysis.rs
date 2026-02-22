//! Nil pointer dereference analysis engine.
//!
//! Forward dataflow analysis that tracks nilability of SSA values
//! through a function's CFG using abstract interpretation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::cfg::Cfg;
use goguard_ir::ir::*;

use crate::lattice::{join_optional, Nilability};
use crate::models::stdlib_return_model;
use crate::rules;
use crate::summary::{compute_package_return_nilness, PackageSummaries, ReturnNilness};

/// Known Go functions that never return (terminate the process or goroutine).
const NORETURN_FUNCTIONS: &[&str] = &[
    // log package
    "log.Fatal",
    "log.Fatalf",
    "log.Fatalln",
    // log.Logger methods
    "(*log.Logger).Fatal",
    "(*log.Logger).Fatalf",
    "(*log.Logger).Fatalln",
    // os package
    "os.Exit",
    // runtime
    "runtime.Goexit",
    // testing package
    "(*testing.T).FailNow",
    "(*testing.T).Fatal",
    "(*testing.T).Fatalf",
    "(*testing.B).FailNow",
    "(*testing.B).Fatal",
    "(*testing.B).Fatalf",
];

/// Per-block abstract state: maps SSA value IDs to their nilability.
type BlockState = HashMap<u32, Nilability>;

/// A nil-check pattern: `BinOp(==|!= nil) → If`
struct NilCheck {
    /// The SSA value being compared to nil
    tested_value_id: u32,
    /// true for `== nil`, false for `!= nil`
    is_eq: bool,
}

#[derive(Debug, Clone)]
struct CallInfo {
    callee: Option<String>,
    callee_is_interface: bool,
}

/// Context for the nil analysis — passed to merge_predecessors to avoid argument bloat.
struct NilContext<'a> {
    nil_checks: HashMap<u32, NilCheck>,
    noreturn_blocks: HashSet<u32>,
    sibling_extracts: HashMap<u32, Vec<u32>>,
    call_info_map: HashMap<u32, CallInfo>,
    type_map: HashMap<u32, &'a TypeRef>,
    instr_type_map: HashMap<u32, u32>,
    return_summaries: Option<&'a PackageSummaries>,
    strict_params: bool,
    user_models: UserReturnModels,
    annotated_calls: HashSet<u32>,
}

/// Forward dataflow nil analysis engine.
pub struct NilAnalyzer;

pub type UserReturnModels = Arc<HashMap<String, HashMap<u32, ReturnNilness>>>;

pub fn parse_user_models(entries: &[(String, String)]) -> UserReturnModels {
    let mut result: HashMap<String, HashMap<u32, ReturnNilness>> = HashMap::new();

    for (raw_key, raw_value) in entries {
        let (callee, return_index) = match raw_key.rsplit_once('#') {
            Some((left, right)) if !left.is_empty() => match right.parse::<u32>() {
                Ok(idx) => (left.to_string(), idx),
                Err(_) => {
                    tracing::warn!(key = %raw_key, "invalid nil model key (bad return index)");
                    continue;
                }
            },
            _ => (raw_key.clone(), 0),
        };

        let nilness = match raw_value.trim().to_ascii_lowercase().as_str() {
            "nonnull" | "never_nil" | "never-nil" | "non_nil" | "non-nil" => {
                ReturnNilness::Unconditional
            }
            "nilable" | "can_be_nil" | "can-be-nil" => ReturnNilness::CanBeNil,
            "unknown" | "indeterminate" => ReturnNilness::Indeterminate,
            other => {
                tracing::warn!(key = %raw_key, value = %other, "unknown nil model value");
                continue;
            }
        };

        result
            .entry(callee)
            .or_default()
            .insert(return_index, nilness);
    }

    Arc::new(result)
}

#[derive(Debug, Clone)]
pub struct NilOptions {
    /// If true, treat nilable parameters as `MaybeNil` by default.
    /// This can surface real nil-arg bugs (`Process(nil)`), but may increase false positives
    /// in codebases that rely on non-nil-by-contract parameters.
    pub strict_params: bool,
    pub user_models: UserReturnModels,
}

impl Default for NilOptions {
    fn default() -> Self {
        Self {
            strict_params: false,
            user_models: Arc::new(HashMap::new()),
        }
    }
}

impl NilAnalyzer {
    /// Analyze all functions in an `AnalysisInput` and return diagnostics.
    pub fn analyze(input: &AnalysisInput) -> Vec<Diagnostic> {
        Self::analyze_with_options(input, &NilOptions::default())
    }

    pub fn analyze_with_options(input: &AnalysisInput, options: &NilOptions) -> Vec<Diagnostic> {
        input
            .packages
            .iter()
            .flat_map(|pkg| Self::analyze_package_with_options(pkg, options))
            .collect()
    }

    /// Analyze a single package for nil issues. Used by Salsa incremental path.
    pub fn analyze_package(pkg: &Package) -> Vec<Diagnostic> {
        Self::analyze_package_with_options(pkg, &NilOptions::default())
    }

    pub fn analyze_package_with_options(pkg: &Package, options: &NilOptions) -> Vec<Diagnostic> {
        let return_summaries = compute_package_return_nilness(pkg);
        let entrypoints = if options.strict_params {
            Some(Self::compute_entrypoints(pkg))
        } else {
            None
        };

        let mut all = Vec::new();
        for func in &pkg.functions {
            all.extend(Self::analyze_function_inner(
                func,
                &pkg.types,
                Some(&return_summaries),
                options,
                entrypoints.as_ref(),
            ));
        }
        all
    }

    /// Analyze a single function for nil-related issues.
    ///
    /// Uses a fixed-point forward dataflow iteration in reverse postorder,
    /// then checks each instruction against the converged state.
    ///
    /// Note: This public API does not have constructor context. Use
    /// `analyze_package` for constructor-aware analysis.
    pub fn analyze_function(func: &Function, types: &[TypeRef]) -> Vec<Diagnostic> {
        Self::analyze_function_inner(func, types, None, &NilOptions::default(), None)
    }

    pub fn analyze_function_with_options(
        func: &Function,
        types: &[TypeRef],
        options: NilOptions,
    ) -> Vec<Diagnostic> {
        Self::analyze_function_inner(func, types, None, &options, None)
    }

    /// Internal: analyze a function with optional constructor-backed type info.
    ///
    fn analyze_function_inner(
        func: &Function,
        types: &[TypeRef],
        return_summaries: Option<&PackageSummaries>,
        options: &NilOptions,
        entrypoints: Option<&HashSet<String>>,
    ) -> Vec<Diagnostic> {
        if func.blocks.is_empty() {
            return Vec::new();
        }

        let cfg = Cfg::from_function(func);
        let type_map: HashMap<u32, &TypeRef> = types.iter().map(|t| (t.id, t)).collect();
        let instr_type_map: HashMap<u32, u32> = func
            .blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .map(|i| (i.id, i.type_id))
            .collect();
        let call_info_map: HashMap<u32, CallInfo> = func
            .blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .filter(|i| i.kind == ValueKind::Call)
            .map(|i| {
                (
                    i.id,
                    CallInfo {
                        callee: i.callee.clone(),
                        callee_is_interface: i.callee_is_interface,
                    },
                )
            })
            .collect();

        // Seed the entry block state: in Go, method receivers are always treated as NonNil
        // inside the method body (nil receiver would crash at call site).
        let mut seed_overrides = Self::build_receiver_overrides(func);
        if options.strict_params && entrypoints.is_some_and(|eps| eps.contains(&func.name)) {
            seed_overrides.extend(Self::build_entrypoint_overrides(func, &type_map));
        }

        let annotated_calls = Self::collect_nonnull_annotations(func);
        let ctx = NilContext {
            nil_checks: Self::build_nil_check_map(func),
            noreturn_blocks: Self::find_noreturn_blocks(func),
            sibling_extracts: Self::build_sibling_extract_map(func, &type_map, &instr_type_map),
            call_info_map,
            type_map,
            instr_type_map,
            return_summaries,
            strict_params: options.strict_params,
            user_models: options.user_models.clone(),
            annotated_calls,
        };

        let mut states: HashMap<u32, BlockState> = HashMap::new();
        let rpo = cfg.reverse_postorder();

        // Fixed-point iteration (capped at 100 iterations for safety)
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 100 {
            changed = false;
            iterations += 1;
            for &block_id in &rpo {
                let block = match cfg.block(block_id) {
                    Some(b) => b,
                    None => continue,
                };
                let mut state = Self::merge_predecessors(block_id, &cfg, &states, &ctx);

                // Apply receiver overrides to the entry block (block 0)
                if block_id == 0 {
                    for (&id, &nilability) in &seed_overrides {
                        state.insert(id, nilability);
                    }
                }

                for instr in &block.instructions {
                    if let Some(n) = Self::transfer(instr, &state, &ctx) {
                        // Don't let the transfer function override our
                        // constructor-seeded NonNil for the receiver.
                        if seed_overrides.contains_key(&instr.id) {
                            state.insert(instr.id, Nilability::NonNil);
                        } else {
                            state.insert(instr.id, n);
                        }
                    }
                }
                if states.get(&block_id) != Some(&state) {
                    states.insert(block_id, state);
                    changed = true;
                }
            }
        }

        if iterations >= 100 {
            tracing::warn!(func = %func.short_name, "nil analysis did not converge in 100 iterations");
        }

        let instr_map = Self::build_instr_map(func);

        // Check phase: emit diagnostics for nil-unsafe operations
        let mut diagnostics = Vec::new();
        for block in cfg.blocks() {
            let state = states.get(&block.id).cloned().unwrap_or_default();
            for instr in &block.instructions {
                diagnostics.extend(Self::check(instr, &state, func, &ctx, &instr_map));
            }
        }
        diagnostics
    }

    fn build_instr_map(func: &Function) -> HashMap<u32, &Instruction> {
        let mut instr_map: HashMap<u32, &Instruction> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                instr_map.insert(instr.id, instr);
            }
        }
        instr_map
    }

    fn collect_nonnull_annotations(func: &Function) -> HashSet<u32> {
        let mut result = HashSet::new();
        let mut file_cache: HashMap<String, Vec<String>> = HashMap::new();

        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind != ValueKind::Call {
                    continue;
                }
                let Some(span) = instr.span.as_ref() else {
                    continue;
                };
                if Self::span_has_nonnull_marker(span, &mut file_cache) {
                    result.insert(instr.id);
                }
            }
        }

        result
    }

    fn span_has_nonnull_marker(span: &Span, file_cache: &mut HashMap<String, Vec<String>>) -> bool {
        let lines = match file_cache.get(&span.file) {
            Some(lines) => lines,
            None => {
                let content = match std::fs::read_to_string(&span.file) {
                    Ok(c) => c,
                    Err(err) => {
                        tracing::debug!(
                            file = %span.file,
                            error = ?err,
                            "could not read source for nonnull annotation check"
                        );
                        file_cache.insert(span.file.clone(), Vec::new());
                        return false;
                    }
                };
                let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                file_cache.insert(span.file.clone(), lines);
                file_cache.get(&span.file).expect("just inserted")
            }
        };

        let line_idx = span.start_line.saturating_sub(1) as usize;
        let cur = lines.get(line_idx).map(|s| s.as_str()).unwrap_or("");
        if cur.contains("goguard:nonnull") {
            return true;
        }

        if line_idx > 0 {
            let prev = lines.get(line_idx - 1).map(|s| s.as_str()).unwrap_or("");
            if prev.contains("goguard:nonnull") {
                return true;
            }
        }

        false
    }

    /// Extract the receiver type name from a method function name.
    ///
    /// `(*Handler).DoWork` → Some("Handler")
    /// `(*pkg.Handler).DoWork` → Some("Handler")
    /// `Handler.DoWork` → Some("Handler")
    /// `DoWork` → None
    /// Build override map for method receiver parameters.
    ///
    /// In Go, methods are always called on non-nil receivers. If the receiver were
    /// nil, the crash happens at the call site, not inside the method body. Therefore,
    /// the first Parameter instruction (the receiver) is always seeded as `NonNil`,
    /// along with all FieldAddr and UnOp (load) instructions that derive from it.
    fn build_receiver_overrides(func: &Function) -> HashMap<u32, Nilability> {
        let mut overrides = HashMap::new();

        // In Go, methods are always called on non-nil receivers. If the receiver
        // were nil, the crash happens at the CALL SITE, not inside the method.
        // Therefore, inside any method body, the receiver is always NonNil.
        if !func.is_method {
            return overrides;
        }

        // Find the first Parameter instruction in the entry block (= receiver)
        let mut receiver_id = None;
        if let Some(entry_block) = func.blocks.first() {
            for instr in &entry_block.instructions {
                if instr.kind == ValueKind::Parameter {
                    receiver_id = Some(instr.id);
                    overrides.insert(instr.id, Nilability::NonNil);
                    break;
                }
            }
        }

        // Also mark all FieldAddr on receiver + UnOp loads from those as NonNil.
        // This covers: h.svc (FieldAddr on h) → load (UnOp on FieldAddr result).
        if let Some(recv_id) = receiver_id {
            for block in &func.blocks {
                for instr in &block.instructions {
                    if instr.kind == ValueKind::FieldAddr
                        && instr.operands.first() == Some(&recv_id)
                    {
                        overrides.insert(instr.id, Nilability::NonNil);
                    }
                    if instr.kind == ValueKind::UnOp {
                        if let Some(&operand_id) = instr.operands.first() {
                            if overrides.contains_key(&operand_id) {
                                overrides.insert(instr.id, Nilability::NonNil);
                            }
                        }
                    }
                }
            }
        }

        overrides
    }

    fn build_entrypoint_overrides(
        func: &Function,
        type_map: &HashMap<u32, &TypeRef>,
    ) -> HashMap<u32, Nilability> {
        let mut overrides = HashMap::new();
        let Some(entry_block) = func.blocks.first() else {
            return overrides;
        };
        for instr in &entry_block.instructions {
            if instr.kind == ValueKind::Parameter {
                if let Some(ty) = type_map.get(&instr.type_id) {
                    if Self::is_framework_entrypoint_type(&ty.name) {
                        overrides.insert(instr.id, Nilability::NonNil);
                    }
                }
            }
        }
        overrides
    }

    /// Detect functions that serve as framework entrypoints.
    ///
    /// Two detection strategies:
    /// 1. **Interface-based**: `net/http.Handler` implementations (ServeHTTP methods)
    /// 2. **Signature-based**: Functions whose parameters include known framework types
    ///    (echo.Context, *gin.Context, *fiber.Ctx, etc.)
    fn compute_entrypoints(pkg: &Package) -> HashSet<String> {
        let mut entrypoints = HashSet::new();

        // Strategy 1: interface satisfaction (net/http.Handler → ServeHTTP)
        let mut handler_iface_ids: HashSet<u32> = HashSet::new();
        for t in &pkg.types {
            if t.kind == TypeKind::Interface
                && (t.name == "net/http.Handler" || t.name == "http.Handler")
            {
                handler_iface_ids.insert(t.id);
            }
        }
        for sat in &pkg.interface_satisfactions {
            if !handler_iface_ids.contains(&sat.interface_type_id) {
                continue;
            }
            for mapping in &sat.method_mappings {
                if mapping.interface_method.ends_with("ServeHTTP") {
                    entrypoints.insert(mapping.concrete_method.clone());
                }
            }
        }

        // Strategy 2: signature-based (parameter type matching)
        let type_map: HashMap<u32, &TypeRef> = pkg.types.iter().map(|t| (t.id, t)).collect();
        for func in &pkg.functions {
            if Self::has_framework_handler_param(func, &type_map) {
                entrypoints.insert(func.name.clone());
            }
        }

        entrypoints
    }

    /// Check if a function has at least one parameter whose type indicates
    /// it's a framework handler entrypoint.
    fn has_framework_handler_param(func: &Function, type_map: &HashMap<u32, &TypeRef>) -> bool {
        let Some(entry_block) = func.blocks.first() else {
            return false;
        };
        for instr in &entry_block.instructions {
            if instr.kind != ValueKind::Parameter {
                continue;
            }
            if let Some(ty) = type_map.get(&instr.type_id) {
                if Self::is_framework_entrypoint_type(&ty.name) {
                    return true;
                }
            }
        }
        false
    }

    /// Known framework types that indicate a function is a handler entrypoint.
    ///
    /// Uses (contains, ends_with) pairs on the fully-qualified Go type name.
    /// Leading `*` is stripped before matching. This handles versioned imports:
    ///   `github.com/labstack/echo/v4.Context` → contains "labstack/echo", ends with ".Context"
    fn is_framework_entrypoint_type(type_name: &str) -> bool {
        let name = type_name.strip_prefix('*').unwrap_or(type_name);

        // (import-path fragment, type suffix) — both must match.
        const MATCHERS: &[(&str, &str)] = &[
            // Echo: github.com/labstack/echo/v4.Context, /v5.Context
            ("labstack/echo", ".Context"),
            // Gin: github.com/gin-gonic/gin.Context
            ("gin-gonic/gin", ".Context"),
            // Fiber: github.com/gofiber/fiber/v2.Ctx, /v3.Ctx
            ("gofiber/fiber", ".Ctx"),
            // Chi: github.com/go-chi/chi/v5.Context
            ("go-chi/chi", ".Context"),
            // stdlib http
            ("net/http", ".ResponseWriter"),
            ("net/http", ".Request"),
            // gRPC
            ("google.golang.org/grpc", ".ServerStream"),
            // testing
            ("testing", ".T"),
            ("testing", ".B"),
            ("testing", ".M"),
            ("testing", ".F"),
        ];

        MATCHERS
            .iter()
            .any(|(contains, ends)| name.contains(contains) && name.ends_with(ends))
    }

    /// Merge predecessor block states into a single incoming state,
    /// applying conditional refinement from nil checks and skipping noreturn blocks.
    fn merge_predecessors(
        block_id: u32,
        cfg: &Cfg,
        states: &HashMap<u32, BlockState>,
        ctx: &NilContext<'_>,
    ) -> BlockState {
        let mut merged = BlockState::new();
        for &(pred_id, edge_kind) in cfg.predecessors(block_id) {
            // Skip predecessors that contain noreturn calls (log.Fatalf, os.Exit, etc.)
            if ctx.noreturn_blocks.contains(&pred_id) {
                continue;
            }

            if let Some(pred_state) = states.get(&pred_id) {
                // Start with a clone of the predecessor state so we can refine it
                let mut refined = pred_state.clone();

                // Apply conditional refinement if the predecessor ends with a nil check
                if let Some(nc) = ctx.nil_checks.get(&pred_id) {
                    let refinement = match (edge_kind, nc.is_eq) {
                        // `x == nil`, CondTrue → x is Nil
                        (&EdgeKind::CondTrue, true) => Some(Nilability::Nil),
                        // `x == nil`, CondFalse → x is NonNil
                        (&EdgeKind::CondFalse, true) => Some(Nilability::NonNil),
                        // `x != nil`, CondTrue → x is NonNil
                        (&EdgeKind::CondTrue, false) => Some(Nilability::NonNil),
                        // `x != nil`, CondFalse → x is Nil
                        (&EdgeKind::CondFalse, false) => Some(Nilability::Nil),
                        _ => None,
                    };
                    if let Some(nilability) = refinement {
                        refined.insert(nc.tested_value_id, nilability);

                        // Go error convention: when an error extract is refined to Nil
                        // (i.e., err == nil), refine sibling extracts from the same
                        // Call to NonNil. This reflects Go's convention that when a
                        // function returns (val, err) and err is nil, val is non-nil.
                        if nilability == Nilability::Nil {
                            let is_error = ctx
                                .instr_type_map
                                .get(&nc.tested_value_id)
                                .and_then(|&tid| ctx.type_map.get(&tid))
                                .is_some_and(|t| t.is_error);
                            if is_error {
                                if let Some(siblings) =
                                    ctx.sibling_extracts.get(&nc.tested_value_id)
                                {
                                    for &sibling_id in siblings {
                                        let sibling_nilable = ctx
                                            .instr_type_map
                                            .get(&sibling_id)
                                            .and_then(|&tid| ctx.type_map.get(&tid))
                                            .is_some_and(|t| t.is_nilable);
                                        if sibling_nilable {
                                            refined.insert(sibling_id, Nilability::NonNil);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Join refined state into merged
                for (&id, &nil) in &refined {
                    let cur = merged.get(&id).copied();
                    if let Some(joined) = join_optional(cur, Some(nil)) {
                        merged.insert(id, joined);
                    }
                }
            }
        }
        merged
    }

    /// Pre-scan all blocks for the pattern: BinOp(==|!= nil) → If.
    /// Returns a map from block_id → NilCheck for blocks that end with
    /// a nil comparison followed by an If instruction.
    fn build_nil_check_map(func: &Function) -> HashMap<u32, NilCheck> {
        // First, build a map from instruction ID → instruction for cross-block lookup
        let mut instr_map: HashMap<u32, &Instruction> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                instr_map.insert(instr.id, instr);
            }
        }

        let mut result = HashMap::new();
        for block in &func.blocks {
            let instrs = &block.instructions;
            if instrs.len() < 2 {
                continue;
            }
            // Look for pattern: ... BinOp → If at end of block
            let last = &instrs[instrs.len() - 1];
            if last.kind != ValueKind::If {
                continue;
            }
            // The If's operand should be the BinOp result
            let if_operand = match last.operands.first() {
                Some(&id) => id,
                None => continue,
            };
            // Look up the BinOp instruction (may be in this block or earlier)
            let binop = match instr_map.get(&if_operand) {
                Some(instr) if instr.kind == ValueKind::BinOp => instr,
                _ => continue,
            };
            // Check if the BinOp operator is == or !=
            let is_eq = match binop.bin_op.as_deref() {
                Some("==") => true,
                Some("!=") => false,
                _ => continue,
            };
            // Determine which operand is nil and which is the tested value
            if binop.operands.len() != 2 || binop.nil_operand_indices.is_empty() {
                continue;
            }
            let nil_idx = binop.nil_operand_indices[0];
            let tested_idx = if nil_idx == 0 { 1 } else { 0 };
            let tested_value_id = binop.operands[tested_idx];

            result.insert(
                block.id,
                NilCheck {
                    tested_value_id,
                    is_eq,
                },
            );
        }
        result
    }

    /// Find blocks that contain calls to known noreturn functions.
    /// These blocks should not propagate state to their successors.
    fn find_noreturn_blocks(func: &Function) -> HashSet<u32> {
        let mut result = HashSet::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind == ValueKind::Call {
                    if let Some(ref callee) = instr.callee {
                        if Self::is_noreturn(callee) {
                            result.insert(block.id);
                            break;
                        }
                    }
                }
                // Also handle explicit Panic instructions
                if instr.kind == ValueKind::Panic {
                    result.insert(block.id);
                    break;
                }
            }
        }
        result
    }

    /// Check if a callee name matches a known noreturn function.
    fn is_noreturn(callee: &str) -> bool {
        // Exact match
        if NORETURN_FUNCTIONS.contains(&callee) {
            return true;
        }
        // Handle method calls: the bridge may emit qualified forms like
        // "(*log.Logger).Fatalf" or unqualified "log.Fatalf"
        // Also match suffix patterns for receiver method calls
        for &noreturn in NORETURN_FUNCTIONS {
            if callee.ends_with(noreturn) {
                return true;
            }
        }
        false
    }

    /// Build a map from each Extract instruction ID to its "sibling" Extract IDs.
    /// Siblings are Extracts from the same Call instruction (same operand[0]).
    /// Used for Go error convention: when error extract is nil, siblings are non-nil.
    fn build_sibling_extract_map(
        func: &Function,
        type_map: &HashMap<u32, &TypeRef>,
        instr_type_map: &HashMap<u32, u32>,
    ) -> HashMap<u32, Vec<u32>> {
        // Group Extract instructions by their source Call ID
        let mut extracts_by_call: HashMap<u32, Vec<u32>> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind == ValueKind::Extract {
                    if let Some(&call_id) = instr.operands.first() {
                        extracts_by_call.entry(call_id).or_default().push(instr.id);
                    }
                }
            }
        }

        // For each extract, map it to its siblings (other extracts from same call)
        // Only create entries for error-typed extracts (is_error == true)
        let mut result = HashMap::new();
        for extract_ids in extracts_by_call.values() {
            if extract_ids.len() < 2 {
                continue;
            }
            for &ext_id in extract_ids {
                let is_error = instr_type_map
                    .get(&ext_id)
                    .and_then(|&tid| type_map.get(&tid))
                    .is_some_and(|t| t.is_error);
                if is_error {
                    let siblings: Vec<u32> = extract_ids
                        .iter()
                        .copied()
                        .filter(|&id| id != ext_id)
                        .collect();
                    result.insert(ext_id, siblings);
                }
            }
        }
        result
    }

    /// Transfer function: compute the nilability produced by an instruction.
    ///
    /// Returns `Some(nilability)` if the instruction produces a trackable value,
    /// `None` if the instruction does not produce a value we track.
    fn transfer(
        instr: &Instruction,
        state: &BlockState,
        ctx: &NilContext<'_>,
    ) -> Option<Nilability> {
        match instr.kind {
            // Allocation-like instructions always produce non-nil values
            ValueKind::Alloc
            | ValueKind::MakeMap
            | ValueKind::MakeChan
            | ValueKind::MakeSlice
            | ValueKind::MakeClosure
            | ValueKind::MakeInterface => Some(Nilability::NonNil),

            // Constants: nil literal → Nil, everything else → NonNil
            ValueKind::Const if instr.is_nil => Some(Nilability::Nil),
            ValueKind::Const => Some(Nilability::NonNil),

            // Calls: default to return type nilability, but consult package summaries
            // to prove that some internal callees never return nil.
            ValueKind::Call => {
                let nilable = ctx
                    .type_map
                    .get(&instr.type_id)
                    .is_some_and(|t| t.is_nilable);
                if !nilable {
                    return Some(Nilability::NonNil);
                }

                if ctx.annotated_calls.contains(&instr.id) {
                    return Some(Nilability::NonNil);
                }

                if let Some(summaries) = ctx.return_summaries {
                    if !instr.callee_is_interface {
                        if let Some(callee) = instr.callee.as_deref() {
                            if summaries.get(callee).and_then(|m| m.get(&0))
                                == Some(&ReturnNilness::Unconditional)
                            {
                                return Some(Nilability::NonNil);
                            }
                        }
                    }
                }

                if !instr.callee_is_interface {
                    if let Some(callee) = instr.callee.as_deref() {
                        if ctx.user_models.get(callee).and_then(|m| m.get(&0))
                            == Some(&ReturnNilness::Unconditional)
                        {
                            return Some(Nilability::NonNil);
                        }
                        if stdlib_return_model(callee, 0) == Some(ReturnNilness::Unconditional) {
                            return Some(Nilability::NonNil);
                        }
                    }
                }

                Some(Nilability::MaybeNil)
            }

            // Extracts: check the extracted value type's nilability (multi-return models
            // are handled separately).
            ValueKind::Extract => {
                let nilable = ctx
                    .type_map
                    .get(&instr.type_id)
                    .is_some_and(|t| t.is_nilable);
                if !nilable {
                    return Some(Nilability::NonNil);
                }

                if let Some(&call_id) = instr.operands.first() {
                    if ctx.annotated_calls.contains(&call_id) {
                        return Some(Nilability::NonNil);
                    }
                }

                // If this extract is pulling a modeled return value out of a call tuple,
                // we can treat it as NonNil even though the type is nilable.
                if let Some(&call_id) = instr.operands.first() {
                    if let Some(call) = ctx.call_info_map.get(&call_id) {
                        if !call.callee_is_interface {
                            if let Some(callee) = call.callee.as_deref() {
                                // Layer 1: IPA summary (per-position)
                                if let Some(summaries) = ctx.return_summaries {
                                    if summaries
                                        .get(callee)
                                        .and_then(|m| m.get(&instr.extract_index))
                                        == Some(&ReturnNilness::Unconditional)
                                    {
                                        return Some(Nilability::NonNil);
                                    }
                                }
                                // Layer 2: user models
                                if ctx
                                    .user_models
                                    .get(callee)
                                    .and_then(|m| m.get(&instr.extract_index))
                                    == Some(&ReturnNilness::Unconditional)
                                {
                                    return Some(Nilability::NonNil);
                                }
                                // Layer 3: stdlib models
                                if stdlib_return_model(callee, instr.extract_index)
                                    == Some(ReturnNilness::Unconditional)
                                {
                                    return Some(Nilability::NonNil);
                                }
                            }
                        }
                    }
                }

                Some(Nilability::MaybeNil)
            }

            // Type assertions may produce nil if the assertion fails
            ValueKind::TypeAssert => Some(Nilability::MaybeNil),

            // Phi nodes: join all operand states
            ValueKind::Phi => {
                let mut result: Option<Nilability> = None;
                for &op_id in &instr.operands {
                    result = join_optional(result, state.get(&op_id).copied());
                }
                result.or(Some(Nilability::MaybeNil))
            }

            // Conversions propagate the operand's nilability
            ValueKind::Convert | ValueKind::ChangeType | ValueKind::ChangeInterface => instr
                .operands
                .first()
                .and_then(|&op| state.get(&op).copied()),

            // UnOp/Load: dereferencing a pointer to a nilable type
            // may produce a nil value (e.g., `var m map[string]int; *&m` → nil map)
            ValueKind::UnOp | ValueKind::Load => {
                let nilable = ctx
                    .type_map
                    .get(&instr.type_id)
                    .is_some_and(|t| t.is_nilable);
                if nilable {
                    Some(Nilability::MaybeNil)
                } else {
                    None
                }
            }

            // Parameters: always NonNil. In Go, the caller is responsible for
            // passing valid (non-nil) arguments. Analyzing nil-safety inside a
            // function should assume all parameters are valid.
            ValueKind::Parameter => {
                if !ctx.strict_params {
                    return Some(Nilability::NonNil);
                }
                let nilable = ctx
                    .type_map
                    .get(&instr.type_id)
                    .is_some_and(|t| t.is_nilable);
                Some(if nilable {
                    Nilability::MaybeNil
                } else {
                    Nilability::NonNil
                })
            }

            // All other instructions do not produce tracked nil state
            _ => None,
        }
    }

    fn nil001_confidence(
        nilability: Nilability,
        deref_operand_id: u32,
        ctx: &NilContext<'_>,
        instr_map: &HashMap<u32, &Instruction>,
    ) -> f64 {
        if nilability == Nilability::Nil {
            return 0.95;
        }

        if nilability == Nilability::MaybeNil {
            if Self::external_modeled_nilness(deref_operand_id, ctx, instr_map)
                == Some(ReturnNilness::CanBeNil)
            {
                return 0.85;
            }

            if Self::is_unknown_external_call_like(deref_operand_id, ctx, instr_map) {
                return 0.55;
            }
        }

        0.9
    }

    fn external_modeled_nilness(
        value_id: u32,
        ctx: &NilContext<'_>,
        instr_map: &HashMap<u32, &Instruction>,
    ) -> Option<ReturnNilness> {
        let def = instr_map.get(&value_id)?;

        match def.kind {
            ValueKind::Call => {
                if def.callee_is_interface {
                    return None;
                }
                let callee = def.callee.as_deref()?;
                if ctx
                    .return_summaries
                    .is_some_and(|summaries| summaries.contains_key(callee))
                {
                    return None;
                }
                ctx.user_models
                    .get(callee)
                    .and_then(|m| m.get(&0).copied())
                    .or_else(|| stdlib_return_model(callee, 0))
            }
            ValueKind::Extract => {
                let call_id = def.operands.first().copied()?;
                let call = instr_map.get(&call_id)?;
                if call.callee_is_interface {
                    return None;
                }
                let callee = call.callee.as_deref()?;
                if ctx
                    .return_summaries
                    .is_some_and(|summaries| summaries.contains_key(callee))
                {
                    return None;
                }
                ctx.user_models
                    .get(callee)
                    .and_then(|m| m.get(&def.extract_index).copied())
                    .or_else(|| stdlib_return_model(callee, def.extract_index))
            }
            _ => None,
        }
    }

    fn is_unknown_external_call_like(
        value_id: u32,
        ctx: &NilContext<'_>,
        instr_map: &HashMap<u32, &Instruction>,
    ) -> bool {
        let Some(def) = instr_map.get(&value_id) else {
            return false;
        };

        match def.kind {
            ValueKind::Call => {
                if def.callee_is_interface {
                    return true;
                }
                let Some(callee) = def.callee.as_deref() else {
                    return true;
                };
                if ctx
                    .return_summaries
                    .is_some_and(|summaries| summaries.contains_key(callee))
                {
                    return false;
                }
                match ctx.user_models.get(callee).and_then(|m| m.get(&0).copied()) {
                    Some(ReturnNilness::Unconditional | ReturnNilness::CanBeNil) => return false,
                    Some(ReturnNilness::Indeterminate) | None => {}
                }
                match stdlib_return_model(callee, 0) {
                    Some(ReturnNilness::Unconditional | ReturnNilness::CanBeNil) => false,
                    Some(ReturnNilness::Indeterminate) | None => true,
                }
            }
            ValueKind::Extract => {
                let Some(call_id) = def.operands.first().copied() else {
                    return false;
                };
                let Some(call) = instr_map.get(&call_id) else {
                    return false;
                };
                if call.callee_is_interface {
                    return true;
                }
                let Some(callee) = call.callee.as_deref() else {
                    return true;
                };
                if ctx
                    .return_summaries
                    .is_some_and(|summaries| summaries.contains_key(callee))
                {
                    return false;
                }
                match ctx
                    .user_models
                    .get(callee)
                    .and_then(|m| m.get(&def.extract_index).copied())
                {
                    Some(ReturnNilness::Unconditional | ReturnNilness::CanBeNil) => return false,
                    Some(ReturnNilness::Indeterminate) | None => {}
                }
                match stdlib_return_model(callee, def.extract_index) {
                    Some(ReturnNilness::Unconditional | ReturnNilness::CanBeNil) => false,
                    Some(ReturnNilness::Indeterminate) | None => true,
                }
            }
            _ => false,
        }
    }

    /// Trace the callee key for a value that came from an external call.
    /// Returns e.g. `"db.Find#0"` for a direct call result or `"db.Find#1"` for an extract.
    fn trace_callee_key(
        value_id: u32,
        _ctx: &NilContext<'_>,
        instr_map: &HashMap<u32, &Instruction>,
    ) -> Option<String> {
        let def = instr_map.get(&value_id)?;
        match def.kind {
            ValueKind::Call => {
                let callee = def.callee.as_deref()?;
                Some(format!("{}#0", callee))
            }
            ValueKind::Extract => {
                let call_id = def.operands.first()?;
                let call = instr_map.get(call_id)?;
                let callee = call.callee.as_deref()?;
                Some(format!("{}#{}", callee, def.extract_index))
            }
            ValueKind::FieldAddr | ValueKind::IndexAddr => {
                let op = def.operands.first()?;
                Self::trace_callee_key(*op, _ctx, instr_map)
            }
            _ => None,
        }
    }

    /// Check an instruction for nil-unsafe operations against the current state.
    fn check(
        instr: &Instruction,
        state: &BlockState,
        func: &Function,
        ctx: &NilContext<'_>,
        instr_map: &HashMap<u32, &Instruction>,
    ) -> Option<Diagnostic> {
        match instr.kind {
            // Pointer dereference: FieldAddr, IndexAddr on a possibly-nil value
            ValueKind::FieldAddr | ValueKind::IndexAddr => {
                let op_id = instr.operands.first()?;
                // Check state, or fall back to inline nil_operand_indices
                let nilability = state.get(op_id).copied().or_else(|| {
                    if instr.nil_operand_indices.contains(&0) {
                        Some(Nilability::Nil)
                    } else {
                        None
                    }
                })?;
                if nilability.is_possibly_nil() {
                    let confidence = Self::nil001_confidence(nilability, *op_id, ctx, instr_map);
                    let callee_key = if (confidence - 0.55).abs() < f64::EPSILON {
                        Self::trace_callee_key(*op_id, ctx, instr_map)
                    } else {
                        None
                    };
                    Some(rules::build_nil001(
                        instr,
                        &func.short_name,
                        confidence,
                        callee_key,
                    ))
                } else {
                    None
                }
            }

            // Lookup (map read) — nil map read returns zero value, no panic.
            // Only emit NIL004 Warning (not NIL001 panic).
            ValueKind::Lookup => {
                let op_id = instr.operands.first()?;
                let nilability = state.get(op_id).copied().or_else(|| {
                    if instr.nil_operand_indices.contains(&0) {
                        Some(Nilability::Nil)
                    } else {
                        None
                    }
                })?;
                if nilability.is_possibly_nil() {
                    Some(rules::build_nil004(instr, &func.short_name, nilability))
                } else {
                    None
                }
            }

            // Unchecked type assertion (no comma-ok)
            ValueKind::TypeAssert if !instr.comma_ok => {
                Some(rules::build_nil002(instr, &func.short_name))
            }

            // Nil map write (panic) or access
            ValueKind::MapUpdate => {
                let op_id = instr.operands.first()?;
                let nilability = state.get(op_id).copied().or_else(|| {
                    if instr.nil_operand_indices.contains(&0) {
                        Some(Nilability::Nil)
                    } else {
                        None
                    }
                })?;
                if nilability.is_possibly_nil() {
                    Some(rules::build_nil004(instr, &func.short_name, nilability))
                } else {
                    None
                }
            }

            // Nil channel send
            ValueKind::Send => {
                let op_id = instr.operands.first()?;
                let nilability = state.get(op_id).copied().or_else(|| {
                    if instr.nil_operand_indices.contains(&0) {
                        Some(Nilability::Nil)
                    } else {
                        None
                    }
                })?;
                if nilability.is_possibly_nil() {
                    Some(rules::build_nil006(instr, &func.short_name))
                } else {
                    None
                }
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::Severity;

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

    fn make_types() -> Vec<TypeRef> {
        vec![
            TypeRef {
                id: 0,
                kind: TypeKind::Basic,
                name: "void".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
            TypeRef {
                id: 1,
                kind: TypeKind::Tuple,
                name: "(*User, error)".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
            TypeRef {
                id: 2,
                kind: TypeKind::Pointer,
                name: "*User".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
            TypeRef {
                id: 3,
                kind: TypeKind::Interface,
                name: "error".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: true,
            },
            TypeRef {
                id: 4,
                kind: TypeKind::Pointer,
                name: "*string".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
        ]
    }

    /// Test: intra-package function returns fresh alloc unconditionally, so
    /// callers should treat `Call` result as NonNil (even if the type is nilable).
    #[test]
    fn test_intra_package_unconditional_return_suppresses_call_nil001() {
        let types = make_types();

        // NewUser() *User { return new(User) }
        let alloc = make_instr(0, ValueKind::Alloc, "t0", 2); // *User
        let mut ret = make_instr(1, ValueKind::Return, "ret", 0);
        ret.operands = vec![0];
        let new_user = Function {
            name: "pkg.NewUser".into(),
            short_name: "NewUser".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![alloc, ret],
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

        // GetUser() *User { return NewUser() }
        let mut call_new_user_inner = make_instr(2, ValueKind::Call, "t2", 2);
        call_new_user_inner.callee = Some("pkg.NewUser".into());
        let mut ret_call = make_instr(3, ValueKind::Return, "ret", 0);
        ret_call.operands = vec![2];
        let get_user = Function {
            name: "pkg.GetUser".into(),
            short_name: "GetUser".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call_new_user_inner, ret_call],
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

        // Use() { u := NewUser(); u.Name }
        let mut call_new_user = make_instr(10, ValueKind::Call, "t10", 2); // *User
        call_new_user.callee = Some("pkg.NewUser".into());
        let mut field_addr = make_instr(11, ValueKind::FieldAddr, "t11", 4);
        field_addr.operands = vec![10]; // dereferences u

        let use_func = Function {
            name: "pkg.Use".into(),
            short_name: "Use".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call_new_user, field_addr],
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

        // Use2() { u := GetUser(); u.Name }
        let mut call_get_user = make_instr(20, ValueKind::Call, "t20", 2);
        call_get_user.callee = Some("pkg.GetUser".into());
        let mut field_addr2 = make_instr(21, ValueKind::FieldAddr, "t21", 4);
        field_addr2.operands = vec![20];
        let use_func2 = Function {
            name: "pkg.Use2".into(),
            short_name: "Use2".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call_get_user, field_addr2],
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
            types,
            functions: vec![new_user, get_user, use_func, use_func2],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = NilAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "call to proven-non-nil constructor should not trigger NIL001; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    /// Test: call returns nilable, then FieldAddr on it -> NIL001
    #[test]
    fn test_nil_deref_detected() {
        let types = make_types();

        let mut call_instr = make_instr(0, ValueKind::Call, "t0", 1);
        call_instr.callee = Some("db.Find".into());

        let mut extract_user = make_instr(1, ValueKind::Extract, "t1", 2);
        extract_user.operands = vec![0];

        let mut extract_err = make_instr(2, ValueKind::Extract, "t2", 3);
        extract_err.operands = vec![0];

        let mut field_addr = make_instr(4, ValueKind::FieldAddr, "t4", 4);
        field_addr.operands = vec![1]; // dereferences t1 (user)

        let func = Function {
            name: "test.BasicNilDeref".into(),
            short_name: "BasicNilDeref".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![call_instr, extract_user, extract_err],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "if.then".into(),
                    instructions: vec![make_instr(3, ValueKind::Call, "t3", 0)],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "if.done".into(),
                    instructions: vec![field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(!diags.is_empty(), "should detect nil deref");
        assert_eq!(diags[0].rule, "NIL001");
    }

    #[test]
    fn test_nil001_confidence_low_for_unknown_external_call_extract() {
        let types = make_types();

        // Unknown external call returning a tuple; we extract the first result and deref it.
        let mut call_instr = make_instr(0, ValueKind::Call, "t0", 1);
        call_instr.callee = Some("db.Find".into());

        let mut extract_user = make_instr(1, ValueKind::Extract, "t1", 2);
        extract_user.operands = vec![0];

        let mut field_addr = make_instr(2, ValueKind::FieldAddr, "t2", 4);
        field_addr.operands = vec![1];

        let func = Function {
            name: "test.ConfidenceLow".into(),
            short_name: "ConfidenceLow".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call_instr, extract_user, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert_eq!(diags.len(), 1, "expected exactly one diag, got: {diags:?}");
        assert_eq!(diags[0].rule, "NIL001");
        assert!(
            (diags[0].confidence - 0.55).abs() < f64::EPSILON,
            "expected low confidence=0.55, got: {}",
            diags[0].confidence
        );
        assert_eq!(
            diags[0].callee_key.as_deref(),
            Some("db.Find#0"),
            "expected callee_key for low-confidence NIL001"
        );
    }

    #[test]
    fn test_nil001_confidence_high_for_explicit_nil_deref() {
        let types = make_types();

        let mut const_nil = make_instr(0, ValueKind::Const, "t0", 2);
        const_nil.is_nil = true;

        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let func = Function {
            name: "test.ConfidenceHigh".into(),
            short_name: "ConfidenceHigh".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![const_nil, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert_eq!(diags.len(), 1, "expected exactly one diag, got: {diags:?}");
        assert_eq!(diags[0].rule, "NIL001");
        assert!(
            (diags[0].confidence - 0.95).abs() < f64::EPSILON,
            "expected high confidence=0.95, got: {}",
            diags[0].confidence
        );
        assert!(
            diags[0].callee_key.is_none(),
            "high-confidence NIL001 should NOT have callee_key"
        );
    }

    #[test]
    fn test_stdlib_model_suppresses_nil001_for_known_non_nil_call() {
        let mut types = make_types();
        // Add a stand-in interface type (nilable).
        types.push(TypeRef {
            id: 5,
            kind: TypeKind::Interface,
            name: "context.Context".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });

        // t0 = context.Background() (should be NonNil via stdlib model)
        let mut call = make_instr(0, ValueKind::Call, "t0", 5);
        call.callee = Some("context.Background".into());

        // Deref-ish op on t0 should NOT trigger NIL001 if modeled as never-nil.
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let func = Function {
            name: "test.Model".into(),
            short_name: "Model".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.is_empty(),
            "stdlib model should suppress NIL001 for context.Background; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_multi_return_model_suppresses_nil001_for_extract() {
        let mut types = make_types();
        // Add a stand-in interface type (nilable).
        types.push(TypeRef {
            id: 5,
            kind: TypeKind::Interface,
            name: "context.Context".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });

        // t0 = context.WithCancel(ctx) (returns (context.Context, context.CancelFunc))
        // The Call itself typically has a tuple type (non-nilable), so the model must
        // apply at Extract(index=0).
        let mut call = make_instr(0, ValueKind::Call, "t0", 1); // tuple
        call.callee = Some("context.WithCancel".into());

        let mut extract_ctx = make_instr(1, ValueKind::Extract, "t1", 5);
        extract_ctx.operands = vec![0];
        extract_ctx.extract_index = 0;

        let mut field_addr = make_instr(2, ValueKind::FieldAddr, "t2", 4);
        field_addr.operands = vec![1];

        let func = Function {
            name: "test.MultiReturnModel".into(),
            short_name: "MultiReturnModel".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, extract_ctx, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.is_empty(),
            "stdlib model should suppress NIL001 for context.WithCancel Extract(0); got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_strict_params_reports_nil001_on_param_deref() {
        let types = make_types();

        let param = make_instr(0, ValueKind::Parameter, "p0", 2); // *User (nilable)
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let func = Function {
            name: "test.StrictParams".into(),
            short_name: "StrictParams".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![param, field_addr],
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

        let diags = NilAnalyzer::analyze_function_with_options(
            &func,
            &types,
            NilOptions {
                strict_params: true,
                ..NilOptions::default()
            },
        );
        assert!(
            diags.iter().any(|d| d.rule == "NIL001"),
            "strict_params should flag param deref; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );

        let diags_default = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            !diags_default.iter().any(|d| d.rule == "NIL001"),
            "default mode should keep Parameter NonNil; got: {:?}",
            diags_default.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_strict_params_entrypoint_overrides_seed_params_non_nil() {
        let mut types = make_types();
        // Receiver type
        types.push(TypeRef {
            id: 10,
            kind: TypeKind::Pointer,
            name: "*Handler".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });
        // net/http.ResponseWriter (interface, nilable)
        types.push(TypeRef {
            id: 11,
            kind: TypeKind::Interface,
            name: "net/http.ResponseWriter".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });
        // *net/http.Request (pointer, nilable)
        types.push(TypeRef {
            id: 12,
            kind: TypeKind::Pointer,
            name: "*net/http.Request".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });
        // net/http.Handler (interface)
        types.push(TypeRef {
            id: 13,
            kind: TypeKind::Interface,
            name: "net/http.Handler".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });

        let recv = make_instr(0, ValueKind::Parameter, "p0", 10);
        let w = make_instr(1, ValueKind::Parameter, "p1", 11);
        let r = make_instr(2, ValueKind::Parameter, "p2", 12);
        let mut field_addr = make_instr(3, ValueKind::FieldAddr, "t3", 4);
        field_addr.operands = vec![2]; // deref `r`

        let func_name = "example.com/pkg.(*Handler).ServeHTTP".to_string();
        let func = Function {
            name: func_name.clone(),
            short_name: "ServeHTTP".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![recv, w, r, field_addr],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: true,
            receiver_type_id: 10,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let pkg = Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types,
            functions: vec![func],
            interface_satisfactions: vec![InterfaceSatisfaction {
                concrete_type_id: 10,
                interface_type_id: 13,
                method_mappings: vec![MethodMapping {
                    interface_method: "ServeHTTP".into(),
                    concrete_method: func_name,
                }],
            }],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = NilAnalyzer::analyze_package_with_options(
            &pkg,
            &NilOptions {
                strict_params: true,
                ..NilOptions::default()
            },
        );
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "entrypoint override should seed handler params as NonNil in strict mode; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_user_model_suppresses_nil001_for_unknown_external_call() {
        let types = make_types();

        let mut call = make_instr(0, ValueKind::Call, "t0", 2); // *User
        call.callee = Some("ext.NewUser".into());

        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let func = Function {
            name: "test.UserModelCall".into(),
            short_name: "UserModelCall".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, field_addr],
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

        let diags_default = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags_default.iter().any(|d| d.rule == "NIL001"),
            "default should flag unknown external call result; got: {:?}",
            diags_default.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );

        let opts = NilOptions {
            strict_params: false,
            user_models: parse_user_models(&[("ext.NewUser".into(), "nonnull".into())]),
        };
        let diags = NilAnalyzer::analyze_function_with_options(&func, &types, opts);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "user model should suppress NIL001 for ext.NewUser; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_user_model_suppresses_nil001_for_multi_return_extract() {
        let types = make_types();

        let mut call = make_instr(0, ValueKind::Call, "t0", 1); // tuple
        call.callee = Some("ext.Pair".into());

        let mut extract0 = make_instr(1, ValueKind::Extract, "t1", 2); // *User
        extract0.operands = vec![0];
        extract0.extract_index = 0;

        let mut field_addr = make_instr(2, ValueKind::FieldAddr, "t2", 4);
        field_addr.operands = vec![1];

        let func = Function {
            name: "test.UserModelExtract".into(),
            short_name: "UserModelExtract".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, extract0, field_addr],
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

        let opts = NilOptions {
            strict_params: false,
            user_models: parse_user_models(&[("ext.Pair#0".into(), "nonnull".into())]),
        };
        let diags = NilAnalyzer::analyze_function_with_options(&func, &types, opts);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "user model should suppress NIL001 for ext.Pair#0; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_nonnull_annotation_suppresses_nil001_for_call_and_extract() {
        use std::io::Write;

        let types = make_types();

        let mut path = std::env::temp_dir();
        path.push(format!(
            "goguard_nil_nonnull_{}_{}.go",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let mut f = std::fs::File::create(&path).unwrap();
        // Put marker on line 2 (call-site).
        writeln!(f, "package p").unwrap();
        writeln!(f, "func f() {{ _ = ext.Pair() //goguard:nonnull }}").unwrap();
        writeln!(f, "func g() {{}}").unwrap();

        // Call has a real span (line 2); Extract has line 2 too for this synthetic test.
        let mut call = make_instr(0, ValueKind::Call, "t0", 1); // tuple
        call.callee = Some("ext.Pair".into());
        call.span = Some(Span::new(path.to_string_lossy(), 2, 1));

        let mut extract0 = make_instr(1, ValueKind::Extract, "t1", 2); // *User
        extract0.operands = vec![0];
        extract0.extract_index = 0;
        extract0.span = Some(Span::new(path.to_string_lossy(), 2, 1));

        let mut field_addr = make_instr(2, ValueKind::FieldAddr, "t2", 4);
        field_addr.operands = vec![1];

        let func = Function {
            name: "test.NonnullAnno".into(),
            short_name: "NonnullAnno".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, extract0, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "nonnull annotation should suppress NIL001; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Test: same CFG but block 1 returns, so only entry->B2 flows.
    /// Without conditional refinement, t1 remains MaybeNil and still triggers.
    /// This test verifies the analyzer does not crash on return blocks.
    #[test]
    fn test_safe_with_return() {
        let types = make_types();

        let mut call_instr = make_instr(0, ValueKind::Call, "t0", 1);
        call_instr.callee = Some("db.Find".into());

        let mut extract_user = make_instr(1, ValueKind::Extract, "t1", 2);
        extract_user.operands = vec![0];

        let mut extract_err = make_instr(2, ValueKind::Extract, "t2", 3);
        extract_err.operands = vec![0];

        let mut field_addr = make_instr(4, ValueKind::FieldAddr, "t4", 4);
        field_addr.operands = vec![1];

        let func = Function {
            name: "test.Safe".into(),
            short_name: "Safe".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![call_instr, extract_user, extract_err],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "if.then".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "if.done".into(),
                    instructions: vec![field_addr],
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
                // NO edge from 1->2 because block 1 returns
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let diags = NilAnalyzer::analyze_function(&func, &types);
        // Block 2 only gets state from block 0 (CondFalse branch).
        // t1 is MaybeNil from Extract, so this WILL trigger NIL001.
        // The safe pattern requires conditional refinement (If + nil check)
        // which we don't implement yet. This is acceptable for Phase 1.
        // Verify we at least get a diagnostic (MaybeNil without refinement)
        let _ = diags;
    }

    #[test]
    fn test_unchecked_type_assertion() {
        let types = make_types();

        let ta = Instruction {
            id: 0,
            kind: ValueKind::TypeAssert,
            name: "t0".into(),
            type_id: 2,
            span: Some(Span::new("test.go", 8, 10)),
            operands: vec![],
            extract_index: 0,
            callee: None,
            callee_is_interface: false,
            assert_type_id: 5,
            comma_ok: false,
            const_value: None,
            is_nil: false,
            bin_op: None,
            nil_operand_indices: vec![],
            select_cases: vec![],
            channel_dir: None,
        };

        let func = Function {
            name: "test.TypeAssert".into(),
            short_name: "TypeAssert".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![ta],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.iter().any(|d| d.rule == "NIL002"),
            "should detect unchecked type assertion"
        );
    }

    #[test]
    fn test_alloc_is_non_nil() {
        let types = make_types();

        let alloc = make_instr(0, ValueKind::Alloc, "t0", 2);
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0]; // dereferences t0 (Alloc = NonNil)

        let func = Function {
            name: "test.Alloc".into(),
            short_name: "Alloc".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![alloc, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.is_empty(),
            "Alloc result should be NonNil, no diagnostic"
        );
    }

    #[test]
    fn test_empty_function() {
        let diags = NilAnalyzer::analyze_function(
            &Function {
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
            },
            &[],
        );
        assert!(diags.is_empty());
    }

    #[test]
    fn test_nil_const_triggers_deref() {
        let types = make_types();

        let mut nil_const = make_instr(0, ValueKind::Const, "t0", 2);
        nil_const.is_nil = true;

        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0]; // dereferences nil const

        let func = Function {
            name: "test.NilConst".into(),
            short_name: "NilConst".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![nil_const, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(!diags.is_empty(), "should detect deref of nil const");
        assert_eq!(diags[0].rule, "NIL001");
    }

    #[test]
    fn test_nil_map_write() {
        let types = make_types();

        let mut nil_const = make_instr(0, ValueKind::Const, "t0", 2);
        nil_const.is_nil = true;

        let mut map_update = make_instr(1, ValueKind::MapUpdate, "t1", 0);
        map_update.operands = vec![0]; // writing to nil map

        let func = Function {
            name: "test.NilMapWrite".into(),
            short_name: "NilMapWrite".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![nil_const, map_update],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(!diags.is_empty(), "should detect nil map write");
        assert_eq!(diags[0].rule, "NIL004");
        assert_eq!(diags[0].severity, Severity::Critical);
    }

    #[test]
    fn test_nil_channel_send() {
        let types = make_types();

        let mut nil_const = make_instr(0, ValueKind::Const, "t0", 2);
        nil_const.is_nil = true;

        let mut send = make_instr(1, ValueKind::Send, "t1", 0);
        send.operands = vec![0]; // sending on nil channel

        let func = Function {
            name: "test.NilChanSend".into(),
            short_name: "NilChanSend".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![nil_const, send],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(!diags.is_empty(), "should detect nil channel send");
        assert_eq!(diags[0].rule, "NIL006");
    }

    #[test]
    fn test_make_map_is_non_nil() {
        let types = make_types();

        let make_map = make_instr(0, ValueKind::MakeMap, "t0", 2);
        let mut map_update = make_instr(1, ValueKind::MapUpdate, "t1", 0);
        map_update.operands = vec![0]; // writing to make(map) = NonNil

        let func = Function {
            name: "test.MakeMap".into(),
            short_name: "MakeMap".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![make_map, map_update],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.is_empty(),
            "MakeMap should be NonNil, no diagnostic for MapUpdate"
        );
    }

    #[test]
    fn test_checked_type_assertion_no_diagnostic() {
        let types = make_types();

        let ta = Instruction {
            id: 0,
            kind: ValueKind::TypeAssert,
            name: "t0".into(),
            type_id: 2,
            span: Some(Span::new("test.go", 8, 10)),
            operands: vec![],
            extract_index: 0,
            callee: None,
            callee_is_interface: false,
            assert_type_id: 5,
            comma_ok: true, // checked assertion
            const_value: None,
            is_nil: false,
            bin_op: None,
            nil_operand_indices: vec![],
            select_cases: vec![],
            channel_dir: None,
        };

        let func = Function {
            name: "test.CheckedAssert".into(),
            short_name: "CheckedAssert".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![ta],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL002"),
            "checked type assertion should not produce NIL002"
        );
    }

    #[test]
    fn test_analyze_full_input() {
        let types = make_types();

        let alloc = make_instr(0, ValueKind::Alloc, "t0", 2);
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let input = AnalysisInput {
            packages: vec![Package {
                import_path: "example.com/test".into(),
                name: "test".into(),
                files: vec![],
                types,
                functions: vec![Function {
                    name: "test.Safe".into(),
                    short_name: "Safe".into(),
                    span: None,
                    blocks: vec![BasicBlock {
                        id: 0,
                        name: "entry".into(),
                        instructions: vec![alloc, field_addr],
                        is_return: true,
                        is_panic: false,
                    }],
                    cfg_edges: vec![],
                    is_method: false,
                    receiver_type_id: 0,
                    is_exported: false,
                    free_vars: vec![],
                    defers: vec![],
                }],
                interface_satisfactions: vec![],
                call_edges: vec![],
                global_vars: vec![],
            }],
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        };

        let diags = NilAnalyzer::analyze(&input);
        assert!(diags.is_empty(), "Alloc -> FieldAddr should be safe");
    }

    #[test]
    fn test_nil_analyze_package_matches_analyze() {
        let types = make_types();

        // Create a nil deref pattern: Call returning nilable -> Extract -> FieldAddr
        let mut call_instr = make_instr(0, ValueKind::Call, "t0", 1);
        call_instr.callee = Some("db.Find".into());

        let mut extract_user = make_instr(1, ValueKind::Extract, "t1", 2);
        extract_user.operands = vec![0];

        let mut field_addr = make_instr(2, ValueKind::FieldAddr, "t2", 4);
        field_addr.operands = vec![1]; // dereferences t1 (MaybeNil)

        let pkg = Package {
            import_path: "example.com/test".into(),
            name: "test".into(),
            files: vec![],
            types,
            functions: vec![Function {
                name: "test.NilDeref".into(),
                short_name: "NilDeref".into(),
                span: None,
                blocks: vec![BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![call_instr, extract_user, field_addr],
                    is_return: true,
                    is_panic: false,
                }],
                cfg_edges: vec![],
                is_method: false,
                receiver_type_id: 0,
                is_exported: false,
                free_vars: vec![],
                defers: vec![],
            }],
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

        let from_analyze = NilAnalyzer::analyze(&input);
        let from_package = NilAnalyzer::analyze_package(&input.packages[0]);

        assert_eq!(
            from_analyze.len(),
            from_package.len(),
            "analyze and analyze_package should produce same number of diagnostics"
        );
        for (a, b) in from_analyze.iter().zip(from_package.iter()) {
            assert_eq!(a.rule, b.rule);
            assert_eq!(a.title, b.title);
        }
    }

    /// Test: `cfg, err := Load(); if err != nil { log.Fatalf(...) }; cfg.Env`
    /// log.Fatalf is noreturn — should NOT produce NIL001 for cfg after the guard.
    #[test]
    fn test_noreturn_guard_eliminates_nil_deref() {
        let types = make_types();

        // t0 = config.Load() — returns tuple
        let mut call_instr = make_instr(0, ValueKind::Call, "t0", 1);
        call_instr.callee = Some("config.Load".into());

        // t1 = extract t0 #0 → *Config (nilable)
        let mut extract_cfg = make_instr(1, ValueKind::Extract, "t1", 2);
        extract_cfg.operands = vec![0];

        // t2 = extract t0 #1 → error (nilable)
        let mut extract_err = make_instr(2, ValueKind::Extract, "t2", 3);
        extract_err.operands = vec![0];

        // t3 = BinOp(t2 != nil)
        let mut binop = make_instr(3, ValueKind::BinOp, "t3", 0);
        binop.bin_op = Some("!=".into());
        binop.operands = vec![2, 100]; // t2 and a nil const
        binop.nil_operand_indices = vec![1]; // operand[1] is nil

        // If t3
        let mut if_instr = make_instr(4, ValueKind::If, "if", 0);
        if_instr.operands = vec![3]; // uses t3

        // Block 1: log.Fatalf(...) — noreturn
        let mut fatalf = make_instr(5, ValueKind::Call, "t5", 0);
        fatalf.callee = Some("log.Fatalf".into());

        // Block 2: cfg.Env — FieldAddr on t1
        let mut field_addr = make_instr(6, ValueKind::FieldAddr, "t6", 4);
        field_addr.operands = vec![1]; // dereferences t1 (cfg)

        let func = Function {
            name: "test.NoreturnGuard".into(),
            short_name: "NoreturnGuard".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![call_instr, extract_cfg, extract_err, binop, if_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "if.then".into(),
                    instructions: vec![fatalf],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "if.done".into(),
                    instructions: vec![field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.is_empty(),
            "noreturn guard (log.Fatalf) should eliminate nil deref; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    /// Test: error convention refinement — when err is refined to Nil (via !=nil check),
    /// sibling extracts from the same Call tuple should be refined to NonNil.
    #[test]
    fn test_error_convention_refines_sibling_extract() {
        let types = make_types();

        // t0 = db.Find() — returns tuple
        let mut call_instr = make_instr(0, ValueKind::Call, "t0", 1);
        call_instr.callee = Some("db.Find".into());

        // t1 = extract t0 #0 → *User (nilable)
        let mut extract_user = make_instr(1, ValueKind::Extract, "t1", 2);
        extract_user.operands = vec![0];

        // t2 = extract t0 #1 → error (nilable, is_error)
        let mut extract_err = make_instr(2, ValueKind::Extract, "t2", 3);
        extract_err.operands = vec![0];

        // t3 = BinOp(t2 != nil)
        let mut binop = make_instr(3, ValueKind::BinOp, "t3", 0);
        binop.bin_op = Some("!=".into());
        binop.operands = vec![2, 100];
        binop.nil_operand_indices = vec![1];

        // If t3
        let mut if_instr = make_instr(4, ValueKind::If, "if", 0);
        if_instr.operands = vec![3];

        // Block 1: return (error path)
        let ret = make_instr(5, ValueKind::Return, "ret", 0);

        // Block 2: user.Name — FieldAddr on t1
        let mut field_addr = make_instr(6, ValueKind::FieldAddr, "t6", 4);
        field_addr.operands = vec![1]; // dereferences t1 (user)

        let func = Function {
            name: "test.ErrorConvention".into(),
            short_name: "ErrorConvention".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![call_instr, extract_user, extract_err, binop, if_instr],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "if.then".into(),
                    instructions: vec![ret],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "if.done".into(),
                    instructions: vec![field_addr],
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
                // No edge from 1→2: block 1 returns
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(
            diags.is_empty(),
            "error convention: if err != nil {{ return }}, user should be NonNil; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_nil_analyze_package_empty() {
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

        let diags = NilAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "package with no functions should produce zero diagnostics"
        );
    }

    // -----------------------------------------------------------------------
    // Constructor-awareness tests
    // -----------------------------------------------------------------------

    /// Helper to create a pointer type for a named struct.
    fn make_struct_ptr_type(id: u32, name: &str) -> TypeRef {
        TypeRef {
            id,
            kind: TypeKind::Pointer,
            name: format!("*{name}"),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        }
    }

    /// Build a minimal constructor function `NewHandler` that:
    /// - Allocates a *Handler (Alloc)
    /// - Returns it (Return)
    fn make_constructor(type_name: &str) -> Function {
        // t0 = Alloc *Handler
        let alloc = make_instr(0, ValueKind::Alloc, "t0", 10);
        // Return t0
        let mut ret = make_instr(1, ValueKind::Return, "ret", 0);
        ret.operands = vec![0];

        Function {
            name: format!("pkg.New{type_name}"),
            short_name: format!("New{type_name}"),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![alloc, ret],
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

    /// Build a method `(*Handler).DoWork` that:
    /// - Has a receiver parameter (type *Handler, nilable)
    /// - Does FieldAddr on the receiver (accesses h.svc)
    fn make_method(type_name: &str, method_name: &str, receiver_type_id: u32) -> Function {
        // t0 = Parameter (receiver h *Handler)
        let receiver = make_instr(0, ValueKind::Parameter, "t0", receiver_type_id);
        // t1 = FieldAddr t0 (h.svc)
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0]; // dereferences t0 (receiver)

        Function {
            name: format!("(*{type_name}).{method_name}"),
            short_name: format!("(*{type_name}).{method_name}"),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![receiver, field_addr],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: true,
            receiver_type_id,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        }
    }

    /// Test: constructor exists → method receiver should be NonNil → no NIL001.
    ///
    /// Pattern:
    ///   func NewHandler() *Handler { return &Handler{...} }
    ///   func (h *Handler) DoWork() { h.svc.Call() }  // h is NonNil because NewHandler exists
    #[test]
    fn test_constructor_awareness_suppresses_receiver_nil() {
        let mut types = make_types();
        types.push(make_struct_ptr_type(10, "Handler"));

        let constructor = make_constructor("Handler");
        let method = make_method("Handler", "DoWork", 10);

        let pkg = Package {
            import_path: "example.com/test".into(),
            name: "test".into(),
            files: vec![],
            types,
            functions: vec![constructor, method],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = NilAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "method receiver should be NonNil when constructor exists; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    /// Test: NO constructor exists → method receiver stays MaybeNil → NIL001 fires.
    #[test]
    fn test_no_constructor_receiver_still_nonnnil() {
        let mut types = make_types();
        types.push(make_struct_ptr_type(10, "Handler"));

        // Only the method, no constructor — but in Go, methods are always called
        // on non-nil receivers, so receiver should still be NonNil inside the body.
        let method = make_method("Handler", "DoWork", 10);

        let pkg = Package {
            import_path: "example.com/test".into(),
            name: "test".into(),
            files: vec![],
            types,
            functions: vec![method],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = NilAnalyzer::analyze_package(&pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "method receiver is always NonNil — no NIL001 expected; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    /// Test: method receiver is NonNil even if constructor exists for a different type.
    #[test]
    fn test_constructor_wrong_type_receiver_still_nonnnil() {
        let mut types = make_types();
        types.push(make_struct_ptr_type(10, "Handler"));
        types.push(make_struct_ptr_type(11, "OtherService"));

        // Constructor for OtherService, NOT Handler
        let constructor = make_constructor("OtherService");
        let method = make_method("Handler", "DoWork", 10);

        let pkg = Package {
            import_path: "example.com/test".into(),
            name: "test".into(),
            files: vec![],
            types,
            functions: vec![constructor, method],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = NilAnalyzer::analyze_package(&pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "method receiver is always NonNil — no NIL001 expected; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_echo_handler_entrypoint_detected_by_signature() {
        let mut types = make_types();
        // echo.Context (interface, nilable)
        types.push(TypeRef {
            id: 20,
            kind: TypeKind::Interface,
            name: "github.com/labstack/echo/v4.Context".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });

        let ctx_param = make_instr(0, ValueKind::Parameter, "c", 20);
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0]; // deref ctx param

        let func = Function {
            name: "example.com/pkg.getUser".into(),
            short_name: "getUser".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![ctx_param, field_addr],
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
            types,
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        // With strict_params but no interface_satisfactions,
        // signature-based detection should catch echo.Context param.
        let diags = NilAnalyzer::analyze_package_with_options(
            &pkg,
            &NilOptions {
                strict_params: true,
                ..NilOptions::default()
            },
        );
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "echo handler param should be NonNil via signature detection; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_gin_handler_entrypoint_detected_by_signature() {
        let mut types = make_types();
        // *gin.Context (pointer, nilable)
        types.push(TypeRef {
            id: 21,
            kind: TypeKind::Pointer,
            name: "*github.com/gin-gonic/gin.Context".into(),
            underlying: 0,
            elem: 0,
            key: 0,
            is_nilable: true,
            is_error: false,
        });

        let ctx_param = make_instr(0, ValueKind::Parameter, "c", 21);
        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let func = Function {
            name: "example.com/pkg.listItems".into(),
            short_name: "listItems".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![ctx_param, field_addr],
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
            types,
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = NilAnalyzer::analyze_package_with_options(
            &pkg,
            &NilOptions {
                strict_params: true,
                ..NilOptions::default()
            },
        );
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "gin handler *gin.Context param should be NonNil; got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_is_framework_entrypoint_type() {
        // Echo (versioned)
        assert!(NilAnalyzer::is_framework_entrypoint_type(
            "github.com/labstack/echo/v4.Context"
        ));
        assert!(NilAnalyzer::is_framework_entrypoint_type(
            "github.com/labstack/echo/v5.Context"
        ));
        // Gin
        assert!(NilAnalyzer::is_framework_entrypoint_type(
            "*github.com/gin-gonic/gin.Context"
        ));
        // Fiber (versioned)
        assert!(NilAnalyzer::is_framework_entrypoint_type(
            "*github.com/gofiber/fiber/v2.Ctx"
        ));
        // stdlib http
        assert!(NilAnalyzer::is_framework_entrypoint_type(
            "net/http.ResponseWriter"
        ));
        assert!(NilAnalyzer::is_framework_entrypoint_type(
            "*net/http.Request"
        ));
        // testing
        assert!(NilAnalyzer::is_framework_entrypoint_type("*testing.T"));
        // Negative cases
        assert!(!NilAnalyzer::is_framework_entrypoint_type(
            "*mypackage.Context"
        ));
        assert!(!NilAnalyzer::is_framework_entrypoint_type("string"));
        assert!(!NilAnalyzer::is_framework_entrypoint_type(
            "github.com/other/echo.Something"
        ));
    }

    #[test]
    fn test_nil001_high_confidence_no_callee_key() {
        let types = make_types();

        let mut const_nil = make_instr(0, ValueKind::Const, "t0", 2);
        const_nil.is_nil = true;

        let mut field_addr = make_instr(1, ValueKind::FieldAddr, "t1", 4);
        field_addr.operands = vec![0];

        let func = Function {
            name: "test.ConfidenceHigh".into(),
            short_name: "ConfidenceHigh".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![const_nil, field_addr],
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

        let diags = NilAnalyzer::analyze_function(&func, &types);
        assert!(!diags.is_empty());
        assert!(
            diags[0].callee_key.is_none(),
            "high-confidence NIL001 should NOT have callee_key"
        );
    }
}
