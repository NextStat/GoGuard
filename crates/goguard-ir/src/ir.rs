//! High-level IR wrappers for Go code analysis.
//!
//! These types mirror the JSON schema produced by goguard-go-bridge
//! and provide the intermediate representation for all analysis passes.

use serde::{Deserialize, Serialize};

use crate::generated as fb;
use flatbuffers;

/// Root type — complete analysis input from Go bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisInput {
    pub packages: Vec<Package>,
    pub go_version: String,
    pub bridge_version: String,
    /// Interface table: known interfaces and their implementors.
    #[serde(default)]
    pub interface_table: Vec<InterfaceEntry>,
    /// Enum-like constant groups (iota/const blocks).
    #[serde(default)]
    pub enum_groups: Vec<EnumGroup>,
}

/// A Go package with full SSA IR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub import_path: String,
    pub name: String,
    pub files: Vec<FileInfo>,
    pub types: Vec<TypeRef>,
    pub functions: Vec<Function>,
    pub interface_satisfactions: Vec<InterfaceSatisfaction>,
    pub call_edges: Vec<CallEdge>,
    /// Global variables in the package.
    #[serde(default)]
    pub global_vars: Vec<Variable>,
}

/// File-level metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub package_name: String,
    pub is_generated: bool,
    pub is_test: bool,
    #[serde(default)]
    pub imports: Vec<String>,
}

/// Type reference with unique ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRef {
    pub id: u32,
    pub kind: TypeKind,
    pub name: String,
    #[serde(default)]
    pub underlying: u32,
    #[serde(default)]
    pub elem: u32,
    #[serde(default)]
    pub key: u32,
    pub is_nilable: bool,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TypeKind {
    Basic,
    Named,
    Pointer,
    Slice,
    Array,
    Map,
    Chan,
    Struct,
    Interface,
    Signature,
    Tuple,
    #[serde(other)]
    Unknown,
}

/// A variable reference (used for free_vars and global_vars).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    #[serde(default)]
    pub span: Option<Span>,
}

/// Defer information attached to a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferInfo {
    pub call_target: String,
    #[serde(default)]
    pub span: Option<Span>,
    #[serde(default)]
    pub index: u32,
}

/// An enum-like constant group (iota/const block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumGroup {
    pub type_name: String,
    pub constants: Vec<EnumConstant>,
}

/// A single constant in an enum group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumConstant {
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// An interface with its known implementors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceEntry {
    pub interface_name: String,
    pub implementors: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
}

/// A select case in a Select instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectCase {
    pub dir: String,
    pub channel: String,
    #[serde(default)]
    pub is_default: bool,
}

/// Source location span
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub file: String,
    pub start_line: u32,
    pub start_col: u32,
    #[serde(default)]
    pub end_line: u32,
    #[serde(default)]
    pub end_col: u32,
}

impl Span {
    pub fn new(file: impl Into<String>, line: u32, col: u32) -> Self {
        Self {
            file: file.into(),
            start_line: line,
            start_col: col,
            end_line: line,
            end_col: col,
        }
    }
}

/// SSA Instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub id: u32,
    pub kind: ValueKind,
    pub name: String,
    pub type_id: u32,
    #[serde(default)]
    pub span: Option<Span>,
    #[serde(default)]
    pub operands: Vec<u32>,
    /// For `Extract` instructions: which tuple index is being extracted (0-based).
    #[serde(default)]
    pub extract_index: u32,

    // Call-specific
    #[serde(default)]
    pub callee: Option<String>,
    #[serde(default)]
    pub callee_is_interface: bool,

    // TypeAssert-specific
    #[serde(default)]
    pub assert_type_id: u32,
    #[serde(default)]
    pub comma_ok: bool,

    // Const-specific
    #[serde(default)]
    pub const_value: Option<String>,
    #[serde(default)]
    pub is_nil: bool,

    // BinOp-specific
    #[serde(default)]
    pub bin_op: Option<String>,

    /// Indices of operands that are nil constants (for conditional refinement)
    #[serde(default)]
    pub nil_operand_indices: Vec<usize>,

    // Select-specific
    #[serde(default)]
    pub select_cases: Vec<SelectCase>,

    // Channel-specific
    #[serde(default)]
    pub channel_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValueKind {
    Const,
    Parameter,
    Alloc,
    FieldAddr,
    IndexAddr,
    Call,
    BinOp,
    UnOp,
    Phi,
    Extract,
    TypeAssert,
    MakeChan,
    MakeMap,
    MakeSlice,
    MakeInterface,
    MakeClosure,
    Lookup,
    Range,
    Next,
    Slice,
    Convert,
    ChangeInterface,
    ChangeType,
    FreeVar,
    Global,
    Builtin,
    Return,
    If,
    Jump,
    Panic,
    Go,
    Defer,
    Send,
    Store,
    Load,
    RunDefers,
    Select,
    MapUpdate,
    DebugRef,
    #[serde(other)]
    Unknown,
}

/// CFG edge between basic blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from_block: u32,
    pub to_block: u32,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeKind {
    Unconditional,
    CondTrue,
    CondFalse,
    DefaultCase,
    SwitchCase,
    Panic,
    Deferred,
    #[serde(other)]
    Unknown,
}

/// SSA Basic Block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: u32,
    pub name: String,
    pub instructions: Vec<Instruction>,
    #[serde(default)]
    pub is_return: bool,
    #[serde(default)]
    pub is_panic: bool,
}

/// SSA Function with full CFG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub short_name: String,
    #[serde(default)]
    pub span: Option<Span>,
    pub blocks: Vec<BasicBlock>,
    pub cfg_edges: Vec<CfgEdge>,
    #[serde(default)]
    pub is_method: bool,
    #[serde(default)]
    pub receiver_type_id: u32,
    #[serde(default)]
    pub is_exported: bool,
    /// Free variables captured by this closure (from Go SSA).
    #[serde(default)]
    pub free_vars: Vec<Variable>,
    /// Deferred calls in this function.
    #[serde(default)]
    pub defers: Vec<DeferInfo>,
}

/// Interface satisfaction info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSatisfaction {
    pub concrete_type_id: u32,
    pub interface_type_id: u32,
    pub method_mappings: Vec<MethodMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodMapping {
    pub interface_method: String,
    pub concrete_method: String,
}

/// Static call graph edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    #[serde(default)]
    pub span: Option<Span>,
    #[serde(default)]
    pub is_dynamic: bool,
    /// True if this call is via a `go` statement.
    #[serde(default)]
    pub is_go: bool,
    /// True if this call is via a `defer` statement.
    #[serde(default)]
    pub is_defer: bool,
}

// ---------------------------------------------------------------------------
// FlatBuffers → Owned IR conversion
// ---------------------------------------------------------------------------

impl AnalysisInput {
    /// Deserialize a FlatBuffers binary blob into an owned `AnalysisInput`.
    pub fn from_flatbuffers(data: &[u8]) -> Result<Self, String> {
        // Large Go projects (900+ files) produce millions of FlatBuffers tables.
        // Default VerifierOptions limits to 1M tables — raise to 100M.
        let opts = flatbuffers::VerifierOptions {
            max_tables: 100_000_000,
            ..Default::default()
        };
        let root = fb::root_as_analysis_result_with_opts(&opts, data)
            .map_err(|e| format!("invalid FlatBuffers: {e}"))?;

        let go_version = root.go_version().unwrap_or("").to_owned();
        let bridge_version = String::new(); // FlatBuffers schema does not carry bridge_version

        let mut packages = Vec::new();
        if let Some(fb_pkgs) = root.packages() {
            for i in 0..fb_pkgs.len() {
                let fb_pkg = fb_pkgs.get(i);
                packages.push(convert_package(&fb_pkg, &root));
            }
        }

        Ok(AnalysisInput {
            packages,
            go_version,
            bridge_version,
            interface_table: vec![],
            enum_groups: vec![],
        })
    }
}

/// Convert a FlatBuffers `TypeKind` enum to the owned `TypeKind`.
#[allow(dead_code)]
fn convert_type_kind(k: fb::TypeKind) -> TypeKind {
    match k {
        fb::TypeKind::Basic => TypeKind::Basic,
        fb::TypeKind::Named => TypeKind::Named,
        fb::TypeKind::Pointer => TypeKind::Pointer,
        fb::TypeKind::Slice => TypeKind::Slice,
        fb::TypeKind::Array => TypeKind::Array,
        fb::TypeKind::Map => TypeKind::Map,
        fb::TypeKind::Channel => TypeKind::Chan,
        fb::TypeKind::Struct => TypeKind::Struct,
        fb::TypeKind::Interface => TypeKind::Interface,
        fb::TypeKind::Function => TypeKind::Signature,
        fb::TypeKind::Tuple => TypeKind::Tuple,
        fb::TypeKind::Nil => TypeKind::Unknown, // Nil kind → Unknown
        _ => TypeKind::Unknown,
    }
}

/// Convert a FlatBuffers `InstructionKind` to the owned `ValueKind`.
fn convert_instruction_kind(k: fb::InstructionKind) -> ValueKind {
    match k {
        fb::InstructionKind::Alloc => ValueKind::Alloc,
        fb::InstructionKind::Phi => ValueKind::Phi,
        fb::InstructionKind::Call => ValueKind::Call,
        fb::InstructionKind::BinOp => ValueKind::BinOp,
        fb::InstructionKind::UnOp => ValueKind::UnOp,
        fb::InstructionKind::Convert => ValueKind::Convert,
        fb::InstructionKind::ChangeType => ValueKind::ChangeType,
        fb::InstructionKind::MakeInterface => ValueKind::MakeInterface,
        fb::InstructionKind::MakeSlice => ValueKind::MakeSlice,
        fb::InstructionKind::MakeMap => ValueKind::MakeMap,
        fb::InstructionKind::MakeChan => ValueKind::MakeChan,
        fb::InstructionKind::MakeClosure => ValueKind::MakeClosure,
        fb::InstructionKind::FieldAddr => ValueKind::FieldAddr,
        fb::InstructionKind::IndexAddr => ValueKind::IndexAddr,
        fb::InstructionKind::Lookup => ValueKind::Lookup,
        fb::InstructionKind::MapLookup => ValueKind::Lookup, // MapLookup → Lookup
        fb::InstructionKind::Slice => ValueKind::Slice,
        fb::InstructionKind::If => ValueKind::If,
        fb::InstructionKind::Jump => ValueKind::Jump,
        fb::InstructionKind::Return => ValueKind::Return,
        fb::InstructionKind::Panic => ValueKind::Panic,
        fb::InstructionKind::Go => ValueKind::Go,
        fb::InstructionKind::Defer => ValueKind::Defer,
        fb::InstructionKind::Select => ValueKind::Select,
        fb::InstructionKind::Send => ValueKind::Send,
        fb::InstructionKind::TypeAssert => ValueKind::TypeAssert,
        fb::InstructionKind::ChangeInterface => ValueKind::ChangeInterface,
        fb::InstructionKind::Extract => ValueKind::Extract,
        fb::InstructionKind::Next => ValueKind::Next,
        fb::InstructionKind::Range => ValueKind::Range,
        fb::InstructionKind::Store => ValueKind::Store,
        fb::InstructionKind::Load => ValueKind::Load,
        fb::InstructionKind::MapUpdate => ValueKind::MapUpdate,
        fb::InstructionKind::RunDefers => ValueKind::RunDefers,
        fb::InstructionKind::Unknown => ValueKind::Unknown,
        fb::InstructionKind::FuncParam => ValueKind::Parameter,
        _ => ValueKind::Unknown,
    }
}

/// Returns true for type kinds that are nilable in Go.
#[allow(dead_code)]
fn is_nilable_kind(k: &TypeKind) -> bool {
    matches!(
        k,
        TypeKind::Pointer
            | TypeKind::Slice
            | TypeKind::Map
            | TypeKind::Chan
            | TypeKind::Interface
            | TypeKind::Signature
    )
}

/// Convert a FlatBuffers `TypeInfo` to an owned `TypeRef`.
#[allow(dead_code)]
fn convert_type_info(ti: &fb::TypeInfo<'_>, id: u32) -> TypeRef {
    let kind = convert_type_kind(ti.kind());
    TypeRef {
        id,
        kind: kind.clone(),
        name: ti.name().unwrap_or("").to_owned(),
        underlying: 0,
        elem: 0,
        key: 0,
        is_nilable: is_nilable_kind(&kind),
        is_error: ti.is_error(),
    }
}

/// Convert a FlatBuffers `SourcePos` to an owned `Span`.
fn convert_source_pos(sp: &fb::SourcePos<'_>) -> Span {
    Span {
        file: sp.file().unwrap_or("").to_owned(),
        start_line: sp.line() as u32,
        start_col: sp.column() as u32,
        end_line: sp.end_line() as u32,
        end_col: sp.end_column() as u32,
    }
}

/// Convert a FlatBuffers `Instruction` to an owned `Instruction`.
/// Also pushes any inline `TypeRef` into `types_acc` so that
/// `Package.types` gets populated.
fn convert_instruction(
    fb_instr: &fb::Instruction<'_>,
    fallback_id: u32,
    types_acc: &mut Vec<TypeRef>,
) -> Instruction {
    let kind = convert_instruction_kind(fb_instr.kind());
    let span = fb_instr.source_pos().map(|sp| convert_source_pos(&sp));

    // Parse the instruction's own ID from its result_var name (format "t{id}").
    // This preserves the Go bridge's global counter so operand references match.
    let result_var = fb_instr.result_var().unwrap_or("");
    let instr_id = result_var
        .strip_prefix('t')
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(fallback_id);

    // Parse operand IDs from Operand.name (format "t{id}") and track nil operands.
    let mut operands = Vec::new();
    let mut nil_operand_indices = Vec::new();
    let mut is_nil = false;
    let mut const_value = None;

    if let Some(ops) = fb_instr.operands() {
        for i in 0..ops.len() {
            let op = ops.get(i);
            // Extract actual instruction ID from operand name "t{id}"
            let name = op.name().unwrap_or("");
            let op_id = name
                .strip_prefix('t')
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(i as u32);
            operands.push(op_id);

            // Track nil operand indices for conditional refinement
            if op.is_nil() {
                nil_operand_indices.push(i);
                is_nil = true;
            }
            if op.is_constant() {
                const_value = op.constant_value().map(|s| s.to_owned());
            }
        }
    }

    // Extract type_id from result_type (instead of hardcoding 0).
    // Use the instruction's own ID as the type reference ID,
    // and push a TypeRef into the accumulator.
    let type_id = if let Some(ti) = fb_instr.result_type() {
        let tr = convert_type_info(&ti, instr_id);
        let id = tr.id;
        types_acc.push(tr);
        id
    } else {
        0u32
    };

    // Extract BinOp operator from field_name
    let bin_op = if kind == ValueKind::BinOp {
        fb_instr.field_name().map(|s| s.to_owned())
    } else {
        None
    };

    let extract_index = if kind == ValueKind::Extract {
        fb_instr.extract_index().max(0) as u32
    } else {
        0
    };

    Instruction {
        id: instr_id,
        kind,
        name: fb_instr.result_var().unwrap_or("").to_owned(),
        type_id,
        span,
        operands,
        extract_index,
        callee: fb_instr
            .call_target_qualified()
            .or_else(|| fb_instr.call_target())
            .map(|s| s.to_owned()),
        callee_is_interface: fb_instr.is_interface_call(),
        assert_type_id: 0,
        comma_ok: fb_instr.type_assert_has_ok(),
        const_value,
        is_nil,
        bin_op,
        nil_operand_indices,
        select_cases: Vec::new(),
        channel_dir: None,
    }
}

/// Convert a FlatBuffers `BasicBlock` to an owned `BasicBlock`.
/// Also collects instructions; returns the block and the index of the
/// last instruction (used for CFG edge kind inference).
fn convert_basic_block(
    fb_block: &fb::BasicBlock<'_>,
    instr_counter: &mut u32,
    types_acc: &mut Vec<TypeRef>,
) -> BasicBlock {
    let block_id = fb_block.id() as u32;

    let mut instructions = Vec::new();
    if let Some(fb_instrs) = fb_block.instructions() {
        for i in 0..fb_instrs.len() {
            let fb_instr = fb_instrs.get(i);
            let id = *instr_counter;
            *instr_counter += 1;
            instructions.push(convert_instruction(&fb_instr, id, types_acc));
        }
    }

    // Determine is_return and is_panic from the last instruction's kind.
    let is_return = instructions
        .last()
        .map(|i| i.kind == ValueKind::Return)
        .unwrap_or(false);
    let is_panic = instructions
        .last()
        .map(|i| i.kind == ValueKind::Panic)
        .unwrap_or(false);

    // Use block index as name; FlatBuffers blocks don't carry a name field.
    let name = format!("b{block_id}");

    BasicBlock {
        id: block_id,
        name,
        instructions,
        is_return: is_return || fb_block.is_exit(),
        is_panic,
    }
}

/// Derive CFG edges from a FlatBuffers function's blocks.
///
/// For each block, its `successors` array provides the target block IDs.
/// Edge kinds are inferred:
///   - If the block has exactly 2 successors and ends with `If`:
///     first successor → CondTrue, second → CondFalse.
///   - Otherwise: Unconditional.
fn derive_cfg_edges(
    blocks: &[BasicBlock],
    fb_blocks: &flatbuffers::Vector<'_, flatbuffers::ForwardsUOffset<fb::BasicBlock<'_>>>,
) -> Vec<CfgEdge> {
    let mut edges = Vec::new();

    for i in 0..fb_blocks.len() {
        let fb_block = fb_blocks.get(i);
        let block_id = fb_block.id() as u32;

        if let Some(successors) = fb_block.successors() {
            let last_kind = blocks
                .iter()
                .find(|b| b.id == block_id)
                .and_then(|b| b.instructions.last())
                .map(|instr| &instr.kind);

            let is_if = last_kind == Some(&ValueKind::If);
            let num_succs = successors.len();

            for j in 0..num_succs {
                let succ_id = successors.get(j) as u32;
                let kind = if is_if && num_succs == 2 {
                    if j == 0 {
                        EdgeKind::CondTrue
                    } else {
                        EdgeKind::CondFalse
                    }
                } else {
                    EdgeKind::Unconditional
                };
                edges.push(CfgEdge {
                    from_block: block_id,
                    to_block: succ_id,
                    kind,
                });
            }
        }
    }

    edges
}

/// Convert a FlatBuffers `Function` to an owned `Function`.
fn convert_function(fb_func: &fb::Function<'_>, types_acc: &mut Vec<TypeRef>) -> Function {
    let name = fb_func.qualified_name().unwrap_or("").to_owned();
    let short_name = fb_func.name().unwrap_or("").to_owned();
    let span = fb_func.source_pos().map(|sp| convert_source_pos(&sp));
    let is_exported = !short_name.is_empty() && short_name.as_bytes()[0].is_ascii_uppercase();

    let mut instr_counter = 0u32;
    let mut blocks = Vec::new();

    let cfg_edges = if let Some(fb_blocks) = fb_func.blocks() {
        for i in 0..fb_blocks.len() {
            let fb_block = fb_blocks.get(i);
            blocks.push(convert_basic_block(
                &fb_block,
                &mut instr_counter,
                types_acc,
            ));
        }
        derive_cfg_edges(&blocks, &fb_blocks)
    } else {
        Vec::new()
    };

    Function {
        name,
        short_name,
        span,
        blocks,
        cfg_edges,
        is_method: fb_func.is_method(),
        receiver_type_id: 0,
        is_exported,
        free_vars: {
            let mut vars = Vec::new();
            if let Some(fv_list) = fb_func.free_vars() {
                for i in 0..fv_list.len() {
                    let fv = fv_list.get(i);
                    let name = fv.name().unwrap_or("").to_owned();
                    let type_name = fv
                        .type_info()
                        .and_then(|ti| ti.name())
                        .unwrap_or("")
                        .to_owned();
                    let span = fv.source_pos().map(|sp| convert_source_pos(&sp));
                    vars.push(Variable {
                        name,
                        type_name,
                        span,
                    });
                }
            }
            vars
        },
        defers: {
            let mut defs = Vec::new();
            if let Some(d_list) = fb_func.defers() {
                for i in 0..d_list.len() {
                    let d = d_list.get(i);
                    let call_target = d.call_target().unwrap_or("").to_owned();
                    let span = d.source_pos().map(|sp| convert_source_pos(&sp));
                    let index = d.index() as u32;
                    defs.push(DeferInfo {
                        call_target,
                        span,
                        index,
                    });
                }
            }
            defs
        },
    }
}

/// Convert a FlatBuffers `Package` to an owned `Package`.
fn convert_package(fb_pkg: &fb::Package<'_>, root: &fb::AnalysisResult<'_>) -> Package {
    let import_path = fb_pkg.path().unwrap_or("").to_owned();
    let pkg_name = fb_pkg.name().unwrap_or("").to_owned();

    // Convert functions, collecting inline types from instructions
    let mut types_acc: Vec<TypeRef> = Vec::new();
    let mut functions = Vec::new();
    if let Some(fb_funcs) = fb_pkg.functions() {
        for i in 0..fb_funcs.len() {
            let fb_func = fb_funcs.get(i);
            functions.push(convert_function(&fb_func, &mut types_acc));
        }
    }

    // Deduplicate types by ID (multiple instructions may share the same type)
    types_acc.sort_by_key(|t| t.id);
    types_acc.dedup_by_key(|t| t.id);
    let types = types_acc;

    // Convert call graph edges for this package from the root-level CallGraph.
    let mut call_edges = Vec::new();
    if let Some(cg) = root.call_graph() {
        if let Some(edges) = cg.edges() {
            for i in 0..edges.len() {
                let fb_edge = edges.get(i);
                let caller = fb_edge.caller().unwrap_or("").to_owned();
                let callee = fb_edge.callee().unwrap_or("").to_owned();

                // Only include edges where the caller belongs to this package.
                if caller.starts_with(&import_path)
                    || caller.starts_with(&format!("({import_path}"))
                    || import_path.is_empty()
                {
                    let span = fb_edge.call_site().map(|sp| convert_source_pos(&sp));
                    call_edges.push(CallEdge {
                        caller,
                        callee,
                        span,
                        is_dynamic: !fb_edge.is_static(),
                        is_go: fb_edge.is_go(),
                        is_defer: fb_edge.is_defer(),
                    });
                }
            }
        }
    }

    Package {
        import_path,
        name: pkg_name,
        files: Vec::new(), // FlatBuffers schema does not carry file-level metadata
        types,
        functions,
        interface_satisfactions: Vec::new(), // Not represented in FlatBuffers CallGraph
        call_edges,
        global_vars: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_analysis_input() {
        let json = r#"{
            "packages": [{
                "import_path": "example.com/pkg",
                "name": "pkg",
                "files": [{"path": "main.go", "package_name": "main", "is_generated": false, "is_test": false}],
                "types": [{"id": 1, "kind": "Basic", "name": "int", "is_nilable": false}],
                "functions": [{
                    "name": "pkg.Hello",
                    "short_name": "Hello",
                    "blocks": [{"id": 0, "name": "entry", "instructions": [], "is_return": true}],
                    "cfg_edges": [],
                    "is_exported": true
                }],
                "interface_satisfactions": [],
                "call_edges": []
            }],
            "go_version": "1.26",
            "bridge_version": "0.2.0"
        }"#;

        let input: AnalysisInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.packages.len(), 1);
        assert_eq!(input.packages[0].name, "pkg");
        assert_eq!(input.packages[0].functions[0].short_name, "Hello");
        assert!(input.packages[0].functions[0].is_exported);
    }

    #[test]
    fn test_deserialize_function_with_cfg() {
        let json = r#"{
            "name": "main.GetUser",
            "short_name": "GetUser",
            "span": {"file": "main.go", "start_line": 10, "start_col": 1, "end_line": 20, "end_col": 1},
            "blocks": [
                {"id": 0, "name": "entry", "instructions": [
                    {"id": 1, "kind": "Call", "name": "t1", "type_id": 2, "callee": "db.Find"}
                ]},
                {"id": 1, "name": "if.then", "instructions": [], "is_return": true},
                {"id": 2, "name": "if.else", "instructions": [
                    {"id": 2, "kind": "FieldAddr", "name": "t2", "type_id": 3}
                ], "is_return": true}
            ],
            "cfg_edges": [
                {"from_block": 0, "to_block": 1, "kind": "CondTrue"},
                {"from_block": 0, "to_block": 2, "kind": "CondFalse"}
            ],
            "is_exported": true
        }"#;

        let func: Function = serde_json::from_str(json).unwrap();
        assert_eq!(func.short_name, "GetUser");
        assert_eq!(func.blocks.len(), 3);
        assert_eq!(func.cfg_edges.len(), 2);
        assert_eq!(func.cfg_edges[0].kind, EdgeKind::CondTrue);
        assert_eq!(func.cfg_edges[1].kind, EdgeKind::CondFalse);
    }

    #[test]
    fn test_deserialize_instruction_kinds() {
        let json = r#"{"id": 1, "kind": "TypeAssert", "name": "t1", "type_id": 5, "assert_type_id": 3, "comma_ok": true}"#;
        let instr: Instruction = serde_json::from_str(json).unwrap();
        assert_eq!(instr.kind, ValueKind::TypeAssert);
        assert!(instr.comma_ok);
        assert_eq!(instr.assert_type_id, 3);

        let json2 = r#"{"id": 2, "kind": "Const", "name": "t2", "type_id": 1, "const_value": "nil", "is_nil": true}"#;
        let instr2: Instruction = serde_json::from_str(json2).unwrap();
        assert_eq!(instr2.kind, ValueKind::Const);
        assert!(instr2.is_nil);
    }

    #[test]
    fn test_type_nilability() {
        let nilable_kinds = vec![
            ("Pointer", true),
            ("Slice", true),
            ("Map", true),
            ("Chan", true),
            ("Interface", true),
            ("Signature", true),
            ("Basic", false),
            ("Struct", false),
            ("Array", false),
        ];

        for (kind_str, expected_nilable) in nilable_kinds {
            let json = format!(
                r#"{{"id": 1, "kind": "{}", "name": "test", "is_nilable": {}}}"#,
                kind_str, expected_nilable
            );
            let type_ref: TypeRef = serde_json::from_str(&json).unwrap();
            assert_eq!(
                type_ref.is_nilable, expected_nilable,
                "TypeKind::{} nilability",
                kind_str
            );
        }
    }

    #[test]
    fn test_generated_file_detection() {
        let file = FileInfo {
            path: "types.pb.go".into(),
            package_name: "main".into(),
            is_generated: true,
            is_test: false,
            imports: vec![],
        };
        assert!(file.is_generated);
    }

    #[test]
    fn test_span_creation() {
        let span = Span::new("main.go", 10, 5);
        assert_eq!(span.file, "main.go");
        assert_eq!(span.start_line, 10);
        assert_eq!(span.start_col, 5);
    }

    // -----------------------------------------------------------------------
    // FlatBuffers → owned IR conversion tests
    // -----------------------------------------------------------------------

    /// Build a minimal FlatBuffers AnalysisResult and convert it.
    #[test]
    fn test_from_flatbuffers_minimal() {
        use flatbuffers::FlatBufferBuilder;

        let mut builder = FlatBufferBuilder::new();

        let go_ver = builder.create_string("1.26");
        let mod_path = builder.create_string("example.com/test");
        let pkg_name = builder.create_string("main");
        let pkg_path = builder.create_string("example.com/test/main");

        let pkg = fb::Package::create(
            &mut builder,
            &fb::PackageArgs {
                path: Some(pkg_path),
                name: Some(pkg_name),
                functions: None,
                global_vars: None,
                is_generated: false,
            },
        );

        let pkgs = builder.create_vector(&[pkg]);

        let root = fb::AnalysisResult::create(
            &mut builder,
            &fb::AnalysisResultArgs {
                packages: Some(pkgs),
                call_graph: None,
                interface_table: None,
                enum_groups: None,
                errors: None,
                go_version: Some(go_ver),
                module_path: Some(mod_path),
            },
        );

        builder.finish(root, None);
        let buf = builder.finished_data();

        let input = AnalysisInput::from_flatbuffers(buf).unwrap();
        assert_eq!(input.packages.len(), 1);
        assert_eq!(input.packages[0].name, "main");
        assert_eq!(input.packages[0].import_path, "example.com/test/main");
        assert_eq!(input.go_version, "1.26");
    }

    /// Build a FlatBuffers AnalysisResult with a function containing blocks
    /// and instructions, then convert and verify CFG edges are derived.
    #[test]
    fn test_from_flatbuffers_with_function() {
        use flatbuffers::FlatBufferBuilder;

        let mut builder = FlatBufferBuilder::new();

        // Build an If instruction for block 0
        let result_var = builder.create_string("t0");
        let if_instr = fb::Instruction::create(
            &mut builder,
            &fb::InstructionArgs {
                kind: fb::InstructionKind::If,
                result_var: Some(result_var),
                ..Default::default()
            },
        );
        let instrs0 = builder.create_vector(&[if_instr]);

        // Build a Return instruction for block 1
        let result_var1 = builder.create_string("t1");
        let ret_instr = fb::Instruction::create(
            &mut builder,
            &fb::InstructionArgs {
                kind: fb::InstructionKind::Return,
                result_var: Some(result_var1),
                ..Default::default()
            },
        );
        let instrs1 = builder.create_vector(&[ret_instr]);

        // Block 2 is empty (also an exit)

        // Build successors for block 0: [1, 2]
        let succs0 = builder.create_vector(&[1i32, 2i32]);

        // Build predecessors for block 1 and 2: [0]
        let preds1 = builder.create_vector(&[0i32]);
        let preds2 = builder.create_vector(&[0i32]);

        // Create blocks
        let block0 = fb::BasicBlock::create(
            &mut builder,
            &fb::BasicBlockArgs {
                id: 0,
                instructions: Some(instrs0),
                successors: Some(succs0),
                predecessors: None,
                is_entry: true,
                is_exit: false,
                is_defer_block: false,
                source_pos: None,
            },
        );
        let block1 = fb::BasicBlock::create(
            &mut builder,
            &fb::BasicBlockArgs {
                id: 1,
                instructions: Some(instrs1),
                successors: None,
                predecessors: Some(preds1),
                is_entry: false,
                is_exit: true,
                is_defer_block: false,
                source_pos: None,
            },
        );
        let block2 = fb::BasicBlock::create(
            &mut builder,
            &fb::BasicBlockArgs {
                id: 2,
                instructions: None,
                successors: None,
                predecessors: Some(preds2),
                is_entry: false,
                is_exit: true,
                is_defer_block: false,
                source_pos: None,
            },
        );

        let blocks = builder.create_vector(&[block0, block1, block2]);

        // Create function
        let func_name = builder.create_string("GetUser");
        let qual_name = builder.create_string("main.GetUser");

        // Add source position
        let file_str = builder.create_string("main.go");
        let src_pos = fb::SourcePos::create(
            &mut builder,
            &fb::SourcePosArgs {
                file: Some(file_str),
                line: 10,
                column: 1,
                end_line: 20,
                end_column: 1,
                offset: 0,
            },
        );

        let func = fb::Function::create(
            &mut builder,
            &fb::FunctionArgs {
                name: Some(func_name),
                qualified_name: Some(qual_name),
                blocks: Some(blocks),
                source_pos: Some(src_pos),
                is_method: false,
                ..Default::default()
            },
        );

        let funcs = builder.create_vector(&[func]);

        let pkg_name = builder.create_string("main");
        let pkg_path = builder.create_string("example.com/test");
        let pkg = fb::Package::create(
            &mut builder,
            &fb::PackageArgs {
                path: Some(pkg_path),
                name: Some(pkg_name),
                functions: Some(funcs),
                global_vars: None,
                is_generated: false,
            },
        );

        let pkgs = builder.create_vector(&[pkg]);
        let go_ver = builder.create_string("1.26");
        let mod_path = builder.create_string("example.com/test");

        let root = fb::AnalysisResult::create(
            &mut builder,
            &fb::AnalysisResultArgs {
                packages: Some(pkgs),
                call_graph: None,
                interface_table: None,
                enum_groups: None,
                errors: None,
                go_version: Some(go_ver),
                module_path: Some(mod_path),
            },
        );

        builder.finish(root, None);
        let buf = builder.finished_data();

        let input = AnalysisInput::from_flatbuffers(buf).unwrap();
        assert_eq!(input.packages.len(), 1);

        let func = &input.packages[0].functions[0];
        assert_eq!(func.name, "main.GetUser");
        assert_eq!(func.short_name, "GetUser");
        assert!(func.is_exported);
        assert_eq!(func.blocks.len(), 3);

        // Verify span was converted
        let span = func.span.as_ref().unwrap();
        assert_eq!(span.file, "main.go");
        assert_eq!(span.start_line, 10);
        assert_eq!(span.start_col, 1);

        // Block 0 ends with If and has 2 successors → should produce CondTrue + CondFalse edges
        assert_eq!(func.cfg_edges.len(), 2);
        assert_eq!(func.cfg_edges[0].from_block, 0);
        assert_eq!(func.cfg_edges[0].to_block, 1);
        assert_eq!(func.cfg_edges[0].kind, EdgeKind::CondTrue);
        assert_eq!(func.cfg_edges[1].from_block, 0);
        assert_eq!(func.cfg_edges[1].to_block, 2);
        assert_eq!(func.cfg_edges[1].kind, EdgeKind::CondFalse);

        // Block 0 instruction should be If
        assert_eq!(func.blocks[0].instructions[0].kind, ValueKind::If);

        // Block 1 instruction should be Return
        assert_eq!(func.blocks[1].instructions[0].kind, ValueKind::Return);
        assert!(func.blocks[1].is_return);

        // Block 2 has no instructions but is an exit block
        assert!(func.blocks[2].is_return);
    }

    /// Test that all InstructionKind values are properly mapped.
    #[test]
    fn test_instruction_kind_mapping() {
        let mappings = vec![
            (fb::InstructionKind::Alloc, ValueKind::Alloc),
            (fb::InstructionKind::Phi, ValueKind::Phi),
            (fb::InstructionKind::Call, ValueKind::Call),
            (fb::InstructionKind::BinOp, ValueKind::BinOp),
            (fb::InstructionKind::UnOp, ValueKind::UnOp),
            (fb::InstructionKind::Convert, ValueKind::Convert),
            (fb::InstructionKind::ChangeType, ValueKind::ChangeType),
            (fb::InstructionKind::MakeInterface, ValueKind::MakeInterface),
            (fb::InstructionKind::MakeSlice, ValueKind::MakeSlice),
            (fb::InstructionKind::MakeMap, ValueKind::MakeMap),
            (fb::InstructionKind::MakeChan, ValueKind::MakeChan),
            (fb::InstructionKind::MakeClosure, ValueKind::MakeClosure),
            (fb::InstructionKind::FieldAddr, ValueKind::FieldAddr),
            (fb::InstructionKind::IndexAddr, ValueKind::IndexAddr),
            (fb::InstructionKind::Lookup, ValueKind::Lookup),
            (fb::InstructionKind::MapLookup, ValueKind::Lookup),
            (fb::InstructionKind::Slice, ValueKind::Slice),
            (fb::InstructionKind::If, ValueKind::If),
            (fb::InstructionKind::Jump, ValueKind::Jump),
            (fb::InstructionKind::Return, ValueKind::Return),
            (fb::InstructionKind::Panic, ValueKind::Panic),
            (fb::InstructionKind::Go, ValueKind::Go),
            (fb::InstructionKind::Defer, ValueKind::Defer),
            (fb::InstructionKind::Select, ValueKind::Select),
            (fb::InstructionKind::Send, ValueKind::Send),
            (fb::InstructionKind::TypeAssert, ValueKind::TypeAssert),
            (
                fb::InstructionKind::ChangeInterface,
                ValueKind::ChangeInterface,
            ),
            (fb::InstructionKind::Extract, ValueKind::Extract),
            (fb::InstructionKind::Next, ValueKind::Next),
            (fb::InstructionKind::Range, ValueKind::Range),
            (fb::InstructionKind::Store, ValueKind::Store),
            (fb::InstructionKind::Load, ValueKind::Load),
            (fb::InstructionKind::RunDefers, ValueKind::RunDefers),
            (fb::InstructionKind::Unknown, ValueKind::Unknown),
        ];

        for (fb_kind, expected) in mappings {
            let result = convert_instruction_kind(fb_kind);
            assert_eq!(
                result, expected,
                "InstructionKind {:?} should map to {:?}",
                fb_kind, expected
            );
        }
    }

    /// Test that TypeKind mapping is correct.
    #[test]
    fn test_type_kind_mapping() {
        let mappings = vec![
            (fb::TypeKind::Basic, TypeKind::Basic),
            (fb::TypeKind::Named, TypeKind::Named),
            (fb::TypeKind::Pointer, TypeKind::Pointer),
            (fb::TypeKind::Slice, TypeKind::Slice),
            (fb::TypeKind::Array, TypeKind::Array),
            (fb::TypeKind::Map, TypeKind::Map),
            (fb::TypeKind::Channel, TypeKind::Chan),
            (fb::TypeKind::Struct, TypeKind::Struct),
            (fb::TypeKind::Interface, TypeKind::Interface),
            (fb::TypeKind::Function, TypeKind::Signature),
            (fb::TypeKind::Tuple, TypeKind::Tuple),
            (fb::TypeKind::Nil, TypeKind::Unknown),
        ];

        for (fb_kind, expected) in mappings {
            let result = convert_type_kind(fb_kind);
            assert_eq!(
                result, expected,
                "TypeKind {:?} should map to {:?}",
                fb_kind, expected
            );
        }
    }

    /// Test nilability inference from TypeKind.
    #[test]
    fn test_nilability_from_type_kind() {
        assert!(is_nilable_kind(&TypeKind::Pointer));
        assert!(is_nilable_kind(&TypeKind::Slice));
        assert!(is_nilable_kind(&TypeKind::Map));
        assert!(is_nilable_kind(&TypeKind::Chan));
        assert!(is_nilable_kind(&TypeKind::Interface));
        assert!(is_nilable_kind(&TypeKind::Signature));

        assert!(!is_nilable_kind(&TypeKind::Basic));
        assert!(!is_nilable_kind(&TypeKind::Named));
        assert!(!is_nilable_kind(&TypeKind::Struct));
        assert!(!is_nilable_kind(&TypeKind::Array));
        assert!(!is_nilable_kind(&TypeKind::Tuple));
        assert!(!is_nilable_kind(&TypeKind::Unknown));
    }

    /// Test invalid FlatBuffers data produces a proper error.
    #[test]
    fn test_from_flatbuffers_invalid_data() {
        let result = AnalysisInput::from_flatbuffers(&[0, 1, 2, 3]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid FlatBuffers"));
    }

    /// Test with a function that has a Call instruction with callee info.
    #[test]
    fn test_from_flatbuffers_call_instruction() {
        use flatbuffers::FlatBufferBuilder;

        let mut builder = FlatBufferBuilder::new();

        // Build a Call instruction with a callee
        let result_var = builder.create_string("t0");
        let call_target = builder.create_string("db.Find");
        let call_instr = fb::Instruction::create(
            &mut builder,
            &fb::InstructionArgs {
                kind: fb::InstructionKind::Call,
                result_var: Some(result_var),
                call_target: Some(call_target),
                is_interface_call: true,
                ..Default::default()
            },
        );
        let instrs = builder.create_vector(&[call_instr]);

        let block = fb::BasicBlock::create(
            &mut builder,
            &fb::BasicBlockArgs {
                id: 0,
                instructions: Some(instrs),
                is_entry: true,
                is_exit: true,
                ..Default::default()
            },
        );

        let blocks = builder.create_vector(&[block]);
        let func_name = builder.create_string("DoStuff");
        let qual_name = builder.create_string("main.DoStuff");

        let func = fb::Function::create(
            &mut builder,
            &fb::FunctionArgs {
                name: Some(func_name),
                qualified_name: Some(qual_name),
                blocks: Some(blocks),
                ..Default::default()
            },
        );

        let funcs = builder.create_vector(&[func]);
        let pkg_name = builder.create_string("main");
        let pkg_path = builder.create_string("example.com/test");

        let pkg = fb::Package::create(
            &mut builder,
            &fb::PackageArgs {
                path: Some(pkg_path),
                name: Some(pkg_name),
                functions: Some(funcs),
                ..Default::default()
            },
        );

        let pkgs = builder.create_vector(&[pkg]);
        let go_ver = builder.create_string("1.26");
        let mod_path = builder.create_string("test");

        let root = fb::AnalysisResult::create(
            &mut builder,
            &fb::AnalysisResultArgs {
                packages: Some(pkgs),
                go_version: Some(go_ver),
                module_path: Some(mod_path),
                ..Default::default()
            },
        );

        builder.finish(root, None);
        let buf = builder.finished_data();

        let input = AnalysisInput::from_flatbuffers(buf).unwrap();
        let instr = &input.packages[0].functions[0].blocks[0].instructions[0];
        assert_eq!(instr.kind, ValueKind::Call);
        assert_eq!(instr.callee.as_deref(), Some("db.Find"));
        assert!(instr.callee_is_interface);
        assert_eq!(instr.name, "t0");
    }
}
