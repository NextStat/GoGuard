//! Error checking analysis engine for unchecked error returns.

use std::collections::{HashMap, HashSet};

use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::ir::{AnalysisInput, Function, Package, TypeRef, ValueKind};

use crate::rules;

const DEFAULT_IGNORE: &[&str] = &[
    "fmt.Print",
    "fmt.Println",
    "fmt.Printf",
    "fmt.Fprint",
    "fmt.Fprintln",
    "fmt.Fprintf",
    "fmt.Sprint",
    "fmt.Sprintln",
    "fmt.Sprintf",
];

pub struct ErrcheckAnalyzer;

impl ErrcheckAnalyzer {
    pub fn analyze(ir: &AnalysisInput) -> Vec<Diagnostic> {
        Self::analyze_with_ignore(ir, DEFAULT_IGNORE)
    }

    pub fn analyze_with_ignore(ir: &AnalysisInput, ignore: &[&str]) -> Vec<Diagnostic> {
        ir.packages
            .iter()
            .flat_map(|pkg| Self::check_package(pkg, ignore))
            .collect()
    }

    /// Check a single package for unchecked errors. Used by Salsa incremental path.
    pub fn check_package(pkg: &Package, ignore: &[&str]) -> Vec<Diagnostic> {
        let mut diags = Vec::new();
        let type_map: HashMap<u32, &TypeRef> = pkg.types.iter().map(|t| (t.id, t)).collect();
        for func in &pkg.functions {
            Self::check_function(func, &type_map, ignore, &mut diags);
        }
        diags
    }

    fn check_function(
        func: &Function,
        type_map: &HashMap<u32, &TypeRef>,
        ignore: &[&str],
        diags: &mut Vec<Diagnostic>,
    ) {
        // Collect which instruction IDs are used as operands by other instructions
        let mut used_values: HashSet<u32> = HashSet::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                for &op_id in &instr.operands {
                    used_values.insert(op_id);
                }
            }
        }

        // Find all Extract instructions that reference Call instructions,
        // so we can check if error Extracts are used.
        // Map: call_id -> Vec<(extract_id, extract_type_is_error)>
        let mut call_extracts: HashMap<u32, Vec<(u32, bool)>> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind == ValueKind::Extract {
                    if let Some(&call_id) = instr.operands.first() {
                        let is_err = type_map.get(&instr.type_id).is_some_and(|t| t.is_error);
                        call_extracts
                            .entry(call_id)
                            .or_default()
                            .push((instr.id, is_err));
                    }
                }
            }
        }

        // Check each Call instruction
        for block in &func.blocks {
            for instr in &block.instructions {
                if instr.kind != ValueKind::Call {
                    continue;
                }

                let callee_name = match &instr.callee {
                    Some(c) => c.as_str(),
                    None => continue,
                };

                // Check ignore list
                if should_ignore(callee_name, ignore) {
                    continue;
                }

                let type_is_error = type_map.get(&instr.type_id).is_some_and(|t| t.is_error);

                if type_is_error {
                    // Direct error return (e.g., os.Remove returns error)
                    if !used_values.contains(&instr.id) {
                        diags.push(rules::build_err001(instr, &func.short_name, callee_name));
                    }
                } else if let Some(extracts) = call_extracts.get(&instr.id) {
                    // Tuple return containing error (e.g., os.Open returns (*File, error))
                    // Check if any error Extract has unused result
                    for &(extract_id, is_err) in extracts {
                        if is_err && !used_values.contains(&extract_id) {
                            diags.push(rules::build_err002(instr, &func.short_name, callee_name));
                            break; // one diagnostic per call site
                        }
                    }
                }
            }
        }
    }
}

fn should_ignore(callee: &str, ignore: &[&str]) -> bool {
    ignore.iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix('*') {
            callee.starts_with(prefix)
        } else {
            callee == *pat
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::{
        AnalysisInput, BasicBlock, Function, Instruction, Package, Span, TypeKind, TypeRef,
        ValueKind,
    };

    fn make_span() -> Option<Span> {
        Some(Span {
            file: "test.go".into(),
            start_line: 10,
            start_col: 2,
            end_line: 10,
            end_col: 20,
        })
    }

    fn make_instr(id: u32, kind: ValueKind, type_id: u32) -> Instruction {
        Instruction {
            id,
            kind,
            name: format!("t{id}"),
            type_id,
            span: make_span(),
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

    fn make_call(id: u32, callee: &str, type_id: u32) -> Instruction {
        let mut instr = make_instr(id, ValueKind::Call, type_id);
        instr.callee = Some(callee.to_string());
        instr
    }

    fn make_extract(id: u32, call_id: u32, type_id: u32) -> Instruction {
        let mut instr = make_instr(id, ValueKind::Extract, type_id);
        instr.operands = vec![call_id];
        instr
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
            // error type (direct return)
            TypeRef {
                id: 1,
                kind: TypeKind::Interface,
                name: "error".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: true,
            },
            // tuple type (*File, error)
            TypeRef {
                id: 2,
                kind: TypeKind::Tuple,
                name: "(*os.File, error)".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: false,
                is_error: false,
            },
            // *os.File type
            TypeRef {
                id: 3,
                kind: TypeKind::Pointer,
                name: "*os.File".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
        ]
    }

    fn make_analysis_input(functions: Vec<Function>, types: Vec<TypeRef>) -> AnalysisInput {
        AnalysisInput {
            packages: vec![Package {
                import_path: "test".into(),
                name: "test".into(),
                files: vec![],
                types,
                functions,
                interface_satisfactions: vec![],
                call_edges: vec![],
                global_vars: vec![],
            }],
            go_version: "1.26".into(),
            bridge_version: "0.1.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        }
    }

    #[test]
    fn test_err001_direct_error_ignored() {
        // os.Remove returns error directly; not used -> ERR001
        let call = make_call(10, "os.Remove", 1);
        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "ERR001");
        assert!(diags[0].explanation.contains("os.Remove"));
    }

    #[test]
    fn test_err001_direct_error_used() {
        // os.Remove returns error, result is used by another instruction -> no diagnostic
        let call = make_call(10, "os.Remove", 1);
        let mut user = make_instr(11, ValueKind::If, 0);
        user.operands = vec![10]; // uses the call result

        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, user],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert!(diags.is_empty(), "used error should not produce diagnostic");
    }

    #[test]
    fn test_err002_error_extract_unused() {
        // os.Open returns (*File, error) as tuple (type_id=2)
        // Extract for *File (type_id=3) is used
        // Extract for error (type_id=1) is NOT used -> ERR002
        let call = make_call(10, "os.Open", 2);
        let file_extract = make_extract(11, 10, 3); // *File extract
        let err_extract = make_extract(12, 10, 1); // error extract (unused)
        let mut user = make_instr(13, ValueKind::Store, 0);
        user.operands = vec![11]; // uses the file extract only

        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, file_extract, err_extract, user],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "ERR002");
        assert!(diags[0].explanation.contains("os.Open"));
    }

    #[test]
    fn test_err002_error_extract_used() {
        // os.Open returns (*File, error) as tuple
        // Both extracts used -> no diagnostic
        let call = make_call(10, "os.Open", 2);
        let file_extract = make_extract(11, 10, 3);
        let err_extract = make_extract(12, 10, 1);
        let mut user1 = make_instr(13, ValueKind::Store, 0);
        user1.operands = vec![11]; // uses file
        let mut user2 = make_instr(14, ValueKind::If, 0);
        user2.operands = vec![12]; // uses error

        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, file_extract, err_extract, user1, user2],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert!(diags.is_empty(), "all results used, no diagnostic expected");
    }

    #[test]
    fn test_ignore_list_exact() {
        // fmt.Println returns error but is in ignore list
        let call = make_call(10, "fmt.Println", 1);
        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert!(diags.is_empty(), "fmt.Println should be ignored");
    }

    #[test]
    fn test_ignore_list_glob() {
        // Custom ignore with glob pattern
        let call = make_call(10, "mylib.LogError", 1);
        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze_with_ignore(&ir, &["mylib.Log*"]);
        assert!(diags.is_empty(), "mylib.Log* should be ignored");
    }

    #[test]
    fn test_empty_input() {
        let ir = AnalysisInput {
            packages: vec![],
            go_version: "1.26".into(),
            bridge_version: "0.1.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        };
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_no_callee_skipped() {
        // Call instruction with no callee -> skip
        let call = make_instr(10, ValueKind::Call, 1);
        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let diags = ErrcheckAnalyzer::analyze(&ir);
        assert!(diags.is_empty(), "call with no callee should be skipped");
    }

    #[test]
    fn test_should_ignore() {
        assert!(should_ignore("fmt.Println", DEFAULT_IGNORE));
        assert!(should_ignore("fmt.Printf", DEFAULT_IGNORE));
        assert!(should_ignore("fmt.Sprintf", DEFAULT_IGNORE));
        assert!(should_ignore("fmt.Fprintln", DEFAULT_IGNORE));
        assert!(!should_ignore("os.Remove", DEFAULT_IGNORE));
        assert!(!should_ignore("io.ReadAll", DEFAULT_IGNORE));
    }

    #[test]
    fn test_should_ignore_glob() {
        let patterns = &["mylib.Log*", "exact.Match"];
        assert!(should_ignore("mylib.LogInfo", patterns));
        assert!(should_ignore("mylib.LogError", patterns));
        assert!(should_ignore("exact.Match", patterns));
        assert!(!should_ignore("exact.MatchNot", patterns));
        assert!(!should_ignore("other.Func", patterns));
    }

    #[test]
    fn test_errcheck_package_matches_analyze() {
        // os.Remove returns error directly; not used -> ERR001
        let call = make_call(10, "os.Remove", 1);
        let func = Function {
            name: "test.DoStuff".into(),
            short_name: "DoStuff".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());

        let from_analyze = ErrcheckAnalyzer::analyze(&ir);
        let from_package = ErrcheckAnalyzer::check_package(&ir.packages[0], DEFAULT_IGNORE);

        assert_eq!(
            from_analyze.len(),
            from_package.len(),
            "analyze and check_package should produce same number of diagnostics"
        );
        for (a, b) in from_analyze.iter().zip(from_package.iter()) {
            assert_eq!(a.rule, b.rule);
            assert_eq!(a.title, b.title);
        }
    }

    #[test]
    fn test_errcheck_package_with_ignore() {
        // Create a function with two calls:
        // - fmt.Println (in DEFAULT_IGNORE) returning error
        // - os.Remove (not ignored) returning error
        let call_println = make_call(10, "fmt.Println", 1);
        let call_remove = make_call(11, "os.Remove", 1);
        let func = Function {
            name: "test.Mixed".into(),
            short_name: "Mixed".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call_println, call_remove],
                is_return: false,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        };

        let ir = make_analysis_input(vec![func], make_types());
        let pkg = &ir.packages[0];

        // With DEFAULT_IGNORE: fmt.Println ignored, os.Remove flagged
        let diags_default = ErrcheckAnalyzer::check_package(pkg, DEFAULT_IGNORE);
        assert_eq!(diags_default.len(), 1, "only os.Remove should be flagged");
        assert!(diags_default[0].explanation.contains("os.Remove"));

        // With custom ignore that also ignores os.Remove
        let diags_all_ignored = ErrcheckAnalyzer::check_package(pkg, &["fmt.*", "os.*"]);
        assert!(
            diags_all_ignored.is_empty(),
            "all calls ignored, no diagnostics"
        );

        // With empty ignore list: both should be flagged
        let diags_none_ignored = ErrcheckAnalyzer::check_package(pkg, &[]);
        assert_eq!(
            diags_none_ignored.len(),
            2,
            "both calls should be flagged with empty ignore"
        );
    }
}
