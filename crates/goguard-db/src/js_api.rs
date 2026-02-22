//! GoGuard JavaScript API bindings for Code Mode.
//!
//! Registers a `goguard` global object in a boa [`Context`] with methods that
//! expose analysis data (diagnostics, packages, call graph, functions, rules,
//! taint flows, and config) to user-authored JavaScript queries.
//!
//! All data is pre-serialized to [`serde_json::Value`] at construction time so
//! that native function callbacks are cheap (just JSON → JsValue conversion).

use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsResult, JsValue, NativeFunction};

use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_diagnostics::rules::get_all_rules;
use goguard_ir::ir::Package;

/// Pre-serialized GoGuard analysis data for injection into a JS context.
///
/// All fields are [`serde_json::Value`] so they can be cheaply cloned into
/// boa native function closures (which require `'static` captures).
#[derive(Debug, Clone)]
#[must_use]
pub struct GoGuardJsApi {
    diagnostics_json: serde_json::Value,
    packages_json: serde_json::Value,
    functions_json: serde_json::Value,
    rules_json: serde_json::Value,
    call_edges_json: serde_json::Value,
    config_json: serde_json::Value,
}

impl GoGuardJsApi {
    /// Build a new JS API data bundle from analysis results.
    ///
    /// The constructor pre-serializes all data so that repeated calls to
    /// [`register_api`] are fast.
    pub fn new(
        diagnostics: &[Diagnostic],
        packages: &[Package],
        config: serde_json::Value,
    ) -> Self {
        // Pre-serialize diagnostics.
        let diagnostics_json = serde_json::to_value(diagnostics).unwrap_or_default();

        // Pre-serialize packages (summary view: import_path, name, files, type summaries, function names).
        let packages_json = serde_json::Value::Array(
            packages
                .iter()
                .map(|pkg| {
                    serde_json::json!({
                        "import_path": pkg.import_path,
                        "name": pkg.name,
                        "files": pkg.files.iter().map(|f| &f.path).collect::<Vec<_>>(),
                        "types": pkg.types.iter().map(|t| serde_json::json!({
                            "id": t.id,
                            "name": t.name,
                            "kind": format!("{:?}", t.kind),
                            "is_nilable": t.is_nilable,
                            "is_error": t.is_error,
                        })).collect::<Vec<_>>(),
                        "functions": pkg.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        );

        // Pre-serialize all functions across all packages (including full blocks + instructions).
        let functions_json = serde_json::Value::Array(
            packages
                .iter()
                .flat_map(|pkg| {
                    pkg.functions.iter().map(move |f| {
                        serde_json::json!({
                            "name": f.name,
                            "short_name": f.short_name,
                            "package": pkg.import_path,
                            "span": f.span.as_ref().map(|s| serde_json::json!({
                                "file": s.file,
                                "start_line": s.start_line,
                                "start_col": s.start_col,
                                "end_line": s.end_line,
                                "end_col": s.end_col,
                            })),
                            "is_method": f.is_method,
                            "is_exported": f.is_exported,
                            "blocks": f.blocks.iter().map(|b| serde_json::json!({
                                "id": b.id,
                                "name": b.name,
                                "is_return": b.is_return,
                                "is_panic": b.is_panic,
                                "instructions": b.instructions.iter().map(|i| serde_json::json!({
                                    "id": i.id,
                                    "kind": format!("{:?}", i.kind),
                                    "name": i.name,
                                    "type_id": i.type_id,
                                    "operands": i.operands,
                                    "callee": i.callee,
                                    "callee_is_interface": i.callee_is_interface,
                                    "const_value": i.const_value,
                                    "is_nil": i.is_nil,
                                    "bin_op": i.bin_op,
                                    "span": i.span.as_ref().map(|s| serde_json::json!({
                                        "file": s.file,
                                        "start_line": s.start_line,
                                        "start_col": s.start_col,
                                    })),
                                })).collect::<Vec<_>>(),
                            })).collect::<Vec<_>>(),
                        })
                    })
                })
                .collect(),
        );

        // Pre-serialize rules.
        let all_rules = get_all_rules();
        let rules_json = serde_json::to_value(&all_rules).unwrap_or_default();

        // Pre-serialize call edges from all packages.
        let call_edges_json = serde_json::Value::Array(
            packages
                .iter()
                .flat_map(|pkg| {
                    pkg.call_edges.iter().map(|e| {
                        serde_json::json!({
                            "caller": e.caller,
                            "callee": e.callee,
                            "is_dynamic": e.is_dynamic,
                            "is_go": e.is_go,
                            "is_defer": e.is_defer,
                            "span": e.span.as_ref().map(|s| serde_json::json!({
                                "file": s.file,
                                "start_line": s.start_line,
                                "start_col": s.start_col,
                                "end_line": s.end_line,
                                "end_col": s.end_col,
                            })),
                        })
                    })
                })
                .collect(),
        );

        Self {
            diagnostics_json,
            packages_json,
            functions_json,
            rules_json,
            call_edges_json,
            config_json: config,
        }
    }
}

/// Register the `goguard` global object on a boa [`Context`].
///
/// After calling this, JavaScript code executed in the context can use:
/// - `goguard.diagnostics(filter?)` — array of diagnostics, optionally filtered by rule
/// - `goguard.packages()` — array of package summaries
/// - `goguard.callGraph()` — object with `callersOf(name)`, `calleesOf(name)`, `edges()` methods
/// - `goguard.functions(filter?)` — array of function objects, optionally filtered by name substring
/// - `goguard.rules(category?)` — array of rule definitions, optionally filtered by category
/// - `goguard.taintFlows(from?, to?)` — taint-related diagnostics, filtered by source/sink pattern
/// - `goguard.config` — read-only config object
pub fn register_api(api: &GoGuardJsApi, context: &mut Context) -> JsResult<()> {
    // SAFETY for all `NativeFunction::from_closure` calls below:
    // The safety invariant requires captured variables to not contain boa GC-traced
    // types (`Gc<T>`). All closures capture only `serde_json::Value` (standard Rust
    // types: String, Vec, f64, bool) which do not implement boa's `Trace` trait.
    // Inner closures (e.g. inside callGraph) are also safe for the same reason.

    // --- goguard.diagnostics(filter?) ---
    let diag_data = api.diagnostics_json.clone();
    let diagnostics_fn = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let filter = args
                .first()
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped());

            let result = if let Some(rule_filter) = filter {
                if let serde_json::Value::Array(arr) = &diag_data {
                    let filtered: Vec<_> = arr
                        .iter()
                        .filter(|d| {
                            d.get("rule")
                                .and_then(|r| r.as_str())
                                .is_some_and(|r| r == rule_filter)
                        })
                        .cloned()
                        .collect();
                    serde_json::Value::Array(filtered)
                } else {
                    diag_data.clone()
                }
            } else {
                diag_data.clone()
            };

            JsValue::from_json(&result, ctx)
        })
    };

    // --- goguard.packages() ---
    let pkg_data = api.packages_json.clone();
    let packages_fn = unsafe {
        NativeFunction::from_closure(move |_this, _args, ctx| JsValue::from_json(&pkg_data, ctx))
    };

    // --- goguard.functions(filter?) ---
    let func_data = api.functions_json.clone();
    let functions_fn = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let filter = args
                .first()
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped());

            let result = if let Some(name_filter) = filter {
                if let serde_json::Value::Array(arr) = &func_data {
                    let filtered: Vec<_> = arr
                        .iter()
                        .filter(|f| {
                            f.get("name")
                                .and_then(|n| n.as_str())
                                .is_some_and(|n| n.contains(&name_filter))
                                || f.get("short_name")
                                    .and_then(|n| n.as_str())
                                    .is_some_and(|n| n.contains(&name_filter))
                        })
                        .cloned()
                        .collect();
                    serde_json::Value::Array(filtered)
                } else {
                    func_data.clone()
                }
            } else {
                func_data.clone()
            };

            JsValue::from_json(&result, ctx)
        })
    };

    // --- goguard.rules(category?) ---
    let rules_data = api.rules_json.clone();
    let rules_fn = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let filter = args
                .first()
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped());

            let result = if let Some(cat_filter) = filter {
                if let serde_json::Value::Array(arr) = &rules_data {
                    let filtered: Vec<_> = arr
                        .iter()
                        .filter(|r| {
                            r.get("category")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c == cat_filter)
                        })
                        .cloned()
                        .collect();
                    serde_json::Value::Array(filtered)
                } else {
                    rules_data.clone()
                }
            } else {
                rules_data.clone()
            };

            JsValue::from_json(&result, ctx)
        })
    };

    // --- goguard.taintFlows(from?, to?) ---
    let taint_diag_data = api.diagnostics_json.clone();
    let taint_flows_fn = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let from_filter = args
                .first()
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped());
            let to_filter = args
                .get(1)
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped());

            let result = if let serde_json::Value::Array(arr) = &taint_diag_data {
                let filtered: Vec<_> = arr
                    .iter()
                    .filter(|d| {
                        // Must be a taint diagnostic (rule starts with "TAINT").
                        let is_taint = d
                            .get("rule")
                            .and_then(|r| r.as_str())
                            .is_some_and(|r| r.starts_with("TAINT"));
                        if !is_taint {
                            return false;
                        }

                        // Optional "from" filter: match against title or explanation.
                        if let Some(ref from) = from_filter {
                            let title_match = d
                                .get("title")
                                .and_then(|t| t.as_str())
                                .is_some_and(|t| t.contains(from.as_str()));
                            let explanation_match = d
                                .get("explanation")
                                .and_then(|e| e.as_str())
                                .is_some_and(|e| e.contains(from.as_str()));
                            if !title_match && !explanation_match {
                                return false;
                            }
                        }

                        // Optional "to" filter: match against title or explanation.
                        if let Some(ref to) = to_filter {
                            let title_match = d
                                .get("title")
                                .and_then(|t| t.as_str())
                                .is_some_and(|t| t.contains(to.as_str()));
                            let explanation_match = d
                                .get("explanation")
                                .and_then(|e| e.as_str())
                                .is_some_and(|e| e.contains(to.as_str()));
                            if !title_match && !explanation_match {
                                return false;
                            }
                        }

                        true
                    })
                    .cloned()
                    .collect();
                serde_json::Value::Array(filtered)
            } else {
                serde_json::json!([])
            };

            JsValue::from_json(&result, ctx)
        })
    };

    // --- goguard.callGraph() ---
    // Returns an object with callersOf(name), calleesOf(name), edges() methods.
    // We rebuild the object on each call because JsObject is GC-managed and
    // cannot be safely captured across boa closure boundaries.
    let cg_edges_data = api.call_edges_json.clone();
    let call_graph_fn = unsafe {
        NativeFunction::from_closure(move |_this, _args, ctx| {
            let edges_c = cg_edges_data.clone();
            let callers_fn = NativeFunction::from_closure(move |_this, args, ctx| {
                let name = args
                    .first()
                    .and_then(|v| v.as_string())
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();
                let result = if let serde_json::Value::Array(arr) = &edges_c {
                    let filtered: Vec<_> = arr
                        .iter()
                        .filter(|e| {
                            e.get("callee")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c == name)
                        })
                        .cloned()
                        .collect();
                    serde_json::Value::Array(filtered)
                } else {
                    serde_json::json!([])
                };
                JsValue::from_json(&result, ctx)
            });

            let edges_e = cg_edges_data.clone();
            let callees_fn = NativeFunction::from_closure(move |_this, args, ctx| {
                let name = args
                    .first()
                    .and_then(|v| v.as_string())
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();
                let result = if let serde_json::Value::Array(arr) = &edges_e {
                    let filtered: Vec<_> = arr
                        .iter()
                        .filter(|e| {
                            e.get("caller")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c == name)
                        })
                        .cloned()
                        .collect();
                    serde_json::Value::Array(filtered)
                } else {
                    serde_json::json!([])
                };
                JsValue::from_json(&result, ctx)
            });

            let edges_all = cg_edges_data.clone();
            let all_fn = NativeFunction::from_closure(move |_this, _args, ctx| {
                JsValue::from_json(&edges_all, ctx)
            });

            let obj = ObjectInitializer::new(ctx)
                .function(callers_fn, js_string!("callersOf"), 1)
                .function(callees_fn, js_string!("calleesOf"), 1)
                .function(all_fn, js_string!("edges"), 0)
                .build();

            Ok(obj.into())
        })
    };

    // --- Build the goguard global object ---
    // Convert config to JsValue for the read-only property.
    let config_js = JsValue::from_json(&api.config_json, context)?;

    let goguard_obj = ObjectInitializer::new(context)
        .function(diagnostics_fn, js_string!("diagnostics"), 1)
        .function(packages_fn, js_string!("packages"), 0)
        .function(call_graph_fn, js_string!("callGraph"), 0)
        .function(functions_fn, js_string!("functions"), 1)
        .function(rules_fn, js_string!("rules"), 1)
        .function(taint_flows_fn, js_string!("taintFlows"), 2)
        .property(js_string!("config"), config_js, Attribute::READONLY)
        .build();

    context.register_global_property(
        js_string!("goguard"),
        goguard_obj,
        Attribute::READONLY | Attribute::NON_ENUMERABLE,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use boa_engine::Source;
    use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};
    use goguard_ir::ir::{BasicBlock, CallEdge, Function, Package, Span};
    use serde_json::json;

    // -- Test helpers --

    /// Execute JS code with GoGuard API registered and return the result as JSON.
    fn eval_with_api(api: &GoGuardJsApi, code: &str) -> serde_json::Value {
        let mut context = Context::default();
        register_api(api, &mut context).expect("register_api should succeed");
        let result = context.eval(Source::from_bytes(code.as_bytes()));
        match result {
            Ok(val) => val
                .to_json(&mut context)
                .expect("to_json should succeed")
                .unwrap_or(serde_json::Value::Null),
            Err(e) => panic!("JS execution failed: {e}"),
        }
    }

    fn make_test_diagnostic(rule: &str, source: DiagnosticSource) -> Diagnostic {
        DiagnosticBuilder::new(
            rule,
            Severity::Error,
            format!("test diagnostic {rule}"),
            source,
        )
        .location("main.go", 10, 5)
        .explanation(format!("explanation for {rule}"))
        .build()
    }

    fn make_test_package() -> Package {
        Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![
                Function {
                    name: "example.com/pkg.GetUser".into(),
                    short_name: "GetUser".into(),
                    span: Some(Span::new("handler.go", 10, 1)),
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
                    is_exported: true,
                    free_vars: vec![],
                    defers: vec![],
                },
                Function {
                    name: "example.com/pkg.saveUser".into(),
                    short_name: "saveUser".into(),
                    span: Some(Span::new("handler.go", 30, 1)),
                    blocks: vec![],
                    cfg_edges: vec![],
                    is_method: true,
                    receiver_type_id: 1,
                    is_exported: false,
                    free_vars: vec![],
                    defers: vec![],
                },
            ],
            interface_satisfactions: vec![],
            call_edges: vec![
                CallEdge {
                    caller: "example.com/pkg.GetUser".into(),
                    callee: "db.Find".into(),
                    span: None,
                    is_dynamic: false,
                    is_go: false,
                    is_defer: false,
                },
                CallEdge {
                    caller: "example.com/pkg.Main".into(),
                    callee: "example.com/pkg.GetUser".into(),
                    span: None,
                    is_dynamic: false,
                    is_go: true,
                    is_defer: false,
                },
            ],
            global_vars: vec![],
        }
    }

    // -- Tests --

    #[test]
    fn test_goguard_object_exists() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "typeof goguard");
        assert_eq!(result, json!("object"));
    }

    #[test]
    fn test_diagnostics_returns_all() {
        let diags = vec![
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
            make_test_diagnostic("ERR001", DiagnosticSource::Errcheck),
        ];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        let result = eval_with_api(&api, "goguard.diagnostics().length");
        assert_eq!(result, json!(2));
    }

    #[test]
    fn test_diagnostics_filter_by_rule() {
        let diags = vec![
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
            make_test_diagnostic("ERR001", DiagnosticSource::Errcheck),
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
        ];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        let result = eval_with_api(&api, "goguard.diagnostics('NIL001').length");
        assert_eq!(result, json!(2));
    }

    #[test]
    fn test_diagnostics_filter_no_match() {
        let diags = vec![make_test_diagnostic("NIL001", DiagnosticSource::Nil)];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        let result = eval_with_api(&api, "goguard.diagnostics('NONEXISTENT').length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_diagnostics_returns_correct_fields() {
        let diags = vec![make_test_diagnostic("NIL001", DiagnosticSource::Nil)];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        let result = eval_with_api(&api, "goguard.diagnostics()[0].rule");
        assert_eq!(result, json!("NIL001"));

        let result = eval_with_api(&api, "goguard.diagnostics()[0].severity");
        assert_eq!(result, json!("error"));

        let result = eval_with_api(&api, "goguard.diagnostics()[0].location.file");
        assert_eq!(result, json!("main.go"));
    }

    #[test]
    fn test_diagnostics_empty() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.diagnostics().length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_packages_returns_all() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(&api, "goguard.packages().length");
        assert_eq!(result, json!(1));
    }

    #[test]
    fn test_packages_returns_correct_fields() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(&api, "goguard.packages()[0].import_path");
        assert_eq!(result, json!("example.com/pkg"));

        let result = eval_with_api(&api, "goguard.packages()[0].name");
        assert_eq!(result, json!("pkg"));

        // functions is now an array of function names
        let result = eval_with_api(&api, "goguard.packages()[0].functions.length");
        assert_eq!(result, json!(2));

        // types is now an array (may be empty in test package)
        let result = eval_with_api(&api, "Array.isArray(goguard.packages()[0].types)");
        assert_eq!(result, json!(true));
    }

    #[test]
    fn test_packages_empty() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.packages().length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_functions_returns_all() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(&api, "goguard.functions().length");
        assert_eq!(result, json!(2));
    }

    #[test]
    fn test_functions_filter_by_name() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(&api, "goguard.functions('GetUser').length");
        assert_eq!(result, json!(1));

        let result = eval_with_api(&api, "goguard.functions('GetUser')[0].short_name");
        assert_eq!(result, json!("GetUser"));
    }

    #[test]
    fn test_functions_filter_partial_match() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        // "User" should match both GetUser and saveUser
        let result = eval_with_api(&api, "goguard.functions('User').length");
        assert_eq!(result, json!(2));
    }

    #[test]
    fn test_functions_returns_correct_fields() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(
            &api,
            r#"
            (function() {
                let f = goguard.functions('GetUser')[0];
                return {
                    name: f.name,
                    is_method: f.is_method,
                    is_exported: f.is_exported,
                    has_blocks: Array.isArray(f.blocks),
                    block_count: f.blocks.length,
                    has_span: f.span !== null,
                };
            })()
            "#,
        );
        assert_eq!(
            result,
            json!({
                "name": "example.com/pkg.GetUser",
                "is_method": false,
                "is_exported": true,
                "has_blocks": true,
                "block_count": 1,
                "has_span": true,
            })
        );
    }

    #[test]
    fn test_functions_include_instructions() {
        // Verify the block/instruction structure is accessible from JS.
        // make_test_package() has GetUser with one empty BasicBlock — that's fine,
        // we verify the structural shape even when instructions is empty.
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(
            &api,
            r#"
            (function() {
                let f = goguard.functions('GetUser')[0];
                let block = f.blocks[0];
                return {
                    block_name: block.name,
                    is_return: block.is_return,
                    instructions_is_array: Array.isArray(block.instructions),
                };
            })()
            "#,
        );
        assert_eq!(
            result,
            json!({
                "block_name": "entry",
                "is_return": true,
                "instructions_is_array": true,
            })
        );
    }

    #[test]
    fn test_functions_empty() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.functions().length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_rules_returns_all() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.rules().length");
        // Should match the number of rules in get_all_rules()
        let expected = get_all_rules().len();
        assert_eq!(result, json!(expected));
    }

    #[test]
    fn test_rules_filter_by_category() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.rules('nil').length");
        let expected = get_all_rules()
            .iter()
            .filter(|r| r.category == "nil")
            .count();
        assert_eq!(result, json!(expected));
    }

    #[test]
    fn test_rules_filter_no_match() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.rules('nonexistent').length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_rules_returns_correct_fields() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(
            &api,
            "goguard.rules('nil').filter(r => r.code === 'NIL001')[0].name",
        );
        assert_eq!(result, json!("Nil pointer dereference"));
    }

    #[test]
    fn test_call_graph_callers_of() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(
            &api,
            "goguard.callGraph().callersOf('example.com/pkg.GetUser').length",
        );
        assert_eq!(result, json!(1));

        let result = eval_with_api(
            &api,
            "goguard.callGraph().callersOf('example.com/pkg.GetUser')[0].caller",
        );
        assert_eq!(result, json!("example.com/pkg.Main"));
    }

    #[test]
    fn test_call_graph_callees_of() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(
            &api,
            "goguard.callGraph().calleesOf('example.com/pkg.GetUser').length",
        );
        assert_eq!(result, json!(1));

        let result = eval_with_api(
            &api,
            "goguard.callGraph().calleesOf('example.com/pkg.GetUser')[0].callee",
        );
        assert_eq!(result, json!("db.Find"));
    }

    #[test]
    fn test_call_graph_edges() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(&api, "goguard.callGraph().edges().length");
        assert_eq!(result, json!(2));
    }

    #[test]
    fn test_call_graph_empty() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.callGraph().edges().length");
        assert_eq!(result, json!(0));

        let result = eval_with_api(&api, "goguard.callGraph().callersOf('anything').length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_call_graph_edge_fields() {
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&[], &pkgs, json!({}));
        let result = eval_with_api(
            &api,
            r#"
            (function() {
                let edges = goguard.callGraph().calleesOf('example.com/pkg.Main');
                return {
                    callee: edges[0].callee,
                    is_go: edges[0].is_go,
                    is_dynamic: edges[0].is_dynamic,
                };
            })()
            "#,
        );
        assert_eq!(
            result,
            json!({
                "callee": "example.com/pkg.GetUser",
                "is_go": true,
                "is_dynamic": false,
            })
        );
    }

    #[test]
    fn test_taint_flows_returns_taint_diagnostics() {
        let diags = vec![
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
            DiagnosticBuilder::new(
                "TAINT001",
                Severity::Critical,
                "SQL injection via user input",
                DiagnosticSource::Taint,
            )
            .location("handler.go", 42, 5)
            .explanation("Tainted data from request flows to db.Query")
            .build(),
        ];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        let result = eval_with_api(&api, "goguard.taintFlows().length");
        assert_eq!(result, json!(1));

        let result = eval_with_api(&api, "goguard.taintFlows()[0].rule");
        assert_eq!(result, json!("TAINT001"));
    }

    #[test]
    fn test_taint_flows_filter_by_from() {
        let diags = vec![
            DiagnosticBuilder::new(
                "TAINT001",
                Severity::Critical,
                "SQL injection via user input",
                DiagnosticSource::Taint,
            )
            .location("handler.go", 42, 5)
            .explanation("Tainted data from request flows to db.Query")
            .build(),
            DiagnosticBuilder::new(
                "TAINT002",
                Severity::Critical,
                "Command injection via env var",
                DiagnosticSource::Taint,
            )
            .location("cmd.go", 10, 1)
            .explanation("Environment variable flows to exec.Command")
            .build(),
        ];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        let result = eval_with_api(&api, "goguard.taintFlows('SQL').length");
        assert_eq!(result, json!(1));
    }

    #[test]
    fn test_taint_flows_filter_by_from_and_to() {
        let diags = vec![DiagnosticBuilder::new(
            "TAINT001",
            Severity::Critical,
            "SQL injection via user input",
            DiagnosticSource::Taint,
        )
        .location("handler.go", 42, 5)
        .explanation("Tainted data from request flows to db.Query")
        .build()];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        // Both filters match
        let result = eval_with_api(&api, "goguard.taintFlows('SQL', 'db.Query').length");
        assert_eq!(result, json!(1));

        // "to" filter doesn't match
        let result = eval_with_api(&api, "goguard.taintFlows('SQL', 'nonexistent').length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_taint_flows_empty() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "goguard.taintFlows().length");
        assert_eq!(result, json!(0));
    }

    #[test]
    fn test_config_accessible() {
        let config = json!({
            "version": "1.0.0",
            "timeout_ms": 5000,
            "passes": ["nil", "errcheck", "taint"]
        });
        let api = GoGuardJsApi::new(&[], &[], config);
        let result = eval_with_api(&api, "goguard.config.version");
        assert_eq!(result, json!("1.0.0"));

        let result = eval_with_api(&api, "goguard.config.timeout_ms");
        assert_eq!(result, json!(5000));

        let result = eval_with_api(&api, "goguard.config.passes.length");
        assert_eq!(result, json!(3));
    }

    #[test]
    fn test_config_empty() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));
        let result = eval_with_api(&api, "typeof goguard.config");
        assert_eq!(result, json!("object"));
    }

    #[test]
    fn test_complex_query_combining_apis() {
        let diags = vec![
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
            make_test_diagnostic("ERR001", DiagnosticSource::Errcheck),
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
        ];
        let pkgs = vec![make_test_package()];
        let api = GoGuardJsApi::new(&diags, &pkgs, json!({"version": "1.0"}));

        // Complex query: count nil diagnostics and exported functions
        let result = eval_with_api(
            &api,
            r#"
            (function() {
                let nilCount = goguard.diagnostics('NIL001').length;
                let exportedFns = goguard.functions().filter(f => f.is_exported).length;
                let pkgCount = goguard.packages().length;
                return { nilCount, exportedFns, pkgCount };
            })()
            "#,
        );
        assert_eq!(
            result,
            json!({
                "nilCount": 2,
                "exportedFns": 1,
                "pkgCount": 1,
            })
        );
    }

    #[test]
    fn test_all_empty_data() {
        let api = GoGuardJsApi::new(&[], &[], json!({}));

        // All methods should return empty arrays, not errors.
        assert_eq!(
            eval_with_api(&api, "goguard.diagnostics().length"),
            json!(0)
        );
        assert_eq!(eval_with_api(&api, "goguard.packages().length"), json!(0));
        assert_eq!(eval_with_api(&api, "goguard.functions().length"), json!(0));
        assert_eq!(
            eval_with_api(&api, "goguard.callGraph().edges().length"),
            json!(0)
        );
        assert_eq!(eval_with_api(&api, "goguard.taintFlows().length"), json!(0));
        assert_eq!(
            eval_with_api(&api, "typeof goguard.config"),
            json!("object")
        );
        // rules() always has data from the catalog
        let rules_count = eval_with_api(&api, "goguard.rules().length");
        assert_ne!(rules_count, json!(0), "rules should not be empty");
    }

    #[test]
    fn test_diagnostics_no_filter_argument_returns_all() {
        let diags = vec![
            make_test_diagnostic("NIL001", DiagnosticSource::Nil),
            make_test_diagnostic("ERR001", DiagnosticSource::Errcheck),
        ];
        let api = GoGuardJsApi::new(&diags, &[], json!({}));
        // Calling without arguments returns all
        let result = eval_with_api(&api, "goguard.diagnostics().length");
        assert_eq!(result, json!(2));
    }
}
