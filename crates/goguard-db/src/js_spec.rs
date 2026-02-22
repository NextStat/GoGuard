//! GoGuard spec object for Code Mode API discovery.
//!
//! Generates a `spec` global object that agents can use to self-discover the
//! GoGuard JS API without reading documentation. The spec includes:
//!
//! - `spec.api` — all GoGuard JS API methods with signatures and descriptions
//! - `spec.rules` — full rule catalog from [`goguard_diagnostics::rules`]
//! - `spec.ir_schema` — IR structure descriptions (Package, Function, etc.)
//! - `spec.examples` — example JS queries the agent can adapt

use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsValue};

use goguard_diagnostics::rules::get_all_rules;

/// Generate the GoGuard spec object for Code Mode API discovery.
///
/// Returns a [`serde_json::Value`] with four sections: `api`, `rules`,
/// `ir_schema`, and `examples`. This can be registered as a read-only
/// global on a boa [`Context`] via [`register_spec`].
pub fn build_spec() -> serde_json::Value {
    serde_json::json!({
        "api": build_api_spec(),
        "rules": build_rules_spec(),
        "ir_schema": build_ir_schema_spec(),
        "examples": build_examples_spec(),
    })
}

/// Describe each `goguard.*` method: signature, description, return type.
fn build_api_spec() -> serde_json::Value {
    serde_json::json!({
        "diagnostics": {
            "signature": "diagnostics(filter?: string)",
            "description": "Returns array of diagnostics. Optional filter by rule code (e.g., 'NIL001').",
            "returns": "Diagnostic[]"
        },
        "packages": {
            "signature": "packages()",
            "description": "Returns array of analyzed packages with name, import_path, functions, types.",
            "returns": "Package[]"
        },
        "functions": {
            "signature": "functions(filter?: string)",
            "description": "Returns array of functions. Optional filter by name substring.",
            "returns": "Function[]"
        },
        "rules": {
            "signature": "rules(category?: string)",
            "description": "Returns array of rule definitions. Optional filter by category (nil, errcheck, concurrency, ownership, exhaustive, taint).",
            "returns": "Rule[]"
        },
        "callGraph": {
            "signature": "callGraph()",
            "description": "Returns call graph object with .callersOf(name: string), .calleesOf(name: string), .edges() methods.",
            "returns": "CallGraph"
        },
        "taintFlows": {
            "signature": "taintFlows(from?: string, to?: string)",
            "description": "Returns taint flow diagnostics. Optional source/sink pattern filters.",
            "returns": "TaintFlow[]"
        },
        "config": {
            "signature": "config",
            "description": "Read-only GoGuard configuration object.",
            "returns": "Config"
        }
    })
}

/// Serialize the full rule catalog from [`goguard_diagnostics::rules`].
fn build_rules_spec() -> serde_json::Value {
    let all_rules = get_all_rules();
    serde_json::to_value(&all_rules).unwrap_or_default()
}

/// Describe the IR data structures available through the GoGuard JS API.
fn build_ir_schema_spec() -> serde_json::Value {
    serde_json::json!({
        "Package": {
            "fields": ["import_path", "name", "files", "types", "functions", "call_edges", "global_vars"]
        },
        "Function": {
            "fields": ["name", "signature", "parameters", "instructions", "blocks", "free_vars", "defers", "referrers"]
        },
        "CallEdge": {
            "fields": ["caller", "callee", "span", "is_dynamic", "is_go", "is_defer"]
        },
        "Diagnostic": {
            "fields": ["id", "rule", "severity", "title", "explanation", "location", "root_cause", "fix"]
        },
        "BasicBlock": {
            "fields": ["id", "name", "instructions", "is_return", "is_panic"]
        },
        "Instruction": {
            "fields": ["id", "kind", "name", "type_id", "operands", "callee", "span"]
        },
        "Span": {
            "fields": ["file", "start_line", "start_col", "end_line", "end_col"]
        },
        "Type": {
            "fields": ["id", "name", "kind", "is_nilable", "is_error"]
        }
    })
}

/// Provide example JS queries that agents can adapt.
fn build_examples_spec() -> serde_json::Value {
    serde_json::json!([
        {
            "description": "List all critical diagnostics",
            "code": "goguard.diagnostics().filter(d => d.severity === 'critical')"
        },
        {
            "description": "Count diagnostics by severity",
            "code": "(() => { let ds = goguard.diagnostics(); return { total: ds.length, critical: ds.filter(d => d.severity === 'critical').length }; })()"
        },
        {
            "description": "Find callers of a function",
            "code": "goguard.callGraph().callersOf('pkg.handler')"
        },
        {
            "description": "Get all taint rules",
            "code": "spec.rules.filter(r => r.category === 'taint')"
        },
        {
            "description": "Explore available API methods",
            "code": "Object.keys(spec.api)"
        },
        {
            "description": "Get functions matching a name pattern",
            "code": "goguard.functions('Handler').map(f => f.name)"
        },
        {
            "description": "List all rule categories",
            "code": "[...new Set(spec.rules.map(r => r.category))]"
        },
        {
            "description": "Find diagnostics in a specific file",
            "code": "goguard.diagnostics().filter(d => d.location.file === 'handler.go')"
        }
    ])
}

/// Register the `spec` global object on a boa [`Context`].
///
/// After calling this, JavaScript code executed in the context can use:
/// - `spec.api` — method signatures and descriptions
/// - `spec.rules` — full rule catalog array
/// - `spec.ir_schema` — IR structure descriptions
/// - `spec.examples` — example JS queries
///
/// The `spec` global is read-only and non-enumerable.
pub fn register_spec(context: &mut Context) -> Result<(), boa_engine::JsError> {
    let spec_json = build_spec();
    let spec_js = JsValue::from_json(&spec_json, context)?;

    context.register_global_property(
        js_string!("spec"),
        spec_js,
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
    use serde_json::json;

    /// Execute JS code with the spec global registered and return the result as JSON.
    fn eval_with_spec(code: &str) -> serde_json::Value {
        let mut context = Context::default();
        register_spec(&mut context).expect("register_spec should succeed");
        let result = context.eval(Source::from_bytes(code.as_bytes()));
        match result {
            Ok(val) => val
                .to_json(&mut context)
                .expect("to_json should succeed")
                .unwrap_or(serde_json::Value::Null),
            Err(e) => panic!("JS execution failed: {e}"),
        }
    }

    #[test]
    fn test_build_spec_has_all_sections() {
        let spec = build_spec();
        assert!(spec.get("api").is_some(), "spec must have 'api' key");
        assert!(spec.get("rules").is_some(), "spec must have 'rules' key");
        assert!(
            spec.get("ir_schema").is_some(),
            "spec must have 'ir_schema' key"
        );
        assert!(
            spec.get("examples").is_some(),
            "spec must have 'examples' key"
        );
    }

    #[test]
    fn test_spec_rules_match_catalog() {
        let spec = build_spec();
        let spec_rules = spec["rules"].as_array().expect("rules should be an array");
        let catalog_count = get_all_rules().len();
        assert_eq!(
            spec_rules.len(),
            catalog_count,
            "spec.rules count ({}) should match get_all_rules() count ({})",
            spec_rules.len(),
            catalog_count
        );
    }

    #[test]
    fn test_spec_api_has_all_methods() {
        let spec = build_spec();
        let api = spec["api"].as_object().expect("api should be an object");
        let expected_methods = [
            "diagnostics",
            "packages",
            "functions",
            "rules",
            "callGraph",
            "taintFlows",
            "config",
        ];
        for method in &expected_methods {
            assert!(
                api.contains_key(*method),
                "spec.api should contain method '{method}'"
            );
        }
        assert_eq!(
            api.len(),
            expected_methods.len(),
            "spec.api should have exactly {} methods",
            expected_methods.len()
        );
    }

    #[test]
    fn test_register_spec_on_context() {
        let result = eval_with_spec("typeof spec");
        assert_eq!(result, json!("object"));
    }

    #[test]
    fn test_spec_examples_nonempty() {
        let spec = build_spec();
        let examples = spec["examples"]
            .as_array()
            .expect("examples should be an array");
        assert!(!examples.is_empty(), "spec.examples should not be empty");
        for (i, example) in examples.iter().enumerate() {
            assert!(
                example.get("code").is_some(),
                "example[{i}] must have 'code' field"
            );
            assert!(
                example.get("description").is_some(),
                "example[{i}] must have 'description' field"
            );
            assert!(
                example["code"].as_str().is_some_and(|s| !s.is_empty()),
                "example[{i}].code must be non-empty string"
            );
            assert!(
                example["description"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()),
                "example[{i}].description must be non-empty string"
            );
        }
    }

    #[test]
    fn test_spec_api_method_has_signature_and_description() {
        let spec = build_spec();
        let api = spec["api"].as_object().unwrap();
        for (name, method) in api {
            assert!(
                method.get("signature").is_some(),
                "spec.api.{name} must have 'signature'"
            );
            assert!(
                method.get("description").is_some(),
                "spec.api.{name} must have 'description'"
            );
            assert!(
                method.get("returns").is_some(),
                "spec.api.{name} must have 'returns'"
            );
        }
    }

    #[test]
    fn test_spec_ir_schema_has_core_types() {
        let spec = build_spec();
        let schema = spec["ir_schema"]
            .as_object()
            .expect("ir_schema should be an object");
        let expected_types = [
            "Package",
            "Function",
            "CallEdge",
            "Diagnostic",
            "BasicBlock",
            "Instruction",
            "Span",
            "Type",
        ];
        for ty in &expected_types {
            assert!(
                schema.contains_key(*ty),
                "ir_schema should contain type '{ty}'"
            );
        }
    }

    #[test]
    fn test_spec_accessible_from_js() {
        // Verify we can access spec.api keys from JS.
        let result = eval_with_spec("Object.keys(spec.api).sort()");
        let keys = result.as_array().expect("should be array");
        assert!(keys.len() >= 7, "should have at least 7 API methods");
    }

    #[test]
    fn test_spec_rules_accessible_from_js() {
        let result = eval_with_spec("spec.rules.length");
        let count = result.as_u64().expect("should be number");
        assert_eq!(count as usize, get_all_rules().len());
    }

    #[test]
    fn test_spec_rules_filter_by_category_from_js() {
        let result = eval_with_spec("spec.rules.filter(r => r.category === 'nil').length");
        let nil_count = result.as_u64().expect("should be number");
        let expected = get_all_rules()
            .iter()
            .filter(|r| r.category == "nil")
            .count();
        assert_eq!(nil_count as usize, expected);
    }

    #[test]
    fn test_spec_examples_accessible_from_js() {
        let result = eval_with_spec("spec.examples[0].description");
        let desc = result.as_str().expect("should be string");
        assert!(
            !desc.is_empty(),
            "first example description should not be empty"
        );
    }

    #[test]
    fn test_spec_ir_schema_accessible_from_js() {
        let result = eval_with_spec("spec.ir_schema.Package.fields");
        let fields = result.as_array().expect("should be array");
        assert!(
            fields.contains(&json!("import_path")),
            "Package fields should include import_path"
        );
        assert!(
            fields.contains(&json!("functions")),
            "Package fields should include functions"
        );
    }
}
