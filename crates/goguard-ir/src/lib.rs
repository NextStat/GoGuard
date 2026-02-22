//! GoGuard IR — intermediate representation for Go code analysis.
//!
//! In the Fat Bridge architecture, the IR is built by the Go compiler frontend
//! (goguard-go-bridge) and deserialized in Rust. This crate provides:
//! - High-level IR wrappers matching the bridge output (JSON and FlatBuffers)
//! - CFG navigation helpers
//! - Type system helpers
//! - Call graph representation

pub mod call_graph; // Call graph queries
pub mod cfg; // CFG navigation helpers
pub mod generated;
pub mod ir; // High-level IR wrappers
pub mod types; // Type system helpers // FlatBuffers-generated code

/// Load a FlatBuffers binary file and convert it to the owned IR.
pub fn load_flatbuffers_file(path: &std::path::Path) -> Result<ir::AnalysisInput, String> {
    let data = std::fs::read(path).map_err(|e| format!("read error: {e}"))?;
    ir::AnalysisInput::from_flatbuffers(&data)
}

/// Load a bridge fixture file from `tests/bridge_fixtures/` by name.
/// The fixture file should have a `.fb` extension.
///
/// This is available in test builds and when the `test-fixtures` feature is enabled.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn load_bridge_fixture(name: &str) -> ir::AnalysisInput {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_path = manifest_dir
        .join("../../tests/bridge_fixtures")
        .join(format!("{name}.fb"));
    load_flatbuffers_file(&fixture_path)
        .unwrap_or_else(|e| panic!("failed to load fixture {name}: {e}"))
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    /// All nil-analysis fixture names, matching the .go files in tests/fixtures/nil/.
    const NIL_FIXTURES: &[&str] = &[
        "basic_nil_deref",
        "missing_return",
        "type_assertion",
        "nil_map",
        "error_ignored",
        "safe_patterns",
    ];

    #[test]
    fn test_load_all_nil_fixtures() {
        for name in NIL_FIXTURES {
            let ir = load_bridge_fixture(&format!("nil/{name}"));
            assert!(
                !ir.packages.is_empty(),
                "fixture {name} should have at least one package"
            );
            let total_funcs: usize = ir.packages.iter().map(|p| p.functions.len()).sum();
            assert!(
                total_funcs > 0,
                "fixture {name} should have at least one function"
            );
        }
    }

    #[test]
    fn test_basic_nil_deref_fixture() {
        let ir = load_bridge_fixture("nil/basic_nil_deref");
        assert_eq!(ir.packages.len(), 1);

        let pkg = &ir.packages[0];
        assert_eq!(pkg.name, "fixtures");

        // Should have at least BasicNilDeref function
        // Note: methods like FindByID are currently not serialized as top-level
        // functions by the Go bridge (they are accessed via named types in SSA).
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();
        assert!(
            func_names.contains(&"BasicNilDeref"),
            "should contain BasicNilDeref, found: {:?}",
            func_names
        );

        // BasicNilDeref should have basic blocks (it has an if statement)
        let basic_nil_deref = pkg
            .functions
            .iter()
            .find(|f| f.short_name == "BasicNilDeref")
            .unwrap();
        assert!(
            basic_nil_deref.blocks.len() >= 2,
            "BasicNilDeref should have >= 2 blocks (has if), got {}",
            basic_nil_deref.blocks.len()
        );
        assert!(
            !basic_nil_deref.cfg_edges.is_empty(),
            "BasicNilDeref should have CFG edges"
        );
    }

    #[test]
    fn test_safe_patterns_fixture() {
        let ir = load_bridge_fixture("nil/safe_patterns");
        assert_eq!(ir.packages.len(), 1);

        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();

        // Should contain the safe pattern functions
        assert!(
            func_names.contains(&"SafeNilCheck"),
            "should contain SafeNilCheck, found: {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"SafeTypeAssertion"),
            "should contain SafeTypeAssertion, found: {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"SafeMapInit"),
            "should contain SafeMapInit, found: {:?}",
            func_names
        );
    }

    #[test]
    fn test_type_assertion_fixture() {
        let ir = load_bridge_fixture("nil/type_assertion");
        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();

        assert!(
            func_names.contains(&"TypeAssertionWithoutOk"),
            "should contain TypeAssertionWithoutOk, found: {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"TypeAssertionSafe"),
            "should contain TypeAssertionSafe, found: {:?}",
            func_names
        );

        // TypeAssertionWithoutOk should have a TypeAssert instruction
        let unsafe_fn = pkg
            .functions
            .iter()
            .find(|f| f.short_name == "TypeAssertionWithoutOk")
            .unwrap();

        let has_type_assert = unsafe_fn.blocks.iter().any(|b| {
            b.instructions
                .iter()
                .any(|i| i.kind == ir::ValueKind::TypeAssert)
        });
        assert!(
            has_type_assert,
            "TypeAssertionWithoutOk should contain a TypeAssert instruction"
        );
    }

    #[test]
    fn test_error_ignored_fixture() {
        let ir = load_bridge_fixture("nil/error_ignored");
        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();

        assert!(
            func_names.contains(&"ErrorIgnored"),
            "should contain ErrorIgnored, found: {:?}",
            func_names
        );
    }

    #[test]
    fn test_missing_return_fixture() {
        let ir = load_bridge_fixture("nil/missing_return");
        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();

        assert!(
            func_names.contains(&"MissingReturnAfterHTTPError"),
            "should contain MissingReturnAfterHTTPError, found: {:?}",
            func_names
        );

        // This function should have CFG edges (it has an if block)
        let missing_ret = pkg
            .functions
            .iter()
            .find(|f| f.short_name == "MissingReturnAfterHTTPError")
            .unwrap();
        assert!(
            !missing_ret.cfg_edges.is_empty(),
            "MissingReturnAfterHTTPError should have CFG edges"
        );
    }

    #[test]
    fn test_nil_map_fixture() {
        let ir = load_bridge_fixture("nil/nil_map");
        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();

        assert!(
            func_names.contains(&"NilMapAccess"),
            "should contain NilMapAccess, found: {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"NilMapWrite"),
            "should contain NilMapWrite, found: {:?}",
            func_names
        );
    }

    #[test]
    fn test_fixtures_have_valid_go_version() {
        for name in NIL_FIXTURES {
            let ir = load_bridge_fixture(&format!("nil/{name}"));
            assert!(
                !ir.go_version.is_empty(),
                "fixture {name} should have a go_version"
            );
        }
    }

    // --- Errcheck fixtures ---

    /// All errcheck-analysis fixture names, matching the .go files in tests/fixtures/errcheck/.
    const ERRCHECK_FIXTURES: &[&str] = &["ignored_error", "safe_error_handling"];

    #[test]
    fn test_load_all_errcheck_fixtures() {
        for name in ERRCHECK_FIXTURES {
            let ir = load_bridge_fixture(&format!("errcheck/{name}"));
            assert!(
                !ir.packages.is_empty(),
                "fixture {name} should have at least one package"
            );
            let total_funcs: usize = ir.packages.iter().map(|p| p.functions.len()).sum();
            assert!(
                total_funcs > 0,
                "fixture {name} should have at least one function"
            );
        }
    }

    #[test]
    fn test_errcheck_ignored_error_fixture() {
        let ir = load_bridge_fixture("errcheck/ignored_error");
        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();
        assert!(
            func_names.contains(&"IgnoredError"),
            "should contain IgnoredError, found: {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"ErrorAssignedToBlank"),
            "should contain ErrorAssignedToBlank, found: {:?}",
            func_names
        );
    }

    #[test]
    fn test_errcheck_safe_error_handling_fixture() {
        let ir = load_bridge_fixture("errcheck/safe_error_handling");
        let pkg = &ir.packages[0];
        let func_names: Vec<&str> = pkg
            .functions
            .iter()
            .map(|f| f.short_name.as_str())
            .collect();
        assert!(
            func_names.contains(&"SafeErrorHandling"),
            "should contain SafeErrorHandling, found: {:?}",
            func_names
        );
        assert!(
            func_names.contains(&"AllowedIgnore"),
            "should contain AllowedIgnore, found: {:?}",
            func_names
        );
    }

    #[test]
    fn test_errcheck_fixtures_have_valid_go_version() {
        for name in ERRCHECK_FIXTURES {
            let ir = load_bridge_fixture(&format!("errcheck/{name}"));
            assert!(
                !ir.go_version.is_empty(),
                "fixture {name} should have a go_version"
            );
        }
    }
}
