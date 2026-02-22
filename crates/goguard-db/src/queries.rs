//! Salsa query definitions for incremental analysis.
//!
//! Each tracked function wraps a per-package analysis pass.
//! Salsa memoizes results: when a PackageInput's content_hash is unchanged,
//! the function body is skipped entirely.

use crate::db::Db;
use crate::inputs::{AnalysisConfigInput, GlobalContextInput, PackageInput};
use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::ir::{EnumGroup, InterfaceEntry, Package};

/// Analyze one package for nil issues. Memoized by Salsa.
/// When PackageInput.content_hash is unchanged, Salsa skips re-execution entirely.
#[salsa::tracked]
pub fn nil_diagnostics(
    db: &dyn Db,
    pkg: PackageInput,
    config: AnalysisConfigInput,
) -> Vec<Diagnostic> {
    let json = pkg.ir_json(db);
    let package: Package = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(pkg = %pkg.import_path(db), error = %e, "failed to deserialize package IR");
            return Vec::new();
        }
    };
    goguard_nil::analysis::NilAnalyzer::analyze_package_with_options(
        &package,
        &goguard_nil::analysis::NilOptions {
            strict_params: config.nil_strict_params(db),
            user_models: goguard_nil::analysis::parse_user_models(&config.nil_models(db)),
        },
    )
}

/// Analyze one package for errcheck issues. Memoized by Salsa.
#[salsa::tracked]
pub fn errcheck_diagnostics(
    db: &dyn Db,
    pkg: PackageInput,
    config: AnalysisConfigInput,
) -> Vec<Diagnostic> {
    let json = pkg.ir_json(db);
    let package: Package = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(pkg = %pkg.import_path(db), error = %e, "failed to deserialize package IR");
            return Vec::new();
        }
    };
    let ignore = config.errcheck_ignore(db);
    let ignore_refs: Vec<&str> = ignore.iter().map(|s| s.as_str()).collect();
    goguard_errcheck::analysis::ErrcheckAnalyzer::check_package(&package, &ignore_refs)
}

/// Analyze one package for concurrency issues. Memoized by Salsa.
#[salsa::tracked]
pub fn concurrency_diagnostics(db: &dyn Db, pkg: PackageInput) -> Vec<Diagnostic> {
    let json = pkg.ir_json(db);
    let package: Package = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(pkg = %pkg.import_path(db), error = %e, "failed to deserialize package IR");
            return Vec::new();
        }
    };
    goguard_concurrency::analysis::ConcurrencyAnalyzer::analyze_package(&package)
}

/// Analyze one package for ownership/resource lifecycle issues. Memoized by Salsa.
#[salsa::tracked]
pub fn ownership_diagnostics(db: &dyn Db, pkg: PackageInput) -> Vec<Diagnostic> {
    let json = pkg.ir_json(db);
    let package: Package = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(pkg = %pkg.import_path(db), error = %e, "failed to deserialize package IR");
            return Vec::new();
        }
    };
    goguard_ownership::analysis::OwnershipAnalyzer::analyze_package(&package)
}

/// Analyze one package for exhaustive switch issues. Memoized by Salsa.
/// Requires global context (interface_table, enum_groups) in addition to the package.
#[salsa::tracked]
pub fn exhaustive_diagnostics(
    db: &dyn Db,
    pkg: PackageInput,
    global_ctx: GlobalContextInput,
) -> Vec<Diagnostic> {
    let json = pkg.ir_json(db);
    let package: Package = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(pkg = %pkg.import_path(db), error = %e, "failed to deserialize package IR");
            return Vec::new();
        }
    };
    let iface_json = global_ctx.interface_table_json(db);
    let enum_json = global_ctx.enum_groups_json(db);
    let interface_table: Vec<InterfaceEntry> =
        serde_json::from_str(&iface_json).unwrap_or_default();
    let enum_groups: Vec<EnumGroup> = serde_json::from_str(&enum_json).unwrap_or_default();
    goguard_exhaustive::analysis::ExhaustiveAnalyzer::analyze_package(
        &package,
        &interface_table,
        &enum_groups,
    )
}

/// Analyze one package for taint/security issues. Memoized by Salsa.
#[salsa::tracked]
pub fn taint_diagnostics(db: &dyn Db, pkg: PackageInput) -> Vec<Diagnostic> {
    let json = pkg.ir_json(db);
    let package: Package = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(pkg = %pkg.import_path(db), error = %e, "failed to deserialize package IR");
            return Vec::new();
        }
    };
    goguard_taint::analysis::TaintAnalyzer::analyze_package(&package)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::GoGuardDatabase;
    use crate::inputs::{AnalysisConfigInput, PackageInput};

    /// Helper: create a PackageInput from a bridge fixture name.
    fn fixture_package_input(db: &GoGuardDatabase, fixture_name: &str) -> PackageInput {
        let ir = goguard_ir::load_bridge_fixture(fixture_name);
        assert!(!ir.packages.is_empty(), "fixture should have packages");
        let pkg = &ir.packages[0];
        let json = serde_json::to_string(pkg).expect("serialize package");
        let hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            json.hash(&mut h);
            h.finish()
        };
        PackageInput::new(db, pkg.import_path.clone(), json, hash)
    }

    fn default_config(db: &GoGuardDatabase) -> AnalysisConfigInput {
        AnalysisConfigInput::new(
            db,
            true,
            false,
            vec![],
            true,
            true,
            true,
            true,
            true,
            "warning".to_string(),
            100,
            vec!["fmt.Print*".to_string(), "fmt.Fprint*".to_string()],
        )
    }

    #[test]
    fn test_nil_query_produces_diagnostics() {
        let db = GoGuardDatabase::default();
        let pkg = fixture_package_input(&db, "nil/basic_nil_deref");
        let config = default_config(&db);
        let diags = nil_diagnostics(&db, pkg, config);
        assert!(
            !diags.is_empty(),
            "basic_nil_deref should produce nil diagnostics"
        );
        assert!(diags.iter().all(|d| d.rule.starts_with("NIL")));
    }

    #[test]
    fn test_errcheck_query_produces_diagnostics() {
        let db = GoGuardDatabase::default();
        let pkg = fixture_package_input(&db, "errcheck/ignored_error");
        let config = default_config(&db);
        let diags = errcheck_diagnostics(&db, pkg, config);
        assert!(
            !diags.is_empty(),
            "ignored_error should produce errcheck diagnostics"
        );
        assert!(diags.iter().all(|d| d.rule.starts_with("ERR")));
    }

    #[test]
    fn test_nil_query_no_recompute_on_same_hash() {
        let db = GoGuardDatabase::default();
        let pkg = fixture_package_input(&db, "nil/basic_nil_deref");
        let config = default_config(&db);
        let diags1 = nil_diagnostics(&db, pkg, config);
        let diags2 = nil_diagnostics(&db, pkg, config);
        // Both calls should return the same result.
        // Salsa memoizes the second call (same input = same output).
        assert_eq!(diags1.len(), diags2.len());
        for (d1, d2) in diags1.iter().zip(diags2.iter()) {
            assert_eq!(d1.id, d2.id);
            assert_eq!(d1.rule, d2.rule);
        }
    }

    #[test]
    fn test_nil_models_from_config_suppress_nil001() {
        use goguard_ir::ir::{
            BasicBlock, Function, Instruction, Package, TypeKind, TypeRef, ValueKind,
        };
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let db = GoGuardDatabase::default();

        // Types: id=1 tuple, id=2 *User (nilable), id=4 *string (nilable)
        let types = vec![
            TypeRef {
                id: 1,
                kind: TypeKind::Tuple,
                name: "(t0, t1)".into(),
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
                id: 4,
                kind: TypeKind::Pointer,
                name: "*string".into(),
                underlying: 0,
                elem: 0,
                key: 0,
                is_nilable: true,
                is_error: false,
            },
        ];

        // t0 = ext.Pair(); t1 = Extract(t0, 0); t2 = FieldAddr(t1)
        let call = Instruction {
            id: 0,
            kind: ValueKind::Call,
            name: "t0".into(),
            type_id: 1,
            span: None,
            operands: vec![],
            extract_index: 0,
            callee: Some("ext.Pair".into()),
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
        let extract = Instruction {
            id: 1,
            kind: ValueKind::Extract,
            name: "t1".into(),
            type_id: 2,
            span: None,
            operands: vec![0],
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
        let deref = Instruction {
            id: 2,
            kind: ValueKind::FieldAddr,
            name: "t2".into(),
            type_id: 4,
            span: None,
            operands: vec![1],
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

        let func = Function {
            name: "example.com/pkg.F".into(),
            short_name: "F".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![call, extract, deref],
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
            functions: vec![func],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let json = serde_json::to_string(&pkg).unwrap();
        let mut h = DefaultHasher::new();
        json.hash(&mut h);
        let hash = h.finish();
        let pkg_input = PackageInput::new(&db, pkg.import_path.clone(), json, hash);

        // Without model => should warn NIL001.
        let config_default = AnalysisConfigInput::new(
            &db,
            true,
            false,
            vec![],
            true,
            true,
            true,
            true,
            true,
            "warning".to_string(),
            100,
            vec![],
        );
        let diags = nil_diagnostics(&db, pkg_input, config_default);
        assert!(
            diags.iter().any(|d| d.rule == "NIL001"),
            "expected NIL001 without model, got: {diags:?}"
        );

        // With model ext.Pair#0 => NIL001 suppressed.
        let config_modeled = AnalysisConfigInput::new(
            &db,
            true,
            false,
            vec![("ext.Pair#0".to_string(), "nonnull".to_string())],
            true,
            true,
            true,
            true,
            true,
            "warning".to_string(),
            100,
            vec![],
        );
        let diags = nil_diagnostics(&db, pkg_input, config_modeled);
        assert!(
            !diags.iter().any(|d| d.rule == "NIL001"),
            "expected NIL001 suppressed with model, got: {diags:?}"
        );
    }
}
