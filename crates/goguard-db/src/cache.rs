//! Caching layer mapping bridge IR to Salsa inputs.
//!
//! `IrCache` serializes each `Package` to JSON, computes a hash, and only
//! updates the corresponding `PackageInput` in the Salsa DB if the hash changed.
//! This is the key optimization: if a package hasn't changed, Salsa skips all
//! analysis functions that depend on it.

use std::collections::HashMap;

use salsa::Setter;

use crate::db::GoGuardDatabase;
use crate::inputs::{AnalysisConfigInput, GlobalContextInput, PackageInput};
use goguard_ir::ir::AnalysisInput;

/// Manages the mapping between bridge IR packages and Salsa inputs.
#[derive(Clone)]
pub struct IrCache {
    /// Maps import_path -> PackageInput for existing packages.
    packages: HashMap<String, PackageInput>,
    /// The analysis config input, if set.
    config: Option<AnalysisConfigInput>,
    /// Global context (interface_table, enum_groups) for exhaustive analysis.
    global_context: Option<GlobalContextInput>,
}

impl IrCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            packages: HashMap::new(),
            config: None,
            global_context: None,
        }
    }

    /// Update the Salsa DB with new IR from the bridge.
    /// Returns the count of actually-changed packages (where hash differed).
    pub fn update_ir(&mut self, db: &mut GoGuardDatabase, ir: &AnalysisInput) -> usize {
        let mut changed = 0;

        // Track which import paths are in the current IR
        let mut current_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

        for pkg in &ir.packages {
            current_paths.insert(pkg.import_path.clone());

            let json = serde_json::to_string(pkg).expect("serialize Package to JSON");
            let hash = hash_str(&json);

            if let Some(&existing) = self.packages.get(&pkg.import_path) {
                // Package already exists -- check if hash changed
                if existing.content_hash(db) == hash {
                    // No change -- skip update
                    continue;
                }
                // Hash changed -- update the existing input
                existing.set_ir_json(db).to(json);
                existing.set_content_hash(db).to(hash);
                changed += 1;
            } else {
                // New package -- create a new Salsa input
                let input = PackageInput::new(db, pkg.import_path.clone(), json, hash);
                self.packages.insert(pkg.import_path.clone(), input);
                changed += 1;
            }
        }

        // Remove stale packages that are no longer in the IR
        self.packages.retain(|path, _| current_paths.contains(path));

        changed
    }

    /// Update the analysis configuration.
    /// Takes individual fields to avoid circular dependency with goguard-core.
    #[allow(clippy::too_many_arguments)]
    pub fn update_config(
        &mut self,
        db: &mut GoGuardDatabase,
        nil_enabled: bool,
        nil_strict_params: bool,
        nil_models: &[(String, String)],
        errcheck_enabled: bool,
        concurrency_enabled: bool,
        ownership_enabled: bool,
        exhaustive_enabled: bool,
        taint_enabled: bool,
        severity_threshold: &str,
        max_diagnostics: usize,
        errcheck_ignore: &[String],
    ) {
        match self.config {
            Some(existing) => {
                existing.set_nil_enabled(db).to(nil_enabled);
                existing.set_nil_strict_params(db).to(nil_strict_params);
                existing.set_nil_models(db).to(nil_models.to_vec());
                existing.set_errcheck_enabled(db).to(errcheck_enabled);
                existing.set_concurrency_enabled(db).to(concurrency_enabled);
                existing.set_ownership_enabled(db).to(ownership_enabled);
                existing.set_exhaustive_enabled(db).to(exhaustive_enabled);
                existing.set_taint_enabled(db).to(taint_enabled);
                existing
                    .set_severity_threshold(db)
                    .to(severity_threshold.to_string());
                existing.set_max_diagnostics(db).to(max_diagnostics);
                existing
                    .set_errcheck_ignore(db)
                    .to(errcheck_ignore.to_vec());
            }
            None => {
                let config = AnalysisConfigInput::new(
                    db,
                    nil_enabled,
                    nil_strict_params,
                    nil_models.to_vec(),
                    errcheck_enabled,
                    concurrency_enabled,
                    ownership_enabled,
                    exhaustive_enabled,
                    taint_enabled,
                    severity_threshold.to_string(),
                    max_diagnostics,
                    errcheck_ignore.to_vec(),
                );
                self.config = Some(config);
            }
        }
    }

    /// Update the global analysis context (interface_table, enum_groups).
    pub fn update_global_context(&mut self, db: &mut GoGuardDatabase, ir: &AnalysisInput) {
        let iface_json =
            serde_json::to_string(&ir.interface_table).expect("serialize interface_table");
        let enum_json = serde_json::to_string(&ir.enum_groups).expect("serialize enum_groups");
        let combined = format!("{}{}", iface_json, enum_json);
        let hash = hash_str(&combined);

        match self.global_context {
            Some(existing) => {
                if existing.content_hash(db) != hash {
                    existing.set_interface_table_json(db).to(iface_json);
                    existing.set_enum_groups_json(db).to(enum_json);
                    existing.set_content_hash(db).to(hash);
                }
            }
            None => {
                let ctx = GlobalContextInput::new(db, iface_json, enum_json, hash);
                self.global_context = Some(ctx);
            }
        }
    }

    /// Get all tracked package inputs.
    pub fn all_packages(&self) -> Vec<PackageInput> {
        self.packages.values().copied().collect()
    }

    /// Get the config input, if set.
    pub fn config(&self) -> Option<AnalysisConfigInput> {
        self.config
    }

    /// Get the global context input, if set.
    pub fn global_context(&self) -> Option<GlobalContextInput> {
        self.global_context
    }
}

impl Default for IrCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a hash of a string using the standard library's DefaultHasher.
fn hash_str(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::GoGuardDatabase;
    use goguard_ir::ir::{AnalysisInput, Package};

    fn make_ir(packages: Vec<Package>) -> AnalysisInput {
        AnalysisInput {
            packages,
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        }
    }

    fn make_package(import_path: &str) -> Package {
        Package {
            import_path: import_path.into(),
            name: import_path.split('/').next_back().unwrap_or("main").into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        }
    }

    #[test]
    fn test_update_ir_first_time() {
        let mut db = GoGuardDatabase::default();
        let mut cache = IrCache::new();
        let ir = make_ir(vec![
            make_package("example.com/a"),
            make_package("example.com/b"),
        ]);
        let changed = cache.update_ir(&mut db, &ir);
        assert_eq!(changed, 2, "both packages should be new");
        assert_eq!(cache.all_packages().len(), 2);
    }

    #[test]
    fn test_update_ir_no_change() {
        let mut db = GoGuardDatabase::default();
        let mut cache = IrCache::new();
        let ir = make_ir(vec![make_package("example.com/a")]);
        cache.update_ir(&mut db, &ir);
        let changed = cache.update_ir(&mut db, &ir);
        assert_eq!(changed, 0, "same IR should produce zero changes");
    }

    #[test]
    fn test_update_ir_one_changed() {
        let mut db = GoGuardDatabase::default();
        let mut cache = IrCache::new();

        let ir1 = make_ir(vec![
            make_package("example.com/a"),
            make_package("example.com/b"),
        ]);
        cache.update_ir(&mut db, &ir1);

        // Modify package b by adding a function
        let mut pkg_b = make_package("example.com/b");
        pkg_b.functions.push(goguard_ir::ir::Function {
            name: "b.Hello".into(),
            short_name: "Hello".into(),
            span: None,
            blocks: vec![],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: true,
            free_vars: vec![],
            defers: vec![],
        });
        let ir2 = make_ir(vec![make_package("example.com/a"), pkg_b]);
        let changed = cache.update_ir(&mut db, &ir2);
        assert_eq!(changed, 1, "only package b should have changed");
    }

    #[test]
    fn test_update_config() {
        let mut db = GoGuardDatabase::default();
        let mut cache = IrCache::new();

        cache.update_config(
            &mut db,
            true,
            false,
            &[],
            true,
            true,
            true,
            true,
            true,
            "warning",
            100,
            &["fmt.Print*".to_string()],
        );
        let config = cache.config().expect("config should be set");
        assert!(config.nil_enabled(&db));
        assert!(config.concurrency_enabled(&db));
        assert!(config.taint_enabled(&db));
        assert_eq!(config.max_diagnostics(&db), 100);

        // Update config
        cache.update_config(
            &mut db,
            false,
            false,
            &[],
            true,
            false,
            true,
            true,
            false,
            "error",
            50,
            &[],
        );
        let config = cache.config().expect("config should still be set");
        assert!(!config.nil_enabled(&db));
        assert!(!config.concurrency_enabled(&db));
        assert_eq!(config.severity_threshold(&db), "error");
        assert_eq!(config.max_diagnostics(&db), 50);
    }
}
