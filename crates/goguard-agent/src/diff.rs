//! Git diff-based incremental analysis for changed files.
//!
//! Detects changed `.go` files using gix (pure-Rust git), maps them to
//! Go packages, and expands affected packages via reverse call graph edges.

use std::collections::{HashSet, VecDeque};
use std::path::Path;

use goguard_ir::ir::Package;

/// Changed files detected by git diff.
#[derive(Debug, Clone, Default)]
pub struct ChangedFiles {
    /// Relative paths of changed `.go` files.
    pub go_files: Vec<String>,
    /// True if the project is not a git repo (fall back to full analysis).
    pub no_git: bool,
}

/// Errors from diff detection.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("not a git repository")]
    NotGitRepo,
    #[error("git error: {0}")]
    Git(String),
}

/// Detect changed `.go` files (worktree vs HEAD).
///
/// Uses gix to discover the repo, then iterates the status to find
/// modified/added/deleted `.go` files. Returns `ChangedFiles { no_git: true }`
/// if the directory is not a git repository.
pub fn detect_changed_go_files(project_dir: &Path) -> Result<ChangedFiles, DiffError> {
    let repo = match gix::discover(project_dir) {
        Ok(repo) => repo,
        Err(e) => {
            // Check if it's specifically "not a repo" vs other errors
            let msg = e.to_string();
            if msg.contains("not a git repository") || msg.contains("could not find") {
                return Ok(ChangedFiles {
                    go_files: vec![],
                    no_git: true,
                });
            }
            return Err(DiffError::Git(msg));
        }
    };

    let mut go_files = Vec::new();

    // Use gix status to find changed files (index vs worktree).
    // `into_index_worktree_iter` takes `impl IntoIterator<Item = BString>` patterns.
    let status = repo
        .status(gix::progress::Discard)
        .map_err(|e| DiffError::Git(e.to_string()))?
        .into_index_worktree_iter(Vec::<gix::bstr::BString>::new())
        .map_err(|e| DiffError::Git(e.to_string()))?;

    for item in status {
        let item = item.map_err(|e| DiffError::Git(e.to_string()))?;
        // Get the path from the status entry
        let path_str = item.rela_path().to_string();
        if path_str.ends_with(".go") {
            go_files.push(path_str);
        }
    }

    Ok(ChangedFiles {
        go_files,
        no_git: false,
    })
}

/// Map file paths to package import paths.
///
/// Given a list of changed `.go` file paths (relative to module root),
/// the module path (e.g., `example.com/app`), and the module root directory,
/// computes the set of affected package import paths.
///
/// Example: `"internal/handler/user.go"` + `"example.com/app"` -> `"example.com/app/internal/handler"`
pub fn files_to_packages(
    changed: &ChangedFiles,
    module_path: &str,
    _module_root: &Path,
) -> Vec<String> {
    let mut packages: HashSet<String> = HashSet::new();

    for file in &changed.go_files {
        // Strip the filename to get the directory
        let dir = match file.rsplit_once('/') {
            Some((dir, _)) => dir,
            None => "", // root package
        };

        let import_path = if dir.is_empty() {
            module_path.to_string()
        } else {
            format!("{}/{}", module_path, dir)
        };
        packages.insert(import_path);
    }

    packages.into_iter().collect()
}

/// Expand changed packages to include reverse callers via call_edges.
///
/// Given a set of directly changed packages and all packages (with call edges),
/// performs a BFS through the reverse dependency graph to find all packages
/// that might be affected by the changes.
pub fn expand_affected_packages(changed_pkgs: &[String], all_packages: &[Package]) -> Vec<String> {
    // Build reverse dependency map: callee_pkg -> {caller_pkg, ...}
    let mut reverse_deps: std::collections::HashMap<String, HashSet<String>> =
        std::collections::HashMap::new();

    for pkg in all_packages {
        for edge in &pkg.call_edges {
            // Determine the callee's package from the callee function name
            // Callee is like "example.com/app/handler.GetUser" -> package is "example.com/app/handler"
            let callee_pkg = function_to_package(&edge.callee);
            let caller_pkg = &pkg.import_path;

            if callee_pkg != *caller_pkg {
                reverse_deps
                    .entry(callee_pkg)
                    .or_default()
                    .insert(caller_pkg.clone());
            }
        }
    }

    // BFS from changed packages through reverse deps
    let mut affected: HashSet<String> = changed_pkgs.iter().cloned().collect();
    let mut queue: VecDeque<String> = changed_pkgs.iter().cloned().collect();

    while let Some(pkg) = queue.pop_front() {
        if let Some(callers) = reverse_deps.get(&pkg) {
            for caller in callers {
                if affected.insert(caller.clone()) {
                    queue.push_back(caller.clone());
                }
            }
        }
    }

    affected.into_iter().collect()
}

/// Extract the package path from a fully-qualified Go function name.
///
/// `"example.com/app/handler.GetUser"` -> `"example.com/app/handler"`
/// `"(example.com/app/handler.Server).Start"` -> `"example.com/app/handler"`
fn function_to_package(func_name: &str) -> String {
    // Handle method receivers like "(pkg.Type).Method"
    let name = func_name
        .strip_prefix('(')
        .and_then(|s| s.split_once(')'))
        .map(|(inside, _)| inside)
        .unwrap_or(func_name);

    // Remove the function/method name after the last dot
    // But be careful: the package path itself contains dots (e.g., "example.com")
    // The function name is after the last '.' that follows a '/'
    // "example.com/handler.GetUser" -> last segment is "handler.GetUser"
    match name.rsplit_once('/') {
        Some((prefix, last_segment)) => {
            // last_segment is like "handler.GetUser" or "handler.Server"
            match last_segment.split_once('.') {
                Some((pkg_part, _)) => format!("{}/{}", prefix, pkg_part),
                None => name.to_string(), // no dot in last segment, whole thing is the package
            }
        }
        None => {
            // No '/' -- could be "main.Func" or just "Func"
            match name.split_once('.') {
                Some((pkg_part, _)) => pkg_part.to_string(),
                None => name.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::{CallEdge, Package};

    fn make_package_with_edges(import_path: &str, edges: Vec<CallEdge>) -> Package {
        Package {
            import_path: import_path.into(),
            name: import_path.split('/').next_back().unwrap_or("main").into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: edges,
            global_vars: vec![],
        }
    }

    fn make_edge(caller: &str, callee: &str) -> CallEdge {
        CallEdge {
            caller: caller.into(),
            callee: callee.into(),
            span: None,
            is_dynamic: false,
            is_go: false,
            is_defer: false,
        }
    }

    #[test]
    fn test_files_to_packages_basic() {
        let changed = ChangedFiles {
            go_files: vec!["handler/user.go".into()],
            no_git: false,
        };
        let pkgs = files_to_packages(&changed, "example.com/app", Path::new("."));
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs.contains(&"example.com/app/handler".to_string()));
    }

    #[test]
    fn test_files_to_packages_root_file() {
        let changed = ChangedFiles {
            go_files: vec!["main.go".into()],
            no_git: false,
        };
        let pkgs = files_to_packages(&changed, "example.com/app", Path::new("."));
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs.contains(&"example.com/app".to_string()));
    }

    #[test]
    fn test_files_to_packages_nested() {
        let changed = ChangedFiles {
            go_files: vec!["internal/handler/v2/user.go".into()],
            no_git: false,
        };
        let pkgs = files_to_packages(&changed, "example.com/app", Path::new("."));
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs.contains(&"example.com/app/internal/handler/v2".to_string()));
    }

    #[test]
    fn test_expand_no_callers() {
        let pkg_a = make_package_with_edges("example.com/a", vec![]);
        let pkg_b = make_package_with_edges("example.com/b", vec![]);
        let all = vec![pkg_a, pkg_b];

        let mut result = expand_affected_packages(&["example.com/a".into()], &all);
        result.sort();
        assert_eq!(result, vec!["example.com/a"]);
    }

    #[test]
    fn test_expand_with_callers() {
        // Package A calls into package B
        let pkg_a = make_package_with_edges(
            "example.com/a",
            vec![make_edge("example.com/a.Foo", "example.com/b.Bar")],
        );
        let pkg_b = make_package_with_edges("example.com/b", vec![]);
        let all = vec![pkg_a, pkg_b];

        // B changes -> A should also be affected (A calls B)
        let mut result = expand_affected_packages(&["example.com/b".into()], &all);
        result.sort();
        assert_eq!(result, vec!["example.com/a", "example.com/b"]);
    }
}
