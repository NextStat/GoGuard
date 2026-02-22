//! Call graph helpers for inter-procedural analysis.
//!
//! Provides indexed access to the call graph edges produced by the Go bridge.
//! The call graph is built by go/ssa's pointer analysis in the bridge and
//! deserialized here for traversal.

use crate::ir::{CallEdge, Package};
use std::collections::{HashMap, HashSet};

/// Indexed call graph for a package
pub struct CallGraph {
    /// Edges indexed by caller function name
    callers: HashMap<String, Vec<CallEdge>>,
    /// Edges indexed by callee function name
    callees: HashMap<String, Vec<CallEdge>>,
    /// All unique function names in the call graph
    functions: HashSet<String>,
}

impl CallGraph {
    /// Build a call graph index from a package's call edges
    pub fn from_package(pkg: &Package) -> Self {
        let mut callers: HashMap<String, Vec<CallEdge>> = HashMap::new();
        let mut callees: HashMap<String, Vec<CallEdge>> = HashMap::new();
        let mut functions = HashSet::new();

        for edge in &pkg.call_edges {
            functions.insert(edge.caller.clone());
            functions.insert(edge.callee.clone());
            callers
                .entry(edge.caller.clone())
                .or_default()
                .push(edge.clone());
            callees
                .entry(edge.callee.clone())
                .or_default()
                .push(edge.clone());
        }

        Self {
            callers,
            callees,
            functions,
        }
    }

    /// Get all call edges where `func_name` is the caller
    pub fn calls_from(&self, func_name: &str) -> &[CallEdge] {
        self.callers
            .get(func_name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all call edges where `func_name` is the callee
    pub fn calls_to(&self, func_name: &str) -> &[CallEdge] {
        self.callees
            .get(func_name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all function names in the call graph
    pub fn functions(&self) -> &HashSet<String> {
        &self.functions
    }

    /// Check if a function has any callers
    pub fn has_callers(&self, func_name: &str) -> bool {
        self.callees
            .get(func_name)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Check if a function calls anything
    pub fn has_callees(&self, func_name: &str) -> bool {
        self.callers
            .get(func_name)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Get the number of edges in the call graph
    pub fn edge_count(&self) -> usize {
        self.callers.values().map(|v| v.len()).sum()
    }

    /// Find all functions transitively reachable from the given function
    pub fn transitive_callees(&self, func_name: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(func_name.to_string());

        while let Some(name) = queue.pop_front() {
            if visited.insert(name.clone()) {
                for edge in self.calls_from(&name) {
                    if !visited.contains(&edge.callee) {
                        queue.push_back(edge.callee.clone());
                    }
                }
            }
        }

        // Remove the starting function itself
        visited.remove(func_name);
        visited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::*;

    fn make_test_package() -> Package {
        Package {
            import_path: "example.com/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            global_vars: vec![],
            call_edges: vec![
                CallEdge {
                    caller: "pkg.Main".into(),
                    callee: "pkg.GetUser".into(),
                    span: None,
                    is_dynamic: false,
                    is_go: false,
                    is_defer: false,
                },
                CallEdge {
                    caller: "pkg.Main".into(),
                    callee: "pkg.SaveUser".into(),
                    span: None,
                    is_dynamic: false,
                    is_go: false,
                    is_defer: false,
                },
                CallEdge {
                    caller: "pkg.GetUser".into(),
                    callee: "db.Find".into(),
                    span: None,
                    is_dynamic: false,
                    is_go: false,
                    is_defer: false,
                },
                CallEdge {
                    caller: "pkg.SaveUser".into(),
                    callee: "db.Save".into(),
                    span: None,
                    is_dynamic: false,
                    is_go: false,
                    is_defer: false,
                },
            ],
        }
    }

    #[test]
    fn test_calls_from() {
        let pkg = make_test_package();
        let cg = CallGraph::from_package(&pkg);

        let from_main = cg.calls_from("pkg.Main");
        assert_eq!(from_main.len(), 2);

        let from_get = cg.calls_from("pkg.GetUser");
        assert_eq!(from_get.len(), 1);
        assert_eq!(from_get[0].callee, "db.Find");
    }

    #[test]
    fn test_calls_to() {
        let pkg = make_test_package();
        let cg = CallGraph::from_package(&pkg);

        let to_get = cg.calls_to("pkg.GetUser");
        assert_eq!(to_get.len(), 1);
        assert_eq!(to_get[0].caller, "pkg.Main");

        let to_main = cg.calls_to("pkg.Main");
        assert_eq!(to_main.len(), 0);
    }

    #[test]
    fn test_has_callers_callees() {
        let pkg = make_test_package();
        let cg = CallGraph::from_package(&pkg);

        assert!(cg.has_callees("pkg.Main"));
        assert!(!cg.has_callers("pkg.Main"));
        assert!(cg.has_callers("pkg.GetUser"));
        assert!(cg.has_callees("pkg.GetUser"));
        assert!(cg.has_callers("db.Find"));
        assert!(!cg.has_callees("db.Find"));
    }

    #[test]
    fn test_edge_count() {
        let pkg = make_test_package();
        let cg = CallGraph::from_package(&pkg);
        assert_eq!(cg.edge_count(), 4);
    }

    #[test]
    fn test_transitive_callees() {
        let pkg = make_test_package();
        let cg = CallGraph::from_package(&pkg);

        let reachable = cg.transitive_callees("pkg.Main");
        assert!(reachable.contains("pkg.GetUser"));
        assert!(reachable.contains("pkg.SaveUser"));
        assert!(reachable.contains("db.Find"));
        assert!(reachable.contains("db.Save"));
        assert!(!reachable.contains("pkg.Main")); // excludes self
    }

    #[test]
    fn test_empty_call_graph() {
        let pkg = Package {
            import_path: "empty".into(),
            name: "empty".into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };
        let cg = CallGraph::from_package(&pkg);
        assert_eq!(cg.edge_count(), 0);
        assert!(cg.functions().is_empty());
    }
}
