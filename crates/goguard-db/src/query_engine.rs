//! Query execution engine for GoGuard QL.
//!
//! Executes parsed [`Query`] ASTs against a set of [`Diagnostic`]s.

use std::collections::HashMap;

use crate::query::{Entity, Filter, Query, SortOrder};
use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::ir::Package;
use serde::Serialize;

/// The result of executing a GoGuard QL query.
#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    /// The result rows, each serialized as JSON.
    pub rows: Vec<serde_json::Value>,
    /// Total number of matching results (before limit/offset).
    pub total: usize,
}

/// Executes GoGuard QL queries against diagnostic and IR data.
pub struct QueryEngine<'a> {
    diagnostics: &'a [Diagnostic],
    packages: Option<&'a [Package]>,
}

impl<'a> QueryEngine<'a> {
    /// Create a new query engine over the given diagnostics (no IR data).
    pub fn new(diagnostics: &'a [Diagnostic]) -> Self {
        Self {
            diagnostics,
            packages: None,
        }
    }

    /// Create a query engine with both diagnostics and IR package data.
    ///
    /// This enables queries that require call graph or IR information,
    /// such as `callers of "pkg.Func"`.
    pub fn with_ir(diagnostics: &'a [Diagnostic], packages: &'a [Package]) -> Self {
        Self {
            diagnostics,
            packages: Some(packages),
        }
    }

    /// Execute JavaScript code against the analysis data (Code Mode).
    ///
    /// Delegates to [`JsRuntime::execute_with_setup`](crate::js_runtime::JsRuntime::execute_with_setup)
    /// with the `goguard` global object registered. The `goguard` global provides
    /// access to diagnostics, packages, functions, call graph, rules, taint flows,
    /// and config.
    ///
    /// # Errors
    ///
    /// Returns [`JsRuntimeError`](crate::js_runtime::JsRuntimeError) on syntax
    /// errors, runtime errors, infinite loops (via runtime limits), or if the
    /// result cannot be converted to JSON.
    pub fn execute_js(
        &self,
        code: &str,
    ) -> Result<serde_json::Value, crate::js_runtime::JsRuntimeError> {
        let packages = self.packages.unwrap_or(&[]);
        let api =
            crate::js_api::GoGuardJsApi::new(self.diagnostics, packages, serde_json::json!({}));

        let rt = crate::js_runtime::JsRuntime::new();
        rt.execute_with_setup(code, |ctx| {
            crate::js_api::register_api(&api, ctx)
                .map_err(|e| crate::js_runtime::JsRuntimeError::RuntimeError(e.to_string()))
        })
    }

    /// Execute a parsed query and return the results.
    pub fn execute(&self, query: &Query) -> QueryResult {
        match &query.entity {
            Entity::Diagnostics => self.query_diagnostics(query),
            Entity::Functions => self.query_functions(query),
            Entity::Packages => self.query_packages(query),
            Entity::Callers { target } => self.query_callers(target, query),
            Entity::TaintPaths { from, to } => self.query_taint_paths(from, to, query),
        }
    }

    // -----------------------------------------------------------------------
    // Diagnostics query
    // -----------------------------------------------------------------------

    fn query_diagnostics(&self, query: &Query) -> QueryResult {
        let mut results: Vec<&Diagnostic> = self.diagnostics.iter().collect();

        // Apply filter.
        if let Some(ref filter) = query.filter {
            results.retain(|d| matches_filter(d, filter));
        }

        let total = results.len();

        // Apply sorting.
        if let Some((ref field, ref order)) = query.order_by {
            results.sort_by(|a, b| {
                let va = get_field(a, field);
                let vb = get_field(b, field);
                let cmp = va.cmp(&vb);
                match order {
                    SortOrder::Asc => cmp,
                    SortOrder::Desc => cmp.reverse(),
                }
            });
        }

        // Apply offset.
        if let Some(offset) = query.offset {
            if offset < results.len() {
                results = results[offset..].to_vec();
            } else {
                results.clear();
            }
        }

        // Apply limit.
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        let rows = results
            .into_iter()
            .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null))
            .collect();

        QueryResult { rows, total }
    }

    // -----------------------------------------------------------------------
    // Functions query — group diagnostics by a "function" heuristic
    // -----------------------------------------------------------------------

    fn query_functions(&self, query: &Query) -> QueryResult {
        // Group diagnostics by file:line as a proxy for "function".
        // In a real implementation this would use bridge IR data.
        let mut groups: HashMap<String, Vec<&Diagnostic>> = HashMap::new();
        for d in self.diagnostics {
            let key = format!("{}:{}", d.location.file, d.location.line);
            groups.entry(key).or_default().push(d);
        }

        let mut rows: Vec<serde_json::Value> = groups
            .into_iter()
            .map(|(func, diags)| {
                serde_json::json!({
                    "function": func,
                    "diagnostic_count": diags.len(),
                    "diagnostics": diags.iter().map(|d| &d.id).collect::<Vec<_>>(),
                })
            })
            .collect();

        let total = rows.len();

        // Apply sorting.
        if let Some((ref field, ref order)) = query.order_by {
            rows.sort_by(|a, b| {
                let va = a.get(field).and_then(|v| v.as_i64()).unwrap_or(0);
                let vb = b.get(field).and_then(|v| v.as_i64()).unwrap_or(0);
                let cmp = va.cmp(&vb);
                match order {
                    SortOrder::Asc => cmp,
                    SortOrder::Desc => cmp.reverse(),
                }
            });
        }

        // Apply offset.
        if let Some(offset) = query.offset {
            if offset < rows.len() {
                rows = rows[offset..].to_vec();
            } else {
                rows.clear();
            }
        }

        // Apply limit.
        if let Some(limit) = query.limit {
            rows.truncate(limit);
        }

        QueryResult { rows, total }
    }

    // -----------------------------------------------------------------------
    // Packages query — group diagnostics by file (as package proxy)
    // -----------------------------------------------------------------------

    fn query_packages(&self, query: &Query) -> QueryResult {
        let mut groups: HashMap<String, Vec<&Diagnostic>> = HashMap::new();
        for d in self.diagnostics {
            // Use the file path as a package proxy (simplified).
            let package = d.location.file.clone();
            groups.entry(package).or_default().push(d);
        }

        let mut rows: Vec<serde_json::Value> = groups
            .into_iter()
            .map(|(pkg, diags)| {
                let rules: Vec<&str> = diags.iter().map(|d| d.rule.as_str()).collect();
                serde_json::json!({
                    "package": pkg,
                    "diagnostic_count": diags.len(),
                    "rules": rules,
                })
            })
            .collect();

        let total = rows.len();

        // Apply sorting.
        if let Some((ref field, ref order)) = query.order_by {
            rows.sort_by(|a, b| {
                let va = a.get(field).and_then(|v| v.as_i64()).unwrap_or(0);
                let vb = b.get(field).and_then(|v| v.as_i64()).unwrap_or(0);
                let cmp = va.cmp(&vb);
                match order {
                    SortOrder::Asc => cmp,
                    SortOrder::Desc => cmp.reverse(),
                }
            });
        }

        // Apply offset / limit.
        if let Some(offset) = query.offset {
            if offset < rows.len() {
                rows = rows[offset..].to_vec();
            } else {
                rows.clear();
            }
        }
        if let Some(limit) = query.limit {
            rows.truncate(limit);
        }

        QueryResult { rows, total }
    }

    // -----------------------------------------------------------------------
    // Callers / Taint — require bridge IR data; return empty for now.
    // -----------------------------------------------------------------------

    fn query_callers(&self, target: &str, query: &Query) -> QueryResult {
        let packages = match self.packages {
            Some(pkgs) => pkgs,
            None => {
                return QueryResult {
                    rows: Vec::new(),
                    total: 0,
                }
            }
        };

        let mut rows = Vec::new();
        for pkg in packages {
            let cg = goguard_ir::call_graph::CallGraph::from_package(pkg);
            for edge in cg.calls_to(target) {
                rows.push(serde_json::json!({
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "is_dynamic": edge.is_dynamic,
                    "is_go": edge.is_go,
                    "is_defer": edge.is_defer,
                    "span": edge.span.as_ref().map(|s| format!("{}:{}", s.file, s.start_line)),
                }));
            }
        }

        let total = rows.len();

        // Apply offset.
        if let Some(offset) = query.offset {
            if offset < rows.len() {
                rows = rows[offset..].to_vec();
            } else {
                rows.clear();
            }
        }
        // Apply limit.
        if let Some(limit) = query.limit {
            rows.truncate(limit);
        }

        QueryResult { rows, total }
    }

    fn query_taint_paths(&self, from: &str, to: &str, query: &Query) -> QueryResult {
        let from_lower = from.to_lowercase();
        let to_lower = to.to_lowercase();

        let mut rows: Vec<serde_json::Value> = self
            .diagnostics
            .iter()
            .filter(|d| d.rule.starts_with("TAINT"))
            .filter(|d| {
                let title_lower = d.title.to_lowercase();
                let explanation_lower = d.explanation.to_lowercase();
                let root_cause_lower = d
                    .root_cause
                    .as_ref()
                    .map(|rc| rc.description.to_lowercase())
                    .unwrap_or_default();

                let matches_from =
                    title_lower.contains(&from_lower) || root_cause_lower.contains(&from_lower);
                let matches_to =
                    title_lower.contains(&to_lower) || explanation_lower.contains(&to_lower);
                matches_from && matches_to
            })
            .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null))
            .collect();

        let total = rows.len();

        // Apply offset.
        if let Some(offset) = query.offset {
            if offset < rows.len() {
                rows = rows[offset..].to_vec();
            } else {
                rows.clear();
            }
        }
        // Apply limit.
        if let Some(limit) = query.limit {
            rows.truncate(limit);
        }

        QueryResult { rows, total }
    }
}

// ---------------------------------------------------------------------------
// Filter matching
// ---------------------------------------------------------------------------

/// Evaluate a [`Filter`] against a single diagnostic.
fn matches_filter(d: &Diagnostic, filter: &Filter) -> bool {
    match filter {
        Filter::Eq(field, value) => {
            let actual = get_field(d, field);
            actual.eq_ignore_ascii_case(value)
        }
        Filter::Ne(field, value) => {
            let actual = get_field(d, field);
            !actual.eq_ignore_ascii_case(value)
        }
        Filter::StartsWith(field, prefix) => {
            let actual = get_field(d, field);
            actual.starts_with(prefix.as_str())
        }
        Filter::Contains(field, substr) => {
            let actual = get_field(d, field);
            actual.contains(substr.as_str())
        }
        Filter::HasRule(pattern) => {
            // Simple glob: "NIL*" matches any rule starting with "NIL".
            if let Some(prefix) = pattern.strip_suffix('*') {
                d.rule.starts_with(prefix)
            } else {
                d.rule == *pattern
            }
        }
        Filter::And(a, b) => matches_filter(d, a) && matches_filter(d, b),
        Filter::Or(a, b) => matches_filter(d, a) || matches_filter(d, b),
    }
}

/// Extract a string field value from a diagnostic for comparison.
fn get_field(d: &Diagnostic, field: &str) -> String {
    match field {
        "severity" => d.severity.to_string(),
        "file" => d.location.file.clone(),
        "rule" => d.rule.clone(),
        "id" => d.id.clone(),
        "title" => d.title.clone(),
        "source" => d.source.to_string(),
        "confidence" => d.confidence.to_string(),
        "line" => d.location.line.to_string(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{Entity, Filter, Query};
    use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};
    use goguard_ir::ir::{CallEdge, Package, Span};

    fn test_diagnostics() -> Vec<Diagnostic> {
        vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "err ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 20, 1)
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("a.go", 30, 1)
            .build(),
        ]
    }

    #[test]
    fn test_query_diagnostics_no_filter() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let q = Query {
            entity: Entity::Diagnostics,
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 3);
        assert_eq!(result.total, 3);
    }

    #[test]
    fn test_query_diagnostics_severity_filter() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let q = Query {
            entity: Entity::Diagnostics,
            filter: Some(Filter::Eq("severity".into(), "critical".into())),
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn test_query_diagnostics_rule_starts_with() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let q = Query {
            entity: Entity::Diagnostics,
            filter: Some(Filter::StartsWith("rule".into(), "NIL".into())),
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn test_query_diagnostics_and_filter() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let q = Query {
            entity: Entity::Diagnostics,
            filter: Some(Filter::And(
                Box::new(Filter::Eq("file".into(), "a.go".into())),
                Box::new(Filter::StartsWith("rule".into(), "NIL".into())),
            )),
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 2); // NIL001 and NIL004, both in a.go
    }

    #[test]
    fn test_query_diagnostics_limit() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let q = Query {
            entity: Entity::Diagnostics,
            filter: None,
            order_by: None,
            limit: Some(2),
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.total, 3); // total is unfiltered count
    }

    #[test]
    fn test_query_packages() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let q = Query {
            entity: Entity::Packages,
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        // Should group by file (simplified: a.go has 2, b.go has 1)
        assert!(!result.rows.is_empty());
    }

    // -----------------------------------------------------------------------
    // Helper: build a test package with call edges
    // -----------------------------------------------------------------------

    fn make_test_package() -> Package {
        Package {
            import_path: "test/pkg".into(),
            name: "pkg".into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![
                CallEdge {
                    caller: "pkg.main".into(),
                    callee: "pkg.handler".into(),
                    span: Some(Span {
                        file: "main.go".into(),
                        start_line: 10,
                        start_col: 5,
                        end_line: 10,
                        end_col: 20,
                    }),
                    is_dynamic: false,
                    is_go: false,
                    is_defer: false,
                },
                CallEdge {
                    caller: "pkg.handler".into(),
                    callee: "pkg.process".into(),
                    span: Some(Span {
                        file: "handler.go".into(),
                        start_line: 25,
                        start_col: 3,
                        end_line: 25,
                        end_col: 18,
                    }),
                    is_dynamic: false,
                    is_go: true,
                    is_defer: false,
                },
                CallEdge {
                    caller: "pkg.init".into(),
                    callee: "pkg.handler".into(),
                    span: None,
                    is_dynamic: true,
                    is_go: false,
                    is_defer: false,
                },
            ],
            global_vars: vec![],
        }
    }

    fn make_taint_diagnostics() -> Vec<Diagnostic> {
        vec![
            DiagnosticBuilder::new(
                "TAINT001",
                Severity::Critical,
                "Taint flow from HTTP request to SQL query",
                DiagnosticSource::Taint,
            )
            .location("handler.go", 42, 5)
            .explanation("User input reaches sql.DB.Exec without sanitization")
            .root_cause("handler.go", 30, "HTTP request parameter read")
            .build(),
            DiagnosticBuilder::new(
                "TAINT002",
                Severity::Error,
                "Taint flow from HTTP request to command execution",
                DiagnosticSource::Taint,
            )
            .location("exec.go", 15, 3)
            .explanation("User input reaches os/exec.Command")
            .root_cause("exec.go", 10, "HTTP request body parsed")
            .build(),
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil pointer dereference",
                DiagnosticSource::Nil,
            )
            .location("main.go", 5, 1)
            .build(),
        ]
    }

    // -----------------------------------------------------------------------
    // QueryEngine with IR — creation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_engine_with_ir_creation() {
        let diags = test_diagnostics();
        let pkgs = vec![make_test_package()];
        let engine = QueryEngine::with_ir(&diags, &pkgs);

        // Diagnostics query should still work normally.
        let q = Query {
            entity: Entity::Diagnostics,
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 3);
        assert_eq!(result.total, 3);
    }

    #[test]
    fn test_engine_without_ir_callers_empty() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);

        let q = Query {
            entity: Entity::Callers {
                target: "pkg.handler".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.rows.len(), 0);
        assert_eq!(result.total, 0);
    }

    // -----------------------------------------------------------------------
    // query_callers tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_query_callers_found() {
        let diags = vec![];
        let pkgs = vec![make_test_package()];
        let engine = QueryEngine::with_ir(&diags, &pkgs);

        let q = Query {
            entity: Entity::Callers {
                target: "pkg.handler".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        // pkg.main and pkg.init both call pkg.handler
        assert_eq!(result.total, 2);
        assert_eq!(result.rows.len(), 2);

        let callers: Vec<&str> = result
            .rows
            .iter()
            .filter_map(|r| r.get("caller").and_then(|v| v.as_str()))
            .collect();
        assert!(callers.contains(&"pkg.main"));
        assert!(callers.contains(&"pkg.init"));

        // Verify span formatting for the edge with a span
        let main_row = result
            .rows
            .iter()
            .find(|r| r.get("caller").and_then(|v| v.as_str()) == Some("pkg.main"))
            .unwrap();
        assert_eq!(
            main_row.get("span").and_then(|v| v.as_str()),
            Some("main.go:10")
        );

        // Verify the dynamic edge has null span
        let init_row = result
            .rows
            .iter()
            .find(|r| r.get("caller").and_then(|v| v.as_str()) == Some("pkg.init"))
            .unwrap();
        assert!(init_row.get("is_dynamic").and_then(|v| v.as_bool()) == Some(true));
        assert!(init_row.get("span").unwrap().is_null());
    }

    #[test]
    fn test_query_callers_not_found() {
        let diags = vec![];
        let pkgs = vec![make_test_package()];
        let engine = QueryEngine::with_ir(&diags, &pkgs);

        let q = Query {
            entity: Entity::Callers {
                target: "pkg.nonexistent".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.total, 0);
        assert_eq!(result.rows.len(), 0);
    }

    #[test]
    fn test_query_callers_limit() {
        let diags = vec![];
        let pkgs = vec![make_test_package()];
        let engine = QueryEngine::with_ir(&diags, &pkgs);

        let q = Query {
            entity: Entity::Callers {
                target: "pkg.handler".into(),
            },
            filter: None,
            order_by: None,
            limit: Some(1),
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.total, 2); // Total before limit
        assert_eq!(result.rows.len(), 1); // Limited to 1
    }

    #[test]
    fn test_query_callers_offset() {
        let diags = vec![];
        let pkgs = vec![make_test_package()];
        let engine = QueryEngine::with_ir(&diags, &pkgs);

        let q = Query {
            entity: Entity::Callers {
                target: "pkg.handler".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: Some(1),
        };
        let result = engine.execute(&q);
        assert_eq!(result.total, 2); // Total before offset
        assert_eq!(result.rows.len(), 1); // Offset skips 1, leaves 1
    }

    // -----------------------------------------------------------------------
    // query_taint_paths tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_query_taint_paths_match() {
        let diags = make_taint_diagnostics();
        let engine = QueryEngine::new(&diags);

        let q = Query {
            entity: Entity::TaintPaths {
                from: "HTTP request".into(),
                to: "SQL".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        // Only TAINT001 matches: title has "HTTP request" and explanation has "sql"
        assert_eq!(result.total, 1);
        assert_eq!(result.rows.len(), 1);

        let row = &result.rows[0];
        assert_eq!(row.get("rule").and_then(|v| v.as_str()), Some("TAINT001"));
    }

    #[test]
    fn test_query_taint_paths_no_match() {
        let diags = make_taint_diagnostics();
        let engine = QueryEngine::new(&diags);

        let q = Query {
            entity: Entity::TaintPaths {
                from: "file system".into(),
                to: "network".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.total, 0);
        assert_eq!(result.rows.len(), 0);
    }

    #[test]
    fn test_query_taint_paths_excludes_non_taint() {
        let diags = make_taint_diagnostics();
        let engine = QueryEngine::new(&diags);

        // Even though NIL001 exists, taint_paths should only look at TAINT rules
        let q = Query {
            entity: Entity::TaintPaths {
                from: "nil".into(),
                to: "nil".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.total, 0);
    }

    #[test]
    fn test_query_taint_paths_limit() {
        let diags = make_taint_diagnostics();
        let engine = QueryEngine::new(&diags);

        // Both TAINT001 and TAINT002 match "HTTP request" in title
        // and both have "command" or "sql" matching any "to" that
        // appears in their explanation. Let's use a broad query.
        let q = Query {
            entity: Entity::TaintPaths {
                from: "HTTP request".into(),
                to: "exec".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        // TAINT001 explanation contains "sql.DB.Exec" — matches "exec"
        // TAINT002 explanation contains "os/exec.Command" — matches "exec"
        assert_eq!(result.total, 2);

        // Now with limit 1
        let q_limited = Query {
            entity: Entity::TaintPaths {
                from: "HTTP request".into(),
                to: "exec".into(),
            },
            filter: None,
            order_by: None,
            limit: Some(1),
            offset: None,
        };
        let result_limited = engine.execute(&q_limited);
        assert_eq!(result_limited.total, 2); // Total before limit
        assert_eq!(result_limited.rows.len(), 1);
    }

    #[test]
    fn test_query_taint_paths_case_insensitive() {
        let diags = make_taint_diagnostics();
        let engine = QueryEngine::new(&diags);

        // Test case-insensitive matching
        let q = Query {
            entity: Entity::TaintPaths {
                from: "http REQUEST".into(),
                to: "sql".into(),
            },
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        };
        let result = engine.execute(&q);
        assert_eq!(result.total, 1);
    }

    // -----------------------------------------------------------------------
    // execute_js — Code Mode integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_execute_js_goguard_global_exists() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let result = engine.execute_js("typeof goguard").unwrap();
        assert_eq!(result, serde_json::json!("object"));
    }

    #[test]
    fn test_execute_js_cross_entity_join() {
        // Correlate diagnostics with their file locations via JS.
        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref in handler",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 10, 1)
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "err ignored",
                DiagnosticSource::Errcheck,
            )
            .location("main.go", 20, 1)
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Critical,
                "nil map write",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 30, 1)
            .build(),
        ];
        let engine = QueryEngine::new(&diags);

        let result = engine
            .execute_js(
                r#"
                goguard.diagnostics()
                    .filter(d => d.severity === "critical")
                    .map(d => ({ rule: d.rule, file: d.location.file }))
                "#,
            )
            .unwrap();

        let arr = result.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
        // Both critical diagnostics should be present.
        let rules: Vec<&str> = arr
            .iter()
            .filter_map(|v| v.get("rule").and_then(|r| r.as_str()))
            .collect();
        assert!(rules.contains(&"NIL001"));
        assert!(rules.contains(&"NIL004"));
        // Verify file mapping.
        for item in arr {
            let rule = item.get("rule").unwrap().as_str().unwrap();
            let file = item.get("file").unwrap().as_str().unwrap();
            match rule {
                "NIL001" => assert_eq!(file, "handler.go"),
                "NIL004" => assert_eq!(file, "handler.go"),
                _ => panic!("unexpected rule: {rule}"),
            }
        }
    }

    #[test]
    fn test_execute_js_aggregation() {
        // Count diagnostics by severity.
        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "err ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 20, 1)
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Critical,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("a.go", 30, 1)
            .build(),
        ];
        let engine = QueryEngine::new(&diags);

        let result = engine
            .execute_js(
                r#"
                (() => {
                    let ds = goguard.diagnostics();
                    return {
                        total: ds.length,
                        critical: ds.filter(d => d.severity === "critical").length,
                        error: ds.filter(d => d.severity === "error").length
                    };
                })()
                "#,
            )
            .unwrap();

        assert_eq!(result.get("total").unwrap(), &serde_json::json!(3));
        assert_eq!(result.get("critical").unwrap(), &serde_json::json!(2));
        assert_eq!(result.get("error").unwrap(), &serde_json::json!(1));
    }

    #[test]
    fn test_execute_js_filtering_chaining() {
        // Chained filter + map to extract IDs of NIL-prefixed diagnostics.
        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "err ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 20, 1)
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("a.go", 30, 1)
            .build(),
        ];
        let engine = QueryEngine::new(&diags);

        let result = engine
            .execute_js(
                r#"
                goguard.diagnostics()
                    .filter(d => d.rule.startsWith("NIL"))
                    .map(d => d.id)
                "#,
            )
            .unwrap();

        let arr = result.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
        // All returned IDs should start with "NIL".
        for id_val in arr {
            let id = id_val.as_str().expect("id should be string");
            assert!(id.starts_with("NIL"), "expected NIL-prefixed id, got: {id}");
        }
    }

    #[test]
    fn test_execute_js_syntax_error() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let result = engine.execute_js("function {");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::js_runtime::JsRuntimeError::SyntaxError(_)),
            "Expected SyntaxError, got: {err:?}"
        );
    }

    #[test]
    fn test_execute_js_runtime_error() {
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let result = engine.execute_js("null.foo");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::js_runtime::JsRuntimeError::RuntimeError(_)),
            "Expected RuntimeError, got: {err:?}"
        );
    }

    #[test]
    fn test_execute_js_infinite_loop() {
        // The default loop iteration limit (1M) will catch this quickly.
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);
        let result = engine.execute_js("while(true) {}");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::js_runtime::JsRuntimeError::Timeout(_)),
            "Expected Timeout from RuntimeLimit, got: {err:?}"
        );
    }

    #[test]
    fn test_execute_js_with_packages() {
        // QueryEngine::with_ir() should expose packages via goguard.packages().
        let diags = test_diagnostics();
        let pkgs = vec![make_test_package()];
        let engine = QueryEngine::with_ir(&diags, &pkgs);

        let result = engine.execute_js("goguard.packages().length").unwrap();
        assert_eq!(result, serde_json::json!(1));

        let result = engine.execute_js("goguard.packages()[0].name").unwrap();
        assert_eq!(result, serde_json::json!("pkg"));
    }

    #[test]
    fn test_execute_js_without_packages() {
        // QueryEngine::new() has no packages — goguard.packages() returns [].
        let diags = test_diagnostics();
        let engine = QueryEngine::new(&diags);

        let result = engine.execute_js("goguard.packages().length").unwrap();
        assert_eq!(result, serde_json::json!(0));
    }
}
