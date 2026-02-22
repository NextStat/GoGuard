//! Core taint analysis engine.
//!
//! Top-level `TaintAnalyzer` that orchestrates intra- and inter-procedural
//! taint analysis and converts detected flows into `Diagnostic` values.

use std::collections::HashMap;

use goguard_diagnostics::diagnostic::{
    Diagnostic, DiagnosticBuilder, DiagnosticSource, Frequency, Severity,
};
use goguard_ir::ir::{AnalysisInput, Package};

use crate::propagation::{self, TaintFlow, TaintState};
use crate::sinks::SinkKind;

/// Top-level taint analyzer.
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    /// Analyze all packages in the input for taint vulnerabilities.
    pub fn analyze(input: &AnalysisInput) -> Vec<Diagnostic> {
        input
            .packages
            .iter()
            .flat_map(Self::analyze_package)
            .collect()
    }

    /// Analyze a single package for taint vulnerabilities.
    ///
    /// Used by the Salsa incremental computation path.
    pub fn analyze_package(pkg: &Package) -> Vec<Diagnostic> {
        let mut all_flows = Vec::new();
        let mut function_taints: HashMap<String, HashMap<u32, TaintState>> = HashMap::new();

        // Phase 1: Intra-procedural taint analysis for each function.
        for func in &pkg.functions {
            let flows = propagation::propagate_taint(func, pkg);
            all_flows.extend(flows);

            // Build per-function taint maps for inter-procedural analysis.
            let mut taint_map = HashMap::new();
            // Re-run lightweight taint tracking to capture the full map.
            // (The propagate_taint function returns flows, not the map itself,
            //  so we reconstruct the essentials here.)
            for block in &func.blocks {
                for instr in &block.instructions {
                    if let Some(source) = crate::sources::is_source_instruction(instr) {
                        taint_map.insert(
                            instr.id,
                            TaintState::Tainted {
                                source,
                                source_instruction_id: instr.id,
                            },
                        );
                    }
                    if instr.kind == goguard_ir::ir::ValueKind::Call {
                        if let Some(callee) = &instr.callee {
                            if let Some(source) = crate::sources::classify_source(callee) {
                                taint_map.insert(
                                    instr.id,
                                    TaintState::Tainted {
                                        source,
                                        source_instruction_id: instr.id,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            if !taint_map.is_empty() {
                function_taints.insert(func.name.clone(), taint_map);
            }
        }

        // Phase 2: Inter-procedural taint propagation.
        let tainted_params = propagation::propagate_interprocedural(pkg, &function_taints);

        // Re-analyze functions with newly tainted parameters.
        for func in &pkg.functions {
            if let Some(params) = tainted_params.get(&func.name) {
                if !params.is_empty() {
                    let extra_flows = propagation::propagate_taint_with_params(func, pkg, params);
                    all_flows.extend(extra_flows);
                }
            }
        }

        // Phase 3: Convert flows to diagnostics.
        all_flows.iter().map(flow_to_diagnostic).collect()
    }
}

/// Convert a `TaintFlow` into a `Diagnostic`.
fn flow_to_diagnostic(flow: &TaintFlow) -> Diagnostic {
    let (rule, severity, confidence, pattern_name, go_idiom) = match flow.sink_kind {
        SinkKind::SqlQuery => (
            "TAINT001",
            Severity::Critical,
            0.9,
            "sql-injection",
            "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
        ),
        SinkKind::CommandExec => (
            "TAINT002",
            Severity::Critical,
            0.9,
            "command-injection",
            "Validate and sanitize input before passing to exec.Command, or use an allowlist",
        ),
        SinkKind::FilePath => (
            "TAINT003",
            Severity::Critical,
            0.85,
            "path-traversal",
            "Use filepath.Clean and filepath.Base to sanitize paths, and validate against a base directory",
        ),
        SinkKind::HtmlOutput => (
            "TAINT004",
            Severity::Warning,
            0.8,
            "xss",
            "Use html.EscapeString or html/template auto-escaping instead of html/template.HTML",
        ),
    };

    let title = format!(
        "Tainted data from {} flows to {} without sanitization",
        flow.source, flow.sink_kind
    );

    let explanation = format!(
        "User-controlled data originating from {} reaches a dangerous {} operation \
         in function `{}`. This can lead to {}.",
        flow.source,
        flow.sink_kind,
        flow.function_name,
        match flow.sink_kind {
            SinkKind::SqlQuery => "SQL injection attacks",
            SinkKind::CommandExec => "arbitrary command execution",
            SinkKind::FilePath => "path traversal attacks",
            SinkKind::HtmlOutput => "cross-site scripting (XSS)",
        }
    );

    let (file, line, col) = match &flow.sink_span {
        Some(span) => (span.file.as_str(), span.start_line, span.start_col),
        None => ("unknown", 0, 0),
    };

    let mut builder = DiagnosticBuilder::new(rule, severity, &title, DiagnosticSource::Taint)
        .location(file, line, col)
        .confidence(confidence)
        .explanation(explanation)
        .pattern(pattern_name, Frequency::Common, go_idiom);

    // Add root cause if source span is available.
    if let Some(source_span) = &flow.source_span {
        builder = builder.root_cause(
            &source_span.file,
            source_span.start_line,
            format!("User input enters here via {}", flow.source),
        );
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_ir::ir::*;

    fn make_instr(id: u32, kind: ValueKind, name: &str, type_id: u32) -> Instruction {
        Instruction {
            id,
            kind,
            name: name.into(),
            type_id,
            span: Some(Span::new("handler.go", id + 10, 1)),
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

    fn make_call(id: u32, callee: &str, operands: Vec<u32>, type_id: u32) -> Instruction {
        let mut instr = make_instr(id, ValueKind::Call, &format!("t{}", id), type_id);
        instr.callee = Some(callee.into());
        instr.operands = operands;
        instr
    }

    fn make_block(id: u32, instructions: Vec<Instruction>) -> BasicBlock {
        BasicBlock {
            id,
            name: format!("b{}", id),
            instructions,
            is_return: true,
            is_panic: false,
        }
    }

    fn make_func(name: &str, blocks: Vec<BasicBlock>) -> Function {
        Function {
            name: name.into(),
            short_name: name.split('.').next_back().unwrap_or(name).into(),
            span: None,
            blocks,
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn make_package(functions: Vec<Function>) -> Package {
        Package {
            import_path: "example.com/test".into(),
            name: "test".into(),
            files: vec![],
            types: vec![],
            functions,
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        }
    }

    #[test]
    fn test_taint001_sql_injection() {
        // HTTP request data -> sql.DB.Query
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sink = make_call(1, "(*database/sql.DB).Query", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "TAINT001");
        assert_eq!(diags[0].severity, Severity::Critical);
        assert_eq!(diags[0].confidence, 0.9);
        assert_eq!(diags[0].source, DiagnosticSource::Taint);
        assert!(diags[0].title.contains("SQL query"));
        assert!(diags[0].explanation.contains("SQL injection"));
    }

    #[test]
    fn test_taint002_command_injection() {
        // Environment variable -> exec.Command
        let source = make_call(0, "os.Getenv", vec![], 0);
        let sink = make_call(1, "os/exec.Command", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "TAINT002");
        assert_eq!(diags[0].severity, Severity::Critical);
        assert!(diags[0].explanation.contains("command execution"));
    }

    #[test]
    fn test_taint003_path_traversal() {
        // HTTP request -> os.Open
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sink = make_call(1, "os.Open", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "TAINT003");
        assert_eq!(diags[0].severity, Severity::Critical);
        assert_eq!(diags[0].confidence, 0.85);
        assert!(diags[0].explanation.contains("path traversal"));
    }

    #[test]
    fn test_taint004_xss() {
        // HTTP request -> html/template.HTML (type conversion)
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sink = make_call(1, "html/template.HTML", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "TAINT004");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].confidence, 0.8);
        assert!(diags[0].explanation.contains("XSS"));
    }

    #[test]
    fn test_safe_with_sanitizer() {
        // HTTP request -> filepath.Clean -> os.Open: no diagnostic.
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sanitizer = make_call(1, "path/filepath.Clean", vec![0], 0);
        let sink = make_call(2, "os.Open", vec![1], 0);

        let func = make_func(
            "test.handler",
            vec![make_block(0, vec![source, sanitizer, sink])],
        );
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "sanitized data should not produce diagnostics, got {} diagnostics",
            diags.len()
        );
    }

    #[test]
    fn test_analyze_empty_package() {
        let pkg = Package {
            import_path: "example.com/empty".into(),
            name: "empty".into(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        };

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "empty package should produce zero diagnostics"
        );
    }

    #[test]
    fn test_analyze_package_matches_analyze() {
        // Verify that analyze() and analyze_package() produce consistent results.
        let source = make_call(0, "os.Getenv", vec![], 0);
        let sink = make_call(1, "os/exec.Command", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let input = AnalysisInput {
            packages: vec![pkg.clone()],
            go_version: "1.26".into(),
            bridge_version: "0.2.0".into(),
            interface_table: vec![],
            enum_groups: vec![],
        };

        let from_analyze = TaintAnalyzer::analyze(&input);
        let from_package = TaintAnalyzer::analyze_package(&input.packages[0]);

        assert_eq!(
            from_analyze.len(),
            from_package.len(),
            "analyze and analyze_package should produce same number of diagnostics"
        );
        for (a, b) in from_analyze.iter().zip(from_package.iter()) {
            assert_eq!(a.rule, b.rule);
            assert_eq!(a.severity, b.severity);
            assert_eq!(a.title, b.title);
        }
    }

    #[test]
    fn test_multiple_flows_in_one_function() {
        // Two distinct flows in the same function.
        let source1 = make_call(0, "os.Getenv", vec![], 0);
        let sink1 = make_call(1, "os/exec.Command", vec![0], 0);
        let source2 = make_call(2, "(*net/http.Request).FormValue", vec![], 0);
        let sink2 = make_call(3, "(*database/sql.DB).Query", vec![2], 0);

        let func = make_func(
            "test.handler",
            vec![make_block(0, vec![source1, sink1, source2, sink2])],
        );
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 2, "should detect two distinct taint flows");

        let rules: Vec<&str> = diags.iter().map(|d| d.rule.as_str()).collect();
        assert!(rules.contains(&"TAINT001"), "should detect SQL injection");
        assert!(
            rules.contains(&"TAINT002"),
            "should detect command injection"
        );
    }

    #[test]
    fn test_diagnostic_has_root_cause() {
        let source = make_call(0, "os.Getenv", vec![], 0);
        let sink = make_call(1, "os/exec.Command", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 1);

        let diag = &diags[0];
        assert!(
            diag.root_cause.is_some(),
            "diagnostic should have root cause"
        );
        let root_cause = diag.root_cause.as_ref().unwrap();
        assert!(
            root_cause.description.contains("User input"),
            "root cause should describe user input"
        );
    }

    #[test]
    fn test_diagnostic_has_pattern() {
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let sink = make_call(1, "(*database/sql.DB).Query", vec![0], 0);

        let func = make_func("test.handler", vec![make_block(0, vec![source, sink])]);
        let pkg = make_package(vec![func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert_eq!(diags.len(), 1);

        let diag = &diags[0];
        assert!(diag.pattern.is_some(), "diagnostic should have pattern");
        let pattern = diag.pattern.as_ref().unwrap();
        assert_eq!(pattern.name, "sql-injection");
        assert!(pattern.go_idiom.contains("parameterized"));
    }

    #[test]
    fn test_interprocedural_taint_detected() {
        // caller() has HTTP source and calls handler(tainted_value).
        // handler(param) passes param to db.Query().
        // Verify: TAINT001 diagnostic is produced in handler via inter-procedural analysis.
        let source = make_call(0, "(*net/http.Request).FormValue", vec![], 0);
        let call_handler = make_call(1, "example.com/test.handler", vec![0], 0);

        let caller_func = make_func(
            "example.com/test.caller",
            vec![make_block(0, vec![source, call_handler])],
        );

        let param = make_instr(10, ValueKind::Parameter, "input", 0);
        let sink = make_call(11, "(*database/sql.DB).Query", vec![10], 0);

        let handler_func = make_func(
            "example.com/test.handler",
            vec![make_block(0, vec![param, sink])],
        );

        let pkg = make_package(vec![caller_func, handler_func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);

        // Should find the flow in handler via inter-procedural taint.
        let taint001_diags: Vec<&Diagnostic> =
            diags.iter().filter(|d| d.rule == "TAINT001").collect();
        assert!(
            !taint001_diags.is_empty(),
            "should detect SQL injection in handler via inter-procedural taint, got {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_interprocedural_no_false_positive() {
        // caller() passes a Const (not tainted) to handler().
        // handler(param) passes param to db.Query().
        // Verify: NO diagnostic.
        let mut const_val = make_instr(0, ValueKind::Const, "safe_query", 0);
        const_val.const_value = Some("SELECT 1".into());
        let call_handler = make_call(1, "example.com/test.handler", vec![0], 0);

        let caller_func = make_func(
            "example.com/test.caller",
            vec![make_block(0, vec![const_val, call_handler])],
        );

        let param = make_instr(10, ValueKind::Parameter, "input", 0);
        let sink = make_call(11, "(*database/sql.DB).Query", vec![10], 0);

        let handler_func = make_func(
            "example.com/test.handler",
            vec![make_block(0, vec![param, sink])],
        );

        let pkg = make_package(vec![caller_func, handler_func]);

        let diags = TaintAnalyzer::analyze_package(&pkg);
        assert!(
            diags.is_empty(),
            "should NOT produce diagnostics when argument is a constant, got {} diagnostics: {:?}",
            diags.len(),
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }
}

/// Integration tests using pre-serialized bridge fixtures.
///
/// These tests load real Go SSA IR produced by the Go bridge from fixture
/// `.go` files, deserialize via FlatBuffers, and run the taint analyzer.
/// They validate end-to-end taint detection on real Go code.
#[cfg(test)]
mod fixture_tests {
    use super::*;

    fn load_fixture(category: &str, name: &str) -> goguard_ir::ir::AnalysisInput {
        goguard_ir::load_bridge_fixture(&format!("{category}/{name}"))
    }

    /// Helper: collect all callee names from the IR for debugging.
    fn collect_callees(input: &goguard_ir::ir::AnalysisInput) -> Vec<String> {
        let mut callees = Vec::new();
        for pkg in &input.packages {
            for func in &pkg.functions {
                for block in &func.blocks {
                    for instr in &block.instructions {
                        if let Some(callee) = &instr.callee {
                            callees.push(callee.clone());
                        }
                    }
                }
            }
        }
        callees
    }

    #[test]
    fn test_fixture_sql_injection() {
        let input = load_fixture("taint", "sql_injection");
        assert!(!input.packages.is_empty(), "fixture should have packages");

        let callees = collect_callees(&input);
        let diags = TaintAnalyzer::analyze(&input);

        // The Go code has r.FormValue("id") -> db.Query("SELECT..."+userID).
        // The bridge SSA produces a call to (*net/http.Request).FormValue
        // and a call to (*database/sql.DB).Query with tainted string concatenation.
        let taint_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.rule.starts_with("TAINT"))
            .collect();
        assert!(
            !taint_diags.is_empty(),
            "Expected TAINT diagnostics for SQL injection fixture, got none. Callees: {:?}",
            callees
        );
        assert!(
            taint_diags.iter().any(|d| d.rule == "TAINT001"),
            "Expected TAINT001 (SQL injection), got rules: {:?}",
            taint_diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fixture_command_injection() {
        let input = load_fixture("taint", "command_injection");
        assert!(!input.packages.is_empty(), "fixture should have packages");

        let callees = collect_callees(&input);
        let diags = TaintAnalyzer::analyze(&input);

        // The Go code has os.Getenv("USER_CMD") -> exec.Command(input).Run().
        let taint_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.rule.starts_with("TAINT"))
            .collect();
        assert!(
            !taint_diags.is_empty(),
            "Expected TAINT diagnostics for command injection fixture, got none. Callees: {:?}",
            callees
        );
        assert!(
            taint_diags.iter().any(|d| d.rule == "TAINT002"),
            "Expected TAINT002 (command injection), got rules: {:?}",
            taint_diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fixture_path_traversal() {
        let input = load_fixture("taint", "path_traversal");
        assert!(!input.packages.is_empty(), "fixture should have packages");

        let callees = collect_callees(&input);
        let diags = TaintAnalyzer::analyze(&input);

        // The Go code has r.FormValue("file") -> os.ReadFile(path).
        let taint_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.rule.starts_with("TAINT"))
            .collect();
        assert!(
            !taint_diags.is_empty(),
            "Expected TAINT diagnostics for path traversal fixture, got none. Callees: {:?}",
            callees
        );
        assert!(
            taint_diags.iter().any(|d| d.rule == "TAINT003"),
            "Expected TAINT003 (path traversal), got rules: {:?}",
            taint_diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fixture_xss() {
        let input = load_fixture("taint", "xss");
        assert!(!input.packages.is_empty(), "fixture should have packages");

        let callees = collect_callees(&input);
        let diags = TaintAnalyzer::analyze(&input);

        // The Go code has r.FormValue("name") -> template.HTML(name) -> tmpl.Execute(w, content).
        // We expect TAINT004 for XSS via template.Execute with tainted content.
        let taint_diags: Vec<_> = diags
            .iter()
            .filter(|d| d.rule.starts_with("TAINT"))
            .collect();
        assert!(
            !taint_diags.is_empty(),
            "Expected TAINT diagnostics for XSS fixture, got none. Callees: {:?}",
            callees
        );
        assert!(
            taint_diags.iter().any(|d| d.rule == "TAINT004"),
            "Expected TAINT004 (XSS), got rules: {:?}",
            taint_diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_fixture_safe_sanitized() {
        let input = load_fixture("taint", "safe_sanitized");
        assert!(!input.packages.is_empty(), "fixture should have packages");

        let callees = collect_callees(&input);
        let diags = TaintAnalyzer::analyze(&input);

        // The Go code has r.FormValue("file") -> filepath.Clean(path) -> os.ReadFile(cleanPath).
        // After sanitization via filepath.Clean, no TAINT003 should be produced.
        let path_traversal_diags: Vec<_> = diags.iter().filter(|d| d.rule == "TAINT003").collect();
        assert!(
            path_traversal_diags.is_empty(),
            "Sanitized path should NOT produce TAINT003 (path traversal), got {} diagnostics. \
             Callees: {:?}",
            path_traversal_diags.len(),
            callees
        );
    }

    #[test]
    fn test_fixture_interprocedural() {
        let input = load_fixture("taint", "interprocedural");
        assert!(!input.packages.is_empty(), "fixture should have packages");

        let diags = TaintAnalyzer::analyze(&input);

        // KNOWN LIMITATION: The Go bridge does not serialize function parameters
        // as Parameter instructions in the IR. Parameters in Go SSA exist at the
        // function level (fn.Params), not as block instructions. The bridge only
        // iterates block.Instrs, so parameters are missing from the IR.
        //
        // This means inter-procedural taint propagation cannot work with bridge IR
        // in its current form, because there are no Parameter instructions to mark
        // as tainted in the callee (processQuery).
        //
        // The Go code has:
        //   handler(): r.FormValue("search") -> string concat -> processQuery(db, query)
        //   processQuery(db, query): db.Query(query)
        //
        // Intra-procedural analysis in handler() detects tainted data flowing to
        // processQuery, and inter-procedural analysis correctly identifies that
        // processQuery's arg_idx 2 receives tainted data. However, processQuery
        // has no Parameter instructions in the IR, so the tainted parameter cannot
        // be tracked to the db.Query sink.
        //
        // TODO: Fix the Go bridge to serialize fn.Params as Parameter instructions.
        // Once that is done, this test should detect TAINT001.

        // For now, verify the fixture loads and analysis runs without panicking.
        // When the bridge is updated to serialize parameters, update this assertion to:
        //   assert!(diags.iter().any(|d| d.rule == "TAINT001"));
        let _ = diags;
    }

    #[test]
    fn test_fixture_taint_loads_all() {
        // Smoke test: all taint fixtures load and parse without errors.
        let fixtures = [
            "sql_injection",
            "command_injection",
            "path_traversal",
            "xss",
            "safe_sanitized",
            "interprocedural",
        ];
        for name in fixtures {
            let input = load_fixture("taint", name);
            assert!(
                !input.packages.is_empty(),
                "fixture {name} should have at least one package"
            );
            let total_funcs: usize = input.packages.iter().map(|p| p.functions.len()).sum();
            assert!(
                total_funcs > 0,
                "fixture {name} should have at least one function"
            );
        }
    }
}
