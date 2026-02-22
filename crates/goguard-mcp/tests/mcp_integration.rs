//! Integration tests for GoGuard MCP server.
//!
//! These tests pre-populate server state using bridge fixtures (via orchestrator::analyze_ir)
//! and then call tool methods directly — no actual Go bridge needed.

use goguard_core::config::Config;
use goguard_core::orchestrator::analyze_ir;
use goguard_mcp::server::GoGuardMcpServer;
use rmcp::ServerHandler;

/// Load bridge fixture, run analysis, create server with diagnostics.
fn server_from_fixture(fixture: &str) -> GoGuardMcpServer {
    let ir = goguard_ir::load_bridge_fixture(fixture);
    let config = Config::default();
    let output = analyze_ir(&ir, &config);
    GoGuardMcpServer::with_diagnostics(output.diagnostics)
}

#[test]
fn test_list_tools_returns_12() {
    let server = GoGuardMcpServer::new();
    let tools = server.tool_router_for_test().list_all();
    assert_eq!(
        tools.len(),
        12,
        "Expected 12 tools: goguard_analyze, goguard_explain, goguard_fix, goguard_verify, goguard_rules, goguard_batch, goguard_query, goguard_snapshot, goguard_autofix, goguard_search, goguard_execute, goguard_teach. Got: {:?}",
        tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>()
    );

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"goguard_analyze"));
    assert!(names.contains(&"goguard_explain"));
    assert!(names.contains(&"goguard_fix"));
    assert!(names.contains(&"goguard_verify"));
    assert!(names.contains(&"goguard_rules"));
    assert!(names.contains(&"goguard_batch"));
    assert!(names.contains(&"goguard_query"));
    assert!(names.contains(&"goguard_snapshot"));
    assert!(names.contains(&"goguard_search"));
    assert!(names.contains(&"goguard_execute"));
    assert!(names.contains(&"goguard_teach"));
}

#[test]
fn test_server_info() {
    let server = GoGuardMcpServer::new();
    let info = server.get_info();
    assert_eq!(info.server_info.name, "goguard");
    assert!(info.capabilities.tools.is_some());
    assert!(info.capabilities.resources.is_some());
    assert!(info.instructions.is_some());
    let instructions = info.instructions.unwrap();
    assert!(instructions.contains("goguard_analyze"));
}

#[tokio::test]
async fn test_explain_after_analyze_fixture() {
    let server = server_from_fixture("nil/basic_nil_deref");

    // Get the first diagnostic ID from state
    let state = server.state_for_test().await;
    assert!(
        !state.diagnostics.is_empty(),
        "basic_nil_deref fixture should produce diagnostics"
    );

    let first_id = state.diagnostics[0].id.clone();
    drop(state);

    // Explain it
    let result = server.explain(&first_id).await.unwrap();

    assert_eq!(result.is_error, Some(false));
    let text = result.content[0].as_text().unwrap();
    assert!(
        text.text.contains("explanation"),
        "Full output should have explanation"
    );
    assert!(
        text.text.contains("root_cause"),
        "Full output should have root_cause"
    );
}

#[tokio::test]
async fn test_fix_graceful_no_fix() {
    let server = server_from_fixture("errcheck/ignored_error");

    let state = server.state_for_test().await;
    assert!(!state.diagnostics.is_empty());

    // Find a diagnostic without a fix
    let diag_without_fix = state.diagnostics.iter().find(|d| d.fix.is_none());
    if let Some(d) = diag_without_fix {
        let id = d.id.clone();
        drop(state);

        let result = server.fix(&id).await.unwrap();

        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("no_fix_available"));
    }
}

#[tokio::test]
async fn test_rules_returns_all() {
    let server = GoGuardMcpServer::new();
    let result = server.rules(None).await.unwrap();

    let text = result.content[0].as_text().unwrap();
    let rules: Vec<serde_json::Value> = serde_json::from_str(&text.text).unwrap();
    assert_eq!(
        rules.len(),
        23,
        "Should have 23 rules across all categories"
    );
}

#[tokio::test]
async fn test_health_from_fixture() {
    use goguard_mcp::server::ProjectHealth;

    let server = server_from_fixture("nil/basic_nil_deref");
    let state = server.state_for_test().await;

    let health = ProjectHealth::from_diagnostics(&state.diagnostics, state.last_analysis_time_ms);
    assert!(health.total > 0, "Fixture should produce diagnostics");
    assert!(
        health.status == "critical" || health.status == "needs_attention",
        "Health status should reflect issues, got: {}",
        health.status
    );
}

#[tokio::test]
async fn test_explain_nonexistent_returns_error() {
    let server = server_from_fixture("nil/basic_nil_deref");

    let result = server.explain("NONEXISTENT-x.go:999").await.unwrap();

    assert_eq!(result.is_error, Some(true));
    let text = result.content[0].as_text().unwrap();
    assert!(text.text.contains("not found"));
}

#[tokio::test]
async fn test_rules_filter_nil() {
    let server = GoGuardMcpServer::new();
    let result = server.rules(Some("nil")).await.unwrap();

    let text = result.content[0].as_text().unwrap();
    let rules: Vec<serde_json::Value> = serde_json::from_str(&text.text).unwrap();
    assert_eq!(
        rules.len(),
        4,
        "Should have 4 nil rules: NIL001, NIL002, NIL004, NIL006"
    );
    for rule in &rules {
        assert!(rule["code"].as_str().unwrap().starts_with("NIL"));
    }
}

// --- Phase 4: GoGuard QL Query Tests ---

#[tokio::test]
async fn test_query_from_fixture() {
    let server = server_from_fixture("nil/basic_nil_deref");

    let result = server
        .query("diagnostics where rule starts_with \"NIL\"")
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(false));
    let text = result.content[0].as_text().unwrap();
    let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
    assert!(
        json["total"].as_u64().unwrap() > 0,
        "nil fixture should produce NIL diagnostics"
    );
}

// --- Phase 2.2: Incremental vs Non-Incremental Parity Tests ---

#[test]
fn test_incremental_all_fixtures_match() {
    use goguard_core::config::Config;
    use goguard_core::orchestrator::{analyze_ir, IncrementalAnalyzer};

    let fixtures = [
        "nil/basic_nil_deref",
        "nil/error_ignored",
        "nil/missing_return",
        "nil/nil_map",
        "nil/safe_patterns",
        "nil/type_assertion",
        "errcheck/ignored_error",
        "errcheck/safe_error_handling",
    ];

    let config = Config::default();

    for fixture in &fixtures {
        let ir = goguard_ir::load_bridge_fixture(fixture);
        let non_inc = analyze_ir(&ir, &config);

        // Create a fresh IncrementalAnalyzer per fixture for fair comparison
        let mut fresh_inc = IncrementalAnalyzer::new();
        let inc_output = fresh_inc.analyze(&ir, &config);

        assert_eq!(
            non_inc.diagnostics.len(),
            inc_output.diagnostics.len(),
            "fixture {fixture}: diagnostic count mismatch"
        );
        for (a, b) in non_inc
            .diagnostics
            .iter()
            .zip(inc_output.diagnostics.iter())
        {
            assert_eq!(a.id, b.id, "fixture {fixture}: diagnostic ID mismatch");
            assert_eq!(
                a.rule, b.rule,
                "fixture {fixture}: diagnostic rule mismatch"
            );
        }
    }
}

#[test]
fn test_incremental_second_run_same_results() {
    use goguard_core::config::Config;
    use goguard_core::orchestrator::IncrementalAnalyzer;

    let config = Config::default();
    let mut inc = IncrementalAnalyzer::new();
    let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");

    let output1 = inc.analyze(&ir, &config);
    let output2 = inc.analyze(&ir, &config);

    assert_eq!(output1.diagnostics.len(), output2.diagnostics.len());
    for (a, b) in output1.diagnostics.iter().zip(output2.diagnostics.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.rule, b.rule);
    }
}

#[test]
fn test_diff_files_to_packages_integration() {
    use goguard_agent::diff::{files_to_packages, ChangedFiles};
    use std::path::Path;

    // Use real-world-like paths that would appear in a Go project
    let changed = ChangedFiles {
        go_files: vec![
            "internal/handler/user.go".into(),
            "internal/handler/admin.go".into(),
            "main.go".into(),
        ],
        no_git: false,
    };

    let result = files_to_packages(&changed, "example.com/myapp", Path::new("."));
    assert_eq!(
        result.len(),
        2,
        "should have 2 packages: root + internal/handler"
    );
    assert!(result.contains(&"example.com/myapp".to_string()));
    assert!(result.contains(&"example.com/myapp/internal/handler".to_string()));
}

// --- Phase 2.5: CodeAct Agent Intelligence Tests ---

#[tokio::test]
async fn test_fix_auto_verify_from_fixture() {
    let server = server_from_fixture("nil/basic_nil_deref");
    let state = server.state_for_test().await;
    let fixable = state.diagnostics.iter().find(|d| d.fix.is_some());
    if let Some(d) = fixable {
        let id = d.id.clone();
        drop(state);
        let result = server.fix(&id).await.unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(
            text.text.contains("verification"),
            "auto_verify should include verification section"
        );
    }
}

#[tokio::test]
async fn test_snapshot_save_diff_from_fixture() {
    let server = server_from_fixture("nil/basic_nil_deref");

    // Save "before" snapshot
    let result = server.snapshot("save", Some("before"), None).await.unwrap();
    let text = result.content[0].as_text().unwrap();
    assert!(text.text.contains("before"));

    // List snapshots
    let list_result = server.snapshot("list", None, None).await.unwrap();
    let text = list_result.content[0].as_text().unwrap();
    assert!(text.text.contains("before"));
}

#[tokio::test]
async fn test_batch_all_nil_from_fixture() {
    let server = server_from_fixture("nil/basic_nil_deref");
    let state = server.state_for_test().await;
    let nil_ids: Vec<String> = state
        .diagnostics
        .iter()
        .filter(|d| d.rule.starts_with("NIL"))
        .map(|d| d.id.clone())
        .collect();
    drop(state);

    if !nil_ids.is_empty() {
        let result = server.batch(nil_ids).await.unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("applied"));
        assert!(text.text.contains("verification"));
    }
}

// --- Phase 4 Task 12: End-to-End Integration Tests ---

#[test]
fn test_patch_roundtrip_from_fixture() {
    use goguard_diagnostics::executable::generate_patches;
    use goguard_diagnostics::full::FixOutput;

    let ir = goguard_ir::load_bridge_fixture("nil/basic_nil_deref");
    let config = Config::default();
    let output = analyze_ir(&ir, &config);

    // Find a diagnostic with a fix
    let fixable = output.diagnostics.iter().find(|d| d.fix.is_some());
    if let Some(diag) = fixable {
        let fix = FixOutput::from_diagnostic(diag).unwrap();

        // Generate patches (just ensure no panic + valid output)
        let patches = generate_patches(&fix.edits);
        assert!(
            !patches.is_empty(),
            "fixable diagnostic should produce patches"
        );
        for patch in &patches {
            assert!(
                patch.unified_diff.contains("---"),
                "patch should have --- header"
            );
            assert!(
                patch.unified_diff.contains("+++"),
                "patch should have +++ header"
            );
            assert!(
                patch.unified_diff.contains("@@"),
                "patch should have @@ hunk header"
            );
        }
    }
}

#[test]
fn test_all_12_tool_names_present() {
    // Verify that the server exposes exactly the 12 expected tools by name.
    let server = GoGuardMcpServer::new();
    let tools = server.tool_router_for_test().list_all();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    let expected_tool_names = [
        "goguard_analyze",
        "goguard_explain",
        "goguard_fix",
        "goguard_verify",
        "goguard_rules",
        "goguard_batch",
        "goguard_query",
        "goguard_snapshot",
        "goguard_autofix",
        "goguard_search",
        "goguard_execute",
        "goguard_teach",
    ];

    for name in &expected_tool_names {
        assert!(
            names.contains(name),
            "Server should expose tool '{name}', but found: {:?}",
            names
        );
    }
    assert_eq!(
        names.len(),
        expected_tool_names.len(),
        "Server should expose exactly {} tools, got: {:?}",
        expected_tool_names.len(),
        names
    );
}

#[test]
fn test_autofix_report_serialization_e2e() {
    use goguard_agent::autofix::{AutoFixReport, SeveritySummary};

    let report = AutoFixReport {
        iterations: 3,
        fixes_applied: 7,
        fixes_skipped: 1,
        skipped_reasons: vec!["ERR001-main.go:5: file not found".into()],
        before: SeveritySummary {
            critical: 3,
            error: 5,
            warning: 2,
            info: 0,
        },
        after: SeveritySummary {
            critical: 0,
            error: 1,
            warning: 2,
            info: 0,
        },
        time_elapsed_ms: 4567,
        build_status: "pass".into(),
        test_status: None,
    };

    let json = serde_json::to_string_pretty(&report).unwrap();

    // Verify structure
    assert!(json.contains("\"iterations\": 3"));
    assert!(json.contains("\"fixes_applied\": 7"));
    assert!(json.contains("\"fixes_skipped\": 1"));
    assert!(json.contains("\"skipped_reasons\""));
    assert!(json.contains("\"before\""));
    assert!(json.contains("\"after\""));
    assert!(json.contains("\"time_elapsed_ms\": 4567"));

    // Verify before/after structure
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["before"]["critical"], 3);
    assert_eq!(parsed["after"]["critical"], 0);
    assert_eq!(parsed["after"]["error"], 1);
}

#[tokio::test]
async fn test_query_diagnostics_from_fixture_e2e() {
    // More complex query test than the existing test_query_from_fixture
    let server = server_from_fixture("nil/basic_nil_deref");

    // Query for all diagnostics (no filter)
    let result = server.query("diagnostics").await.unwrap();
    assert_eq!(result.is_error, Some(false));
    let text = result.content[0].as_text().unwrap();
    let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
    let total = json["total"].as_u64().unwrap();
    assert!(total > 0, "basic_nil_deref should have diagnostics");

    // Query with severity filter
    let result2 = server
        .query("diagnostics where severity == \"critical\"")
        .await
        .unwrap();
    assert_eq!(result2.is_error, Some(false));
    let text2 = result2.content[0].as_text().unwrap();
    let json2: serde_json::Value = serde_json::from_str(&text2.text).unwrap();
    let rows = json2["rows"].as_array().unwrap();
    for row in rows {
        assert_eq!(
            row["severity"], "critical",
            "All results should be critical"
        );
    }
}

// --- Resource Tests ---

#[tokio::test]
async fn test_rule_detail_has_examples() {
    // Test that get_rule returns full detail including examples
    let rule = goguard_diagnostics::rules::get_rule("NIL001");
    assert!(rule.is_some());
    let rule = rule.unwrap();
    assert!(rule.example_bad.is_some(), "NIL001 should have example_bad");
    assert!(
        rule.example_good.is_some(),
        "NIL001 should have example_good"
    );
    assert!(rule.go_idiom.is_some(), "NIL001 should have go_idiom");

    let json = serde_json::to_string_pretty(&rule).unwrap();
    assert!(json.contains("example_bad"));
    assert!(json.contains("go_idiom"));
}

#[tokio::test]
async fn test_annotations_initially_empty() {
    let server = server_from_fixture("nil/basic_nil_deref");
    let state = server.state_for_test().await;
    assert!(state.annotations.is_empty());
}

#[tokio::test]
async fn test_task_manager_tracks_tasks() {
    let server = GoGuardMcpServer::new();
    let tasks = server.task_manager().list_tasks().await;
    assert!(tasks.is_empty(), "Fresh server should have no tasks");
}

#[test]
fn test_get_rule_via_resource_api() {
    // Verify per-rule lookup works for all rule codes
    let rules = goguard_diagnostics::rules::get_all_rules();
    for rule in &rules {
        let found = goguard_diagnostics::rules::get_rule(&rule.code);
        assert!(found.is_some(), "Rule {} should be found", rule.code);
        assert_eq!(found.unwrap().code, rule.code);
    }
}

#[test]
fn test_get_rule_not_found() {
    let rule = goguard_diagnostics::rules::get_rule("NONEXISTENT");
    assert!(rule.is_none());
}

#[test]
fn test_server_has_prompts_capability() {
    let server = GoGuardMcpServer::new();
    let info = server.get_info();
    assert!(
        info.capabilities.prompts.is_some(),
        "Server should advertise prompts capability"
    );
}

// --- Elicitation Tests ---

#[tokio::test]
async fn test_elicitation_store_and_retrieve() {
    let server = GoGuardMcpServer::new();

    // Initially empty
    assert_eq!(server.annotations_count().await, 0);

    // Store an annotation
    server
        .store_annotation("nil_return:pkg.GetUser", "always_nil_on_error")
        .await;
    assert_eq!(server.annotations_count().await, 1);

    // Verify it's in state
    let state = server.state_for_test().await;
    assert_eq!(
        state.annotations.get("nil_return:pkg.GetUser"),
        Some(&"always_nil_on_error".to_string())
    );
}

#[tokio::test]
async fn test_elicitation_overwrite() {
    let server = GoGuardMcpServer::new();

    server
        .store_annotation("nil_return:pkg.Foo", "always_nil_on_error")
        .await;
    server
        .store_annotation("nil_return:pkg.Foo", "partial_result_possible")
        .await;

    assert_eq!(server.annotations_count().await, 1);
    let state = server.state_for_test().await;
    assert_eq!(
        state.annotations.get("nil_return:pkg.Foo"),
        Some(&"partial_result_possible".to_string())
    );
}

#[test]
fn test_elicitation_request_creation() {
    use goguard_mcp::elicitation::nil_return_elicitation;

    let req = nil_return_elicitation("example.com/pkg.GetUser");
    assert_eq!(req.pattern_key, "nil_return:example.com/pkg.GetUser");
    assert_eq!(req.options.len(), 2);
    assert_eq!(req.options[0].value, "always_nil_on_error");
    assert_eq!(req.options[1].value, "partial_result_possible");
}

// --- Auto-fix MCP Tests ---

#[tokio::test]
async fn test_autofix_invalid_severity_returns_error() {
    let server = server_from_fixture("nil/basic_nil_deref");
    let result = server.autofix("bogus", 10, 5, false, false).await.unwrap();
    assert_eq!(result.is_error, Some(true));
    let text = result.content[0].as_text().unwrap();
    assert!(
        text.text.contains("Invalid severity"),
        "Should report invalid severity, got: {}",
        text.text
    );
}

#[tokio::test]
async fn test_autofix_without_bridge_returns_error() {
    // Without the Go bridge binary, run_autofix_orchestrator fails at analyze_project.
    // This tests that the MCP tool gracefully handles the failure and tracks it.
    let server = server_from_fixture("nil/basic_nil_deref");
    let result = server.autofix("error", 10, 5, false, true).await.unwrap();
    // Should be an error because bridge binary isn't available in tests
    assert_eq!(result.is_error, Some(true));
    let text = result.content[0].as_text().unwrap();
    assert!(!text.text.is_empty(), "Error message should not be empty");
}

#[tokio::test]
async fn test_autofix_task_tracked_on_failure() {
    let server = server_from_fixture("nil/basic_nil_deref");
    // Run autofix — will fail because no Go bridge
    let _ = server.autofix("error", 10, 5, false, true).await.unwrap();

    // Verify task was tracked as failed
    let tasks = server.task_manager().list_tasks().await;
    let failed_tasks: Vec<_> = tasks
        .iter()
        .filter(|t| t.status == goguard_mcp::tasks::TaskStatus::Failed)
        .collect();
    assert!(
        !failed_tasks.is_empty(),
        "autofix should create a failed task when bridge is unavailable"
    );
    // Verify the error message is captured
    assert!(
        failed_tasks[0].error.is_some(),
        "failed task should have an error message"
    );
}
