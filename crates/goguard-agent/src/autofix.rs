//! Auto-fix orchestrator -- analyze -> prioritize -> fix -> verify loop.

use goguard_diagnostics::diagnostic::{Diagnostic, Severity};
use goguard_diagnostics::executable;
use goguard_diagnostics::full::FixOutput;
use serde::Serialize;

use crate::go_tools::TestResult;

/// Report produced after the auto-fix loop completes.
#[derive(Debug, Clone, Serialize)]
pub struct AutoFixReport {
    pub iterations: usize,
    pub fixes_applied: usize,
    pub fixes_skipped: usize,
    pub skipped_reasons: Vec<String>,
    pub before: SeveritySummary,
    pub after: SeveritySummary,
    pub time_elapsed_ms: u64,
    /// Status of the last `go build` check: "pass" or "fail".
    #[serde(default)]
    pub build_status: String,
    /// Result of the last `go test` run, if testing was enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_status: Option<TestResult>,
}

/// Counts of diagnostics by severity level.
#[derive(Debug, Clone, Serialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
}

impl SeveritySummary {
    /// Build a severity summary by counting diagnostics.
    pub fn from_diagnostics(diagnostics: &[Diagnostic]) -> Self {
        let mut s = Self {
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
        };
        for d in diagnostics {
            match d.severity {
                Severity::Critical => s.critical += 1,
                Severity::Error => s.error += 1,
                Severity::Warning => s.warning += 1,
                Severity::Info => s.info += 1,
            }
        }
        s
    }
}

/// Prioritize diagnostics for fixing: critical first, then by file grouping.
/// Within the same file, sort bottom-up (higher lines first) to avoid line shifts.
/// Only returns diagnostics that have a fix.
pub fn prioritize(diagnostics: &[Diagnostic]) -> Vec<&Diagnostic> {
    let mut sorted: Vec<_> = diagnostics.iter().filter(|d| d.fix.is_some()).collect();
    sorted.sort_by(|a, b| {
        severity_ord(&a.severity)
            .cmp(&severity_ord(&b.severity))
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| b.location.line.cmp(&a.location.line)) // bottom-up
    });
    sorted
}

fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::Error => 1,
        Severity::Warning => 2,
        Severity::Info => 3,
    }
}

/// Apply a single fix to disk using built-in Rust I/O.
pub fn apply_fix(fix: &FixOutput) -> Result<(), String> {
    let results = executable::apply_edits(&fix.edits);
    if let Some(fail) = results.iter().find(|r| !r.success) {
        return Err(fail.error.clone().unwrap_or_else(|| "unknown error".into()));
    }
    Ok(())
}

/// Revert a fix by swapping old_text/new_text.
pub fn revert_fix(fix: &FixOutput) -> Result<(), String> {
    let results = executable::revert_edits(&fix.edits);
    if let Some(fail) = results.iter().find(|r| !r.success) {
        return Err(fail.error.clone().unwrap_or_else(|| "unknown error".into()));
    }
    Ok(())
}

/// Run the full auto-fix orchestrator loop.
///
/// Applies fixes ONE AT A TIME with build verification after each fix.
/// If `go build` fails after a fix, that fix is reverted and skipped.
/// After all individual fixes in an iteration pass build checks, `go test`
/// is run (if `test=true`). If tests fail, ALL fixes from this iteration
/// are reverted and the loop breaks.
pub fn run_autofix_orchestrator(
    cwd: &std::path::Path,
    packages: &[String],
    config: &goguard_core::config::Config,
    min_severity: &Severity,
    budget: &crate::budget::AutoFixBudget,
    test: bool,
    dry_run: bool,
) -> Result<AutoFixReport, String> {
    let start_time = std::time::Instant::now();

    // Initial analysis
    let initial_output = match goguard_core::orchestrator::analyze_project(cwd, packages, config) {
        Ok(o) => o,
        Err(e) => return Err(format!("Initial analysis failed: {}", e)),
    };

    let before = SeveritySummary::from_diagnostics(&initial_output.diagnostics);

    let mut total_fixed = 0usize;
    let mut total_skipped = 0usize;
    let mut skipped_reasons: Vec<String> = Vec::new();
    let mut iteration = 0usize;
    let mut last_build_status = String::from("pass");
    let mut last_test_status: Option<TestResult> = None;

    loop {
        // Time budget enforcement
        if start_time.elapsed().as_millis() as u64 > budget.max_time_ms {
            break;
        }

        iteration += 1;
        if iteration > budget.max_iterations {
            break;
        }
        if total_fixed >= budget.max_fixes {
            break;
        }

        // Analyze (skip on first iteration because we already have initial_output)
        let output_res = if iteration == 1 {
            Ok(initial_output.clone())
        } else {
            goguard_core::orchestrator::analyze_project(cwd, packages, config)
        };

        let output = match output_res {
            Ok(o) => o,
            Err(e) => {
                skipped_reasons.push(format!("analysis failed: {}", e));
                break;
            }
        };

        // Prioritize and filter
        let fixable: Vec<_> = prioritize(&output.diagnostics)
            .into_iter()
            .filter(|d| severity_ord(&d.severity) <= severity_ord(min_severity))
            .collect();

        if fixable.is_empty() {
            break; // No more fixable diagnostics
        }

        let mut applied_this_iteration = 0;
        // Track fixes applied in this iteration for potential rollback on test failure.
        let mut iteration_fixes: Vec<FixOutput> = Vec::new();

        for diag in fixable.iter().take(budget.max_fixes - total_fixed) {
            // Time budget check inside inner loop too
            if start_time.elapsed().as_millis() as u64 > budget.max_time_ms {
                break;
            }

            let fix = match FixOutput::from_diagnostic(diag) {
                Some(f) => f,
                None => continue,
            };

            if dry_run {
                total_skipped += 1;
                skipped_reasons.push(format!("{}: dry-run", diag.id));
                continue;
            }

            // Apply fix ONE AT A TIME
            match apply_fix(&fix) {
                Ok(()) => {
                    // Verify build after each individual fix
                    let build = crate::go_tools::go_build(cwd, packages);
                    if build.success {
                        // Build passed — keep the fix
                        total_fixed += 1;
                        applied_this_iteration += 1;
                        iteration_fixes.push(fix);
                        last_build_status = "pass".into();
                    } else {
                        // Build failed — revert this fix and skip it
                        let _ = revert_fix(&fix);
                        total_skipped += 1;
                        skipped_reasons.push(format!("{}: build regression after apply", diag.id));
                        last_build_status = "fail".into();
                        if budget.stop_on_regression {
                            break;
                        }
                    }
                }
                Err(e) => {
                    total_skipped += 1;
                    skipped_reasons.push(format!("{}: {}", diag.id, e));
                }
            }
        }

        if dry_run || applied_this_iteration == 0 {
            break;
        }

        // go test check after all individual fixes in this iteration
        if test {
            let test_result = crate::go_tools::go_test(cwd, packages, 120);
            if !test_result.success {
                // Tests failed — revert ALL fixes from this iteration
                for fix in iteration_fixes.iter().rev() {
                    let _ = revert_fix(fix);
                }
                total_fixed -= applied_this_iteration;
                total_skipped += applied_this_iteration;
                skipped_reasons.push(format!(
                    "tests failed ({} errors) — reverted {} fixes",
                    test_result.failed, applied_this_iteration
                ));
                last_test_status = Some(test_result);
                break;
            }
            last_test_status = Some(test_result);
        }
    }

    // Final analysis to get "after" summary
    let final_output = match goguard_core::orchestrator::analyze_project(cwd, packages, config) {
        Ok(o) => o,
        Err(e) => return Err(format!("Final analysis failed: {}", e)),
    };

    let after = SeveritySummary::from_diagnostics(&final_output.diagnostics);

    Ok(AutoFixReport {
        iterations: iteration,
        fixes_applied: total_fixed,
        fixes_skipped: total_skipped,
        skipped_reasons,
        before,
        after,
        time_elapsed_ms: start_time.elapsed().as_millis() as u64,
        build_status: last_build_status,
        test_status: last_test_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::{
        DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
    };

    #[test]
    fn test_prioritize_critical_first() {
        let d_warning = DiagnosticBuilder::new(
            "NIL004",
            Severity::Warning,
            "nil map write",
            DiagnosticSource::Nil,
        )
        .location("a.go", 10, 5)
        .fix(
            "init map",
            vec![Edit {
                file: "a.go".into(),
                range: EditRange {
                    start_line: 10,
                    end_line: 10,
                },
                old_text: Some("m[k] = v".into()),
                new_text: "if m == nil { m = make(map[string]string) }\nm[k] = v".into(),
            }],
        )
        .build();

        let d_critical = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("b.go", 20, 5)
        .fix(
            "Add nil check",
            vec![Edit {
                file: "b.go".into(),
                range: EditRange {
                    start_line: 20,
                    end_line: 20,
                },
                old_text: Some("user.Name".into()),
                new_text: "if user != nil { user.Name }".into(),
            }],
        )
        .build();

        let d_error = DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "err ignored",
            DiagnosticSource::Errcheck,
        )
        .location("c.go", 5, 5)
        .fix(
            "Handle error",
            vec![Edit {
                file: "c.go".into(),
                range: EditRange {
                    start_line: 5,
                    end_line: 5,
                },
                old_text: Some("os.Open(f)".into()),
                new_text: "f, err := os.Open(f)\nif err != nil { return err }".into(),
            }],
        )
        .build();

        let diagnostics = vec![d_warning, d_critical, d_error];
        let prioritized = prioritize(&diagnostics);

        assert_eq!(prioritized.len(), 3);
        assert_eq!(prioritized[0].severity, Severity::Critical);
        assert_eq!(prioritized[1].severity, Severity::Error);
        assert_eq!(prioritized[2].severity, Severity::Warning);
    }

    #[test]
    fn test_prioritize_same_file_bottom_up() {
        let d_line5 = DiagnosticBuilder::new(
            "NIL001",
            Severity::Error,
            "nil deref at 5",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 5, 1)
        .fix(
            "fix 5",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 5,
                    end_line: 5,
                },
                old_text: Some("old5".into()),
                new_text: "new5".into(),
            }],
        )
        .build();

        let d_line20 = DiagnosticBuilder::new(
            "NIL002",
            Severity::Error,
            "nil deref at 20",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 20, 1)
        .fix(
            "fix 20",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 20,
                    end_line: 20,
                },
                old_text: Some("old20".into()),
                new_text: "new20".into(),
            }],
        )
        .build();

        let d_line12 = DiagnosticBuilder::new(
            "NIL003",
            Severity::Error,
            "nil deref at 12",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 12, 1)
        .fix(
            "fix 12",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 12,
                    end_line: 12,
                },
                old_text: Some("old12".into()),
                new_text: "new12".into(),
            }],
        )
        .build();

        let diagnostics = vec![d_line5, d_line20, d_line12];
        let prioritized = prioritize(&diagnostics);

        assert_eq!(prioritized.len(), 3);
        // Same file, same severity -> bottom-up (highest line first)
        assert_eq!(prioritized[0].location.line, 20);
        assert_eq!(prioritized[1].location.line, 12);
        assert_eq!(prioritized[2].location.line, 5);
    }

    #[test]
    fn test_prioritize_no_fix_excluded() {
        let with_fix = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 20, 5)
        .fix(
            "Add nil check",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 20,
                    end_line: 20,
                },
                old_text: Some("user.Name".into()),
                new_text: "if user != nil { user.Name }".into(),
            }],
        )
        .build();

        let without_fix = DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "err ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 10, 5)
        .build();

        let diagnostics = vec![with_fix, without_fix];
        let prioritized = prioritize(&diagnostics);

        assert_eq!(prioritized.len(), 1);
        assert_eq!(prioritized[0].rule, "NIL001");
    }

    #[test]
    fn test_severity_summary() {
        let diagnostics = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 1, 0)
            .build(),
            DiagnosticBuilder::new(
                "NIL002",
                Severity::Critical,
                "nil deref 2",
                DiagnosticSource::Nil,
            )
            .location("a.go", 2, 0)
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "err ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 3, 0)
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("c.go", 4, 0)
            .build(),
            DiagnosticBuilder::new(
                "TAINT001",
                Severity::Info,
                "taint info",
                DiagnosticSource::Taint,
            )
            .location("d.go", 5, 0)
            .build(),
        ];

        let summary = SeveritySummary::from_diagnostics(&diagnostics);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.error, 1);
        assert_eq!(summary.warning, 1);
        assert_eq!(summary.info, 1);
    }

    #[test]
    fn test_autofix_report_serialization() {
        let report = AutoFixReport {
            iterations: 3,
            fixes_applied: 5,
            fixes_skipped: 2,
            skipped_reasons: vec![
                "no safe fix available".into(),
                "would cause regression".into(),
            ],
            before: SeveritySummary {
                critical: 3,
                error: 4,
                warning: 10,
                info: 2,
            },
            after: SeveritySummary {
                critical: 0,
                error: 1,
                warning: 8,
                info: 2,
            },
            time_elapsed_ms: 1234,
            build_status: "pass".into(),
            test_status: None,
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["iterations"], 3);
        assert_eq!(parsed["fixes_applied"], 5);
        assert_eq!(parsed["fixes_skipped"], 2);
        assert!(parsed["skipped_reasons"].is_array());
        assert_eq!(parsed["skipped_reasons"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["before"]["critical"], 3);
        assert_eq!(parsed["after"]["critical"], 0);
        assert_eq!(parsed["time_elapsed_ms"], 1234);
        assert_eq!(parsed["build_status"], "pass");
        // test_status is None, should be absent from serialization
        assert!(parsed.get("test_status").is_none());
    }

    #[test]
    fn test_autofix_report_with_test_status() {
        let test_result = crate::go_tools::TestResult {
            success: true,
            passed: 10,
            failed: 0,
            skipped: 1,
            failures: vec![],
            time_ms: 500,
        };

        let report = AutoFixReport {
            iterations: 1,
            fixes_applied: 2,
            fixes_skipped: 0,
            skipped_reasons: vec![],
            before: SeveritySummary {
                critical: 2,
                error: 0,
                warning: 0,
                info: 0,
            },
            after: SeveritySummary {
                critical: 0,
                error: 0,
                warning: 0,
                info: 0,
            },
            time_elapsed_ms: 800,
            build_status: "pass".into(),
            test_status: Some(test_result),
        };

        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["build_status"], "pass");
        assert!(parsed.get("test_status").is_some());
        assert_eq!(parsed["test_status"]["success"], true);
        assert_eq!(parsed["test_status"]["passed"], 10);
        assert_eq!(parsed["test_status"]["failed"], 0);
        assert_eq!(parsed["test_status"]["skipped"], 1);
    }

    #[test]
    fn test_time_budget_enforcement() {
        // Verify that the time budget check would correctly identify expired budgets.
        // We test the time check logic directly since we can't run the full orchestrator
        // (it requires Go toolchain and a real project).
        let budget = crate::budget::AutoFixBudget {
            max_iterations: 100,
            max_fixes: 100,
            max_time_ms: 1, // 1ms budget — will expire almost immediately
            stop_on_regression: true,
        };

        let start_time = std::time::Instant::now();
        // Busy-wait until at least 2ms have passed
        while start_time.elapsed().as_millis() < 2 {
            std::hint::spin_loop();
        }

        // The time check that the orchestrator uses
        let expired = start_time.elapsed().as_millis() as u64 > budget.max_time_ms;
        assert!(expired, "budget should be expired after 2ms with 1ms limit");
    }

    #[test]
    fn test_rollback_reverts_on_build_failure() {
        // Test the apply_fix / revert_fix roundtrip using tempfile-based fixtures.
        // This validates the per-fix rollback mechanism used by the orchestrator.
        //
        // Uses a single-line-to-single-line replacement so that revert_edits can
        // match the old_text at the same line range after application.
        use goguard_diagnostics::full::{EditRange, FixOutput, TextEdit};

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("handler.go");

        let original = "package main\n\nfunc handler() {\n\tuser.Name\n}\n";
        std::fs::write(&file_path, original).unwrap();

        let path_str = file_path.to_str().unwrap();

        let fix = FixOutput {
            diagnostic_id: "NIL001-handler.go:4".into(),
            description: "Guard nil access".into(),
            edits: vec![TextEdit {
                file: path_str.into(),
                range: EditRange {
                    start_line: 4,
                    end_line: 4,
                },
                old_text: "\tuser.Name".into(),
                new_text: "\t// FIXED: user.Name".into(),
            }],
            commands: vec![],
            apply_script: None,
            verify_after_fix: true,
        };

        // Step 1: Apply the fix
        let result = apply_fix(&fix);
        assert!(result.is_ok(), "apply_fix should succeed: {:?}", result);

        let after_apply = std::fs::read_to_string(&file_path).unwrap();
        assert!(
            after_apply.contains("// FIXED: user.Name"),
            "file should contain the fix: {}",
            after_apply
        );
        // The exact old line "\tuser.Name" should no longer appear standalone
        // (it's now "\t// FIXED: user.Name")
        let has_original_line = after_apply.lines().any(|l| l == "\tuser.Name");
        assert!(
            !has_original_line,
            "old line should be replaced, got: {}",
            after_apply
        );

        // Step 2: Simulate build failure — revert the fix
        let revert_result = revert_fix(&fix);
        assert!(
            revert_result.is_ok(),
            "revert_fix should succeed: {:?}",
            revert_result
        );

        let after_revert = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(
            after_revert, original,
            "file should be restored to original after revert"
        );
    }

    #[test]
    fn test_apply_revert_multiple_fixes_independently() {
        // Test that multiple fixes can be applied and reverted independently,
        // simulating the per-fix rollback behavior in the orchestrator.
        use goguard_diagnostics::full::{EditRange, FixOutput, TextEdit};

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_a = dir.path().join("a.go");
        let file_b = dir.path().join("b.go");

        let original_a = "package main\n\nvar x = 1\nvar y = 2\n";
        let original_b = "package main\n\nfunc foo() {}\n";
        std::fs::write(&file_a, original_a).unwrap();
        std::fs::write(&file_b, original_b).unwrap();

        let fix_a = FixOutput {
            diagnostic_id: "ERR001-a.go:3".into(),
            description: "Fix x".into(),
            edits: vec![TextEdit {
                file: file_a.to_str().unwrap().into(),
                range: EditRange {
                    start_line: 3,
                    end_line: 3,
                },
                old_text: "var x = 1".into(),
                new_text: "var x = 42".into(),
            }],
            commands: vec![],
            apply_script: None,
            verify_after_fix: true,
        };

        let fix_b = FixOutput {
            diagnostic_id: "ERR002-b.go:3".into(),
            description: "Fix foo".into(),
            edits: vec![TextEdit {
                file: file_b.to_str().unwrap().into(),
                range: EditRange {
                    start_line: 3,
                    end_line: 3,
                },
                old_text: "func foo() {}".into(),
                new_text: "func foo() error { return nil }".into(),
            }],
            commands: vec![],
            apply_script: None,
            verify_after_fix: true,
        };

        // Apply fix A — succeeds, keep it
        assert!(apply_fix(&fix_a).is_ok());
        let after_a = std::fs::read_to_string(&file_a).unwrap();
        assert!(after_a.contains("var x = 42"));

        // Apply fix B — suppose build fails, revert ONLY B
        assert!(apply_fix(&fix_b).is_ok());
        let after_b = std::fs::read_to_string(&file_b).unwrap();
        assert!(after_b.contains("func foo() error"));

        // Revert fix B (simulating build regression)
        assert!(revert_fix(&fix_b).is_ok());
        let reverted_b = std::fs::read_to_string(&file_b).unwrap();
        assert_eq!(reverted_b, original_b, "b.go should be back to original");

        // Fix A should still be applied
        let still_a = std::fs::read_to_string(&file_a).unwrap();
        assert!(
            still_a.contains("var x = 42"),
            "a.go should still have fix A applied"
        );
    }

    #[test]
    fn test_stop_on_regression_field_used() {
        // Verify that stop_on_regression is part of the budget and defaults to true.
        let budget = crate::budget::AutoFixBudget::default();
        assert!(
            budget.stop_on_regression,
            "stop_on_regression should default to true"
        );

        let budget_no_stop = crate::budget::AutoFixBudget {
            stop_on_regression: false,
            ..Default::default()
        };
        assert!(!budget_no_stop.stop_on_regression);
    }
}
