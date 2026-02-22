//! Go build and test integration — execute and parse results.

use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct BuildResult {
    pub success: bool,
    pub errors: Vec<String>,
    pub time_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub success: bool,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub failures: Vec<TestFailure>,
    pub time_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestFailure {
    pub package: String,
    pub test_name: String,
    pub output: String,
}

/// Run `go build` in the project directory.
pub fn go_build(project_dir: &Path, packages: &[String]) -> BuildResult {
    let start = std::time::Instant::now();
    let pkgs: Vec<String> = if packages.is_empty() {
        vec!["./...".to_string()]
    } else {
        packages.to_vec()
    };

    let output = Command::new("go")
        .arg("build")
        .args(&pkgs)
        .current_dir(project_dir)
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            BuildResult {
                success: out.status.success(),
                errors: if out.status.success() {
                    vec![]
                } else {
                    stderr
                        .lines()
                        .filter(|l| !l.is_empty())
                        .map(|l| l.to_string())
                        .collect()
                },
                time_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(e) => BuildResult {
            success: false,
            errors: vec![format!("Failed to run go build: {e}")],
            time_ms: start.elapsed().as_millis() as u64,
        },
    }
}

/// Run `go test` with JSON output for parsing.
pub fn go_test(project_dir: &Path, packages: &[String], timeout_secs: u64) -> TestResult {
    let start = std::time::Instant::now();
    let pkgs: Vec<String> = if packages.is_empty() {
        vec!["./...".to_string()]
    } else {
        packages.to_vec()
    };

    let output = Command::new("go")
        .arg("test")
        .arg("-json")
        .arg(format!("-timeout={timeout_secs}s"))
        .args(&pkgs)
        .current_dir(project_dir)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_go_test_json(&stdout, start.elapsed().as_millis() as u64)
        }
        Err(e) => TestResult {
            success: false,
            passed: 0,
            failed: 0,
            skipped: 0,
            failures: vec![TestFailure {
                package: String::new(),
                test_name: String::new(),
                output: format!("Failed to run go test: {e}"),
            }],
            time_ms: start.elapsed().as_millis() as u64,
        },
    }
}

/// Parse `go test -json` output lines.
///
/// Each line is a JSON object like:
/// `{"Time":"...","Action":"pass","Package":"pkg","Test":"TestFoo","Elapsed":0.001}`
/// `{"Time":"...","Action":"output","Package":"pkg","Test":"TestFoo","Output":"=== RUN   TestFoo\n"}`
fn parse_go_test_json(output: &str, time_ms: u64) -> TestResult {
    use std::collections::HashMap;

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<TestFailure> = Vec::new();
    let mut test_outputs: HashMap<(String, String), String> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        let action = obj.get("Action").and_then(|v| v.as_str()).unwrap_or("");
        let package = obj
            .get("Package")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let test = obj
            .get("Test")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        match action {
            "output" => {
                if !test.is_empty() {
                    let out_text = obj.get("Output").and_then(|v| v.as_str()).unwrap_or("");
                    test_outputs
                        .entry((package.clone(), test.clone()))
                        .or_default()
                        .push_str(out_text);
                }
            }
            "pass" => {
                if !test.is_empty() {
                    passed += 1;
                }
            }
            "fail" => {
                if !test.is_empty() {
                    failed += 1;
                    let output_text = test_outputs
                        .get(&(package.clone(), test.clone()))
                        .cloned()
                        .unwrap_or_default();
                    failures.push(TestFailure {
                        package: package.clone(),
                        test_name: test.clone(),
                        output: output_text,
                    });
                }
            }
            "skip" => {
                if !test.is_empty() {
                    skipped += 1;
                }
            }
            _ => {}
        }
    }

    TestResult {
        success: failed == 0,
        passed,
        failed,
        skipped,
        failures,
        time_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_result_serialization() {
        let result = BuildResult {
            success: false,
            errors: vec!["./main.go:5:2: undefined: foo".to_string()],
            time_ms: 123,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["errors"].is_array());
        assert_eq!(json["errors"][0], "./main.go:5:2: undefined: foo");
        assert_eq!(json["time_ms"], 123);
    }

    #[test]
    fn test_test_result_serialization() {
        let result = TestResult {
            success: false,
            passed: 3,
            failed: 1,
            skipped: 2,
            failures: vec![TestFailure {
                package: "example.com/app".to_string(),
                test_name: "TestBar".to_string(),
                output: "expected 1, got 2".to_string(),
            }],
            time_ms: 456,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["passed"], 3);
        assert_eq!(json["failed"], 1);
        assert_eq!(json["skipped"], 2);
        assert!(json["failures"].is_array());
        assert_eq!(json["failures"][0]["package"], "example.com/app");
        assert_eq!(json["failures"][0]["test_name"], "TestBar");
        assert_eq!(json["failures"][0]["output"], "expected 1, got 2");
        assert_eq!(json["time_ms"], 456);
    }

    #[test]
    fn test_parse_go_test_json_pass() {
        let output = r#"{"Action":"run","Package":"example.com/app","Test":"TestFoo"}
{"Action":"output","Package":"example.com/app","Test":"TestFoo","Output":"=== RUN   TestFoo\n"}
{"Action":"output","Package":"example.com/app","Test":"TestFoo","Output":"--- PASS: TestFoo (0.00s)\n"}
{"Action":"pass","Package":"example.com/app","Test":"TestFoo","Elapsed":0.001}
{"Action":"pass","Package":"example.com/app","Elapsed":0.002}"#;

        let result = parse_go_test_json(output, 100);
        assert!(result.success);
        assert_eq!(result.passed, 1);
        assert_eq!(result.failed, 0);
        assert_eq!(result.skipped, 0);
        assert!(result.failures.is_empty());
        assert_eq!(result.time_ms, 100);
    }

    #[test]
    fn test_parse_go_test_json_fail() {
        let output = r#"{"Action":"run","Package":"example.com/app","Test":"TestBar"}
{"Action":"output","Package":"example.com/app","Test":"TestBar","Output":"=== RUN   TestBar\n"}
{"Action":"output","Package":"example.com/app","Test":"TestBar","Output":"    bar_test.go:10: expected 1, got 2\n"}
{"Action":"output","Package":"example.com/app","Test":"TestBar","Output":"--- FAIL: TestBar (0.00s)\n"}
{"Action":"fail","Package":"example.com/app","Test":"TestBar","Elapsed":0.001}
{"Action":"fail","Package":"example.com/app","Elapsed":0.002}"#;

        let result = parse_go_test_json(output, 200);
        assert!(!result.success);
        assert_eq!(result.passed, 0);
        assert_eq!(result.failed, 1);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].package, "example.com/app");
        assert_eq!(result.failures[0].test_name, "TestBar");
        assert!(result.failures[0].output.contains("expected 1, got 2"));
        assert_eq!(result.time_ms, 200);
    }

    #[test]
    fn test_build_result_no_go() {
        // Use a non-existent directory to trigger an error from `go build`.
        let fake_dir = Path::new("/tmp/goguard_nonexistent_dir_for_test_12345");
        let result = go_build(fake_dir, &[]);
        assert!(!result.success);
        assert!(!result.errors.is_empty());
    }
}
