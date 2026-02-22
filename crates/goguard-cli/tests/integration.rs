#![allow(deprecated)]
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_version() {
    Command::cargo_bin("goguard")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("goguard"))
        .stdout(predicate::str::is_match(r"goguard \d+\.\d+\.\d+").unwrap());
}

#[test]
fn test_version_long_includes_git_hash() {
    // --version shows short format "goguard 0.1.0 (abcdef12)"
    let output = Command::cargo_bin("goguard")
        .unwrap()
        .arg("--version")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    // Must contain parenthesized git hash
    assert!(
        stdout.contains('(') && stdout.contains(')'),
        "expected git hash in parens, got: {stdout}"
    );
}

#[test]
fn test_explain_nil001() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["explain", "NIL001"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nil pointer dereference"));
}

#[test]
fn test_explain_nil002() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["explain", "NIL002"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Unchecked type assertion"));
}

#[test]
fn test_explain_err001() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["explain", "ERR001"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Error return value not checked"));
}

#[test]
fn test_explain_err002() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["explain", "ERR002"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Error assigned to blank identifier",
        ));
}

#[test]
fn test_explain_unknown_rule() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["explain", "FAKE999"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_init_creates_config() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Created goguard.toml"));
    assert!(dir.path().join("goguard.toml").exists());
}

#[test]
fn test_init_creates_agents_md() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Created AGENTS.md"));
    assert!(dir.path().join("AGENTS.md").exists());
    let content = std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
    assert!(content.contains("GoGuard Static Analysis"));
    assert!(content.contains("<!-- goguard:begin -->"));
    assert!(content.contains("<!-- goguard:end -->"));
}

#[test]
fn test_init_does_not_overwrite_agents_md() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("AGENTS.md"), "# Existing content\n").unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    let content = std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
    assert_eq!(content, "# Existing content\n");
}

#[test]
fn test_init_fails_if_exists() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("goguard.toml"), "").unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_no_subcommand_shows_help() {
    Command::cargo_bin("goguard")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn test_setup_claude_code() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "claude-code"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mcpServers"))
        .stdout(predicate::str::contains("goguard"))
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("--mcp"));
}

#[test]
fn test_setup_cursor() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "cursor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mcpServers"));
}

#[test]
fn test_setup_windsurf() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "windsurf"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mcpServers"))
        .stdout(predicate::str::contains("goguard"));
}

#[test]
fn test_setup_codex() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[mcp_servers.goguard]"))
        .stdout(predicate::str::contains("command ="))
        .stdout(predicate::str::contains("args = [\"serve\", \"--mcp\"]"));
}

#[test]
fn test_setup_zed() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "zed"])
        .assert()
        .success()
        .stdout(predicate::str::contains("context_servers"))
        .stdout(predicate::str::contains("goguard"));
}

#[test]
fn test_setup_opencode() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "opencode"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"mcp\""))
        .stdout(predicate::str::contains("\"type\": \"local\""))
        .stdout(predicate::str::contains("\"enabled\": true"));
}

#[test]
fn test_setup_unknown() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["setup", "unknown"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_serve_mcp_help() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--mcp"));
}

#[test]
fn test_serve_lsp_help() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--lsp"));
}

#[test]
fn test_update_agents_md_creates_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let agents_path = dir.path().join("AGENTS.md");
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["update-agents-md", "--path", agents_path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated"));
    assert!(agents_path.exists());
    let content = std::fs::read_to_string(&agents_path).unwrap();
    assert!(content.contains("# AGENTS.md"));
    assert!(content.contains("<!-- goguard:begin -->"));
    assert!(content.contains("GoGuard Static Analysis"));
    assert!(content.contains("<!-- goguard:end -->"));
}

#[test]
fn test_update_agents_md_merges_into_existing() {
    let dir = tempfile::tempdir().unwrap();
    let agents_path = dir.path().join("AGENTS.md");
    std::fs::write(
        &agents_path,
        "# My Project\n\nSome content.\n\n<!-- goguard:begin -->\nOLD STUFF\n<!-- goguard:end -->\n\nMore content.\n",
    )
    .unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["update-agents-md", "--path", agents_path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .success();
    let content = std::fs::read_to_string(&agents_path).unwrap();
    assert!(content.contains("# My Project"));
    assert!(content.contains("GoGuard Static Analysis"));
    assert!(!content.contains("OLD STUFF"));
    assert!(content.contains("More content."));
}

#[test]
fn test_update_agents_md_appends_to_unmarked_file() {
    let dir = tempfile::tempdir().unwrap();
    let agents_path = dir.path().join("AGENTS.md");
    std::fs::write(&agents_path, "# My Project\n\nExisting content.\n").unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["update-agents-md", "--path", agents_path.to_str().unwrap()])
        .current_dir(dir.path())
        .assert()
        .success();
    let content = std::fs::read_to_string(&agents_path).unwrap();
    assert!(content.contains("# My Project"));
    assert!(content.contains("Existing content."));
    assert!(content.contains("<!-- goguard:begin -->"));
    assert!(content.contains("GoGuard Static Analysis"));
    assert!(content.contains("<!-- goguard:end -->"));
}

#[test]
fn test_update_agents_md_default_path() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("goguard")
        .unwrap()
        .arg("update-agents-md")
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated AGENTS.md"));
    assert!(dir.path().join("AGENTS.md").exists());
}

// ── sdk call integration tests ──

#[test]
fn test_sdk_call_rules_returns_json() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "call", "rules"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NIL001"))
        .stdout(predicate::str::contains("ERR001"));
}

#[test]
fn test_sdk_call_rules_with_category_filter() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "call", "rules", "--params", r#"{"category": "nil"}"#])
        .assert()
        .success()
        .stdout(predicate::str::contains("NIL001"))
        .stdout(predicate::str::contains("NIL002"));
}

#[test]
fn test_sdk_call_unknown_tool_fails() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "call", "nonexistent"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("Unknown tool"));
}

#[test]
fn test_sdk_call_rules_invalid_params() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "call", "rules", "--params", "not-json"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("Invalid params"));
}

#[test]
fn test_sdk_call_help() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "call", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--params"))
        .stdout(predicate::str::contains("--project-dir"));
}

// ── sdk generate integration tests ──

#[test]
fn test_sdk_generate_python() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "generate", "python"])
        .assert()
        .success()
        .stdout(predicate::str::contains("class GoGuard"));
}

#[test]
fn test_sdk_generate_python_has_methods() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "generate", "python"])
        .assert()
        .success()
        .stdout(predicate::str::contains("def analyze"))
        .stdout(predicate::str::contains("def fix"))
        .stdout(predicate::str::contains("def explain"));
}

#[test]
fn test_sdk_generate_unknown_target() {
    Command::cargo_bin("goguard")
        .unwrap()
        .args(["sdk", "generate", "java"])
        .assert()
        .failure()
        .code(2);
}
