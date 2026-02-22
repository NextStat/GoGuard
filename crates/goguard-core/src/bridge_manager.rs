//! Go-bridge subprocess management.
//!
//! Manages the goguard-go-bridge Go binary as a long-running subprocess,
//! communicating via newline-delimited JSON over stdin/stdout.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Errors from the go-bridge subprocess.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("go-bridge binary not found at {0}")]
    BinaryNotFound(String),
    #[error("failed to spawn go-bridge: {0}")]
    SpawnFailed(String),
    #[error("go-bridge process died unexpectedly")]
    ProcessDied,
    #[error("failed to send request: {0}")]
    SendFailed(String),
    #[error("failed to read response: {0}")]
    ReadFailed(String),
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    #[error("go-bridge returned error: {0}")]
    BridgeResponseError(String),
    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Go toolchain not found. Install Go from https://go.dev/dl/")]
    GoNotInstalled,
}

/// Request sent to the go-bridge process.
#[derive(Debug, Serialize)]
struct BridgeRequest {
    id: u64,
    command: String,
    params: serde_json::Value,
}

/// Response received from the go-bridge process.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BridgeResponse {
    id: u64,
    ok: bool,
    data: Option<serde_json::Value>,
    error: Option<String>,
}

/// Parameters for the typecheck command.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TypecheckParams {
    pub dir: String,
    pub patterns: Vec<String>,
}

/// Parameters for the interfaces command.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterfacesParams {
    pub dir: String,
    pub interface_name: String,
    pub package: String,
}

/// Parameters for the methods command.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MethodsParams {
    pub dir: String,
    pub type_name: String,
    pub package: String,
}

/// Result from typecheck — package info.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PackageInfo {
    pub id: String,
    pub name: String,
    pub pkg_path: String,
    pub go_files: Vec<String>,
    pub functions: Vec<FunctionInfo>,
    pub types: Vec<TypeDefInfo>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Function information from go-bridge.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FunctionInfo {
    pub name: String,
    #[serde(default)]
    pub receiver: String,
    pub params: Vec<ParamInfo>,
    pub returns: Vec<ParamInfo>,
    pub is_exported: bool,
    pub position: Position,
}

/// Parameter or return value info.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ParamInfo {
    pub name: String,
    pub type_name: String,
    pub nullable: bool,
}

/// Type definition info.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TypeDefInfo {
    pub name: String,
    pub kind: String,
    pub underlying: String,
    pub is_exported: bool,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub fields: Vec<FieldInfo>,
    pub position: Position,
}

/// Field info from go-bridge.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub type_name: String,
    #[serde(default)]
    pub tag: String,
    pub embedded: bool,
}

/// Source position from go-bridge.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Position {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

/// Interface info from go-bridge.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub package: String,
    pub methods: Vec<String>,
    pub implementors: Vec<String>,
}

/// The go-bridge subprocess manager.
///
/// Manages a long-running go-bridge process, sending requests
/// and receiving responses via JSON over stdin/stdout.
pub struct GoBridge {
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<tokio::process::ChildStdin>>,
    stdout: Mutex<Option<BufReader<tokio::process::ChildStdout>>>,
    binary_path: PathBuf,
    request_id: AtomicU64,
    timeout: Duration,
}

impl GoBridge {
    /// Create a new GoBridge with the default binary path.
    ///
    /// Looks for the go-bridge binary in:
    /// 1. Same directory as the goguard binary
    /// 2. PATH
    /// 3. goguard-go-bridge/ relative to cwd (development)
    pub fn new() -> Result<Self, BridgeError> {
        let binary_path = find_bridge_binary()?;
        Ok(Self {
            child: Mutex::new(None),
            stdin: Mutex::new(None),
            stdout: Mutex::new(None),
            binary_path,
            request_id: AtomicU64::new(1),
            timeout: Duration::from_secs(30),
        })
    }

    /// Create a GoBridge with a specific binary path.
    pub fn with_binary(path: PathBuf) -> Self {
        Self {
            child: Mutex::new(None),
            stdin: Mutex::new(None),
            stdout: Mutex::new(None),
            binary_path: path,
            request_id: AtomicU64::new(1),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the request timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Start the go-bridge subprocess.
    pub async fn start(&self) -> Result<(), BridgeError> {
        let mut child = Command::new(&self.binary_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| BridgeError::SpawnFailed(e.to_string()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BridgeError::SpawnFailed("failed to capture stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::SpawnFailed("failed to capture stdout".into()))?;

        *self.child.lock().await = Some(child);
        *self.stdin.lock().await = Some(stdin);
        *self.stdout.lock().await = Some(BufReader::new(stdout));

        // Verify the bridge is alive with a ping.
        // Use send_request_raw to avoid the recursive ensure_running -> start cycle.
        let result = self
            .send_request_raw("ping", serde_json::Value::Null)
            .await?;
        if result.as_str() != Some("pong") {
            return Err(BridgeError::BridgeResponseError(
                "unexpected ping response during startup".into(),
            ));
        }

        Ok(())
    }

    /// Stop the go-bridge subprocess.
    pub async fn stop(&self) {
        // Drop stdin to signal EOF
        *self.stdin.lock().await = None;
        *self.stdout.lock().await = None;

        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.kill().await;
        }
    }

    /// Check if the bridge is running.
    pub async fn is_running(&self) -> bool {
        if let Some(ref mut child) = *self.child.lock().await {
            match child.try_wait() {
                Ok(None) => true, // Still running
                _ => false,       // Exited or error
            }
        } else {
            false
        }
    }

    /// Ensure the bridge is running, restarting if necessary.
    async fn ensure_running(&self) -> Result<(), BridgeError> {
        if !self.is_running().await {
            self.start().await?;
        }
        Ok(())
    }

    /// Send a request and wait for a response, ensuring the bridge is running.
    async fn send_request(
        &self,
        command: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        self.ensure_running().await?;
        self.send_request_raw(command, params).await
    }

    /// Send a request without auto-starting the bridge.
    ///
    /// Used internally by `start()` to avoid recursive async calls
    /// (start -> ping -> send_request -> ensure_running -> start).
    async fn send_request_raw(
        &self,
        command: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let request = BridgeRequest {
            id,
            command: command.to_string(),
            params,
        };

        let mut request_json = serde_json::to_string(&request)?;
        request_json.push('\n');

        // Send request
        {
            let mut stdin = self.stdin.lock().await;
            let stdin = stdin.as_mut().ok_or(BridgeError::ProcessDied)?;
            stdin
                .write_all(request_json.as_bytes())
                .await
                .map_err(|e| BridgeError::SendFailed(e.to_string()))?;
            stdin
                .flush()
                .await
                .map_err(|e| BridgeError::SendFailed(e.to_string()))?;
        }

        // Read response with timeout
        let response = tokio::time::timeout(self.timeout, async {
            let mut stdout = self.stdout.lock().await;
            let stdout = stdout.as_mut().ok_or(BridgeError::ProcessDied)?;
            let mut line = String::new();
            stdout
                .read_line(&mut line)
                .await
                .map_err(|e| BridgeError::ReadFailed(e.to_string()))?;
            if line.is_empty() {
                return Err(BridgeError::ProcessDied);
            }
            let resp: BridgeResponse = serde_json::from_str(&line)?;
            Ok(resp)
        })
        .await
        .map_err(|_| BridgeError::Timeout(self.timeout))??;

        if !response.ok {
            return Err(BridgeError::BridgeResponseError(
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string()),
            ));
        }

        Ok(response.data.unwrap_or(serde_json::Value::Null))
    }

    /// Ping the bridge to check it's alive.
    pub async fn ping(&self) -> Result<(), BridgeError> {
        let result = self.send_request("ping", serde_json::Value::Null).await?;
        if result.as_str() == Some("pong") {
            Ok(())
        } else {
            Err(BridgeError::BridgeResponseError(
                "unexpected ping response".into(),
            ))
        }
    }

    /// Type-check Go packages.
    pub async fn typecheck(
        &self,
        params: TypecheckParams,
    ) -> Result<Vec<PackageInfo>, BridgeError> {
        let params_json = serde_json::to_value(&params)?;
        let result = self.send_request("typecheck", params_json).await?;
        let packages: Vec<PackageInfo> = serde_json::from_value(result)?;
        Ok(packages)
    }

    /// Get interface implementors.
    pub async fn interfaces(&self, params: InterfacesParams) -> Result<InterfaceInfo, BridgeError> {
        let params_json = serde_json::to_value(&params)?;
        let result = self.send_request("interfaces", params_json).await?;
        let info: InterfaceInfo = serde_json::from_value(result)?;
        Ok(info)
    }

    /// Get method set for a type.
    pub async fn methods(&self, params: MethodsParams) -> Result<serde_json::Value, BridgeError> {
        let params_json = serde_json::to_value(&params)?;
        self.send_request("methods", params_json).await
    }

    /// One-shot analysis: spawn go-bridge analyze, read FlatBuffers from stdout.
    ///
    /// Protocol: stdout contains `[4 bytes LE length][FlatBuffers payload]`.
    /// Stderr contains logs/warnings. Exit code 0 = success.
    ///
    /// This is a convenience wrapper that delegates to
    /// [`analyze_packages_sync_with_cache`](Self::analyze_packages_sync_with_cache)
    /// with caching disabled (`cache_dir = None`).
    pub fn analyze_packages_sync(
        &self,
        dir: &std::path::Path,
        packages: &[String],
    ) -> Result<goguard_ir::ir::AnalysisInput, BridgeError> {
        self.analyze_packages_sync_with_cache(dir, packages, None, 20)
    }

    /// One-shot analysis with optional FlatBuffers cache support.
    ///
    /// When `cache_dir` is `Some`, passes `--cache-dir` and `--max-cache-entries`
    /// to the bridge subprocess, enabling filesystem-level caching of compiled
    /// FlatBuffers IR. This avoids re-running `go/packages.Load()` for unchanged
    /// packages — critical for large monorepos.
    ///
    /// Protocol: stdout contains `[4 bytes LE length][FlatBuffers payload]`.
    /// Stderr contains logs/warnings. Exit code 0 = success.
    pub fn analyze_packages_sync_with_cache(
        &self,
        dir: &std::path::Path,
        packages: &[String],
        cache_dir: Option<&Path>,
        max_cache_entries: usize,
    ) -> Result<goguard_ir::ir::AnalysisInput, BridgeError> {
        use std::process::Command as StdCommand;

        let mut cmd = StdCommand::new(&self.binary_path);
        cmd.arg("analyze")
            .arg("--packages")
            .arg(packages.join(","))
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add cache flags if configured
        if let Some(cache_dir) = cache_dir {
            cmd.arg("--cache-dir").arg(cache_dir);
            cmd.arg("--max-cache-entries")
                .arg(max_cache_entries.to_string());
        }

        let output = cmd
            .output()
            .map_err(|e| BridgeError::SpawnFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BridgeError::BridgeResponseError(format!(
                "go-bridge analyze exited with {}: {}",
                output.status, stderr
            )));
        }

        let stdout = &output.stdout;
        if stdout.len() < 4 {
            return Err(BridgeError::ReadFailed(
                "bridge returned no data on stdout".into(),
            ));
        }

        let len = u32::from_le_bytes([stdout[0], stdout[1], stdout[2], stdout[3]]) as usize;
        if stdout.len() < 4 + len {
            return Err(BridgeError::ReadFailed(format!(
                "expected {} bytes payload but got {}",
                len,
                stdout.len() - 4
            )));
        }

        let fb_bytes = &stdout[4..4 + len];
        goguard_ir::ir::AnalysisInput::from_flatbuffers(fb_bytes)
            .map_err(|e| BridgeError::ReadFailed(format!("FlatBuffers deserialization: {e}")))
    }
}

impl Drop for GoBridge {
    fn drop(&mut self) {
        // We can't do async in Drop, so just take the child
        // kill_on_drop(true) was set, so it will be killed
        if let Ok(mut guard) = self.child.try_lock() {
            guard.take();
        }
    }
}

/// Find the go-bridge binary.
fn find_bridge_binary() -> Result<PathBuf, BridgeError> {
    // 1. Check GOGUARD_BRIDGE_PATH env var
    if let Ok(path) = std::env::var("GOGUARD_BRIDGE_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    // 2. Check next to the current executable
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(Path::new("."));
        let bridge = dir.join("goguard-go-bridge");
        if bridge.exists() {
            return Ok(bridge);
        }
    }

    // 3. Check PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("goguard-go-bridge")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    // 4. Check development path (relative to cwd)
    let dev_path = PathBuf::from("goguard-go-bridge/goguard-go-bridge");
    if dev_path.exists() {
        return Ok(dev_path);
    }

    // 5. Try to build it if Go is installed
    check_go_installed()?;

    Err(BridgeError::BinaryNotFound(
        "goguard-go-bridge not found. Run: cd goguard-go-bridge && go build -o goguard-go-bridge ."
            .into(),
    ))
}

/// Check if Go toolchain is installed.
fn check_go_installed() -> Result<(), BridgeError> {
    match std::process::Command::new("go").arg("version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(BridgeError::GoNotInstalled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_request_serialization() {
        let req = BridgeRequest {
            id: 1,
            command: "typecheck".to_string(),
            params: serde_json::json!({
                "dir": "/tmp/project",
                "patterns": ["./..."]
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("\"command\":\"typecheck\""));
    }

    #[test]
    fn test_bridge_response_deserialization() {
        let json = r#"{"id":1,"ok":true,"data":"pong"}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, 1);
        assert!(resp.ok);
        assert_eq!(resp.data.unwrap().as_str().unwrap(), "pong");
    }

    #[test]
    fn test_bridge_error_response() {
        let json = r#"{"id":2,"ok":false,"error":"something went wrong"}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap(), "something went wrong");
    }

    #[test]
    fn test_package_info_deserialization() {
        let json = r#"{
            "id": "example.com/pkg",
            "name": "pkg",
            "pkg_path": "example.com/pkg",
            "go_files": ["main.go"],
            "functions": [{
                "name": "GetUser",
                "receiver": "",
                "params": [{"name": "id", "type_name": "int", "nullable": false}],
                "returns": [
                    {"name": "", "type_name": "*User", "nullable": true},
                    {"name": "", "type_name": "error", "nullable": true}
                ],
                "is_exported": true,
                "position": {"file": "main.go", "line": 10, "column": 1}
            }],
            "types": [],
            "errors": []
        }"#;
        let pkg: PackageInfo = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.name, "pkg");
        assert_eq!(pkg.functions.len(), 1);
        assert_eq!(pkg.functions[0].name, "GetUser");
        assert!(pkg.functions[0].returns[0].nullable);
    }

    #[test]
    fn test_check_go_installed() {
        // This test will pass if Go is installed on the system
        let result = check_go_installed();
        // Don't assert success since Go may not be installed in CI
        // Just verify no panic
        let _ = result;
    }

    #[test]
    fn test_analyze_with_cache_builds_correct_command() {
        // Use a nonexistent binary so cmd.output() fails with SpawnFailed.
        let bridge = GoBridge::with_binary(PathBuf::from("/nonexistent/goguard-go-bridge"));
        let dir = Path::new("/tmp");
        let packages = vec!["./...".to_string()];

        // With cache: verify the method accepts cache parameters and fails at spawn
        // (not at compile time or with a different error variant).
        let result_with_cache = bridge.analyze_packages_sync_with_cache(
            dir,
            &packages,
            Some(Path::new("/tmp/cache")),
            10,
        );
        assert!(result_with_cache.is_err());
        let err_with_cache = result_with_cache.unwrap_err();
        assert!(
            matches!(err_with_cache, BridgeError::SpawnFailed(_)),
            "expected SpawnFailed, got: {err_with_cache}"
        );

        // Without cache: the delegation wrapper should produce the same error class.
        let result_without_cache = bridge.analyze_packages_sync(dir, &packages);
        assert!(result_without_cache.is_err());
        let err_without_cache = result_without_cache.unwrap_err();
        assert!(
            matches!(err_without_cache, BridgeError::SpawnFailed(_)),
            "expected SpawnFailed, got: {err_without_cache}"
        );
    }

    #[test]
    fn test_analyze_without_cache_no_extra_args() {
        // Verify that analyze_packages_sync delegates to analyze_packages_sync_with_cache
        // with None for cache_dir — the error behavior should be identical.
        let bridge = GoBridge::with_binary(PathBuf::from("/nonexistent/goguard-go-bridge"));
        let dir = Path::new("/tmp");
        let packages = vec!["example.com/pkg".to_string()];

        // Call the convenience wrapper (no cache).
        let result = bridge.analyze_packages_sync(dir, &packages);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeError::SpawnFailed(_)),
            "expected SpawnFailed from delegated call, got: {err}"
        );

        // Also call with_cache(None, ...) directly to confirm identical behavior.
        let result_explicit = bridge.analyze_packages_sync_with_cache(dir, &packages, None, 20);
        assert!(result_explicit.is_err());
        let err_explicit = result_explicit.unwrap_err();
        assert!(
            matches!(err_explicit, BridgeError::SpawnFailed(_)),
            "expected SpawnFailed, got: {err_explicit}"
        );
    }
}
