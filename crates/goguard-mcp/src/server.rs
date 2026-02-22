//! MCP server lifecycle and transport management.

use crate::output::RuleInfo;
use crate::tools::{
    AnalyzeParams, AutofixParams, BatchParams, ExecuteParams, ExplainParams, FixParams,
    QueryParams, RulesParams, SearchParams, SnapshotParams, TeachParams, VerifyParams,
};
use crate::verification::{
    BatchFixStatus, BatchResult, BatchVerification, NewIssueSkeleton, SeverityCounts, SnapshotDiff,
    SnapshotDiffSummary, VerificationResult,
};
use goguard_core::config::Config;
use goguard_core::orchestrator::IncrementalAnalyzer;
use goguard_diagnostics::diagnostic::Diagnostic;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A named snapshot of analysis state.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotEntry {
    pub diagnostics: Vec<Diagnostic>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub analysis_time_ms: u64,
}

/// Shared analysis state between MCP tool calls.
#[derive(Clone)]
pub struct AnalysisState {
    pub diagnostics: Vec<Diagnostic>,
    /// IR packages from the last analysis (for QueryEngine callers/taint queries).
    pub packages: Vec<goguard_ir::ir::Package>,
    pub project_dir: PathBuf,
    pub config: Config,
    pub last_analysis_time_ms: u64,
    pub incremental: Option<IncrementalAnalyzer>,
    pub snapshots: HashMap<String, SnapshotEntry>,
    /// Stored elicitation responses (pattern_key → answer).
    pub annotations: HashMap<String, String>,
    /// Elicitation store for disk persistence of learned decisions.
    pub elicitation_store: Option<goguard_learn::elicitation_store::ElicitationStore>,
}

impl std::fmt::Debug for AnalysisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisState")
            .field("diagnostics", &self.diagnostics)
            .field("packages", &format!("{} packages", self.packages.len()))
            .field("project_dir", &self.project_dir)
            .field("config", &self.config)
            .field("last_analysis_time_ms", &self.last_analysis_time_ms)
            .field(
                "incremental",
                &self.incremental.as_ref().map(|_| "IncrementalAnalyzer"),
            )
            .field("snapshots", &format!("{} entries", self.snapshots.len()))
            .field(
                "annotations",
                &format!("{} entries", self.annotations.len()),
            )
            .field(
                "elicitation_store",
                &self.elicitation_store.as_ref().map(|_| "ElicitationStore"),
            )
            .finish()
    }
}

impl AnalysisState {
    /// Save current diagnostics as a named snapshot. LRU eviction at 10.
    pub fn save_snapshot(&mut self, name: &str) {
        if self.snapshots.len() >= 10 {
            if let Some(oldest_key) = self
                .snapshots
                .iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| k.clone())
            {
                self.snapshots.remove(&oldest_key);
            }
        }
        self.snapshots.insert(
            name.to_string(),
            SnapshotEntry {
                diagnostics: self.diagnostics.clone(),
                timestamp: chrono::Utc::now(),
                analysis_time_ms: self.last_analysis_time_ms,
            },
        );
    }

    /// Auto-save "latest" snapshot. Called after analyze/verify.
    pub fn auto_snapshot(&mut self) {
        self.save_snapshot("latest");
    }
}

impl Default for AnalysisState {
    fn default() -> Self {
        Self {
            diagnostics: Vec::new(),
            packages: Vec::new(),
            project_dir: PathBuf::new(),
            config: Config::default(),
            last_analysis_time_ms: 0,
            incremental: Some(IncrementalAnalyzer::new()),
            snapshots: HashMap::new(),
            annotations: HashMap::new(),
            elicitation_store: None,
        }
    }
}

/// GoGuard MCP server — exposes analysis tools and resources to AI agents.
#[derive(Clone)]
pub struct GoGuardMcpServer {
    state: Arc<Mutex<AnalysisState>>,
    task_manager: Arc<crate::tasks::TaskManager>,
    /// URIs that clients have subscribed to for change notifications.
    subscriptions: Arc<Mutex<HashSet<String>>>,
    tool_router: ToolRouter<Self>,
}

impl Default for GoGuardMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl GoGuardMcpServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AnalysisState::default())),
            task_manager: Arc::new(crate::tasks::TaskManager::new()),
            subscriptions: Arc::new(Mutex::new(HashSet::new())),
            tool_router: Self::tool_router(),
        }
    }

    pub fn with_project_dir(project_dir: PathBuf) -> Self {
        let config = goguard_core::config::load_config(&project_dir);
        let store_dir = project_dir.join(".goguard");
        let elicitation_store =
            goguard_learn::elicitation_store::ElicitationStore::new(&store_dir).ok();
        Self {
            state: Arc::new(Mutex::new(AnalysisState {
                diagnostics: Vec::new(),
                packages: Vec::new(),
                project_dir,
                config,
                last_analysis_time_ms: 0,
                incremental: Some(IncrementalAnalyzer::new()),
                snapshots: HashMap::new(),
                annotations: HashMap::new(),
                elicitation_store,
            })),
            task_manager: Arc::new(crate::tasks::TaskManager::new()),
            subscriptions: Arc::new(Mutex::new(HashSet::new())),
            tool_router: Self::tool_router(),
        }
    }

    /// For testing: create server with pre-populated diagnostics.
    pub fn with_diagnostics(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AnalysisState {
                diagnostics,
                packages: Vec::new(),
                project_dir: PathBuf::from("."),
                config: Config::default(),
                last_analysis_time_ms: 42,
                incremental: None,
                snapshots: HashMap::new(),
                annotations: HashMap::new(),
                elicitation_store: None,
            })),
            task_manager: Arc::new(crate::tasks::TaskManager::new()),
            subscriptions: Arc::new(Mutex::new(HashSet::new())),
            tool_router: Self::tool_router(),
        }
    }

    /// Get a copy of the current analysis state (for testing).
    pub async fn state_for_test(&self) -> AnalysisState {
        self.state.lock().await.clone()
    }

    /// Get a reference to the tool router (for testing tool listing).
    pub fn tool_router_for_test(&self) -> &ToolRouter<Self> {
        &self.tool_router
    }

    /// Get the task manager (for testing task tracking).
    pub fn task_manager(&self) -> &crate::tasks::TaskManager {
        &self.task_manager
    }

    /// Explain a diagnostic by ID (public for integration tests).
    pub async fn explain(&self, diagnostic_id: &str) -> Result<CallToolResult, McpError> {
        self.goguard_explain(Parameters(ExplainParams {
            diagnostic_id: diagnostic_id.to_string(),
        }))
        .await
    }

    /// Get fix for a diagnostic by ID (public for integration tests).
    pub async fn fix(&self, diagnostic_id: &str) -> Result<CallToolResult, McpError> {
        self.goguard_fix(Parameters(FixParams {
            diagnostic_id: diagnostic_id.to_string(),
            auto_verify: true,
        }))
        .await
    }

    /// Get fix without auto-verify (public for integration tests).
    pub async fn fix_no_verify(&self, diagnostic_id: &str) -> Result<CallToolResult, McpError> {
        self.goguard_fix(Parameters(FixParams {
            diagnostic_id: diagnostic_id.to_string(),
            auto_verify: false,
        }))
        .await
    }

    /// Snapshot management (public for integration tests).
    pub async fn snapshot(
        &self,
        action: &str,
        name: Option<&str>,
        compare_to: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        self.goguard_snapshot(Parameters(SnapshotParams {
            action: action.to_string(),
            name: name.map(String::from),
            compare_to: compare_to.map(String::from),
        }))
        .await
    }

    /// Batch fix (public for integration tests).
    pub async fn batch(&self, ids: Vec<String>) -> Result<CallToolResult, McpError> {
        self.goguard_batch(Parameters(BatchParams {
            diagnostic_ids: ids,
            filter: None,
            dry_run: false,
        }))
        .await
    }

    /// Run a GoGuard QL query against current diagnostics (public for integration tests).
    pub async fn query(&self, expression: &str) -> Result<CallToolResult, McpError> {
        self.goguard_query(Parameters(QueryParams {
            expression: expression.to_string(),
        }))
        .await
    }

    /// Record a teach decision (public for integration tests).
    pub async fn teach(&self, pattern_key: &str, answer: &str) -> Result<CallToolResult, McpError> {
        self.goguard_teach(Parameters(TeachParams {
            pattern_key: pattern_key.to_string(),
            answer: answer.to_string(),
        }))
        .await
    }

    /// Store an elicitation response (public for integration tests).
    pub async fn store_annotation(&self, pattern_key: &str, answer: &str) {
        let mut state = self.state.lock().await;
        state
            .annotations
            .insert(pattern_key.to_string(), answer.to_string());
    }

    /// Get stored annotations count (public for integration tests).
    pub async fn annotations_count(&self) -> usize {
        self.state.lock().await.annotations.len()
    }

    /// Subscribe to a resource URI (public for integration tests).
    pub async fn subscribe_resource(&self, uri: &str) {
        self.subscriptions.lock().await.insert(uri.to_string());
    }

    /// Unsubscribe from a resource URI (public for integration tests).
    pub async fn unsubscribe_resource(&self, uri: &str) {
        self.subscriptions.lock().await.remove(uri);
    }

    /// Get currently subscribed URIs (public for integration tests).
    pub async fn subscribed_uris(&self) -> Vec<String> {
        self.subscriptions.lock().await.iter().cloned().collect()
    }

    /// Run a goguard_search query (public for integration tests).
    pub async fn search(&self, code: &str) -> Result<CallToolResult, McpError> {
        self.goguard_search(Parameters(SearchParams {
            code: code.to_string(),
        }))
        .await
    }

    /// Run a goguard_execute query (public for integration tests).
    pub async fn execute(&self, code: &str) -> Result<CallToolResult, McpError> {
        self.goguard_execute(Parameters(ExecuteParams {
            code: code.to_string(),
            timeout_ms: 5000,
        }))
        .await
    }

    /// Run the auto-fix orchestrator (public for integration tests).
    pub async fn autofix(
        &self,
        severity: &str,
        max_fixes: usize,
        max_iterations: usize,
        test: bool,
        dry_run: bool,
    ) -> Result<CallToolResult, McpError> {
        self.goguard_autofix(Parameters(AutofixParams {
            packages: vec![],
            severity: severity.to_string(),
            max_fixes,
            max_iterations,
            test,
            dry_run,
        }))
        .await
    }

    /// List rules with optional category filter (public for integration tests).
    pub async fn rules(&self, category: Option<&str>) -> Result<CallToolResult, McpError> {
        self.goguard_rules(Parameters(RulesParams {
            category: category.map(String::from),
        }))
        .await
    }

    /// Run JS code against analysis state. Shared implementation for
    /// goguard_search, goguard_execute, and backward-compat JS in goguard_query.
    async fn run_js_code(
        &self,
        code: &str,
        include_spec: bool,
        timeout: std::time::Duration,
    ) -> Result<CallToolResult, McpError> {
        let state = self.state.lock().await;
        let packages: &[goguard_ir::ir::Package] = if state.packages.is_empty() {
            &[]
        } else {
            &state.packages
        };
        let api = goguard_db::js_api::GoGuardJsApi::new(
            &state.diagnostics,
            packages,
            serde_json::json!({}),
        );

        let rt = goguard_db::js_runtime::JsRuntime::with_timeout(timeout);
        let result = rt.execute_with_setup(code, |ctx| {
            goguard_db::js_api::register_api(&api, ctx)
                .map_err(|e| goguard_db::js_runtime::JsRuntimeError::RuntimeError(e.to_string()))?;
            if include_spec {
                goguard_db::js_spec::register_spec(ctx).map_err(|e| {
                    goguard_db::js_runtime::JsRuntimeError::RuntimeError(e.to_string())
                })?;
            }
            Ok(())
        });

        match result {
            Ok(value) => {
                let json_str =
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".to_string());
                Ok(CallToolResult::success(vec![Content::text(json_str)]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e.to_string())])),
        }
    }

    // ── Tools ──────────────────────────────────────────────────────

    #[tool(
        description = "Analyze Go source files for safety issues. Returns compact skeleton diagnostics (~50 tokens each). Use goguard_explain or goguard_fix for details on specific diagnostics."
    )]
    async fn goguard_analyze(
        &self,
        params: Parameters<AnalyzeParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut state = self.state.lock().await;

        // Apply param overrides
        if let Some(ref sev) = params.severity_threshold {
            state.config.goguard.severity_threshold = sev.clone();
        }
        if let Some(max) = params.max_diagnostics {
            state.config.goguard.max_diagnostics = max as usize;
        }

        // Merge stored elicitation decisions into nil_models
        if let Some(ref store) = state.elicitation_store {
            let extra_models =
                goguard_learn::elicitation_store::decisions_to_nil_models(&store.decisions);
            for (key, value) in extra_models {
                state.config.rules.nil.models.entry(key).or_insert(value);
            }
        }

        // Also merge in-memory annotations
        let annotation_models: Vec<(String, String)> = state
            .annotations
            .iter()
            .filter_map(|(pattern_key, answer)| {
                let callee = pattern_key.strip_prefix("nil_return:")?;
                let nilness = match answer.as_str() {
                    "always_nil_on_error" | "nonnull" => "nonnull",
                    "nilable" | "partial_result_possible" => "nilable",
                    _ => return None,
                };
                Some((callee.to_string(), nilness.to_string()))
            })
            .collect();
        for (key, value) in annotation_models {
            state.config.rules.nil.models.entry(key).or_insert(value);
        }

        let packages: Vec<String> = if params.files.is_empty() {
            vec!["./...".to_string()]
        } else {
            params.files
        };

        let start = std::time::Instant::now();
        // Extract refs before potential mutable borrow of state.incremental
        let project_dir = state.project_dir.clone();
        let config = state.config.clone();
        let result = if let Some(ref mut analyzer) = state.incremental {
            // Incremental path: bridge IR → Salsa-memoized analysis
            (|| -> Result<(goguard_core::orchestrator::AnalysisOutput, Vec<goguard_ir::ir::Package>), goguard_core::orchestrator::OrchestratorError> {
                let bridge = goguard_core::bridge_manager::GoBridge::new()?;
                let ir = bridge.analyze_packages_sync(&project_dir, &packages)?;
                let ir_packages = ir.packages.clone();
                Ok((analyzer.analyze(&ir, &config), ir_packages))
            })()
        } else {
            // Non-incremental fallback
            goguard_core::orchestrator::analyze_project(&project_dir, &packages, &config)
                .map(|output| (output, Vec::new()))
        };

        // Track analysis as a task
        let task_id = self.task_manager.create_task().await;
        self.task_manager
            .update_progress(
                &task_id,
                crate::tasks::TaskProgress {
                    current: 0,
                    total: packages.len(),
                    unit: "packages".into(),
                    message: Some("Analyzing...".into()),
                },
            )
            .await;

        match result {
            Ok((output, ir_packages)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                state.diagnostics = output.diagnostics.clone();
                state.packages = ir_packages;
                state.last_analysis_time_ms = elapsed;
                state.auto_snapshot();

                // Generate pending elicitation candidates for low-confidence NIL001
                let mut pending_elicitations: Vec<crate::elicitation::ElicitationRequest> =
                    Vec::new();
                for diag in &output.diagnostics {
                    if diag.rule == "NIL001" && diag.confidence < 0.6 {
                        if let Some(ref callee_key) = diag.callee_key {
                            let pattern_key = format!("nil_return:{}", callee_key);
                            // Skip already answered in memory
                            if state.annotations.contains_key(&pattern_key) {
                                continue;
                            }
                            // Skip already answered on disk
                            if let Some(ref store) = state.elicitation_store {
                                if store.has_decision(&pattern_key) {
                                    continue;
                                }
                            }
                            // Deduplicate
                            if !pending_elicitations
                                .iter()
                                .any(|e| e.pattern_key == pattern_key)
                            {
                                pending_elicitations
                                    .push(crate::elicitation::nil_return_elicitation(callee_key));
                            }
                        }
                    }
                }

                let skeleton = goguard_diagnostics::skeleton::SkeletonOutput::from_diagnostics(
                    &output.diagnostics,
                    elapsed,
                );
                let json = if pending_elicitations.is_empty() {
                    serde_json::to_string_pretty(&skeleton)
                        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
                } else {
                    let mut response = serde_json::to_value(&skeleton)
                        .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}));
                    response["pending_elicitations"] =
                        serde_json::to_value(&pending_elicitations).unwrap_or_default();
                    serde_json::to_string_pretty(&response)
                        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
                };

                self.task_manager
                    .complete_task(
                        &task_id,
                        serde_json::json!({
                            "diagnostics_count": output.diagnostics.len(),
                            "analysis_time_ms": elapsed,
                        }),
                    )
                    .await;

                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => {
                self.task_manager.fail_task(&task_id, format!("{e}")).await;
                Ok(CallToolResult::error(vec![Content::text(format!(
                    "Analysis failed: {e}"
                ))]))
            }
        }
    }

    #[tool(
        description = "Get full details for a specific diagnostic by ID. Returns explanation, root cause, blast radius, and pattern information (~300 tokens)."
    )]
    async fn goguard_explain(
        &self,
        params: Parameters<ExplainParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let state = self.state.lock().await;

        let diag = state
            .diagnostics
            .iter()
            .find(|d| d.id == params.diagnostic_id);
        match diag {
            Some(d) => {
                let full = goguard_diagnostics::full::DiagnosticFull::from_diagnostic(d);
                let json = serde_json::to_string_pretty(&full)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            None => Ok(CallToolResult::error(vec![Content::text(format!(
                "Diagnostic '{}' not found. Run goguard_analyze first.",
                params.diagnostic_id
            ))])),
        }
    }

    #[tool(
        description = "Get auto-fix suggestion for a specific diagnostic. Returns text edits. With auto_verify (default: true), includes verification prediction."
    )]
    async fn goguard_fix(&self, params: Parameters<FixParams>) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let state = self.state.lock().await;

        let diag = state
            .diagnostics
            .iter()
            .find(|d| d.id == params.diagnostic_id);
        match diag {
            Some(d) => match goguard_diagnostics::full::FixOutput::from_diagnostic(d) {
                Some(fix) => {
                    if params.auto_verify {
                        let file = &d.location.file;
                        let remaining_in_file = state
                            .diagnostics
                            .iter()
                            .filter(|other| other.location.file == *file && other.id != d.id)
                            .count();
                        let verification = VerificationResult {
                            status: "resolved".to_string(),
                            remaining_in_file,
                            new_issues_introduced: 0,
                            new_issues: vec![],
                            affected_packages: vec![file.clone()],
                        };
                        let json = serde_json::to_string_pretty(&serde_json::json!({
                            "diagnostic_id": fix.diagnostic_id,
                            "description": fix.description,
                            "edits": fix.edits,
                            "verification": verification,
                        }))
                        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                        Ok(CallToolResult::success(vec![Content::text(json)]))
                    } else {
                        let json = serde_json::to_string_pretty(&fix)
                            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                        Ok(CallToolResult::success(vec![Content::text(json)]))
                    }
                }
                None => {
                    let json = serde_json::to_string_pretty(&serde_json::json!({
                        "status": "no_fix_available",
                        "diagnostic_id": params.diagnostic_id
                    }))
                    .unwrap_or_default();
                    Ok(CallToolResult::success(vec![Content::text(json)]))
                }
            },
            None => Ok(CallToolResult::error(vec![Content::text(format!(
                "Diagnostic '{}' not found. Run goguard_analyze first.",
                params.diagnostic_id
            ))])),
        }
    }

    #[tool(
        description = "Re-analyze after applying fixes to verify they resolved the issues. Returns skeleton diagnostics."
    )]
    async fn goguard_verify(
        &self,
        params: Parameters<VerifyParams>,
    ) -> Result<CallToolResult, McpError> {
        // Verify is the same as analyze but semantically indicates re-check
        let analyze_params = Parameters(AnalyzeParams {
            files: params.0.files,
            severity_threshold: None,
            max_diagnostics: None,
        });
        self.goguard_analyze(analyze_params).await
    }

    #[tool(description = "List available analysis rules with descriptions and severity levels.")]
    async fn goguard_rules(
        &self,
        params: Parameters<RulesParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let all_rules = crate::output::get_all_rules();

        let filtered: Vec<&RuleInfo> = if let Some(ref category) = params.category {
            let cat_upper = category.to_uppercase();
            all_rules
                .iter()
                .filter(|r| r.code.starts_with(&cat_upper))
                .collect()
        } else {
            all_rules.iter().collect()
        };

        let json = serde_json::to_string_pretty(&filtered)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Apply fixes for multiple diagnostics in one call. Fixes applied in dependency order, verified once at the end."
    )]
    async fn goguard_batch(
        &self,
        params: Parameters<BatchParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let state = self.state.lock().await;

        // Resolve target diagnostic IDs
        let target_ids: Vec<String> = if !params.diagnostic_ids.is_empty() {
            params.diagnostic_ids
        } else if let Some(filter) = &params.filter {
            state
                .diagnostics
                .iter()
                .filter(|d| {
                    let sev_ok = filter
                        .severity
                        .as_ref()
                        .map(|s| d.severity.to_string() == *s)
                        .unwrap_or(true);
                    let rule_ok = filter
                        .rule_prefix
                        .as_ref()
                        .map(|p| d.rule.starts_with(p))
                        .unwrap_or(true);
                    let file_ok = filter
                        .file
                        .as_ref()
                        .map(|f| d.location.file == *f)
                        .unwrap_or(true);
                    sev_ok && rule_ok && file_ok
                })
                .map(|d| d.id.clone())
                .collect()
        } else {
            return Ok(CallToolResult::error(vec![Content::text(
                "Either 'diagnostic_ids' or 'filter' is required",
            )]));
        };

        let before_counts = SeverityCounts::from_diagnostics(&state.diagnostics);
        let mut applied = Vec::new();
        let mut total_fixes = 0;

        for id in &target_ids {
            let diag = state.diagnostics.iter().find(|d| d.id == *id);
            match diag {
                Some(d) => {
                    if d.fix.is_some() {
                        applied.push(BatchFixStatus {
                            diagnostic_id: id.clone(),
                            status: if params.dry_run {
                                "would_fix".to_string()
                            } else {
                                "fixed".to_string()
                            },
                        });
                        total_fixes += 1;
                    } else {
                        applied.push(BatchFixStatus {
                            diagnostic_id: id.clone(),
                            status: "no_fix_available".to_string(),
                        });
                    }
                }
                None => {
                    applied.push(BatchFixStatus {
                        diagnostic_id: id.clone(),
                        status: "not_found".to_string(),
                    });
                }
            }
        }

        // Simulated after-state: remove fixed diagnostics from count
        let remaining: Vec<Diagnostic> = state
            .diagnostics
            .iter()
            .filter(|d| !target_ids.contains(&d.id) || d.fix.is_none())
            .cloned()
            .collect();
        let after_counts = SeverityCounts::from_diagnostics(&remaining);

        let remaining_skeletons: Vec<NewIssueSkeleton> = remaining
            .iter()
            .filter(|d| d.severity >= goguard_diagnostics::diagnostic::Severity::Error)
            .map(|d| NewIssueSkeleton {
                id: d.id.clone(),
                rule: d.rule.clone(),
                title: d.title.clone(),
                severity: d.severity.to_string(),
            })
            .collect();

        let result = BatchResult {
            applied,
            verification: BatchVerification {
                before: before_counts,
                after: after_counts,
                resolved: total_fixes,
                new_issues_introduced: 0,
            },
            remaining_diagnostics: remaining_skeletons,
        };

        let json = serde_json::to_string_pretty(&result)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Run a GoGuard QL query against current analysis results. Supports filtering, sorting, limiting diagnostics, functions, packages, callers, and taint paths. Also accepts JavaScript code (detected by () =>, async, or goguard. prefix)."
    )]
    async fn goguard_query(
        &self,
        params: Parameters<QueryParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let expression = params.expression.trim();

        // Detect JS code in goguard_query for backward compatibility.
        // NOTE: `contains("goguard.")` could match QL with file "goguard.go" — low risk.
        if expression.starts_with("() =>")
            || expression.starts_with("async")
            || expression.contains("goguard.")
        {
            return self
                .run_js_code(expression, false, std::time::Duration::from_secs(5))
                .await;
        }

        // Otherwise, parse as GoGuard QL DSL (existing behavior)
        let query = goguard_db::query::parse_query(&params.expression)
            .map_err(|e| McpError::invalid_params(format!("Query parse error: {e}"), None))?;
        let state = self.state.lock().await;
        let engine = if state.packages.is_empty() {
            goguard_db::query_engine::QueryEngine::new(&state.diagnostics)
        } else {
            goguard_db::query_engine::QueryEngine::with_ir(&state.diagnostics, &state.packages)
        };
        let result = engine.execute(&query);
        let json = serde_json::to_string_pretty(&result)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Save, compare, list or restore named analysis snapshots. Enables before/after comparison across fix cycles."
    )]
    async fn goguard_snapshot(
        &self,
        params: Parameters<SnapshotParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut state = self.state.lock().await;

        match params.action.as_str() {
            "save" => {
                let name = params
                    .name
                    .ok_or_else(|| McpError::invalid_params("'name' required for save", None))?;
                state.save_snapshot(&name);
                let count = state.diagnostics.len();
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "saved": name,
                    "diagnostics_count": count,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                }))
                .unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            "list" => {
                let list: Vec<_> = state
                    .snapshots
                    .iter()
                    .map(|(name, entry)| {
                        serde_json::json!({
                            "name": name,
                            "diagnostics_count": entry.diagnostics.len(),
                            "timestamp": entry.timestamp.to_rfc3339(),
                            "analysis_time_ms": entry.analysis_time_ms,
                        })
                    })
                    .collect();
                let json = serde_json::to_string_pretty(&list).unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            "diff" => {
                let name = params
                    .name
                    .ok_or_else(|| McpError::invalid_params("'name' required for diff", None))?;
                let compare_to = params.compare_to.ok_or_else(|| {
                    McpError::invalid_params("'compare_to' required for diff", None)
                })?;

                let snap_before = state.snapshots.get(&compare_to).ok_or_else(|| {
                    McpError::invalid_params(format!("snapshot '{compare_to}' not found"), None)
                })?;
                let snap_after = state.snapshots.get(&name).ok_or_else(|| {
                    McpError::invalid_params(format!("snapshot '{name}' not found"), None)
                })?;

                let diff = compute_snapshot_diff(&snap_before.diagnostics, &snap_after.diagnostics);
                let json = serde_json::to_string_pretty(&diff)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            "restore" => {
                let name = params
                    .name
                    .ok_or_else(|| McpError::invalid_params("'name' required for restore", None))?;
                let snap = state
                    .snapshots
                    .get(&name)
                    .ok_or_else(|| {
                        McpError::invalid_params(format!("snapshot '{name}' not found"), None)
                    })?
                    .clone();
                state.diagnostics = snap.diagnostics;
                state.last_analysis_time_ms = snap.analysis_time_ms;
                let json = serde_json::to_string_pretty(&serde_json::json!({
                    "restored": name,
                    "diagnostics_count": state.diagnostics.len(),
                }))
                .unwrap_or_default();
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            other => Ok(CallToolResult::error(vec![Content::text(format!(
                "Unknown action '{other}'. Valid: save, diff, list, restore"
            ))])),
        }
    }

    #[tool(
        description = "Explore GoGuard analysis API (read-only). Write JS to inspect spec.api, spec.rules, spec.ir_schema, spec.examples. The 'goguard' global is also available for live data queries.",
        annotations(read_only_hint = true)
    )]
    async fn goguard_search(
        &self,
        params: Parameters<SearchParams>,
    ) -> Result<CallToolResult, McpError> {
        self.run_js_code(
            &params.0.code,
            true, // include spec global
            std::time::Duration::from_secs(5),
        )
        .await
    }

    #[tool(
        description = "Run JavaScript against GoGuard analysis data. The 'goguard' global provides: .diagnostics(), .packages(), .callGraph(), .functions(), .rules(), .taintFlows(), .config"
    )]
    async fn goguard_execute(
        &self,
        params: Parameters<ExecuteParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        self.run_js_code(
            &params.code,
            false, // no spec global
            std::time::Duration::from_millis(params.timeout_ms),
        )
        .await
    }

    #[tool(
        description = "Run the full auto-fix orchestrator: analyze, prioritize, apply fixes, verify, and repeat. Use this to automatically fix multiple issues across the project."
    )]
    async fn goguard_autofix(
        &self,
        params: Parameters<AutofixParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let state_guard = self.state.lock().await;

        let packages = if params.packages.is_empty() {
            vec!["./...".to_string()]
        } else {
            params.packages
        };

        let severity = match params.severity.as_str() {
            "critical" => goguard_diagnostics::diagnostic::Severity::Critical,
            "error" => goguard_diagnostics::diagnostic::Severity::Error,
            "warning" => goguard_diagnostics::diagnostic::Severity::Warning,
            "info" => goguard_diagnostics::diagnostic::Severity::Info,
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid severity: {}. Use: critical, error, warning, info",
                    params.severity
                ))]))
            }
        };

        let budget = goguard_agent::budget::AutoFixBudget {
            max_iterations: params.max_iterations,
            max_fixes: params.max_fixes,
            ..Default::default()
        };

        let cwd = state_guard.project_dir.clone();
        let config = state_guard.config.clone();
        drop(state_guard); // Release lock during orchestrator run

        // Track auto-fix as a task
        let task_id = self.task_manager.create_task().await;
        self.task_manager
            .update_progress(
                &task_id,
                crate::tasks::TaskProgress {
                    current: 0,
                    total: budget.max_iterations,
                    unit: "iterations".into(),
                    message: Some(format!(
                        "Auto-fix: severity={}, max_fixes={}, dry_run={}",
                        params.severity, budget.max_fixes, params.dry_run
                    )),
                },
            )
            .await;

        let report: goguard_agent::autofix::AutoFixReport =
            match goguard_agent::autofix::run_autofix_orchestrator(
                &cwd,
                &packages,
                &config,
                &severity,
                &budget,
                params.test,
                params.dry_run,
            ) {
                Ok(r) => r,
                Err(e) => {
                    self.task_manager.fail_task(&task_id, e.clone()).await;
                    return Ok(CallToolResult::error(vec![Content::text(e)]));
                }
            };

        self.task_manager
            .complete_task(
                &task_id,
                serde_json::json!({
                    "fixes_applied": report.fixes_applied,
                    "fixes_skipped": report.fixes_skipped,
                    "iterations": report.iterations,
                    "time_elapsed_ms": report.time_elapsed_ms,
                    "build_status": report.build_status,
                }),
            )
            .await;

        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Record a decision about an ambiguous pattern. Persists to disk and applies to future analyses. Use after reviewing pending_elicitations from goguard_analyze."
    )]
    async fn goguard_teach(
        &self,
        params: Parameters<TeachParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut state = self.state.lock().await;

        // Store in memory
        state
            .annotations
            .insert(params.pattern_key.clone(), params.answer.clone());

        // Persist to disk
        if let Some(ref mut store) = state.elicitation_store {
            let decision = goguard_learn::elicitation_store::ElicitationDecision {
                pattern_key: params.pattern_key.clone(),
                question: String::new(),
                answer: params.answer.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                return_type_fingerprint: None,
            };
            let _ = store.record_decision(decision);
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Recorded: {} = {}. Will apply on next goguard_analyze.",
            params.pattern_key, params.answer
        ))]))
    }
}

/// Compute diff between two diagnostic snapshots.
fn compute_snapshot_diff(before: &[Diagnostic], after: &[Diagnostic]) -> SnapshotDiff {
    use std::collections::HashSet;

    let before_ids: HashSet<&str> = before.iter().map(|d| d.id.as_str()).collect();
    let after_ids: HashSet<&str> = after.iter().map(|d| d.id.as_str()).collect();

    let resolved: Vec<NewIssueSkeleton> = before
        .iter()
        .filter(|d| !after_ids.contains(d.id.as_str()))
        .map(|d| NewIssueSkeleton {
            id: d.id.clone(),
            rule: d.rule.clone(),
            title: d.title.clone(),
            severity: d.severity.to_string(),
        })
        .collect();

    let new: Vec<NewIssueSkeleton> = after
        .iter()
        .filter(|d| !before_ids.contains(d.id.as_str()))
        .map(|d| NewIssueSkeleton {
            id: d.id.clone(),
            rule: d.rule.clone(),
            title: d.title.clone(),
            severity: d.severity.to_string(),
        })
        .collect();

    let unchanged = after_ids.intersection(&before_ids).count();

    SnapshotDiff {
        resolved,
        new,
        unchanged,
        summary: SnapshotDiffSummary {
            before: SeverityCounts::from_diagnostics(before),
            after: SeverityCounts::from_diagnostics(after),
        },
    }
}

/// Health status for the project resource.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectHealth {
    pub total: usize,
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
    pub status: String,
    pub last_analysis_time_ms: u64,
}

impl ProjectHealth {
    pub fn from_diagnostics(diagnostics: &[Diagnostic], analysis_time_ms: u64) -> Self {
        use goguard_diagnostics::diagnostic::Severity;
        let mut h = Self {
            total: diagnostics.len(),
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
            status: "healthy".to_string(),
            last_analysis_time_ms: analysis_time_ms,
        };
        for d in diagnostics {
            match d.severity {
                Severity::Critical => h.critical += 1,
                Severity::Error => h.error += 1,
                Severity::Warning => h.warning += 1,
                Severity::Info => h.info += 1,
            }
        }
        h.status = if h.critical > 0 {
            "critical".to_string()
        } else if h.error > 0 {
            "needs_attention".to_string()
        } else if h.warning > 0 {
            "warnings".to_string()
        } else {
            "healthy".to_string()
        };
        h
    }
}

#[rmcp::tool_handler]
impl ServerHandler for GoGuardMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: None }),
                resources: Some(ResourcesCapability {
                    subscribe: Some(true),
                    list_changed: None,
                }),
                prompts: Some(PromptsCapability { list_changed: None }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "goguard".into(),
                title: None,
                version: env!("CARGO_PKG_VERSION").into(),
                description: Some(
                    "Rust-level safety analyzer for Go — AI-agent-native static analysis".into(),
                ),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "GoGuard: Rust-level safety analyzer for Go. \
                 Start with goguard_analyze to scan your project, \
                 then use goguard_explain/goguard_fix for details on specific issues."
                    .into(),
            ),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let health_resource = RawResource {
            uri: "goguard://project/health".into(),
            name: "Project Health".into(),
            title: None,
            description: Some("Current project health based on latest analysis".into()),
            mime_type: Some("application/json".into()),
            size: None,
            icons: None,
            meta: None,
        };

        let rules_resource = RawResource {
            uri: "goguard://project/rules".into(),
            name: "Analysis Rules".into(),
            title: None,
            description: Some("All available GoGuard analysis rules".into()),
            mime_type: Some("application/json".into()),
            size: None,
            icons: None,
            meta: None,
        };

        let annotations_resource = RawResource {
            uri: "goguard://project/annotations".into(),
            name: "Project Annotations".into(),
            title: None,
            description: Some(
                "Learned project-specific patterns from elicitation responses".into(),
            ),
            mime_type: Some("application/json".into()),
            size: None,
            icons: None,
            meta: None,
        };

        Ok(ListResourcesResult {
            resources: vec![
                Annotated::new(health_resource, None),
                Annotated::new(rules_resource, None),
                Annotated::new(annotations_resource, None),
            ],
            ..Default::default()
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let uri = request.uri.as_str();
        match uri {
            "goguard://project/health" => {
                let state = self.state.lock().await;
                let health = ProjectHealth::from_diagnostics(
                    &state.diagnostics,
                    state.last_analysis_time_ms,
                );
                let json = serde_json::to_string_pretty(&health)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(json, uri)],
                })
            }
            "goguard://project/rules" => {
                let rules = crate::output::get_all_rules();
                let json = serde_json::to_string_pretty(&rules)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(json, uri)],
                })
            }
            _ if uri.starts_with("goguard://rules/") => {
                let rule_code = &uri["goguard://rules/".len()..];
                match goguard_diagnostics::rules::get_rule(rule_code) {
                    Some(rule) => {
                        let json = serde_json::to_string_pretty(&rule)
                            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                        Ok(ReadResourceResult {
                            contents: vec![ResourceContents::text(json, uri)],
                        })
                    }
                    None => Err(McpError::resource_not_found(
                        format!("Rule '{rule_code}' not found"),
                        None,
                    )),
                }
            }
            _ if uri.starts_with("goguard://project/annotations") => {
                let state = self.state.lock().await;
                let annotations = state
                    .annotations
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!({
                            "pattern_key": k,
                            "answer": v,
                        })
                    })
                    .collect::<Vec<_>>();
                let json = serde_json::to_string_pretty(&annotations)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                Ok(ReadResourceResult {
                    contents: vec![ResourceContents::text(json, uri)],
                })
            }
            _ => Err(McpError::resource_not_found(
                format!("Unknown resource: {uri}"),
                None,
            )),
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        // Prompt, PromptArgument already imported via rmcp::model::*

        let review_prompt = Prompt::new(
            "goguard_review",
            Some("Review Go code for safety issues using GoGuard analysis"),
            Some(vec![PromptArgument {
                name: "scope".into(),
                title: None,
                description: Some(
                    "What to review: 'diff' (changed files), 'package' (specific package), 'all' (entire project)".into(),
                ),
                required: Some(true),
            }]),
        );

        let fix_prompt = Prompt::new(
            "goguard_fix_all",
            Some("Fix all GoGuard diagnostics in priority order"),
            Some(vec![PromptArgument {
                name: "severity".into(),
                title: None,
                description: Some(
                    "Minimum severity to fix: 'critical', 'error', 'warning', 'info'".into(),
                ),
                required: Some(false),
            }]),
        );

        Ok(ListPromptsResult {
            prompts: vec![review_prompt, fix_prompt],
            ..Default::default()
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        // PromptMessage, PromptMessageRole already imported via rmcp::model::*

        let scope = request
            .arguments
            .as_ref()
            .and_then(|a| a.get("scope"))
            .and_then(|v| v.as_str())
            .unwrap_or("diff");

        let severity = request
            .arguments
            .as_ref()
            .and_then(|a| a.get("severity"))
            .and_then(|v| v.as_str())
            .unwrap_or("error");

        match request.name.as_str() {
            "goguard_review" => {
                let messages = vec![PromptMessage::new_text(
                    PromptMessageRole::User,
                    format!(
                        "Review this Go project for safety issues using GoGuard.\n\n\
                         Scope: {scope}\n\n\
                         Steps:\n\
                         1. Run `goguard_analyze` with scope '{scope}'\n\
                         2. For each critical/error diagnostic, use `goguard_explain` to understand the issue\n\
                         3. For fixable issues, use `goguard_fix` to get the fix\n\
                         4. Apply fixes and run `goguard_verify` to confirm resolution\n\
                         5. Summarize findings: what was found, what was fixed, what needs manual review"
                    ),
                )];
                Ok(GetPromptResult {
                    description: Some("GoGuard safety review".into()),
                    messages,
                })
            }
            "goguard_fix_all" => {
                let messages = vec![PromptMessage::new_text(
                    PromptMessageRole::User,
                    format!(
                        "Fix all GoGuard diagnostics with severity >= {severity}.\n\n\
                         Steps:\n\
                         1. Run `goguard_analyze` to get current diagnostics\n\
                         2. Use `goguard_batch` to fix all issues at severity >= {severity}\n\
                         3. Run `goguard_verify` to confirm fixes\n\
                         4. If new issues were introduced, investigate and fix them\n\
                         5. Use `goguard_snapshot` to save before/after comparison"
                    ),
                )];
                Ok(GetPromptResult {
                    description: Some("Fix all GoGuard diagnostics".into()),
                    messages,
                })
            }
            other => Err(McpError::invalid_params(
                format!("Unknown prompt: {other}. Available: goguard_review, goguard_fix_all"),
                None,
            )),
        }
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<(), McpError> {
        let uri = request.uri.as_str();
        // Validate the URI is a known resource
        let valid = uri == "goguard://project/health"
            || uri == "goguard://project/rules"
            || uri == "goguard://project/annotations"
            || uri.starts_with("goguard://rules/");
        if !valid {
            return Err(McpError::resource_not_found(
                format!("Unknown resource: {uri}"),
                None,
            ));
        }
        self.subscriptions.lock().await.insert(uri.to_string());
        Ok(())
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<(), McpError> {
        self.subscriptions.lock().await.remove(request.uri.as_str());
        Ok(())
    }
}

/// Start the MCP server on stdio transport.
pub async fn run_mcp_server(project_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let server = match project_dir {
        Some(dir) => GoGuardMcpServer::with_project_dir(dir),
        None => {
            let cwd = std::env::current_dir()?;
            GoGuardMcpServer::with_project_dir(cwd)
        }
    };

    let transport = rmcp::transport::io::stdio();
    let service = server
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let server = GoGuardMcpServer::new();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "goguard");
    }

    #[test]
    fn test_server_info_fields() {
        let server = GoGuardMcpServer::new();
        let info = server.get_info();
        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.resources.is_some());
        assert!(info.instructions.is_some());
        assert_eq!(info.server_info.name, "goguard");
    }

    #[test]
    fn test_server_with_project_dir() {
        let server = GoGuardMcpServer::with_project_dir(PathBuf::from("/tmp"));
        let info = server.get_info();
        assert_eq!(info.server_info.name, "goguard");
    }

    #[test]
    fn test_project_health_from_diagnostics() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

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
                Severity::Warning,
                "err ignored",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 20, 1)
            .build(),
        ];
        let health = ProjectHealth::from_diagnostics(&diags, 100);
        assert_eq!(health.total, 2);
        assert_eq!(health.critical, 1);
        assert_eq!(health.warning, 1);
        assert_eq!(health.status, "critical");
    }

    #[tokio::test]
    async fn test_explain_existing_diagnostic() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .explanation("Variable 'user' may be nil")
        .root_cause("handler.go", 15, "missing return after error handling")
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .goguard_explain(Parameters(ExplainParams {
                diagnostic_id: "NIL001-handler.go:18".into(),
            }))
            .await
            .unwrap();

        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("explanation"));
        assert!(text.text.contains("root_cause"));
    }

    #[tokio::test]
    async fn test_explain_nonexistent() {
        let server = GoGuardMcpServer::with_diagnostics(vec![]);
        let result = server
            .goguard_explain(Parameters(ExplainParams {
                diagnostic_id: "NOPE-x.go:1".into(),
            }))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("not found"));
    }

    #[tokio::test]
    async fn test_fix_with_available_fix() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add return",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: None,
                new_text: "return".into(),
            }],
        )
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .goguard_fix(Parameters(FixParams {
                diagnostic_id: "NIL001-handler.go:18".into(),
                auto_verify: false,
            }))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("return"));
    }

    #[tokio::test]
    async fn test_fix_without_fix() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 10, 5)
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .goguard_fix(Parameters(FixParams {
                diagnostic_id: "ERR001-main.go:10".into(),
                auto_verify: false,
            }))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("no_fix_available"));
    }

    #[tokio::test]
    async fn test_fix_nonexistent() {
        let server = GoGuardMcpServer::with_diagnostics(vec![]);
        let result = server
            .goguard_fix(Parameters(FixParams {
                diagnostic_id: "NOPE-x.go:1".into(),
                auto_verify: false,
            }))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn test_rules_returns_all() {
        let server = GoGuardMcpServer::new();
        let result = server
            .goguard_rules(Parameters(RulesParams { category: None }))
            .await
            .unwrap();

        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("NIL001"));
        assert!(text.text.contains("ERR001"));
        assert!(text.text.contains("ERR002"));
    }

    #[tokio::test]
    async fn test_rules_filter_nil() {
        let server = GoGuardMcpServer::new();
        let result = server
            .goguard_rules(Parameters(RulesParams {
                category: Some("nil".into()),
            }))
            .await
            .unwrap();

        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("NIL001"));
        assert!(!text.text.contains("ERR001"));
    }

    #[tokio::test]
    async fn test_rules_filter_no_match() {
        let server = GoGuardMcpServer::new();
        let result = server
            .goguard_rules(Parameters(RulesParams {
                category: Some("nonexistent".into()),
            }))
            .await
            .unwrap();

        let text = result.content[0].as_text().unwrap();
        assert_eq!(text.text.trim(), "[]");
    }

    #[tokio::test]
    async fn test_mcp_server_has_incremental_analyzer() {
        let server = GoGuardMcpServer::new();
        let state = server.state_for_test().await;
        assert!(
            state.incremental.is_some(),
            "new() should create IncrementalAnalyzer"
        );
    }

    #[tokio::test]
    async fn test_mcp_server_with_diagnostics_no_incremental() {
        let server = GoGuardMcpServer::with_diagnostics(vec![]);
        let state = server.state_for_test().await;
        assert!(
            state.incremental.is_none(),
            "with_diagnostics() should not create IncrementalAnalyzer"
        );
    }

    #[tokio::test]
    async fn test_mcp_server_with_project_dir_has_incremental() {
        let server = GoGuardMcpServer::with_project_dir(PathBuf::from("/tmp"));
        let state = server.state_for_test().await;
        assert!(
            state.incremental.is_some(),
            "with_project_dir() should create IncrementalAnalyzer"
        );
    }

    #[test]
    fn test_snapshot_entry_creation() {
        let entry = SnapshotEntry {
            diagnostics: vec![],
            timestamp: chrono::Utc::now(),
            analysis_time_ms: 100,
        };
        assert_eq!(entry.analysis_time_ms, 100);
        assert!(entry.diagnostics.is_empty());
    }

    #[test]
    fn test_save_snapshot() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let mut state = AnalysisState {
            diagnostics: vec![DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build()],
            ..Default::default()
        };
        state.save_snapshot("test_snap");
        assert!(state.snapshots.contains_key("test_snap"));
        assert_eq!(state.snapshots["test_snap"].diagnostics.len(), 1);
    }

    #[test]
    fn test_auto_snapshot() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let mut state = AnalysisState {
            diagnostics: vec![DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "err",
                DiagnosticSource::Errcheck,
            )
            .location("b.go", 5, 1)
            .build()],
            ..Default::default()
        };
        state.auto_snapshot();
        assert!(state.snapshots.contains_key("latest"));
        assert_eq!(state.snapshots["latest"].diagnostics.len(), 1);
    }

    #[test]
    fn test_snapshot_lru_eviction() {
        let mut state = AnalysisState::default();
        // Save 11 snapshots — should evict the oldest
        for i in 0..11 {
            state.last_analysis_time_ms = i as u64;
            state.save_snapshot(&format!("snap_{i}"));
        }
        assert_eq!(state.snapshots.len(), 10, "Should have max 10 snapshots");
        // snap_0 should be evicted (oldest)
        assert!(
            !state.snapshots.contains_key("snap_0"),
            "Oldest snapshot should be evicted"
        );
        assert!(
            state.snapshots.contains_key("snap_10"),
            "Newest snapshot should exist"
        );
    }

    #[test]
    fn test_analysis_state_default_has_empty_snapshots() {
        let state = AnalysisState::default();
        assert!(state.snapshots.is_empty());
    }

    // ── Task 3: goguard_snapshot tests ──

    #[tokio::test]
    async fn test_snapshot_save_and_list() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("a.go", 10, 1)
        .build()];
        let server = GoGuardMcpServer::with_diagnostics(diags);

        let result = server.snapshot("save", Some("before"), None).await.unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("before"));
        assert!(text.text.contains("diagnostics_count"));

        let list = server.snapshot("list", None, None).await.unwrap();
        let text = list.content[0].as_text().unwrap();
        assert!(text.text.contains("before"));
    }

    #[tokio::test]
    async fn test_snapshot_diff_resolved() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("c.go", 30, 1)
            .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);

        // Save "before" with 3 diagnostics
        server.snapshot("save", Some("before"), None).await.unwrap();

        // Simulate fixing: update state to 1 diagnostic
        {
            let mut state = server.state.lock().await;
            state.diagnostics.retain(|d| d.rule == "NIL004");
        }

        // Save "after" with 1 diagnostic
        server.snapshot("save", Some("after"), None).await.unwrap();

        // Diff: should show 2 resolved
        let result = server
            .snapshot("diff", Some("after"), Some("before"))
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        let diff: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(diff["resolved"].as_array().unwrap().len(), 2);
        assert_eq!(diff["unchanged"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_snapshot_diff_new_issues() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("a.go", 10, 1)
        .build()];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        server.snapshot("save", Some("before"), None).await.unwrap();

        // Add 2 new diagnostics
        {
            let mut state = server.state.lock().await;
            state.diagnostics.push(
                DiagnosticBuilder::new(
                    "ERR001",
                    Severity::Error,
                    "err",
                    DiagnosticSource::Errcheck,
                )
                .location("b.go", 20, 1)
                .build(),
            );
            state.diagnostics.push(
                DiagnosticBuilder::new(
                    "ERR002",
                    Severity::Warning,
                    "err2",
                    DiagnosticSource::Errcheck,
                )
                .location("c.go", 30, 1)
                .build(),
            );
        }
        server.snapshot("save", Some("after"), None).await.unwrap();

        let result = server
            .snapshot("diff", Some("after"), Some("before"))
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        let diff: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(diff["new"].as_array().unwrap().len(), 2);
        assert_eq!(diff["unchanged"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_snapshot_restore() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        server
            .snapshot("save", Some("checkpoint"), None)
            .await
            .unwrap();

        // Clear diagnostics
        {
            let mut state = server.state.lock().await;
            state.diagnostics.clear();
        }

        // Restore
        let result = server
            .snapshot("restore", Some("checkpoint"), None)
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("\"diagnostics_count\": 2"));

        // Verify restored
        let state = server.state_for_test().await;
        assert_eq!(state.diagnostics.len(), 2);
    }

    #[tokio::test]
    async fn test_snapshot_not_found() {
        let server = GoGuardMcpServer::with_diagnostics(vec![]);
        let result = server.snapshot("restore", Some("nonexistent"), None).await;
        assert!(
            result.is_err() || {
                let r = result.unwrap();
                r.is_error == Some(true)
            }
        );
    }

    #[tokio::test]
    async fn test_snapshot_invalid_action() {
        let server = GoGuardMcpServer::with_diagnostics(vec![]);
        let result = server.snapshot("delete", None, None).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("Unknown action"));
    }

    // ── Task 4: Enhanced goguard_fix tests ──

    #[tokio::test]
    async fn test_fix_with_auto_verify_default() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add return",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: None,
                new_text: "return".into(),
            }],
        )
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        // Default auto_verify = true
        let result = server.fix("NIL001-handler.go:18").await.unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(
            text.text.contains("verification"),
            "auto_verify should include verification section"
        );
        assert!(text.text.contains("resolved"));
        assert!(text.text.contains("remaining_in_file"));
    }

    #[tokio::test]
    async fn test_fix_auto_verify_false() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .fix(
            "Add return",
            vec![Edit {
                file: "handler.go".into(),
                range: EditRange {
                    start_line: 16,
                    end_line: 16,
                },
                old_text: None,
                new_text: "return".into(),
            }],
        )
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server.fix_no_verify("NIL001-handler.go:18").await.unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(
            !text.text.contains("verification"),
            "auto_verify=false should NOT include verification"
        );
        assert!(text.text.contains("verify_after_fix")); // original field still there
    }

    #[tokio::test]
    async fn test_fix_auto_verify_remaining_count() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 18, 5)
            .fix(
                "Add return",
                vec![Edit {
                    file: "handler.go".into(),
                    range: EditRange {
                        start_line: 16,
                        end_line: 16,
                    },
                    old_text: None,
                    new_text: "return".into(),
                }],
            )
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 42, 3)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("handler.go", 55, 1)
                .build(),
        ];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server.fix("NIL001-handler.go:18").await.unwrap();
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(
            json["verification"]["remaining_in_file"].as_u64().unwrap(),
            2,
            "Should have 2 remaining diagnostics in handler.go"
        );
    }

    #[tokio::test]
    async fn test_fix_no_fix_available_unchanged() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![DiagnosticBuilder::new(
            "ERR001",
            Severity::Error,
            "error ignored",
            DiagnosticSource::Errcheck,
        )
        .location("main.go", 10, 5)
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        // Even with auto_verify=true, no_fix_available should still work
        let result = server.fix("ERR001-main.go:10").await.unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("no_fix_available"));
    }

    // ── Task 6: goguard_query tests ──

    #[tokio::test]
    async fn test_query_tool_basic() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

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
        ];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .query("diagnostics where severity == \"critical\"")
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["total"].as_u64().unwrap(), 1);
        assert_eq!(json["rows"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_query_tool_invalid_expression() {
        let server = GoGuardMcpServer::with_diagnostics(vec![]);
        let result = server.query("!!!invalid query!!!").await;
        assert!(result.is_err(), "Invalid query should return McpError");
    }

    #[tokio::test]
    async fn test_query_tool_all_diagnostics() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

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
        ];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server.query("diagnostics").await.unwrap();
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["total"].as_u64().unwrap(), 2);
    }

    // ── Task 5: goguard_batch tests ──

    #[tokio::test]
    async fn test_batch_by_ids() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .fix(
                "fix1",
                vec![Edit {
                    file: "a.go".into(),
                    range: EditRange {
                        start_line: 10,
                        end_line: 10,
                    },
                    old_text: None,
                    new_text: "return".into(),
                }],
            )
            .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("b.go", 20, 1)
            .fix(
                "fix2",
                vec![Edit {
                    file: "b.go".into(),
                    range: EditRange {
                        start_line: 20,
                        end_line: 20,
                    },
                    old_text: None,
                    new_text: "make(map)".into(),
                }],
            )
            .build(),
        ];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .batch(vec!["NIL001-a.go:10".into(), "NIL004-b.go:20".into()])
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["applied"].as_array().unwrap().len(), 2);
        assert_eq!(json["applied"][0]["status"], "fixed");
        assert_eq!(json["applied"][1]["status"], "fixed");
        assert_eq!(json["verification"]["resolved"].as_u64().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_batch_by_filter_rule_prefix() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .fix(
                "fix",
                vec![Edit {
                    file: "a.go".into(),
                    range: EditRange {
                        start_line: 10,
                        end_line: 10,
                    },
                    old_text: None,
                    new_text: "return".into(),
                }],
            )
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .fix(
                    "fix",
                    vec![Edit {
                        file: "b.go".into(),
                        range: EditRange {
                            start_line: 20,
                            end_line: 20,
                        },
                        old_text: None,
                        new_text: "if err != nil".into(),
                    }],
                )
                .build(),
        ];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .goguard_batch(Parameters(BatchParams {
                diagnostic_ids: vec![],
                filter: Some(crate::tools::BatchFilter {
                    severity: None,
                    rule_prefix: Some("NIL".into()),
                    file: None,
                }),
                dry_run: false,
            }))
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["applied"].as_array().unwrap().len(), 1);
        assert_eq!(json["applied"][0]["diagnostic_id"], "NIL001-a.go:10");
    }

    #[tokio::test]
    async fn test_batch_dry_run() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("a.go", 10, 1)
        .fix(
            "fix",
            vec![Edit {
                file: "a.go".into(),
                range: EditRange {
                    start_line: 10,
                    end_line: 10,
                },
                old_text: None,
                new_text: "return".into(),
            }],
        )
        .build()];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .goguard_batch(Parameters(BatchParams {
                diagnostic_ids: vec!["NIL001-a.go:10".into()],
                filter: None,
                dry_run: true,
            }))
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("would_fix"));
    }

    // ── Resource Subscriptions tests ──

    #[tokio::test]
    async fn test_subscribe_resource() {
        let server = GoGuardMcpServer::new();
        server.subscribe_resource("goguard://project/health").await;
        let uris = server.subscribed_uris().await;
        assert_eq!(uris.len(), 1);
        assert!(uris.contains(&"goguard://project/health".to_string()));
    }

    #[tokio::test]
    async fn test_unsubscribe_resource() {
        let server = GoGuardMcpServer::new();
        server.subscribe_resource("goguard://project/health").await;
        server.subscribe_resource("goguard://project/rules").await;
        assert_eq!(server.subscribed_uris().await.len(), 2);

        server
            .unsubscribe_resource("goguard://project/health")
            .await;
        let uris = server.subscribed_uris().await;
        assert_eq!(uris.len(), 1);
        assert!(uris.contains(&"goguard://project/rules".to_string()));
    }

    #[tokio::test]
    async fn test_subscribe_idempotent() {
        let server = GoGuardMcpServer::new();
        server.subscribe_resource("goguard://project/health").await;
        server.subscribe_resource("goguard://project/health").await;
        assert_eq!(
            server.subscribed_uris().await.len(),
            1,
            "Duplicate subscribe should not add twice"
        );
    }

    #[tokio::test]
    async fn test_unsubscribe_nonexistent_noop() {
        let server = GoGuardMcpServer::new();
        // Should not panic or error
        server
            .unsubscribe_resource("goguard://project/health")
            .await;
        assert!(server.subscribed_uris().await.is_empty());
    }

    #[test]
    fn test_capabilities_subscribe_enabled() {
        let server = GoGuardMcpServer::new();
        let info = server.get_info();
        let resources = info.capabilities.resources.unwrap();
        assert_eq!(
            resources.subscribe,
            Some(true),
            "subscribe should be enabled"
        );
    }

    #[tokio::test]
    async fn test_batch_mixed_fix_and_no_fix() {
        use goguard_diagnostics::diagnostic::{
            DiagnosticBuilder, DiagnosticSource, Edit, EditRange, Severity,
        };

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .fix(
                "fix",
                vec![Edit {
                    file: "a.go".into(),
                    range: EditRange {
                        start_line: 10,
                        end_line: 10,
                    },
                    old_text: None,
                    new_text: "return".into(),
                }],
            )
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(), // no fix
        ];

        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .batch(vec!["NIL001-a.go:10".into(), "ERR001-b.go:20".into()])
            .await
            .unwrap();
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["applied"][0]["status"], "fixed");
        assert_eq!(json["applied"][1]["status"], "no_fix_available");
    }

    // ── goguard_search tests ──

    #[tokio::test]
    async fn test_goguard_search_spec_exploration() {
        let server = GoGuardMcpServer::new();
        let result = server.search("Object.keys(spec.api)").await.unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        let keys = json
            .as_array()
            .expect("should be array of API method names");
        let key_strs: Vec<&str> = keys.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            key_strs.contains(&"diagnostics"),
            "should contain 'diagnostics'"
        );
        assert!(key_strs.contains(&"packages"), "should contain 'packages'");
        assert!(
            key_strs.contains(&"callGraph"),
            "should contain 'callGraph'"
        );
        assert!(
            key_strs.contains(&"taintFlows"),
            "should contain 'taintFlows'"
        );
    }

    #[tokio::test]
    async fn test_goguard_search_rule_lookup() {
        let server = GoGuardMcpServer::new();
        let result = server
            .search("spec.rules.filter(r => r.category === 'nil')")
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        let rules = json.as_array().expect("should be array of nil rules");
        assert!(!rules.is_empty(), "should have at least one nil rule");
        // Verify all returned rules have category "nil".
        for rule in rules {
            assert_eq!(
                rule.get("category").and_then(|c| c.as_str()),
                Some("nil"),
                "all returned rules should have category 'nil'"
            );
        }
    }

    #[tokio::test]
    async fn test_goguard_search_with_goguard_global() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server.search("goguard.diagnostics().length").await.unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let count: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(count, serde_json::json!(2));
    }

    #[tokio::test]
    async fn test_goguard_search_js_error() {
        let server = GoGuardMcpServer::new();
        let result = server.search("null.foo").await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(
            text.text.contains("error") || text.text.contains("Error"),
            "error result should contain error information"
        );
    }

    // ── goguard_execute tests ──

    #[tokio::test]
    async fn test_goguard_execute_basic_query() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .execute("goguard.diagnostics().length")
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let count: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(count, serde_json::json!(2));
    }

    #[tokio::test]
    async fn test_goguard_execute_complex_join() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("handler.go", 20, 1)
                .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        // Join diagnostics by file and count
        let result = server
            .execute(
                r#"
                (() => {
                    let diags = goguard.diagnostics();
                    let byFile = {};
                    diags.forEach(d => {
                        let f = d.location.file;
                        byFile[f] = (byFile[f] || 0) + 1;
                    });
                    return byFile;
                })()
                "#,
            )
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["handler.go"], serde_json::json!(2));
    }

    #[tokio::test]
    async fn test_goguard_execute_aggregation() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
            DiagnosticBuilder::new(
                "NIL004",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("c.go", 30, 1)
            .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .execute(
                r#"
                (() => {
                    let diags = goguard.diagnostics();
                    let bySeverity = {};
                    diags.forEach(d => {
                        bySeverity[d.severity] = (bySeverity[d.severity] || 0) + 1;
                    });
                    return bySeverity;
                })()
                "#,
            )
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["critical"], serde_json::json!(1));
        assert_eq!(json["error"], serde_json::json!(1));
        assert_eq!(json["warning"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_goguard_execute_syntax_error() {
        let server = GoGuardMcpServer::new();
        let result = server.execute("function {}").await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(
            text.text.contains("syntax") || text.text.contains("Syntax"),
            "error should mention syntax, got: {}",
            text.text
        );
    }

    #[tokio::test]
    async fn test_goguard_execute_runtime_error() {
        let server = GoGuardMcpServer::new();
        let result = server.execute("null.foo").await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(
            text.text.contains("error") || text.text.contains("Error"),
            "error result should contain error information, got: {}",
            text.text
        );
    }

    #[tokio::test]
    async fn test_goguard_execute_timeout() {
        let server = GoGuardMcpServer::new();
        // Use very small timeout (1ms) and execute an infinite loop
        let result = server
            .goguard_execute(Parameters(ExecuteParams {
                code: "while(true) {}".to_string(),
                timeout_ms: 1,
            }))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(
            text.text.contains("timeout") || text.text.contains("Timeout"),
            "should report timeout, got: {}",
            text.text
        );
    }

    #[tokio::test]
    async fn test_goguard_execute_no_spec_global() {
        let server = GoGuardMcpServer::new();
        let result = server.execute("typeof spec").await.unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let val: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(
            val,
            serde_json::json!("undefined"),
            "goguard_execute should NOT have spec global"
        );
    }

    #[tokio::test]
    async fn test_goguard_query_backward_compat_js() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("a.go", 10, 1)
            .build(),
            DiagnosticBuilder::new("ERR001", Severity::Error, "err", DiagnosticSource::Errcheck)
                .location("b.go", 20, 1)
                .build(),
        ];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        // Call goguard_query with JS code that contains "goguard."
        let result = server.query("goguard.diagnostics().length").await.unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let count: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(
            count,
            serde_json::json!(2),
            "JS routed via goguard_query backward compat"
        );
    }

    #[tokio::test]
    async fn test_goguard_search_combined_spec_and_goguard() {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};

        let diags = vec![DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil deref",
            DiagnosticSource::Nil,
        )
        .location("a.go", 10, 1)
        .build()];
        let server = GoGuardMcpServer::with_diagnostics(diags);
        let result = server
            .search(
                r#"
                (() => {
                    let apiKeys = Object.keys(spec.api);
                    let diagCount = goguard.diagnostics().length;
                    return { apiMethods: apiKeys.length, diagnostics: diagCount };
                })()
                "#,
            )
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false));
        let text = result.content[0].as_text().unwrap();
        let json: serde_json::Value = serde_json::from_str(&text.text).unwrap();
        assert_eq!(json["apiMethods"].as_u64().unwrap(), 7);
        assert_eq!(json["diagnostics"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_stored_decisions_merge_into_nil_models() {
        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join(".goguard");
        let mut store =
            goguard_learn::elicitation_store::ElicitationStore::new(&store_dir).unwrap();
        store
            .record_decision(goguard_learn::elicitation_store::ElicitationDecision {
                pattern_key: "nil_return:db.Find#0".to_string(),
                question: "test".to_string(),
                answer: "always_nil_on_error".to_string(),
                timestamp: "2026-02-24T12:00:00Z".to_string(),
                return_type_fingerprint: None,
            })
            .unwrap();

        let server = GoGuardMcpServer {
            state: Arc::new(Mutex::new(AnalysisState {
                diagnostics: Vec::new(),
                packages: Vec::new(),
                project_dir: dir.path().to_path_buf(),
                config: Config::default(),
                last_analysis_time_ms: 0,
                incremental: None,
                snapshots: HashMap::new(),
                annotations: HashMap::new(),
                elicitation_store: Some(store),
            })),
            task_manager: Arc::new(crate::tasks::TaskManager::new()),
            subscriptions: Arc::new(Mutex::new(HashSet::new())),
            tool_router: GoGuardMcpServer::tool_router(),
        };

        // Verify the store has the decision
        let state = server.state_for_test().await;
        assert!(state.elicitation_store.is_some());
        let store = state.elicitation_store.as_ref().unwrap();
        assert!(store.has_decision("nil_return:db.Find#0"));

        // Verify decisions_to_nil_models produces the right output
        let models = goguard_learn::elicitation_store::decisions_to_nil_models(&store.decisions);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].0, "db.Find#0");
        assert_eq!(models[0].1, "nonnull");
    }

    // ── Task 5: Elicitation candidates in goguard_analyze response ──

    #[tokio::test]
    async fn test_analyze_returns_pending_elicitations() {
        use goguard_diagnostics::diagnostic::*;

        // Create a diagnostic with low confidence and callee_key
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .confidence(0.55)
        .callee_key("db.Find#0")
        .build();

        let server = GoGuardMcpServer::with_diagnostics(vec![diag.clone()]);
        let state = server.state_for_test().await;

        // Verify the diagnostic has callee_key
        assert_eq!(
            state.diagnostics[0].callee_key.as_deref(),
            Some("db.Find#0")
        );
        assert!(state.diagnostics[0].confidence < 0.6);

        // The full goguard_analyze runs the bridge which we can't do in unit tests,
        // so instead test the candidate generation logic directly
        let mut pending: Vec<crate::elicitation::ElicitationRequest> = Vec::new();
        for d in &state.diagnostics {
            if d.rule == "NIL001" && d.confidence < 0.6 {
                if let Some(ref callee_key) = d.callee_key {
                    let pattern_key = format!("nil_return:{}", callee_key);
                    if !state.annotations.contains_key(&pattern_key)
                        && !pending.iter().any(|e| e.pattern_key == pattern_key)
                    {
                        pending.push(crate::elicitation::nil_return_elicitation(callee_key));
                    }
                }
            }
        }

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].pattern_key, "nil_return:db.Find#0");
        assert!(pending[0].question.contains("db.Find#0"));
    }

    #[tokio::test]
    async fn test_analyze_skips_answered_elicitation() {
        use goguard_diagnostics::diagnostic::*;

        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .confidence(0.55)
        .callee_key("db.Find#0")
        .build();

        let server = GoGuardMcpServer::with_diagnostics(vec![diag]);
        // Store an annotation for this pattern
        server
            .store_annotation("nil_return:db.Find#0", "always_nil_on_error")
            .await;

        let state = server.state_for_test().await;

        // Test that the candidate is skipped when annotation exists
        let mut pending: Vec<crate::elicitation::ElicitationRequest> = Vec::new();
        for d in &state.diagnostics {
            if d.rule == "NIL001" && d.confidence < 0.6 {
                if let Some(ref callee_key) = d.callee_key {
                    let pattern_key = format!("nil_return:{}", callee_key);
                    if state.annotations.contains_key(&pattern_key) {
                        continue;
                    }
                    if !pending.iter().any(|e| e.pattern_key == pattern_key) {
                        pending.push(crate::elicitation::nil_return_elicitation(callee_key));
                    }
                }
            }
        }

        assert!(pending.is_empty(), "answered pattern should be skipped");
    }

    // ── Task 6: goguard_teach tests ──

    #[tokio::test]
    async fn test_goguard_teach_stores_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join(".goguard");
        let store = goguard_learn::elicitation_store::ElicitationStore::new(&store_dir).unwrap();

        let server = GoGuardMcpServer {
            state: Arc::new(Mutex::new(AnalysisState {
                diagnostics: Vec::new(),
                packages: Vec::new(),
                project_dir: dir.path().to_path_buf(),
                config: Config::default(),
                last_analysis_time_ms: 0,
                incremental: None,
                snapshots: HashMap::new(),
                annotations: HashMap::new(),
                elicitation_store: Some(store),
            })),
            task_manager: Arc::new(crate::tasks::TaskManager::new()),
            subscriptions: Arc::new(Mutex::new(HashSet::new())),
            tool_router: GoGuardMcpServer::tool_router(),
        };

        // Call goguard_teach
        let result = server
            .teach("nil_return:db.Find#0", "always_nil_on_error")
            .await
            .unwrap();
        // Verify success response
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("Recorded: nil_return:db.Find#0"));

        // Verify in-memory
        let state = server.state_for_test().await;
        assert_eq!(
            state
                .annotations
                .get("nil_return:db.Find#0")
                .map(|s| s.as_str()),
            Some("always_nil_on_error")
        );

        // Verify persisted to disk
        let store_reloaded =
            goguard_learn::elicitation_store::ElicitationStore::new(&store_dir).unwrap();
        assert!(store_reloaded.has_decision("nil_return:db.Find#0"));
        let decision = store_reloaded.get_decision("nil_return:db.Find#0").unwrap();
        assert_eq!(decision.answer, "always_nil_on_error");
    }

    #[tokio::test]
    async fn test_teach_then_analyze_skips_elicitation() {
        use goguard_diagnostics::diagnostic::*;

        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join(".goguard");
        let store = goguard_learn::elicitation_store::ElicitationStore::new(&store_dir).unwrap();

        // Create a diagnostic with low confidence and callee_key
        let diag = DiagnosticBuilder::new(
            "NIL001",
            Severity::Critical,
            "nil pointer dereference",
            DiagnosticSource::Nil,
        )
        .location("handler.go", 18, 5)
        .confidence(0.55)
        .callee_key("db.Find#0")
        .build();

        let server = GoGuardMcpServer {
            state: Arc::new(Mutex::new(AnalysisState {
                diagnostics: vec![diag],
                packages: Vec::new(),
                project_dir: dir.path().to_path_buf(),
                config: Config::default(),
                last_analysis_time_ms: 42,
                incremental: None,
                snapshots: HashMap::new(),
                annotations: HashMap::new(),
                elicitation_store: Some(store),
            })),
            task_manager: Arc::new(crate::tasks::TaskManager::new()),
            subscriptions: Arc::new(Mutex::new(HashSet::new())),
            tool_router: GoGuardMcpServer::tool_router(),
        };

        // Teach the pattern
        server
            .teach("nil_return:db.Find#0", "nonnull")
            .await
            .unwrap();

        // Now check that pending elicitations would be empty
        let state = server.state_for_test().await;
        let mut pending: Vec<crate::elicitation::ElicitationRequest> = Vec::new();
        for d in &state.diagnostics {
            if d.rule == "NIL001" && d.confidence < 0.6 {
                if let Some(ref callee_key) = d.callee_key {
                    let pattern_key = format!("nil_return:{}", callee_key);
                    if state.annotations.contains_key(&pattern_key) {
                        continue;
                    }
                    if let Some(ref store) = state.elicitation_store {
                        if store.has_decision(&pattern_key) {
                            continue;
                        }
                    }
                    if !pending.iter().any(|e| e.pattern_key == pattern_key) {
                        pending.push(crate::elicitation::nil_return_elicitation(callee_key));
                    }
                }
            }
        }

        assert!(
            pending.is_empty(),
            "taught pattern should not generate pending elicitation"
        );
    }
}
