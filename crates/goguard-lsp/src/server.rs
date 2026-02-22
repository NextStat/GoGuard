//! LSP server lifecycle and request handling.
//!
//! Implements a full [`LanguageServer`] backend using tower-lsp-server 0.23.
//! On every file save, the Go bridge is invoked to re-analyze the project,
//! and resulting diagnostics are published to the editor.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types;
use tower_lsp_server::ls_types::*;
use tower_lsp_server::{Client, LanguageServer, LspService, Server};

use goguard_core::bridge_manager::GoBridge;
use goguard_core::config::{load_config, Config};
use goguard_core::orchestrator::IncrementalAnalyzer;
use goguard_diagnostics::diagnostic::Diagnostic as GoGuardDiagnostic;

use crate::tree_sitter::ParsedFile;

/// Mutable state shared across LSP handlers.
struct LspState {
    config: Config,
    project_dir: PathBuf,
    incremental: IncrementalAnalyzer,
    /// GoGuard diagnostics grouped by file path (for hover/codeAction lookup).
    diagnostics: HashMap<String, Vec<GoGuardDiagnostic>>,
    /// tree-sitter parsed files for error-tolerant editing.
    parsed_files: HashMap<Uri, ParsedFile>,
}

/// Resolve a file URI to a project-relative path string.
///
/// Returns `None` if the URI is not a valid file path or does not
/// reside inside `project_dir`.
fn resolve_relative_file(uri: &Uri, project_dir: &std::path::Path) -> Option<String> {
    let path = uri.to_file_path()?;
    let relative = path.strip_prefix(project_dir).ok()?;
    Some(relative.to_string_lossy().to_string())
}

/// GoGuard LSP server backend.
pub struct GoGuardBackend {
    client: Client,
    state: Arc<Mutex<LspState>>,
}

impl LanguageServer for GoGuardBackend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Prefer workspace_folders (LSP 3.x), fall back to root_uri.
        let root_path = params
            .workspace_folders
            .as_ref()
            .and_then(|folders| folders.first())
            .and_then(|f| f.uri.to_file_path())
            .map(|cow| cow.into_owned())
            .or_else(|| {
                #[allow(deprecated)]
                params
                    .root_uri
                    .as_ref()
                    .and_then(|u| u.to_file_path())
                    .map(|cow| cow.into_owned())
            });

        if let Some(path) = root_path {
            let mut state = self.state.lock().await;
            state.project_dir = path;
            state.config = load_config(&state.project_dir);
        }

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "goguard".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(false),
                        })),
                        ..Default::default()
                    },
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "GoGuard LSP initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        if let Ok(parsed_file) = crate::tree_sitter::parse_go(&params.text_document.text) {
            let mut state = self.state.lock().await;
            state
                .parsed_files
                .insert(params.text_document.uri, parsed_file);
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.first() {
            if let Ok(parsed_file) = crate::tree_sitter::parse_go(&change.text) {
                let mut state = self.state.lock().await;
                state
                    .parsed_files
                    .insert(params.text_document.uri, parsed_file);
            }
        }
    }

    async fn did_save(&self, _params: DidSaveTextDocumentParams) {
        let (project_dir, config) = {
            let state = self.state.lock().await;
            (state.project_dir.clone(), state.config.clone())
        };

        let result = tokio::task::spawn_blocking(move || {
            let bridge = GoBridge::new()?;
            bridge.analyze_packages_sync(&project_dir, &["./...".to_string()])
        })
        .await;

        match result {
            Ok(Ok(ir)) => {
                // Collect publish tasks while holding the lock, then release
                // before awaiting any client calls to avoid blocking other
                // LSP handlers.
                let publish_tasks = {
                    let mut state = self.state.lock().await;
                    let output = state.incremental.analyze(&ir, &config);

                    // Group diagnostics by file.
                    let mut by_file: HashMap<String, Vec<GoGuardDiagnostic>> = HashMap::new();
                    for diag in &output.diagnostics {
                        by_file
                            .entry(diag.location.file.clone())
                            .or_default()
                            .push(diag.clone());
                    }

                    let mut tasks: Vec<(Uri, Vec<ls_types::Diagnostic>)> = Vec::new();

                    // Prepare diagnostics for files with issues.
                    for (file, diags) in &by_file {
                        let lsp_diags = crate::diagnostics::to_lsp_diagnostics(diags, file);
                        if let Some(file_uri) = Uri::from_file_path(state.project_dir.join(file)) {
                            tasks.push((file_uri, lsp_diags));
                        }
                    }

                    // Clear diagnostics for files that no longer have issues.
                    let old_files: Vec<String> = state.diagnostics.keys().cloned().collect();
                    for old_file in &old_files {
                        if !by_file.contains_key(old_file) {
                            if let Some(file_uri) =
                                Uri::from_file_path(state.project_dir.join(old_file))
                            {
                                tasks.push((file_uri, vec![]));
                            }
                        }
                    }

                    state.diagnostics = by_file;
                    tasks
                }; // lock released here

                for (uri, diags) in publish_tasks {
                    self.client.publish_diagnostics(uri, diags, None).await;
                }
            }
            Ok(Err(e)) => {
                self.client
                    .log_message(MessageType::ERROR, format!("Bridge error: {e}"))
                    .await;
            }
            Err(e) => {
                self.client
                    .log_message(MessageType::ERROR, format!("Analysis task error: {e}"))
                    .await;
            }
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = &params.text_document_position_params.position;

        let state = self.state.lock().await;
        let file = match resolve_relative_file(uri, &state.project_dir) {
            Some(f) => f,
            None => return Ok(None),
        };

        let empty = Vec::new();
        let file_diags = state.diagnostics.get(&file).unwrap_or(&empty);
        Ok(crate::hover::hover_for_position(
            file_diags, &file, position,
        ))
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;

        let state = self.state.lock().await;
        let file = match resolve_relative_file(uri, &state.project_dir) {
            Some(f) => f,
            None => return Ok(None),
        };

        let empty = Vec::new();
        let file_diags = state.diagnostics.get(&file).unwrap_or(&empty);
        let actions =
            crate::code_actions::code_actions_for_range(file_diags, &file, &params.range, uri);

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                actions
                    .into_iter()
                    .map(CodeActionOrCommand::CodeAction)
                    .collect(),
            ))
        }
    }
}

/// Start the LSP server on stdio. Called by `goguard serve --lsp`.
pub async fn run_lsp_server() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| GoGuardBackend {
        client,
        state: Arc::new(Mutex::new(LspState {
            config: Config::default(),
            project_dir: std::env::current_dir().unwrap_or_default(),
            incremental: IncrementalAnalyzer::new(),
            diagnostics: HashMap::new(),
            parsed_files: HashMap::new(),
        })),
    });

    Server::new(stdin, stdout, socket).serve(service).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsp_state_creation() {
        let state = LspState {
            config: Config::default(),
            project_dir: PathBuf::from("/tmp"),
            incremental: IncrementalAnalyzer::new(),
            diagnostics: HashMap::new(),
            parsed_files: HashMap::new(),
        };
        assert!(state.diagnostics.is_empty());
        assert!(state.parsed_files.is_empty());
    }

    #[test]
    fn test_run_lsp_server_signature() {
        // Verify the function exists and returns the right type.
        fn _check() -> impl std::future::Future<Output = anyhow::Result<()>> {
            run_lsp_server()
        }
    }
}
