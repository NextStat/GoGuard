mod sdk_gen;
mod updater;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use goguard_mcp::tools::{
    AnalyzeParams, AutofixParams, BatchParams, ExecuteParams, ExplainParams, FixParams,
    QueryParams, RulesParams, SearchParams, SnapshotParams, VerifyParams,
};
use goguard_mcp::GoGuardMcpServer;

/// Build a long version string: "0.1.0 (abc12345)"
fn long_version() -> &'static str {
    // Use Box::leak to get a 'static str — fine for a one-time allocation
    let s = format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("GIT_HASH"));
    Box::leak(s.into_boxed_str())
}

#[derive(Parser)]
#[command(name = "goguard")]
#[command(about = "Rust-level safety analyzer for Go")]
#[command(version, long_version = long_version())]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze Go source files for safety issues
    Check {
        /// Packages to analyze (default: ./...)
        packages: Vec<String>,
        /// Only analyze packages affected by changed `.go` files in git worktree
        #[arg(long)]
        diff: bool,
        /// Output format: human, json, sarif, markdown (or md)
        #[arg(long, default_value = "human")]
        format: String,
        /// Severity threshold: info, warning, error, critical
        #[arg(long)]
        severity: Option<String>,
        /// Max diagnostics to report (0 = unlimited)
        #[arg(long)]
        max_diagnostics: Option<usize>,
        /// Disable colored output
        #[arg(long)]
        no_color: bool,
        /// Disable bridge cache
        #[arg(long)]
        no_cache: bool,
        /// Override bridge cache directory
        #[arg(long)]
        cache_dir: Option<String>,
        /// Strict parameter mode: treat nilable params as MaybeNil (more findings, may have FP)
        #[arg(long)]
        strict_params: bool,
    },
    /// Explain a rule in detail
    Explain {
        /// Rule code (e.g., NIL001)
        rule: String,
    },
    /// Initialize GoGuard in current project
    Init,
    /// Start as language server or MCP server
    Serve {
        /// Run as LSP server
        #[arg(long)]
        lsp: bool,
        /// Run as MCP server (for AI agent integration)
        #[arg(long)]
        mcp: bool,
    },
    /// Print MCP server configuration for an AI tool
    Setup {
        /// Target tool: claude-code, cursor, codex, windsurf, zed, opencode
        target: String,
    },
    /// Update GoGuard section in AGENTS.md
    UpdateAgentsMd {
        /// Path to AGENTS.md (default: ./AGENTS.md)
        #[arg(long, default_value = "AGENTS.md")]
        path: String,
    },
    /// Run a GoGuard QL query against analysis results
    Query {
        /// Query expression (e.g., "diagnostics where severity == \"critical\"")
        expression: Option<String>,
        /// Interactive REPL mode — analyze once, run multiple queries
        #[arg(long)]
        repl: bool,
        /// Project directory
        #[arg(long)]
        project_dir: Option<PathBuf>,
    },
    /// Apply a fix for a specific diagnostic
    Fix {
        /// Diagnostic ID (e.g., "NIL001-handler.go:18")
        diagnostic_id: String,
        /// Apply fix to disk using built-in Rust I/O
        #[arg(long)]
        apply: bool,
        /// Output unified diff (portable, pipe to `patch -p0`)
        #[arg(long)]
        patch: bool,
        /// Re-analyze after applying to verify fix
        #[arg(long)]
        verify: bool,
    },
    /// Autonomous fix loop: analyze -> fix -> build -> test -> repeat
    AutoFix {
        /// Packages to analyze
        #[arg(default_value = "./...")]
        packages: Vec<String>,
        /// Minimum severity to fix: critical, error, warning, info
        #[arg(long, default_value = "error")]
        severity: String,
        /// Maximum number of fix iterations
        #[arg(long, default_value = "10")]
        max_iterations: usize,
        /// Maximum number of fixes to apply
        #[arg(long, default_value = "50")]
        max_fixes: usize,
        /// Time budget in seconds (0 = unlimited)
        #[arg(long, default_value = "300")]
        max_time_secs: u64,
        /// Run go test after each iteration
        #[arg(long)]
        test: bool,
        /// Preview without applying
        #[arg(long)]
        dry_run: bool,
        /// Verbose output with progress
        #[arg(long, short)]
        verbose: bool,
    },
    /// SDK tools
    Sdk {
        #[command(subcommand)]
        action: SdkAction,
    },
    /// Update GoGuard to the latest version
    Update,
}

#[derive(Subcommand)]
enum SdkAction {
    /// Generate SDK for a target language
    Generate {
        /// Target: python
        target: String,
    },
    /// Call an MCP tool via CLI (for SDK integration)
    Call {
        /// Tool name: analyze, explain, fix, verify, rules, batch, snapshot
        tool: String,
        /// JSON parameters (same as MCP tool params)
        #[arg(long, default_value = "{}")]
        params: String,
        /// Project directory
        #[arg(long)]
        project_dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Log to stderr so stdout stays clean for machine output
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Check {
            packages,
            diff,
            format,
            severity,
            max_diagnostics,
            no_color,
            no_cache,
            cache_dir,
            strict_params,
        } => run_check(CheckArgs {
            packages,
            diff,
            format,
            severity_override: severity,
            max_diagnostics,
            no_color,
            no_cache,
            cache_dir,
            strict_params,
        }),
        Commands::Explain { rule } => run_explain(&rule),
        Commands::Init => run_init(),
        Commands::Serve { lsp, mcp } => {
            if lsp {
                run_lsp_server()
            } else if mcp {
                run_mcp_server()
            } else {
                eprintln!("Specify --lsp or --mcp");
                ExitCode::from(2)
            }
        }
        Commands::Setup { target } => run_setup(&target),
        Commands::UpdateAgentsMd { path } => run_update_agents_md(&path),
        Commands::Query {
            expression,
            repl,
            project_dir,
        } => {
            if repl {
                run_query_repl(project_dir)
            } else if let Some(expr) = expression {
                run_query(&expr, project_dir)
            } else {
                eprintln!("Provide a query expression or use --repl for interactive mode");
                ExitCode::from(2)
            }
        }
        Commands::Fix {
            diagnostic_id,
            apply,
            patch,
            verify,
        } => run_fix(&diagnostic_id, apply, patch, verify),
        Commands::AutoFix {
            packages,
            severity,
            max_iterations,
            max_fixes,
            max_time_secs,
            test,
            dry_run,
            verbose,
        } => run_auto_fix(AutoFixArgs {
            packages,
            severity,
            max_iterations,
            max_fixes,
            max_time_secs,
            test,
            dry_run,
            verbose,
        }),
        Commands::Sdk { action } => match action {
            SdkAction::Call {
                tool,
                params,
                project_dir,
            } => run_sdk_call(&tool, &params, project_dir),
            SdkAction::Generate { target } => run_sdk_generate(&target),
        },
        Commands::Update => run_update(),
    }
}

fn run_update() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("Failed to create tokio runtime: {e}");
        std::process::exit(2);
    });

    match rt.block_on(updater::run_update()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Update failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_mcp_server() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("Failed to create tokio runtime: {e}");
        std::process::exit(2);
    });

    rt.spawn(crate::updater::check_for_updates());

    match rt.block_on(goguard_mcp::run_mcp_server(None)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("MCP server error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_lsp_server() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
        eprintln!("Failed to create tokio runtime: {e}");
        std::process::exit(2);
    });

    rt.spawn(crate::updater::check_for_updates());

    match rt.block_on(goguard_lsp::server::run_lsp_server()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("LSP server error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_setup(target: &str) -> ExitCode {
    let goguard_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "goguard".to_string());

    match target {
        // claude-code: .mcp.json or ~/.claude.json
        "claude-code" => {
            let config = serde_json::json!({
                "mcpServers": {
                    "goguard": {
                        "command": goguard_path,
                        "args": ["serve", "--mcp"]
                    }
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&config).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        // cursor: .cursor/mcp.json
        "cursor" => {
            let config = serde_json::json!({
                "mcpServers": {
                    "goguard": {
                        "command": goguard_path,
                        "args": ["serve", "--mcp"]
                    }
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&config).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        // windsurf: ~/.codeium/windsurf/mcp_config.json
        "windsurf" => {
            let config = serde_json::json!({
                "mcpServers": {
                    "goguard": {
                        "command": goguard_path,
                        "args": ["serve", "--mcp"]
                    }
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&config).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        // codex: ~/.codex/config.toml (TOML format)
        "codex" => {
            println!("[mcp_servers.goguard]");
            println!(
                "command = \"{}\"",
                goguard_path.replace('\\', "\\\\").replace('"', "\\\"")
            );
            println!("args = [\"serve\", \"--mcp\"]");
            ExitCode::SUCCESS
        }
        // zed: ~/.config/zed/settings.json (uses context_servers, not mcpServers)
        "zed" => {
            let config = serde_json::json!({
                "context_servers": {
                    "goguard": {
                        "command": goguard_path,
                        "args": ["serve", "--mcp"]
                    }
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&config).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        // opencode: opencode.json (uses mcp key, combined command array, type: local)
        "opencode" => {
            let config = serde_json::json!({
                "mcp": {
                    "goguard": {
                        "type": "local",
                        "command": [goguard_path, "serve", "--mcp"],
                        "enabled": true
                    }
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&config).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        // vscode: .vscode/settings.json (LSP configuration)
        "vscode" => {
            let config = serde_json::json!({
                "goguard.path": goguard_path,
                "goguard.lsp.enabled": true,
                "goguard.lsp.args": ["serve", "--lsp"],
                "goguard.mcp.enabled": true,
                "goguard.mcp.args": ["serve", "--mcp"]
            });
            println!("// Add to .vscode/settings.json:");
            println!(
                "{}",
                serde_json::to_string_pretty(&config).unwrap_or_default()
            );
            println!();
            println!("// Or configure LSP manually in settings.json:");
            let lsp_config = serde_json::json!({
                "lsp": {
                    "goguard": {
                        "command": goguard_path,
                        "args": ["serve", "--lsp"],
                        "languages": ["go"]
                    }
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&lsp_config).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "Unknown target: {target}. Supported: claude-code, cursor, codex, windsurf, zed, opencode, vscode"
            );
            ExitCode::from(2)
        }
    }
}

struct CheckArgs {
    packages: Vec<String>,
    diff: bool,
    format: String,
    severity_override: Option<String>,
    max_diagnostics: Option<usize>,
    no_color: bool,
    no_cache: bool,
    cache_dir: Option<String>,
    strict_params: bool,
}

fn run_check(args: CheckArgs) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut config = goguard_core::config::load_config(&cwd);

    if let Some(sev) = args.severity_override {
        config.goguard.severity_threshold = sev;
    }
    if let Some(max) = args.max_diagnostics {
        config.goguard.max_diagnostics = max;
    }
    if args.no_cache {
        config.goguard.no_cache = true;
    }
    if let Some(dir) = args.cache_dir {
        config.goguard.cache_dir = Some(dir);
    }
    if args.strict_params {
        config.rules.nil.strict_params = true;
    }

    let packages = if args.packages.is_empty() {
        vec!["./...".to_string()]
    } else {
        args.packages
    };

    let output = if args.diff {
        analyze_project_diff(&cwd, &packages, &config)
    } else {
        goguard_core::orchestrator::analyze_project(&cwd, &packages, &config)
    };

    match output {
        Ok(output) => {
            // Print bridge errors as warnings
            for err in &output.bridge_errors {
                eprintln!("warning: Go compilation: {err}");
            }

            match args.format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&output.diagnostics)
                        .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
                    println!("{json}");
                }
                "sarif" => {
                    let version = env!("CARGO_PKG_VERSION");
                    let sarif = goguard_diagnostics::sarif::to_sarif(&output.diagnostics, version);
                    println!("{sarif}");
                }
                "markdown" | "md" => {
                    let project_name = cwd
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("project");
                    let project_dir = cwd.to_str();
                    let md = goguard_diagnostics::markdown::format_markdown(
                        &output.diagnostics,
                        project_name,
                        project_dir,
                    );
                    print!("{md}");
                }
                _ => {
                    let text = goguard_diagnostics::human::format_human(
                        &output.diagnostics,
                        !args.no_color,
                    );
                    print!("{text}");
                }
            }

            // Exit code: 0 clean, 1 issues found
            if output.summary.critical > 0 || output.summary.error > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn analyze_project_diff(
    cwd: &std::path::Path,
    packages: &[String],
    config: &goguard_core::config::Config,
) -> Result<goguard_core::orchestrator::AnalysisOutput, goguard_core::orchestrator::OrchestratorError>
{
    use goguard_agent::diff::{
        detect_changed_go_files, expand_affected_packages, files_to_packages,
    };
    use std::collections::HashSet;
    use std::path::Path;

    let Some(git_root) = find_git_root(cwd) else {
        // Not a git repo — fall back to full analysis.
        return goguard_core::orchestrator::analyze_project(cwd, packages, config);
    };

    let Some(module_root) = find_go_mod_root(cwd, &git_root) else {
        eprintln!("warning: --diff enabled but no go.mod found; falling back to full analysis");
        return goguard_core::orchestrator::analyze_project(cwd, packages, config);
    };

    let Some(module_path) = read_go_mod_module_path(&module_root.join("go.mod")) else {
        eprintln!("warning: --diff enabled but could not parse module path; falling back to full analysis");
        return goguard_core::orchestrator::analyze_project(cwd, packages, config);
    };

    let changed = match detect_changed_go_files(cwd) {
        Ok(changed) => changed,
        Err(e) => {
            eprintln!("warning: --diff enabled but diff detection failed ({e}); falling back to full analysis");
            return goguard_core::orchestrator::analyze_project(cwd, packages, config);
        }
    };

    if changed.no_git {
        // Shouldn't happen if `find_git_root` succeeded, but keep it safe.
        return goguard_core::orchestrator::analyze_project(cwd, packages, config);
    }

    let module_rel = module_root
        .strip_prefix(&git_root)
        .unwrap_or_else(|_| Path::new(""));
    let mut go_files_rel_to_module = Vec::new();
    for rel in changed.go_files {
        let p = Path::new(&rel);
        let p = if module_rel.as_os_str().is_empty() {
            p
        } else if p.starts_with(module_rel) {
            p.strip_prefix(module_rel).unwrap_or(p)
        } else {
            continue;
        };
        let rel = p.to_string_lossy().replace('\\', "/");
        if !rel.is_empty() {
            go_files_rel_to_module.push(rel);
        }
    }

    if go_files_rel_to_module.is_empty() {
        // No changed Go files in this module — treat as clean.
        return Ok(goguard_core::orchestrator::AnalysisOutput {
            diagnostics: Vec::new(),
            summary: goguard_core::orchestrator::AnalysisSummary {
                total: 0,
                critical: 0,
                error: 0,
                warning: 0,
                info: 0,
                packages_analyzed: 0,
                functions_analyzed: 0,
            },
            bridge_errors: Vec::new(),
        });
    }

    let changed = goguard_agent::diff::ChangedFiles {
        go_files: go_files_rel_to_module,
        no_git: false,
    };
    let changed_pkgs = files_to_packages(&changed, &module_path, &module_root);

    // Load IR for the requested package scope, then analyze only packages
    // affected by the changed packages (reverse callers).
    let bridge = goguard_core::bridge_manager::GoBridge::new()?;
    let cache_dir = goguard_core::config::resolve_bridge_cache_dir(&config.goguard);
    let ir = bridge.analyze_packages_sync_with_cache(
        cwd,
        packages,
        cache_dir.as_deref(),
        config.goguard.max_cache_entries,
    )?;

    let affected = expand_affected_packages(&changed_pkgs, &ir.packages);
    let affected_set: HashSet<String> = affected.into_iter().collect();

    let filtered_packages: Vec<goguard_ir::ir::Package> = ir
        .packages
        .into_iter()
        .filter(|p| affected_set.contains(&p.import_path))
        .collect();

    let filtered_ir = goguard_ir::ir::AnalysisInput {
        packages: filtered_packages,
        go_version: ir.go_version,
        bridge_version: ir.bridge_version,
        interface_table: ir.interface_table,
        enum_groups: ir.enum_groups,
    };

    Ok(goguard_core::orchestrator::analyze_ir(&filtered_ir, config))
}

fn find_git_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

fn find_go_mod_root(
    start: &std::path::Path,
    stop_at: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join("go.mod").exists() {
            return Some(dir.to_path_buf());
        }
        if dir == stop_at {
            break;
        }
        cur = dir.parent();
    }
    None
}

fn read_go_mod_module_path(go_mod: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(go_mod).ok()?;
    parse_go_mod_module_path(&content)
}

fn parse_go_mod_module_path(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("module ") {
            let module = rest.trim();
            if !module.is_empty() {
                return Some(module.to_string());
            }
        }
        if let Some(rest) = line.strip_prefix("module\t") {
            let module = rest.trim();
            if !module.is_empty() {
                return Some(module.to_string());
            }
        }
    }
    None
}

fn run_explain(rule: &str) -> ExitCode {
    let explanation = match rule.to_uppercase().as_str() {
        // --- Nil Safety ---
        "NIL001" => concat!(
            "NIL001: Nil pointer dereference\n\n",
            "A value that may be nil is used in a context that would cause a\n",
            "runtime panic (field access, method call, index, etc.).\n\n",
            "Example:\n",
            "  user, _ := GetUser(id)\n",
            "  fmt.Println(user.Name) // user may be nil\n\n",
            "Fix: Check for nil before use:\n",
            "  if user != nil {\n",
            "      fmt.Println(user.Name)\n",
            "  }",
        ),
        "NIL002" => concat!(
            "NIL002: Unchecked type assertion\n\n",
            "A type assertion without the comma-ok pattern will panic at runtime\n",
            "if the assertion fails.\n\n",
            "Example:\n",
            "  s := x.(string) // panics if x is not a string\n\n",
            "Fix: Use comma-ok pattern:\n",
            "  s, ok := x.(string)\n",
            "  if !ok { ... }",
        ),
        "NIL004" => concat!(
            "NIL004: Nil map access\n\n",
            "A map that may be nil is being accessed. Reading from a nil map returns\n",
            "zero-value (warning). Writing to a nil map causes a runtime panic (critical).\n\n",
            "Fix: Initialize the map with make().",
        ),
        "NIL006" => concat!(
            "NIL006: Nil channel operation\n\n",
            "A send or receive on a nil channel blocks forever, causing a goroutine\n",
            "deadlock.\n\n",
            "Example:\n",
            "  var ch chan int\n",
            "  ch <- 42 // blocks forever\n\n",
            "Fix: Initialize the channel with make():\n",
            "  ch := make(chan int)",
        ),
        // --- Error Checking ---
        "ERR001" => concat!(
            "ERR001: Error return value not checked\n\n",
            "A function that returns an error has its error return value ignored.\n\n",
            "Example:\n",
            "  os.Open(\"/tmp/file\") // error not checked\n\n",
            "Fix: Check the error:\n",
            "  f, err := os.Open(\"/tmp/file\")\n",
            "  if err != nil { return err }",
        ),
        "ERR002" => concat!(
            "ERR002: Error assigned to blank identifier\n\n",
            "An error is explicitly discarded using the blank identifier _.\n\n",
            "Example:\n",
            "  f, _ := os.Open(\"/tmp/file\")\n\n",
            "Fix: Handle the error properly.",
        ),
        // --- Concurrency: Data Races ---
        "RACE001" => concat!(
            "RACE001: Shared variable access in goroutine\n\n",
            "A variable from the enclosing scope is accessed inside a goroutine\n",
            "without synchronization, causing a potential data race.\n\n",
            "Example:\n",
            "  count := 0\n",
            "  go func() { count++ }() // data race\n\n",
            "Fix: Use sync.Mutex, atomic operations, or channels.",
        ),
        "RACE002" => concat!(
            "RACE002: Goroutine captures loop variable\n\n",
            "A goroutine captures a loop variable by reference. The variable changes\n",
            "on each iteration, so all goroutines see the final value.\n\n",
            "Example:\n",
            "  for _, v := range items {\n",
            "      go func() { process(v) }() // captures v by reference\n",
            "  }\n\n",
            "Fix: Pass as argument:\n",
            "  go func(v Item) { process(v) }(v)",
        ),
        // --- Concurrency: Goroutine Leaks ---
        "LEAK001" => concat!(
            "LEAK001: Goroutine may never terminate\n\n",
            "A goroutine has no visible termination path — no context cancellation,\n",
            "no channel close, no return. It will leak resources.\n\n",
            "Fix: Pass a context.Context and select on ctx.Done().",
        ),
        "LEAK002" => concat!(
            "LEAK002: Channel created but never used\n\n",
            "A channel is created with make() but is never sent to or received from.\n",
            "This is likely a bug or dead code.\n\n",
            "Fix: Use the channel or remove the declaration.",
        ),
        // --- Concurrency: Channel Operations ---
        "CHAN001" => concat!(
            "CHAN001: Send on possibly closed channel\n\n",
            "A send on a channel that may already be closed will cause a runtime panic.\n\n",
            "Example:\n",
            "  close(ch)\n",
            "  ch <- 42 // panic: send on closed channel\n\n",
            "Fix: Use sync.Once for close, or restructure to avoid sending after close.",
        ),
        "CHAN002" => concat!(
            "CHAN002: Select without default case\n\n",
            "A select statement has no default case and may block indefinitely\n",
            "if no case is ready.\n\n",
            "Fix: Add a default case or a context timeout.",
        ),
        // --- Ownership / Resource Lifecycle ---
        "OWN001" => concat!(
            "OWN001: Resource opened but never closed\n\n",
            "A resource (file, connection, etc.) is opened but never closed in the\n",
            "same function scope. This causes resource leaks.\n\n",
            "Example:\n",
            "  f, err := os.Open(path)\n",
            "  // f is never closed\n\n",
            "Fix: Add defer f.Close() immediately after opening.",
        ),
        "OWN002" => concat!(
            "OWN002: Use after close\n\n",
            "A resource is used after it has been closed. This causes undefined\n",
            "behavior or runtime errors.\n\n",
            "Example:\n",
            "  f.Close()\n",
            "  f.Read(buf) // use after close\n\n",
            "Fix: Restructure code so all uses happen before Close().",
        ),
        "OWN003" => concat!(
            "OWN003: Double close\n\n",
            "A resource is closed more than once. This can cause runtime panics\n",
            "or corrupt state.\n\n",
            "Fix: Use sync.Once or restructure to ensure single close.",
        ),
        "OWN004" => concat!(
            "OWN004: Resource close not deferred\n\n",
            "A resource is closed explicitly but not via defer. If any code between\n",
            "Open and Close panics, the resource will leak.\n\n",
            "Fix: Use defer immediately after opening:\n",
            "  f, err := os.Open(path)\n",
            "  if err != nil { return err }\n",
            "  defer f.Close()",
        ),
        // --- Exhaustiveness ---
        "EXH001" => concat!(
            "EXH001: Type switch missing interface implementor\n\n",
            "A type switch on an interface does not cover all types that implement\n",
            "the interface. Missing cases will fall through to default or be silently\n",
            "ignored.\n\n",
            "Fix: Add cases for all implementors, or add an explicit default.",
        ),
        "EXH002" => concat!(
            "EXH002: Enum switch missing constant value\n\n",
            "A switch on an enum-like const group does not cover all defined values.\n",
            "New values added later will be silently missed.\n\n",
            "Fix: Add cases for all enum constants.",
        ),
        "EXH003" => concat!(
            "EXH003: Missing default case in non-exhaustive switch\n\n",
            "A switch statement is not exhaustive and has no default case.\n\n",
            "Fix: Add a default case to handle unexpected values.",
        ),
        // --- Taint Analysis ---
        "TAINT001" => concat!(
            "TAINT001: SQL injection\n\n",
            "Tainted data from an external source flows to a SQL query without\n",
            "sanitization. An attacker can inject arbitrary SQL.\n\n",
            "Example:\n",
            "  query := \"SELECT * FROM users WHERE id=\" + r.URL.Query().Get(\"id\")\n",
            "  db.Query(query)\n\n",
            "Fix: Use parameterized queries:\n",
            "  db.Query(\"SELECT * FROM users WHERE id=$1\", id)",
        ),
        "TAINT002" => concat!(
            "TAINT002: Command injection\n\n",
            "Tainted data flows to a command execution function without sanitization.\n",
            "An attacker can execute arbitrary OS commands.\n\n",
            "Example:\n",
            "  cmd := exec.Command(\"sh\", \"-c\", userInput)\n\n",
            "Fix: Validate/whitelist input or use exec.Command with separate args.",
        ),
        "TAINT003" => concat!(
            "TAINT003: Path traversal\n\n",
            "Tainted data flows to a file path operation. An attacker can access\n",
            "files outside the intended directory using ../ sequences.\n\n",
            "Fix: Use filepath.Clean() and validate the result is within the expected\n",
            "base directory.",
        ),
        "TAINT004" => concat!(
            "TAINT004: Cross-site scripting (XSS)\n\n",
            "Tainted data flows to HTML output without escaping. An attacker can\n",
            "inject scripts that execute in other users' browsers.\n\n",
            "Fix: Use html/template (auto-escapes) instead of text/template,\n",
            "or manually escape with html.EscapeString().",
        ),
        _ => {
            eprintln!("Unknown rule: {rule}. Use 'goguard check' to see available rules.");
            return ExitCode::from(2);
        }
    };
    println!("{explanation}");
    ExitCode::SUCCESS
}

fn run_init() -> ExitCode {
    let config_path = "goguard.toml";
    if std::path::Path::new(config_path).exists() {
        eprintln!("goguard.toml already exists");
        return ExitCode::from(2);
    }

    match std::fs::write(config_path, goguard_core::config::DEFAULT_CONFIG_TOML) {
        Ok(()) => {
            println!("Created goguard.toml");
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    }

    // Also create AGENTS.md if it doesn't exist
    let agents_path = "AGENTS.md";
    if !std::path::Path::new(agents_path).exists() {
        let content = goguard_ecosystem::agents_md::generate_full(None);
        match std::fs::write(agents_path, content) {
            Ok(()) => println!("Created AGENTS.md"),
            Err(e) => eprintln!("warning: could not create AGENTS.md: {e}"),
        }
    }

    ExitCode::SUCCESS
}

fn run_update_agents_md(path: &str) -> ExitCode {
    let section = goguard_ecosystem::agents_md::generate_section(None);

    let content = if std::path::Path::new(path).exists() {
        let existing = std::fs::read_to_string(path).unwrap_or_default();
        goguard_ecosystem::agents_md::merge_into_existing(&existing, &section)
    } else {
        goguard_ecosystem::agents_md::generate_full(None)
    };

    match std::fs::write(path, &content) {
        Ok(()) => {
            println!("Updated {path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// GoGuard QL REPL
// ---------------------------------------------------------------------------

/// Process a single line of REPL input. Returns the output to print.
/// Returns `None` for quit commands, `Some(text)` for everything else.
fn process_repl_line(
    line: &str,
    diagnostics: &[goguard_diagnostics::diagnostic::Diagnostic],
) -> Option<String> {
    let trimmed = line.trim();

    if trimmed.is_empty() {
        return Some(String::new());
    }

    match trimmed {
        "quit" | "exit" | "q" => None,
        "help" | "h" | "?" => Some(repl_help_text()),
        "count" => Some(format!("{} diagnostics loaded", diagnostics.len())),
        _ => match goguard_db::query::parse_query(trimmed) {
            Ok(query) => {
                let engine = goguard_db::query_engine::QueryEngine::new(diagnostics);
                let result = engine.execute(&query);
                let json = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("JSON error: {e}"));
                Some(json)
            }
            Err(e) => Some(format!(
                "Parse error: {e}\nType 'help' for syntax reference."
            )),
        },
    }
}

fn repl_help_text() -> String {
    "\
GoGuard QL — Interactive Query Language

ENTITIES:
  diagnostics                          All diagnostics
  functions                            Group by function location
  packages                             Group by package/file
  callers of \"pkg.Func\"               Call graph (requires bridge)
  taint_paths from \"A\" to \"B\"         Taint flow (requires bridge)

FILTERS:
  where severity == \"critical\"         Exact match
  where rule != \"NIL001\"               Not equal
  where rule starts_with \"NIL\"         Prefix match
  where file contains \"handler\"        Substring match
  where has_rule(\"ERR*\")               Glob match on rule
  ... and ...                          Combine filters
  ... or ...                           Alternative filters

MODIFIERS:
  order_by field [asc|desc]            Sort results
  limit N                              Limit output rows
  offset N                             Skip first N rows

COMMANDS:
  help, h, ?                           Show this help
  count                                Show loaded diagnostic count
  quit, exit, q                        Exit REPL

EXAMPLES:
  diagnostics where severity == \"critical\"
  diagnostics where file == \"handler.go\" and rule starts_with \"NIL\"
  functions order_by diagnostic_count desc limit 10
  packages where has_rule(\"NIL*\") and has_rule(\"ERR*\")"
        .to_string()
}

fn run_query_repl(project_dir: Option<PathBuf>) -> ExitCode {
    let cwd = project_dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let config = goguard_core::config::load_config(&cwd);

    eprintln!("Analyzing project...");
    let diagnostics =
        match goguard_core::orchestrator::analyze_project(&cwd, &["./...".into()], &config) {
            Ok(output) => output.diagnostics,
            Err(e) => {
                eprintln!("Analysis error: {e}");
                return ExitCode::from(1);
            }
        };

    eprintln!(
        "Loaded {} diagnostics. Type 'help' for syntax, 'quit' to exit.\n",
        diagnostics.len()
    );

    let mut rl = rustyline::DefaultEditor::new().unwrap_or_else(|e| {
        eprintln!("Failed to init readline: {e}");
        std::process::exit(2);
    });

    loop {
        match rl.readline("goguard> ") {
            Ok(line) => {
                let _ = rl.add_history_entry(&line);
                match process_repl_line(&line, &diagnostics) {
                    Some(output) => {
                        if !output.is_empty() {
                            println!("{output}");
                        }
                    }
                    None => {
                        eprintln!("Bye!");
                        break;
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                eprintln!("Ctrl+C — type 'quit' to exit");
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                eprintln!("Bye!");
                break;
            }
            Err(e) => {
                eprintln!("Readline error: {e}");
                break;
            }
        }
    }

    ExitCode::SUCCESS
}

fn run_query(expression: &str, project_dir: Option<PathBuf>) -> ExitCode {
    let cwd = project_dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let config = goguard_core::config::load_config(&cwd);

    // Parse query first (fast fail on syntax error)
    let query = match goguard_db::query::parse_query(expression) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("Query parse error: {e}");
            return ExitCode::from(2);
        }
    };

    // Analyze project
    match goguard_core::orchestrator::analyze_project(&cwd, &["./...".into()], &config) {
        Ok(output) => {
            let engine = goguard_db::query_engine::QueryEngine::new(&output.diagnostics);
            let result = engine.execute(&query);
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_fix(diagnostic_id: &str, apply: bool, patch: bool, verify: bool) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_default();
    let config = goguard_core::config::load_config(&cwd);

    let output = match goguard_core::orchestrator::analyze_project(&cwd, &["./...".into()], &config)
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let diag = output.diagnostics.iter().find(|d| d.id == diagnostic_id);
    let fix = diag.and_then(goguard_diagnostics::full::FixOutput::from_diagnostic);

    match fix {
        Some(fix) => {
            if patch {
                let diff = goguard_diagnostics::executable::generate_combined_patch(&fix.edits);
                print!("{diff}");
            } else if apply {
                let results = goguard_diagnostics::executable::apply_edits(&fix.edits);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&results).unwrap_or_default()
                );

                if verify {
                    match goguard_core::orchestrator::analyze_project(
                        &cwd,
                        &["./...".into()],
                        &config,
                    ) {
                        Ok(after) => {
                            let before_count = output.diagnostics.len();
                            let after_count = after.diagnostics.len();
                            eprintln!(
                                "Verification: {} -> {} diagnostics (delta: {})",
                                before_count,
                                after_count,
                                after_count as isize - before_count as isize
                            );
                        }
                        Err(e) => eprintln!("Verification error: {e}"),
                    }
                }
            } else {
                // Default: print fix details as JSON
                println!("{}", serde_json::to_string_pretty(&fix).unwrap_or_default());
            }
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("No fix available for {diagnostic_id}");
            ExitCode::from(1)
        }
    }
}

struct AutoFixArgs {
    packages: Vec<String>,
    severity: String,
    max_iterations: usize,
    max_fixes: usize,
    max_time_secs: u64,
    test: bool,
    dry_run: bool,
    verbose: bool,
}

fn run_auto_fix(args: AutoFixArgs) -> ExitCode {
    use goguard_agent::autofix;
    use goguard_agent::budget::AutoFixBudget;
    use goguard_diagnostics::diagnostic::Severity;

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = goguard_core::config::load_config(&cwd);

    let budget = AutoFixBudget {
        max_iterations: args.max_iterations,
        max_fixes: args.max_fixes,
        max_time_ms: args.max_time_secs * 1000,
        ..Default::default()
    };

    // Parse minimum severity threshold
    let min_severity = match args.severity.as_str() {
        "critical" => Severity::Critical,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        other => {
            eprintln!("Unknown severity: {other}. Use: critical, error, warning, info");
            return ExitCode::from(2);
        }
    };

    let packages =
        if args.packages.is_empty() || (args.packages.len() == 1 && args.packages[0] == "./...") {
            vec!["./...".to_string()]
        } else {
            args.packages
        };

    if args.verbose {
        eprintln!(
            "Auto-fix: severity={}, max_iterations={}, max_fixes={}, max_time={}s, test={}, dry_run={}",
            args.severity, args.max_iterations, args.max_fixes, args.max_time_secs, args.test, args.dry_run
        );
    }

    let report = match autofix::run_autofix_orchestrator(
        &cwd,
        &packages,
        &config,
        &min_severity,
        &budget,
        args.test,
        args.dry_run,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    if args.verbose {
        eprintln!(
            "Done: {} fixes applied, {} skipped, {} iterations in {}ms",
            report.fixes_applied, report.fixes_skipped, report.iterations, report.time_elapsed_ms,
        );
        if !report.skipped_reasons.is_empty() {
            eprintln!("Skipped reasons:");
            for reason in &report.skipped_reasons {
                eprintln!("  - {reason}");
            }
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
    ExitCode::SUCCESS
}

/// Check if a diagnostic severity meets the minimum threshold.
#[cfg(test)]
fn severity_meets_threshold(
    severity: &goguard_diagnostics::diagnostic::Severity,
    min: &goguard_diagnostics::diagnostic::Severity,
) -> bool {
    use goguard_diagnostics::diagnostic::Severity;
    let ord = |s: &Severity| -> u8 {
        match s {
            Severity::Critical => 0,
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
        }
    };
    ord(severity) <= ord(min)
}

fn run_sdk_generate(target: &str) -> ExitCode {
    match target {
        "python" => {
            let code = sdk_gen::generate_python_sdk();
            print!("{code}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Unknown target: {target}. Supported: python");
            ExitCode::from(2)
        }
    }
}

/// Execute an MCP tool via CLI for SDK integration.
///
/// This enables the Python SDK to call GoGuard tools without running a full MCP server.
/// Tools accept the same JSON parameters as their MCP counterparts.
fn run_sdk_call(tool: &str, params_json: &str, project_dir: Option<PathBuf>) -> ExitCode {
    match tool {
        "rules" => {
            // Rules don't need the bridge or a project — fast path
            let params: RulesParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            let all_rules = goguard_diagnostics::rules::get_all_rules();
            let filtered: Vec<_> = if let Some(ref category) = params.category {
                let cat_upper = category.to_uppercase();
                all_rules
                    .into_iter()
                    .filter(|r| r.code.starts_with(&cat_upper))
                    .collect()
            } else {
                all_rules
            };
            let json = serde_json::to_string_pretty(&filtered)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
            println!("{json}");
            ExitCode::SUCCESS
        }
        "analyze" => {
            // Analyze requires the Go bridge — full project analysis
            let params: AnalyzeParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            let cwd = project_dir
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let mut config = goguard_core::config::load_config(&cwd);
            if let Some(ref sev) = params.severity_threshold {
                config.goguard.severity_threshold = sev.clone();
            }
            let packages: Vec<String> = if params.files.is_empty() {
                vec!["./...".to_string()]
            } else {
                params.files
            };

            match goguard_core::orchestrator::analyze_project(&cwd, &packages, &config) {
                Ok(output) => {
                    let result = serde_json::json!({
                        "diagnostics": output.diagnostics,
                        "summary": output.summary,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Analysis failed: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    ExitCode::from(2)
                }
            }
        }
        // Stateful tools: need a server instance with diagnostics
        "explain" | "fix" | "verify" | "batch" | "snapshot" | "query" | "search" | "execute"
        | "autofix" => {
            let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
                eprintln!("Failed to create tokio runtime: {e}");
                std::process::exit(2);
            });
            rt.block_on(dispatch_tool(tool, params_json, project_dir))
        }
        _ => {
            let err = serde_json::json!({"error": format!("Unknown tool: {tool}. Available: analyze, explain, fix, verify, rules, batch, snapshot, query, search, execute, autofix")});
            println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
            ExitCode::from(1)
        }
    }
}

/// Dispatch a stateful tool call through the MCP server.
///
/// For stateful tools (explain, fix, verify, batch, snapshot), we first run
/// `analyze_project` to populate diagnostics, then create a `GoGuardMcpServer`
/// with those diagnostics and dispatch to its public methods.
async fn dispatch_tool(tool: &str, params_json: &str, project_dir: Option<PathBuf>) -> ExitCode {
    // First, run analysis to populate diagnostics
    let cwd = project_dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let config = goguard_core::config::load_config(&cwd);
    let diagnostics =
        match goguard_core::orchestrator::analyze_project(&cwd, &["./...".to_string()], &config) {
            Ok(output) => output.diagnostics,
            Err(e) => {
                let err = serde_json::json!({"error": format!("Analysis failed: {e}")});
                println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                return ExitCode::from(2);
            }
        };

    let server = GoGuardMcpServer::with_diagnostics(diagnostics);

    let result = match tool {
        "explain" => {
            let params: ExplainParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server.explain(&params.diagnostic_id).await
        }
        "fix" => {
            let params: FixParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            if params.auto_verify {
                server.fix(&params.diagnostic_id).await
            } else {
                server.fix_no_verify(&params.diagnostic_id).await
            }
        }
        "verify" => {
            let params: VerifyParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            // verify is basically re-analyze with specific files
            let _ = params; // params.files used if we re-analyze
            let err = serde_json::json!({"error": "verify requires a running MCP server with existing state. Use 'analyze' instead."});
            println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
            return ExitCode::from(1);
        }
        "batch" => {
            let params: BatchParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server.batch(params.diagnostic_ids).await
        }
        "snapshot" => {
            let params: SnapshotParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server
                .snapshot(
                    &params.action,
                    params.name.as_deref(),
                    params.compare_to.as_deref(),
                )
                .await
        }
        "query" => {
            let params: QueryParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server.query(&params.expression).await
        }
        "search" => {
            let params: SearchParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server.search(&params.code).await
        }
        "execute" => {
            let params: ExecuteParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server.execute(&params.code).await
        }
        "autofix" => {
            let params: AutofixParams = match serde_json::from_str(params_json) {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({"error": format!("Invalid params: {e}")});
                    println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
                    return ExitCode::from(1);
                }
            };
            server
                .autofix(
                    &params.severity,
                    params.max_fixes,
                    params.max_iterations,
                    params.test,
                    params.dry_run,
                )
                .await
        }
        _ => unreachable!("dispatch_tool called with unknown tool: {tool}"),
    };

    match result {
        Ok(call_result) => {
            // Extract text from the MCP CallToolResult
            if let Some(text_content) = call_result.content.first().and_then(|c| c.as_text()) {
                println!("{}", text_content.text);
            }
            if call_result.is_error == Some(true) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            let err = serde_json::json!({"error": format!("Tool error: {e}")});
            println!("{}", serde_json::to_string_pretty(&err).unwrap_or_default());
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_call_rules() {
        // "rules" doesn't need the Go bridge — should succeed and return JSON array
        let exit = run_sdk_call("rules", "{}", None);
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn test_sdk_call_rules_with_category() {
        let exit = run_sdk_call("rules", r#"{"category": "nil"}"#, None);
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn test_sdk_call_analyze_params_deserialize() {
        // Verify AnalyzeParams deserializes correctly from JSON
        let json = r#"{"files": ["./cmd/..."], "severity_threshold": "error"}"#;
        let params: AnalyzeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.files, vec!["./cmd/..."]);
        assert_eq!(params.severity_threshold.as_deref(), Some("error"));
        assert!(params.max_diagnostics.is_none());
    }

    #[test]
    fn test_sdk_call_unknown_tool() {
        let exit = run_sdk_call("nonexistent", "{}", None);
        assert_ne!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn test_sdk_call_rules_invalid_params() {
        // Bad JSON should return error exit code
        let exit = run_sdk_call("rules", "not-json", None);
        assert_ne!(exit, ExitCode::SUCCESS);
    }

    // ── Task 6: goguard query CLI tests ──

    #[test]
    fn test_query_cli_parse_error() {
        // Invalid query expression should return exit code 2
        let exit = run_query("!!!invalid query!!!", None);
        assert_eq!(exit, ExitCode::from(2));
    }

    #[test]
    fn test_query_cli_valid_parse() {
        // Valid query syntax should parse OK (analysis will fail without Go bridge, but parse succeeds)
        let query = goguard_db::query::parse_query("diagnostics where severity == \"critical\"");
        assert!(query.is_ok(), "Valid query should parse");
    }

    // ── goguard query --repl tests ──

    fn make_test_diagnostics() -> Vec<goguard_diagnostics::diagnostic::Diagnostic> {
        use goguard_diagnostics::diagnostic::{DiagnosticBuilder, DiagnosticSource, Severity};
        vec![
            DiagnosticBuilder::new(
                "NIL001",
                Severity::Critical,
                "nil deref",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 10, 5)
            .build(),
            DiagnosticBuilder::new(
                "ERR001",
                Severity::Error,
                "ignored error",
                DiagnosticSource::Errcheck,
            )
            .location("service.go", 20, 1)
            .build(),
            DiagnosticBuilder::new(
                "NIL003",
                Severity::Warning,
                "nil map",
                DiagnosticSource::Nil,
            )
            .location("handler.go", 30, 1)
            .build(),
        ]
    }

    #[test]
    fn test_repl_quit_commands() {
        let diags = make_test_diagnostics();
        assert!(process_repl_line("quit", &diags).is_none());
        assert!(process_repl_line("exit", &diags).is_none());
        assert!(process_repl_line("q", &diags).is_none());
    }

    #[test]
    fn test_repl_help() {
        let diags = make_test_diagnostics();
        let output = process_repl_line("help", &diags).unwrap();
        assert!(output.contains("ENTITIES:"));
        assert!(output.contains("FILTERS:"));
        assert!(output.contains("EXAMPLES:"));

        // Aliases
        let output2 = process_repl_line("h", &diags).unwrap();
        assert_eq!(output, output2);
        let output3 = process_repl_line("?", &diags).unwrap();
        assert_eq!(output, output3);
    }

    #[test]
    fn test_repl_count() {
        let diags = make_test_diagnostics();
        let output = process_repl_line("count", &diags).unwrap();
        assert_eq!(output, "3 diagnostics loaded");
    }

    #[test]
    fn test_repl_empty_line() {
        let diags = make_test_diagnostics();
        let output = process_repl_line("", &diags).unwrap();
        assert!(output.is_empty());
        let output2 = process_repl_line("   ", &diags).unwrap();
        assert!(output2.is_empty());
    }

    #[test]
    fn test_repl_valid_query() {
        let diags = make_test_diagnostics();
        let output =
            process_repl_line("diagnostics where severity == \"critical\"", &diags).unwrap();
        // Should be valid JSON with results
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["total"], 1);
        assert_eq!(parsed["rows"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_repl_query_all_diagnostics() {
        let diags = make_test_diagnostics();
        let output = process_repl_line("diagnostics", &diags).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["total"], 3);
    }

    #[test]
    fn test_repl_query_with_limit() {
        let diags = make_test_diagnostics();
        let output = process_repl_line("diagnostics limit 1", &diags).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["rows"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["total"], 3); // total is pre-limit count
    }

    #[test]
    fn test_repl_query_starts_with_filter() {
        let diags = make_test_diagnostics();
        let output =
            process_repl_line("diagnostics where rule starts_with \"NIL\"", &diags).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["total"], 2); // NIL001 + NIL003
    }

    #[test]
    fn test_repl_parse_error() {
        let diags = make_test_diagnostics();
        let output = process_repl_line("!!!garbage!!!", &diags).unwrap();
        assert!(output.contains("Parse error:"));
        assert!(output.contains("help"));
    }

    #[test]
    fn test_repl_cli_args_repl_flag() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["goguard", "query", "--repl"]).unwrap();
        match cli.command {
            Commands::Query {
                expression,
                repl,
                project_dir,
            } => {
                assert!(repl);
                assert!(expression.is_none());
                assert!(project_dir.is_none());
            }
            _ => panic!("Expected Query command"),
        }
    }

    #[test]
    fn test_repl_cli_args_expression() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "goguard",
            "query",
            "diagnostics where severity == \"error\"",
        ])
        .unwrap();
        match cli.command {
            Commands::Query {
                expression, repl, ..
            } => {
                assert!(!repl);
                assert_eq!(
                    expression.as_deref(),
                    Some("diagnostics where severity == \"error\"")
                );
            }
            _ => panic!("Expected Query command"),
        }
    }

    #[test]
    fn test_repl_help_text_completeness() {
        let help = repl_help_text();
        // Verify all entity types are documented
        assert!(help.contains("diagnostics"));
        assert!(help.contains("functions"));
        assert!(help.contains("packages"));
        assert!(help.contains("callers of"));
        assert!(help.contains("taint_paths"));
        // Verify all filter operators
        assert!(help.contains("=="));
        assert!(help.contains("!="));
        assert!(help.contains("starts_with"));
        assert!(help.contains("contains"));
        assert!(help.contains("has_rule"));
        // Verify modifiers
        assert!(help.contains("order_by"));
        assert!(help.contains("limit"));
        assert!(help.contains("offset"));
    }

    #[test]
    fn test_setup_vscode_target() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["goguard", "setup", "vscode"]).unwrap();
        match cli.command {
            Commands::Setup { target } => assert_eq!(target, "vscode"),
            _ => panic!("Expected Setup command"),
        }
    }

    #[test]
    fn test_setup_all_targets_parse() {
        use clap::Parser;
        for target in &[
            "claude-code",
            "cursor",
            "codex",
            "windsurf",
            "zed",
            "opencode",
            "vscode",
        ] {
            let cli = Cli::try_parse_from(["goguard", "setup", target]).unwrap();
            match cli.command {
                Commands::Setup { target: t } => assert_eq!(&t, target),
                _ => panic!("Expected Setup command for {}", target),
            }
        }
    }

    #[test]
    fn test_setup_unknown_target() {
        let exit = run_setup("unknown_ide");
        assert_eq!(exit, ExitCode::from(2));
    }

    // ── Task 11: goguard auto-fix CLI tests ──

    #[test]
    fn test_auto_fix_cli_args_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "goguard",
            "auto-fix",
            "--severity",
            "warning",
            "--max-iterations",
            "5",
            "--max-fixes",
            "20",
            "--max-time-secs",
            "60",
            "--test",
            "--dry-run",
            "-v",
        ])
        .unwrap();
        match cli.command {
            Commands::AutoFix {
                severity,
                max_iterations,
                max_fixes,
                max_time_secs,
                test,
                dry_run,
                verbose,
                ..
            } => {
                assert_eq!(severity, "warning");
                assert_eq!(max_iterations, 5);
                assert_eq!(max_fixes, 20);
                assert_eq!(max_time_secs, 60);
                assert!(test);
                assert!(dry_run);
                assert!(verbose);
            }
            _ => panic!("Expected AutoFix command"),
        }
    }

    #[test]
    fn test_auto_fix_cli_defaults() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["goguard", "auto-fix"]).unwrap();
        match cli.command {
            Commands::AutoFix {
                severity,
                max_iterations,
                max_fixes,
                max_time_secs,
                test,
                dry_run,
                verbose,
                ..
            } => {
                assert_eq!(severity, "error");
                assert_eq!(max_iterations, 10);
                assert_eq!(max_fixes, 50);
                assert_eq!(max_time_secs, 300);
                assert!(!test);
                assert!(!dry_run);
                assert!(!verbose);
            }
            _ => panic!("Expected AutoFix command"),
        }
    }

    #[test]
    fn test_auto_fix_report_format() {
        use goguard_agent::autofix::{AutoFixReport, SeveritySummary};
        let report = AutoFixReport {
            iterations: 3,
            fixes_applied: 5,
            fixes_skipped: 2,
            skipped_reasons: vec!["ERR001-x.go:5: dry-run".into()],
            before: SeveritySummary {
                critical: 2,
                error: 3,
                warning: 1,
                info: 0,
            },
            after: SeveritySummary {
                critical: 0,
                error: 1,
                warning: 1,
                info: 0,
            },
            time_elapsed_ms: 1234,
            build_status: "pass".into(),
            test_status: None,
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"iterations\": 3"));
        assert!(json.contains("\"fixes_applied\": 5"));
        assert!(json.contains("\"before\""));
        assert!(json.contains("\"after\""));
        assert!(json.contains("\"time_elapsed_ms\""));
    }

    #[test]
    fn test_severity_meets_threshold() {
        use goguard_diagnostics::diagnostic::Severity;
        // critical meets error threshold (critical is higher)
        assert!(super::severity_meets_threshold(
            &Severity::Critical,
            &Severity::Error
        ));
        // error meets error threshold
        assert!(super::severity_meets_threshold(
            &Severity::Error,
            &Severity::Error
        ));
        // warning does NOT meet error threshold
        assert!(!super::severity_meets_threshold(
            &Severity::Warning,
            &Severity::Error
        ));
        // info does NOT meet error threshold
        assert!(!super::severity_meets_threshold(
            &Severity::Info,
            &Severity::Error
        ));
        // everything meets info threshold
        assert!(super::severity_meets_threshold(
            &Severity::Critical,
            &Severity::Info
        ));
        assert!(super::severity_meets_threshold(
            &Severity::Warning,
            &Severity::Info
        ));
    }

    // ── Task 8: goguard fix CLI tests ──

    #[test]
    fn test_fix_cli_help() {
        // Verify --apply, --patch, --verify flags exist by parsing CLI args
        use clap::Parser;
        let result = Cli::try_parse_from([
            "goguard",
            "fix",
            "NIL001-handler.go:18",
            "--apply",
            "--verify",
        ]);
        assert!(result.is_ok(), "fix --apply --verify should parse");

        let result = Cli::try_parse_from(["goguard", "fix", "NIL001-handler.go:18", "--patch"]);
        assert!(result.is_ok(), "fix --patch should parse");
    }

    // ── Task 6: bridge cache CLI flag tests ──

    #[test]
    fn test_cli_no_cache_flag() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["goguard", "check", "--no-cache", "./..."]).unwrap();
        match cli.command {
            Commands::Check {
                no_cache,
                cache_dir,
                packages,
                ..
            } => {
                assert!(no_cache, "--no-cache flag should be true");
                assert!(cache_dir.is_none(), "cache_dir should be None");
                assert_eq!(packages, vec!["./..."]);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_cache_dir_flag() {
        use clap::Parser;
        let cli =
            Cli::try_parse_from(["goguard", "check", "--cache-dir", "/tmp/test", "./..."]).unwrap();
        match cli.command {
            Commands::Check {
                no_cache,
                cache_dir,
                packages,
                ..
            } => {
                assert!(!no_cache, "--no-cache should default to false");
                assert_eq!(cache_dir, Some("/tmp/test".to_string()));
                assert_eq!(packages, vec!["./..."]);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_diff_flag() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["goguard", "check", "--diff", "./..."]).unwrap();
        match cli.command {
            Commands::Check { diff, packages, .. } => {
                assert!(diff, "--diff flag should be true");
                assert_eq!(packages, vec!["./..."]);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_parse_go_mod_module_path() {
        let content = "module example.com/myapp\n\ngo 1.22\n";
        assert_eq!(
            super::parse_go_mod_module_path(content),
            Some("example.com/myapp".to_string())
        );
        let content = "module\texample.com/myapp\n";
        assert_eq!(
            super::parse_go_mod_module_path(content),
            Some("example.com/myapp".to_string())
        );
    }

    #[test]
    fn test_fix_cli_unknown_id_integration() {
        // Without the Go bridge, run_fix will fail at analyze_project, but
        // if somehow it got through, an unknown ID returns exit code 1.
        // Here we test the fix function logic by checking it handles missing diag IDs.
        // The function tries to analyze first, which needs the bridge.
        // So we just test that the CLI args parse correctly.
        use clap::Parser;
        let cli = Cli::try_parse_from(["goguard", "fix", "UNKNOWN-x.go:1"]).unwrap();
        match cli.command {
            Commands::Fix {
                diagnostic_id,
                apply,
                patch,
                verify,
            } => {
                assert_eq!(diagnostic_id, "UNKNOWN-x.go:1");
                assert!(!apply);
                assert!(!patch);
                assert!(!verify);
            }
            _ => panic!("Expected Fix command"),
        }
    }
}
