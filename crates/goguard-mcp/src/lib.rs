//! GoGuard MCP - Model Context Protocol server integration.
//!
//! Exposes GoGuard analysis as MCP tools for AI agents (Claude Code, Cursor, Codex).
//! Start with `goguard serve --mcp` or call `run_mcp_server()` directly.

pub mod output;
pub mod resources;
pub mod server;
pub mod tools;
pub mod verification;

pub mod elicitation;
pub mod prompts;
pub mod tasks;

pub use server::{run_mcp_server, GoGuardMcpServer};
