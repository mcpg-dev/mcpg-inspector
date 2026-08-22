//! mcpg-inspector — MCP inspector for mcpg: web UI, TUI and a
//! scriptable CLI over one engine. Runs standalone, supervised by the
//! gateway (`mcpg --inspector`), or hosted. Design and decision log:
//! `docs/inspector/rfcs/0001-architecture-and-design.md`.

pub mod api;
pub mod config;
pub mod engine;
pub mod http;
/// This process's own engine, as the terminal reads it.
#[cfg(feature = "tui")]
pub mod local_api;
pub mod static_ui;
pub mod verbs;
