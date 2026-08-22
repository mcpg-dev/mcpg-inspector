//! The inspector engine: targets, sessions over `mcpg-mcp-client`,
//! and the wire event log fed by the client's frame tap. Every face
//! (web API, TUI, one-shot CLI verbs) drives this module.

pub mod aauth;
pub mod authlab;
pub mod checks;
pub mod eventlog;
pub mod gateway;
pub mod mcpgconfig;
pub mod oauth;
pub mod ops;
pub mod probe;
pub mod recording;
pub mod registry;
pub mod responders;
pub mod session;
pub mod snapshot;
pub mod stateless;
pub mod target;
