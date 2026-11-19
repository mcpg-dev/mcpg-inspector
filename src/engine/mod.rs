//! The inspector engine: targets, sessions over `mcpg-mcp-client`,
//! and the wire event log fed by the client's frame tap. Every face
//! (web API, TUI, one-shot CLI verbs) drives this module.

pub mod aauth;
pub mod authlab;
pub mod checks;
pub mod client_auth;
pub mod dpop;
pub mod eventlog;
pub mod events;
pub mod gateway;
pub mod idjag;
pub mod keys;
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

/// The `_meta` every MCP 2026-07-28 request carries: the protocol version,
/// the client's identity and its capabilities. For the raw requests the
/// engine builds itself rather than through the client.
pub(crate) fn request_meta(client_name: &str) -> serde_json::Value {
    use mcpg_mcp_wire::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION;
    use mcpg_mcp_wire::v_2026_07_28::wire::meta::{
        META_KEY_CLIENT_CAPABILITIES, META_KEY_CLIENT_INFO, META_KEY_PROTOCOL_VERSION,
    };
    serde_json::json!({
        META_KEY_PROTOCOL_VERSION: SUPPORTED_PROTOCOL_VERSION,
        META_KEY_CLIENT_INFO: { "name": client_name, "version": env!("CARGO_PKG_VERSION") },
        META_KEY_CLIENT_CAPABILITIES: {},
    })
}
