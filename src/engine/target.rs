use std::collections::BTreeMap;
use std::time::Duration;

use mcpg_mcp_client::transport::UpstreamTransport;
use mcpg_mcp_client::upstream::UpstreamConnectOptions;
use serde::{Deserialize, Serialize};

/// `clientInfo.name`-adjacent identity the inspector sends as its
/// loop-detection id on every request.
const INSPECTOR_VIA: &str = "mcpg-inspector";

/// Protocol-version policy for one target. `Auto` runs the SEP-2575
/// probe; the pins force a wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum VersionPolicy {
    #[default]
    Auto,
    #[value(name = "2025-11-25")]
    #[serde(rename = "2025-11-25")]
    Sessionful,
    #[value(name = "2026-07-28")]
    #[serde(rename = "2026-07-28")]
    Stateless,
}

/// One inspectable MCP server. Unknown JSON keys pass silently: the
/// flattened kind precludes `deny_unknown_fields` (a serde
/// limitation), and target objects travel between inspector versions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetSpec {
    /// Display name; targets from the gateway supervisor arrive named
    /// (`gateway`, plus its dialable federation upstreams).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub kind: TargetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub protocol_version: VersionPolicy,
    /// How server→client requests (sampling / elicitation / roots) are
    /// answered for this target.
    #[serde(default)]
    pub responder: crate::engine::responders::ResponderPolicy,
    /// Permit private/loopback addresses. Local modes default to true —
    /// inspecting a server on 127.0.0.1 is the primary use; hosted mode
    /// hard-forces false.
    #[serde(default = "default_allow_private")]
    pub allow_private: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
    /// Sign every request to this target with AAuth HTTP Message
    /// Signatures ([`crate::engine::aauth`]). Absent (default) sends only
    /// the static headers above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aauth: Option<crate::engine::aauth::AauthSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TargetKind {
    Http {
        url: String,
    },
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    /// A recorded exchange, replayed from a file. Dials nothing — which is
    /// what makes it work with the server gone.
    Recording {
        path: String,
    },
}

fn default_allow_private() -> bool {
    true
}
fn default_timeout_ms() -> u64 {
    30_000
}
fn default_max_response_bytes() -> u64 {
    8 * 1024 * 1024
}

impl TargetSpec {
    /// Parse the CLI target forms: an `http(s)://` URL, a
    /// `stdio:<command> [args…]` spec (whitespace-split), or a JSON
    /// `TargetSpec` object.
    pub fn parse_cli(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed).map_err(|e| format!("invalid target JSON: {e}"));
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Ok(Self::with_kind(TargetKind::Http {
                url: trimmed.to_owned(),
            }));
        }
        if let Some(path) = trimmed.strip_prefix("recording:") {
            return Ok(Self::with_kind(TargetKind::Recording {
                path: path.trim().to_owned(),
            }));
        }
        if let Some(rest) = trimmed.strip_prefix("stdio:") {
            let mut parts = rest.split_whitespace();
            let command = parts
                .next()
                .ok_or_else(|| "stdio target needs a command".to_owned())?
                .to_owned();
            return Ok(Self::with_kind(TargetKind::Stdio {
                command,
                args: parts.map(str::to_owned).collect(),
                env: BTreeMap::new(),
            }));
        }
        Err(format!(
            "unrecognized target '{trimmed}': expected an http(s):// URL, \
             stdio:<command> [args…], recording:<path>, or a JSON target object"
        ))
    }

    pub fn is_stdio(&self) -> bool {
        matches!(self.kind, TargetKind::Stdio { .. })
    }

    fn with_kind(kind: TargetKind) -> Self {
        Self {
            name: None,
            kind,
            bearer: None,
            headers: BTreeMap::new(),
            protocol_version: VersionPolicy::Auto,
            responder: crate::engine::responders::ResponderPolicy::default(),
            allow_private: default_allow_private(),
            timeout_ms: default_timeout_ms(),
            max_response_bytes: default_max_response_bytes(),
            aauth: None,
        }
    }

    /// Lower the spec into client connect options. stdio speaks only the
    /// sessionful wire (the client probes HTTP targets only), so a
    /// stateless pin on stdio is rejected rather than silently ignored.
    pub fn connect_options(
        &self,
        tap: Option<mcpg_mcp_client::tap::SharedTap>,
    ) -> Result<UpstreamConnectOptions, String> {
        let (transport, url, command, args, env) = match &self.kind {
            // A recording is served from the file by `Session::connect`; it
            // never reaches here, and inventing connect options for one would
            // be a way to accidentally dial something.
            TargetKind::Recording { .. } => {
                return Err("a recording is replayed, not connected".to_owned());
            }
            TargetKind::Http { url } => (
                UpstreamTransport::StreamableHttp,
                url.clone(),
                None,
                Vec::new(),
                BTreeMap::new(),
            ),
            TargetKind::Stdio { command, args, env } => {
                if self.protocol_version == VersionPolicy::Stateless {
                    return Err("stdio targets speak the sessionful wire only; \
                         drop the 2026-07-28 pin"
                        .to_owned());
                }
                (
                    UpstreamTransport::Stdio,
                    String::new(),
                    Some(command.clone()),
                    args.clone(),
                    env.clone(),
                )
            }
        };
        let (modern, probe) = match (&self.kind, self.protocol_version) {
            (TargetKind::Stdio { .. }, _) => (false, false),
            (_, VersionPolicy::Auto) => (false, true),
            (_, VersionPolicy::Sessionful) => (false, false),
            (_, VersionPolicy::Stateless) => (true, false),
        };
        let capture_stdio_stderr = tap.is_some();
        Ok(UpstreamConnectOptions {
            url,
            bearer_token: self.bearer.clone(),
            tunnel_token: None,
            allow_private: self.allow_private,
            max_response_bytes: self.max_response_bytes,
            timeout: Duration::from_millis(self.timeout_ms),
            gateway_via: INSPECTOR_VIA.to_owned(),
            client_capabilities: serde_json::json!({}),
            transport,
            modern,
            probe,
            headers: self.headers.clone(),
            command,
            args,
            env,
            tap,
            capture_stdio_stderr,
            signer: match &self.aauth {
                Some(spec) => Some(std::sync::Arc::new(crate::engine::aauth::AauthSigner::new(
                    spec,
                )?)),
                None => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_url_stdio_and_json_forms() {
        let t = TargetSpec::parse_cli("https://example.com/mcp").unwrap();
        assert!(matches!(t.kind, TargetKind::Http { .. }));

        let t = TargetSpec::parse_cli("stdio:my-server --flag x").unwrap();
        match &t.kind {
            TargetKind::Stdio { command, args, .. } => {
                assert_eq!(command, "my-server");
                assert_eq!(args, &["--flag", "x"]);
            }
            other => panic!("expected stdio, got {other:?}"),
        }

        let t = TargetSpec::parse_cli(
            r#"{"url":"http://127.0.0.1:8787/mcp","protocol_version":"2026-07-28"}"#,
        )
        .unwrap();
        assert_eq!(t.protocol_version, VersionPolicy::Stateless);

        assert!(TargetSpec::parse_cli("ftp://nope").is_err());
    }

    #[test]
    fn stdio_rejects_stateless_pin() {
        let mut t = TargetSpec::parse_cli("stdio:server").unwrap();
        t.protocol_version = VersionPolicy::Stateless;
        assert!(t.connect_options(None).is_err());
    }

    #[test]
    fn auto_probes_http_but_not_stdio() {
        let t = TargetSpec::parse_cli("https://example.com/mcp").unwrap();
        let o = t.connect_options(None).unwrap();
        assert!(o.probe);
        assert!(!o.modern);

        let t = TargetSpec::parse_cli("stdio:server").unwrap();
        let o = t.connect_options(None).unwrap();
        assert!(!o.probe);
        assert!(!o.modern);
    }
}
