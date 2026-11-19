//! Protocol checks a server should pass, run over raw HTTP.
//!
//! These are deliberately not client calls: each one asserts a
//! transport-level rule of the MCP 2026-07-28 Streamable HTTP transport
//! that the client would otherwise paper over, so they build their own
//! requests and read the raw response.
//!
//! Scope is honest: this is the portable subset, not the full upstream
//! conformance suite. `mcpg-inspector check` says which checks ran.

use mcpg_mcp_wire::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `clientInfo.name` of the checks' own requests. A full `_meta` keeps a
/// server that insists on it answering on the rule a check exercises.
const CLIENT_NAME: &str = "mcpg-inspector-checks";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub description: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Deserializable because an attached TUI reads a report back off the API
/// rather than running the checks itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckReport {
    pub protocol_version: String,
    pub passed: usize,
    pub failed: usize,
    pub checks: Vec<CheckResult>,
}

/// Run the portable check suite against an MCP endpoint.
/// `allow_private` comes from the target's own spec. The checks run after a
/// successful connect, but that connect pinned its address inside its own
/// client — a fresh one here would resolve the name again, which is the window
/// a rebinding record is aiming for.
pub async fn run(url: &str, allow_private: bool) -> Result<CheckReport, String> {
    let client = mcpg_mcp_client::auth::guarded_client(
        url,
        mcpg_mcp_client::auth::DiscoveryPolicy {
            allow_private,
            allow_insecure_http: url.starts_with("http://"),
        },
        std::time::Duration::from_secs(15),
    )
    .await?;
    let mut checks = Vec::new();

    for check in CHECKS {
        let (outcome, detail) = (check.run)(&client, url).await;
        checks.push(CheckResult {
            id: check.id.to_owned(),
            description: check.description.to_owned(),
            outcome,
            detail,
        });
    }

    Ok(CheckReport {
        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
        passed: checks.iter().filter(|c| c.outcome == Outcome::Pass).count(),
        failed: checks.iter().filter(|c| c.outcome == Outcome::Fail).count(),
        checks,
    })
}

type CheckFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = (Outcome, Option<String>)> + Send>>;

struct Check {
    id: &'static str,
    description: &'static str,
    run: fn(&reqwest::Client, &str) -> CheckFuture,
}

const CHECKS: &[Check] = &[
    Check {
        id: "batch-rejected",
        description: "a JSON-RPC batch is rejected",
        run: |client, url| {
            // A REAL batch. `[]` is a degenerate case a server may
            // legitimately treat as an empty request set; the rule
            // being checked is about a batch carrying requests.
            let request = post(client, url).body(
                json!([{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}]).to_string(),
            );
            Box::pin(async move {
                match request.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        // Rejected is rejected. A 4xx and a 200
                        // carrying JSON-RPC -32600 are both refusals —
                        // insisting on the status code alone would fail
                        // a conformant server for choosing the other.
                        if status.is_client_error() || jsonrpc_error_code(&body) == Some(-32600) {
                            (Outcome::Pass, None)
                        } else {
                            (
                                Outcome::Fail,
                                Some(format!(
                                    "batch accepted: HTTP {status} with {}",
                                    truncate(&body)
                                )),
                            )
                        }
                    }
                    Err(e) => (Outcome::Fail, Some(e.to_string())),
                }
            })
        },
    },
    Check {
        id: "unknown-method",
        description: "an unknown method answers with JSON-RPC -32601",
        run: |client, url| {
            let request = post(client, url)
                .header("mcp-method", "definitely/not-a-method")
                .body(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "definitely/not-a-method",
                        "params": { "_meta": super::request_meta(CLIENT_NAME) },
                    })
                    .to_string(),
                );
            Box::pin(async move {
                match request.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        let code = jsonrpc_error_code(&body);
                        // The HTTP status may be 404 or 200; the rule
                        // is the -32601 in the body.
                        if code == Some(-32601) {
                            (Outcome::Pass, None)
                        } else {
                            (
                                Outcome::Fail,
                                Some(format!(
                                    "expected -32601, got HTTP {status} with {}",
                                    truncate(&body)
                                )),
                            )
                        }
                    }
                    Err(e) => (Outcome::Fail, Some(e.to_string())),
                }
            })
        },
    },
    Check {
        id: "protocol-version-header-required",
        description: "a bad MCP-Protocol-Version header is refused (2026-07-28 §-32020)",
        run: |client, url| {
            let request = client
                .post(url)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", "1999-01-01")
                .header("mcp-method", "tools/list")
                .body(
                    json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}).to_string(),
                );
            Box::pin(async move {
                match request.send().await {
                    Ok(resp) if resp.status().is_client_error() => (Outcome::Pass, None),
                    Ok(resp) => (
                        Outcome::Fail,
                        Some(format!(
                            "expected a 4xx for an unsupported version, got HTTP {}",
                            resp.status()
                        )),
                    ),
                    Err(e) => (Outcome::Fail, Some(e.to_string())),
                }
            })
        },
    },
    Check {
        id: "malformed-json",
        description: "a malformed body answers with JSON-RPC -32700 or a 4xx",
        run: |client, url| {
            let request = post(client, url).body("{not json");
            Box::pin(async move {
                match request.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        if status.is_client_error() || jsonrpc_error_code(&body) == Some(-32700) {
                            (Outcome::Pass, None)
                        } else {
                            (
                                Outcome::Fail,
                                Some(format!("expected a parse error, got HTTP {status}")),
                            )
                        }
                    }
                    Err(e) => (Outcome::Fail, Some(e.to_string())),
                }
            })
        },
    },
];

fn post(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", SUPPORTED_PROTOCOL_VERSION)
}

/// The JSON-RPC error code in a body, whether it arrived as a plain
/// object or as SSE `data:` frames.
fn jsonrpc_error_code(body: &str) -> Option<i64> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return value.get("error")?.get("code")?.as_i64();
    }
    for line in body.lines() {
        let Some(data) = line.trim_start().strip_prefix("data:") else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<Value>(data.trim())
            && let Some(code) = value
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_i64)
        {
            return Some(code);
        }
    }
    None
}

fn truncate(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.len() <= 160 {
        return trimmed.to_owned();
    }
    format!("{}…", &trimmed[..160])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_read_from_plain_and_sse_bodies() {
        assert_eq!(
            jsonrpc_error_code(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}"#),
            Some(-32601)
        );
        assert_eq!(
            jsonrpc_error_code(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32700}}\n\n"
            ),
            Some(-32700)
        );
        assert_eq!(jsonrpc_error_code(r#"{"result":{}}"#), None);
        assert_eq!(jsonrpc_error_code("not json at all"), None);
    }

    /// The suite runs after a successful connect, but it builds its own
    /// client — so the connect's address pin does not cover it, and the guard
    /// has to be re-applied here or a rebinding record gets a second chance.
    #[tokio::test]
    async fn the_suite_will_not_probe_a_private_address_when_the_target_forbids_it() {
        let refused = run("http://127.0.0.1:9/mcp", false)
            .await
            .expect_err("a loopback probe must be refused when allow_private is false");
        assert!(
            refused.contains("private") || refused.contains("loopback"),
            "the refusal should name the reason: {refused}"
        );
    }

    #[test]
    fn check_requests_name_the_revision_they_speak() {
        let meta = super::super::request_meta(CLIENT_NAME);
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            SUPPORTED_PROTOCOL_VERSION
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientInfo"]["name"],
            CLIENT_NAME
        );
        assert!(meta["io.modelcontextprotocol/clientCapabilities"].is_object());
    }

    #[test]
    fn every_check_has_a_unique_id() {
        let mut seen = std::collections::BTreeSet::new();
        for check in CHECKS {
            assert!(seen.insert(check.id), "duplicate check id {}", check.id);
        }
    }

    #[test]
    fn truncate_keeps_short_bodies_whole() {
        assert_eq!(truncate("  short  "), "short");
        assert!(truncate(&"x".repeat(500)).ends_with('…'));
    }
}
