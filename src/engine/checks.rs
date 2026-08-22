//! Protocol checks a server should pass, run over raw HTTP.
//!
//! These are deliberately not client calls: each one asserts a
//! transport-level rule the client would otherwise paper over, so they
//! build their own requests and read the raw response. Every check is
//! tagged with the wire it applies to — asserting a sessionful rule
//! against a stateless server is a false failure, so those are skipped
//! and reported as skipped rather than silently dropped.
//!
//! Scope is honest: this is the portable subset, not the full upstream
//! conformance suite. `mcpg-inspector check` says which checks ran.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Which wire a check applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    /// Applies to both revisions.
    Any,
    Sessionful,
    Stateless,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
    /// Not applicable to the negotiated wire.
    Skip,
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
    pub skipped: usize,
    pub checks: Vec<CheckResult>,
}

/// Run the portable check suite against an MCP endpoint.
/// `allow_private` comes from the target's own spec. The checks run after a
/// successful connect, but that connect pinned its address inside its own
/// client — a fresh one here would resolve the name again, which is the window
/// a rebinding record is aiming for.
pub async fn run(url: &str, negotiated: &str, allow_private: bool) -> Result<CheckReport, String> {
    let client = mcpg_mcp_client::auth::guarded_client(
        url,
        mcpg_mcp_client::auth::DiscoveryPolicy {
            allow_private,
            allow_insecure_http: url.starts_with("http://"),
        },
        std::time::Duration::from_secs(15),
    )
    .await?;
    let stateless = negotiated == "2026-07-28";
    let mut checks = Vec::new();

    for check in CHECKS {
        let applies = match check.wire {
            Wire::Any => true,
            Wire::Sessionful => !stateless,
            Wire::Stateless => stateless,
        };
        if !applies {
            checks.push(CheckResult {
                id: check.id.to_owned(),
                description: check.description.to_owned(),
                outcome: Outcome::Skip,
                detail: Some(format!("not applicable to the {negotiated} wire")),
            });
            continue;
        }
        let (outcome, detail) = (check.run)(&client, url, negotiated).await;
        checks.push(CheckResult {
            id: check.id.to_owned(),
            description: check.description.to_owned(),
            outcome,
            detail,
        });
    }

    Ok(CheckReport {
        protocol_version: negotiated.to_owned(),
        passed: checks.iter().filter(|c| c.outcome == Outcome::Pass).count(),
        failed: checks.iter().filter(|c| c.outcome == Outcome::Fail).count(),
        skipped: checks.iter().filter(|c| c.outcome == Outcome::Skip).count(),
        checks,
    })
}

type CheckFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = (Outcome, Option<String>)> + Send>>;

struct Check {
    id: &'static str,
    description: &'static str,
    wire: Wire,
    run: fn(&reqwest::Client, &str, &str) -> CheckFuture,
}

const CHECKS: &[Check] = &[
    Check {
        id: "batch-rejected",
        description: "a JSON-RPC batch is rejected (batching was removed in 2025-06-18)",
        wire: Wire::Any,
        run: |client, url, version| {
            // A REAL batch. `[]` is a degenerate case a server may
            // legitimately treat as an empty request set; the rule
            // being checked is about a batch carrying requests.
            let request = post(client, url, version).body(
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
        wire: Wire::Any,
        run: |client, url, version| {
            let request = post(client, url, version)
                .header("mcp-method", "definitely/not-a-method")
                .body(
                    json!({"jsonrpc":"2.0","id":1,"method":"definitely/not-a-method","params":{}})
                        .to_string(),
                );
            Box::pin(async move {
                match request.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        let code = jsonrpc_error_code(&body);
                        // A stateless server may answer 404 + -32601;
                        // a sessionful one 200 + -32601. Either is the
                        // rule being followed, so both pass.
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
        wire: Wire::Stateless,
        run: |client, url, _version| {
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
        id: "notification-has-no-body",
        description: "a notification is accepted without a JSON-RPC response body",
        wire: Wire::Sessionful,
        run: |client, url, version| {
            let client = client.clone();
            let url = url.to_owned();
            let version = version.to_owned();
            Box::pin(async move {
                // The sessionful wire binds every post-handshake
                // request to a session, so the handshake has to run
                // first — otherwise the server answers "missing
                // mcp-session-id" and the notification rule is never
                // exercised.
                let session_id = match initialize(&client, &url, &version).await {
                    Ok(id) => id,
                    Err(e) => return (Outcome::Fail, Some(format!("initialize failed: {e}"))),
                };
                let mut request = post(&client, &url, &version).body(
                    json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
                );
                if let Some(id) = &session_id {
                    request = request.header("mcp-session-id", id.clone());
                }
                match request.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        // 202 with no body is the spec's shape; a 200
                        // with an empty body is the same contract met
                        // differently, so both pass. A JSON-RPC result
                        // for a notification does not.
                        if body.trim().is_empty() || status == 202 {
                            (Outcome::Pass, None)
                        } else {
                            (
                                Outcome::Fail,
                                Some(format!(
                                    "notification answered with HTTP {status} and a body: {}",
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
        id: "malformed-json",
        description: "a malformed body answers with JSON-RPC -32700 or a 4xx",
        wire: Wire::Any,
        run: |client, url, version| {
            let request = post(client, url, version).body("{not json");
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

/// Run the sessionful handshake and return the server's session id, if
/// it minted one. Used by checks whose rule only applies to an
/// established session.
async fn initialize(
    client: &reqwest::Client,
    url: &str,
    version: &str,
) -> Result<Option<String>, String> {
    let resp = post(client, url, version)
        .body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": version,
                    "capabilities": {},
                    "clientInfo": { "name": "mcpg-inspector-checks", "version": "0.0.0" },
                },
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    Ok(resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned))
}

fn post(client: &reqwest::Client, url: &str, version: &str) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", version.to_owned())
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
        let refused = run("http://127.0.0.1:9/mcp", "2025-11-25", false)
            .await
            .expect_err("a loopback probe must be refused when allow_private is false");
        assert!(
            refused.contains("private") || refused.contains("loopback"),
            "the refusal should name the reason: {refused}"
        );
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
