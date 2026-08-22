//! What the gateway on the other end says about itself.
//!
//! An mcpg gateway serves `/runtime` beside its MCP endpoint: uptime,
//! readiness checks, which plugins loaded and what state they are in. When a
//! tool is missing or a call is refused, that is usually where the answer is —
//! the MCP surface only shows the consequence.
//!
//! Two properties make this safe to read from anywhere the inspector runs. The
//! gateway serves `/runtime` WITHOUT authentication and deliberately redacts
//! what it puts there (sink kinds, not sink configs), so the inspector is
//! reading something already public to anyone who can reach that address. And
//! the fetch goes through the same egress guard as every other probe, so
//! "point the inspector at a gateway" never becomes "read an address the
//! inspector can reach and you cannot".

use serde::{Deserialize, Serialize};

use crate::engine::session::Session;

/// The gateway's own account of itself, reduced to what a developer staring at
/// a missing tool needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayReport {
    /// Where `/runtime` was read from.
    pub url: String,
    pub service: String,
    pub version: String,
    pub uptime_secs: i64,
    /// `ready`, `degraded`, … — whatever the gateway calls it.
    pub readiness: String,
    /// Only the checks that are not passing. A list of everything that works
    /// is noise on a screen someone opened because something does not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing_checks: Vec<FailingCheck>,
    pub log_level: String,
    pub plugin_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<PluginRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailingCheck {
    pub name: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginRow {
    pub id: String,
    pub version: String,
    pub class: String,
    /// `active`, `degraded`, `disabled`. The reason a binding can resolve in
    /// config and still not answer.
    pub state: String,
}

impl GatewayReport {
    /// True when something here is worth acting on.
    pub fn needs_attention(&self) -> bool {
        !self.failing_checks.is_empty() || self.plugins.iter().any(|p| p.state != "active")
    }
}

/// `<scheme>://<host>[:<port>]/runtime` for an MCP endpoint URL.
///
/// `/runtime` sits at the root of the gateway's listener, not beside the MCP
/// path, which is itself configurable — so this rebuilds from the origin
/// rather than editing the path it was given.
pub fn runtime_url(endpoint: &str) -> Result<String, String> {
    let url = url::Url::parse(endpoint).map_err(|e| format!("invalid url {endpoint:?}: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("url {endpoint:?} has no host"))?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(format!("{}://{}/runtime", url.scheme(), authority))
}

/// Read `/runtime` from the gateway serving this endpoint.
pub async fn inspect(endpoint: &str, allow_private: bool) -> Result<GatewayReport, String> {
    let url = runtime_url(endpoint)?;
    let client = mcpg_mcp_client::auth::guarded_client(
        &url,
        mcpg_mcp_client::auth::DiscoveryPolicy {
            allow_private,
            allow_insecure_http: url.starts_with("http://"),
        },
        std::time::Duration::from_secs(10),
    )
    .await?;

    let resp = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!(
            "{url} answered {status} — this target does not look like an mcpg gateway, \
             or its runtime endpoint is not exposed on this listener"
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("{url} did not return JSON: {e}"))?;
    parse(&url, &body)
}

/// Read one runtime snapshot. Split out so the shape is tested against a
/// literal document rather than a live gateway.
pub fn parse(url: &str, body: &serde_json::Value) -> Result<GatewayReport, String> {
    let service = body.get("service").and_then(|v| v.as_str());
    // The document is unauthenticated, so anything could be serving it. A
    // response that carries none of the fields is far more likely to be some
    // other app's `/runtime` than a gateway having a bad day.
    if service.is_none() && body.get("readiness").is_none() && body.get("plugins").is_none() {
        return Err(format!(
            "{url} returned JSON that is not an mcpg runtime snapshot"
        ));
    }

    let failing_checks = body
        .get("readiness")
        .and_then(|r| r.get("checks"))
        .and_then(|c| c.as_array())
        .map(|checks| {
            checks
                .iter()
                .filter(|check| {
                    !matches!(
                        check.get("status").and_then(|v| v.as_str()),
                        Some("pass") | Some("ready") | Some("ok") | Some("healthy")
                    )
                })
                .map(|check| FailingCheck {
                    name: string_at(check, "name").unwrap_or_else(|| "(unnamed)".to_owned()),
                    status: string_at(check, "status").unwrap_or_else(|| "unknown".to_owned()),
                    detail: string_at(check, "detail").or_else(|| string_at(check, "message")),
                })
                .collect()
        })
        .unwrap_or_default();

    let plugins: Vec<PluginRow> = body
        .get("plugins")
        .and_then(|p| p.get("loaded"))
        .and_then(|l| l.as_array())
        .map(|loaded| {
            loaded
                .iter()
                .map(|plugin| PluginRow {
                    id: string_at(plugin, "id").unwrap_or_else(|| "(unnamed)".to_owned()),
                    version: string_at(plugin, "version").unwrap_or_default(),
                    class: string_at(plugin, "plugin_class").unwrap_or_default(),
                    state: string_at(plugin, "state").unwrap_or_else(|| "unknown".to_owned()),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(GatewayReport {
        url: url.to_owned(),
        service: service.unwrap_or("(unknown)").to_owned(),
        version: string_at(body, "version").unwrap_or_default(),
        uptime_secs: body
            .get("uptime_secs")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        readiness: body
            .get("readiness")
            .and_then(|r| string_at(r, "status"))
            .unwrap_or_else(|| "unknown".to_owned()),
        failing_checks,
        log_level: body
            .get("logging")
            .and_then(|l| string_at(l, "level"))
            .unwrap_or_default(),
        plugin_count: body
            .get("plugins")
            .and_then(|p| p.get("total_count"))
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(plugins.len()),
        plugins,
    })
}

/// A string field, however the producer chose to spell the value — statuses
/// arrive as both `"ready"` and `{"Ready": …}`-style tags across versions.
fn string_at(value: &serde_json::Value, key: &str) -> Option<String> {
    match value.get(key)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => map.keys().next().map(|k| k.to_lowercase()),
        other if other.is_null() => None,
        other => Some(other.to_string()),
    }
}

/// Read the gateway behind a connected session.
pub async fn for_session(session: &Session, allow_private: bool) -> Result<GatewayReport, String> {
    let endpoint = session.endpoint_url().ok_or_else(|| {
        "the runtime snapshot is served over HTTP; a stdio target has no listener".to_owned()
    })?;
    inspect(endpoint, allow_private).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot() -> serde_json::Value {
        json!({
            "service": "mcpg",
            "version": "1.0.0-rc.1",
            "uptime_secs": 92,
            "bind_address": "127.0.0.1:8787",
            "logging": { "level": "info", "sinks": ["stderr"], "initialized": true },
            "readiness": {
                "status": "degraded",
                "checks": [
                    { "name": "config", "status": "pass" },
                    { "name": "backend:orders", "status": "fail", "detail": "connection refused" }
                ]
            },
            "plugins": {
                "total_count": 3,
                "loaded": [
                    { "id": "dev.mcpg.identity.oidc", "version": "1.0.0",
                      "plugin_class": "identity", "state": "active" },
                    { "id": "dev.mcpg.backend.sql", "version": "1.0.0",
                      "plugin_class": "backend", "state": "degraded" }
                ]
            }
        })
    }

    #[test]
    fn runtime_lives_at_the_origin_not_beside_the_mcp_path() {
        assert_eq!(
            runtime_url("http://127.0.0.1:8787/mcp").unwrap(),
            "http://127.0.0.1:8787/runtime"
        );
        // A gateway may serve MCP from a nested path; `/runtime` does not move.
        assert_eq!(
            runtime_url("https://gw.example/tenant-a/mcp").unwrap(),
            "https://gw.example/runtime"
        );
        assert!(runtime_url("not a url").is_err());
    }

    #[test]
    fn only_the_checks_that_are_not_passing_survive() {
        let report = parse("http://gw/runtime", &snapshot()).unwrap();
        assert_eq!(report.readiness, "degraded");
        assert_eq!(report.failing_checks.len(), 1, "a passing check is noise");
        assert_eq!(report.failing_checks[0].name, "backend:orders");
        assert_eq!(
            report.failing_checks[0].detail.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn a_plugin_that_loaded_but_is_not_active_is_the_finding() {
        let report = parse("http://gw/runtime", &snapshot()).unwrap();
        assert_eq!(
            report.plugin_count, 3,
            "the count is the gateway's, not ours"
        );
        assert_eq!(report.plugins.len(), 2, "and only two are listed");
        let sql = report
            .plugins
            .iter()
            .find(|p| p.id.ends_with("sql"))
            .unwrap();
        assert_eq!(sql.state, "degraded");
        assert!(report.needs_attention());
    }

    #[test]
    fn a_healthy_gateway_asks_for_nothing() {
        let body = json!({
            "service": "mcpg",
            "version": "1.0.0",
            "uptime_secs": 5,
            "logging": { "level": "info" },
            "readiness": { "status": "ready", "checks": [{ "name": "config", "status": "pass" }] },
            "plugins": { "total_count": 1, "loaded": [
                { "id": "dev.mcpg.backend.http", "version": "1.0.0",
                  "plugin_class": "backend", "state": "active" }] }
        });
        let report = parse("http://gw/runtime", &body).unwrap();
        assert!(report.failing_checks.is_empty());
        assert!(!report.needs_attention());
    }

    /// `/runtime` is unauthenticated, which is what makes it safe to read and
    /// also what would make it a convenient thing to read from inside a pod.
    /// The fetch carries the same egress guard as every other probe.
    #[tokio::test]
    async fn it_will_not_read_a_private_address_when_the_target_forbids_it() {
        let refused = inspect("http://127.0.0.1:9/mcp", false)
            .await
            .expect_err("a loopback runtime read must be refused when allow_private is false");
        assert!(
            refused.contains("private") || refused.contains("loopback"),
            "the refusal should name the reason: {refused}"
        );
    }

    #[test]
    fn something_else_serving_runtime_is_not_reported_as_a_gateway() {
        let body = json!({ "hello": "world" });
        let refused = parse("http://gw/runtime", &body).unwrap_err();
        assert!(
            refused.contains("not an mcpg runtime snapshot"),
            "{refused}"
        );
    }

    #[test]
    fn a_status_that_arrives_tagged_still_reads() {
        // Serialized Rust enums show up as `{"Degraded": null}` in some
        // shapes; the panel should say "degraded", not print a JSON object.
        let body = json!({
            "service": "mcpg",
            "readiness": { "status": { "Degraded": null }, "checks": [] },
            "plugins": { "total_count": 0, "loaded": [] }
        });
        let report = parse("http://gw/runtime", &body).unwrap();
        assert_eq!(report.readiness, "degraded");
    }
}
