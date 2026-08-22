//! Turning what the inspector learned into mcpg configuration.
//!
//! Inspecting a server answers questions an operator then has to re-answer
//! by hand: which wire it speaks, whether it wants a bearer, where its
//! authorization server is, what audience a token needs. All of that is
//! already in the auth lab's report and the connect probe's verdict, so
//! emitting the federation block is a formatting job rather than a research
//! one — and getting it wrong by hand is easy in exactly the places the
//! inspector already checked.
//!
//! What comes out is a `federations:` entry to paste into `server.yml`. Once
//! it is there, the gateway is the thing that holds the credential and
//! speaks to the upstream; clients talk to mcpg and inherit its governance.

use serde::Serialize;

use super::authlab::AuthReport;
use super::target::{TargetKind, TargetSpec};

/// How the generated config authenticates to the upstream, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthPlan {
    /// Nothing asked for a credential.
    None,
    /// The upstream challenged, and its authorization server was found —
    /// mcpg can mint tokens for it through a credential issuer.
    OauthClientCredentials,
    /// The upstream challenged but named no authorization server we could
    /// read. Forwarding the caller's own `Authorization` is the honest
    /// fallback: it needs no credential mcpg does not have.
    PassThrough,
    /// The upstream speaks AAuth, which is an identity plugin rather than
    /// an upstream auth mode.
    Aauth,
}

impl AuthPlan {
    fn mode(&self) -> &'static str {
        match self {
            Self::None | Self::Aauth => "none",
            Self::OauthClientCredentials => "oauth_client_credentials",
            Self::PassThrough => "pass_through",
        }
    }
}

/// A generated federation block plus the notes an operator needs to finish
/// it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedConfig {
    /// The YAML to paste.
    pub yaml: String,
    pub auth_plan: AuthPlan,
    /// What still needs a human: a credential to register, a plugin to
    /// enable. Empty when the block is complete as it stands.
    pub todo: Vec<String>,
}

/// Derive a federation name from a URL host: `api.notion.com` → `notion`.
///
/// A name is a capability prefix, so it has to be a plausible identifier
/// rather than a hostname. Anything unusable falls back to `upstream`,
/// which is obviously a placeholder rather than something that looks right
/// and is not.
fn federation_name(url: &str) -> String {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    let candidate = host
        .split('.')
        .filter(|part| {
            !matches!(
                *part,
                "www" | "api" | "mcp" | "com" | "net" | "org" | "io" | "dev"
            )
        })
        .max_by_key(|part| part.len())
        .unwrap_or("");
    let cleaned: String = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c.is_ascii_digit()) {
        return "upstream".to_owned();
    }
    cleaned.to_lowercase()
}

/// Decide how mcpg should authenticate, from what the probe found.
fn plan(report: &AuthReport) -> AuthPlan {
    // AAuth first: it never speaks through `WWW-Authenticate`, so a server
    // using it can look unprotected to the OAuth chain.
    if report.aauth.is_some() {
        return AuthPlan::Aauth;
    }
    if report.token_endpoint.is_some() {
        return AuthPlan::OauthClientCredentials;
    }
    if report.challenge.is_some() || matches!(report.probe_status, 401 | 403) {
        return AuthPlan::PassThrough;
    }
    AuthPlan::None
}

/// Build the federation block for a target the inspector has probed.
pub fn generate(
    spec: &TargetSpec,
    report: &AuthReport,
    negotiated_version: &str,
) -> Result<GeneratedConfig, String> {
    let TargetKind::Http { url } = &spec.kind else {
        return Err(
            "a stdio target runs a local process; federate it by putting the same \
             command in `upstream.command`, not by generating one from a probe"
                .to_owned(),
        );
    };

    let plan = plan(report);
    let name = federation_name(url);
    let mut todo = Vec::new();

    let mut auth = serde_json::json!({ "mode": plan.mode() });
    if plan == AuthPlan::OauthClientCredentials {
        // The issuer reference is a placeholder: which credential plugin
        // mints this token is an operator decision, and inventing a plugin
        // id would produce config that looks finished and does not boot.
        auth["credential"] =
            serde_json::json!("cred://dev.mcpg.credential.oauth-client-credentials/CHANGEME");
        let mut credential_config = serde_json::Map::new();
        if let Some(resource) = &report.resource {
            credential_config.insert("audience".into(), resource.clone().into());
            credential_config.insert("resource".into(), resource.clone().into());
        }
        if let Some(endpoint) = &report.token_endpoint {
            credential_config.insert("redeem_token_url".into(), endpoint.clone().into());
        }
        if let Some(scope) = report.challenge.as_ref().and_then(|c| c.scope.clone()) {
            credential_config.insert("scope".into(), scope.into());
        }
        auth["credential_config"] = serde_json::Value::Object(credential_config);
        todo.push(
            "register an oauth-client-credentials issuer and replace CHANGEME with its target"
                .to_owned(),
        );
    }
    if plan == AuthPlan::Aauth {
        todo.push(
            "this server speaks AAuth: enable the `dev.mcpg.identity.aauth` plugin and give \
             mcpg an agent identity — upstream `auth` modes do not cover it"
                .to_owned(),
        );
    }
    if plan == AuthPlan::PassThrough {
        todo.push(
            "pass-through forwards the caller's own Authorization header; the caller must \
             already hold a token this upstream accepts"
                .to_owned(),
        );
    }

    let insecure = url.starts_with("http://");
    let private = spec.allow_private;
    let mut safety = serde_json::Map::new();
    if private {
        safety.insert("allow_private_backends".into(), true.into());
    }
    if insecure {
        safety.insert("allow_insecure_http".into(), true.into());
    }

    let mut upstream = serde_json::Map::new();
    upstream.insert("url".into(), url.clone().into());
    // The wire is the probe's verdict, not a guess: pinning it means the
    // gateway skips its own probe and cannot land on a different answer.
    upstream.insert(
        "protocol_version".into(),
        // The serde names are the dated revisions themselves, not the Rust
        // variant spellings — a config written with the latter parses
        // nowhere.
        match negotiated_version {
            "2026-07-28" => "2026-07-28",
            _ => "2025-11-25",
        }
        .into(),
    );
    upstream.insert("auth".into(), auth);
    if !spec.headers.is_empty() {
        upstream.insert(
            "headers".into(),
            serde_json::to_value(&spec.headers).unwrap_or_default(),
        );
        todo.push(
            "the headers below came from the inspector's target; move any secret to \
             ${env.NAME} before committing this"
                .to_owned(),
        );
    }
    if !safety.is_empty() {
        upstream.insert("upstream_safety".into(), serde_json::Value::Object(safety));
    }

    // Deliberately no `governance` override. Imported capabilities inherit
    // the gateway's default trust floor, which is the safe answer — but it
    // also means an operator who pastes this and then tests anonymously
    // sees an empty tool list and concludes the federation failed. Saying
    // so is the difference between config that works and config that looks
    // broken.
    todo.push(
        "imported capabilities inherit this gateway's default trust floor, so an          anonymous caller may see none of them; set `governance.minimum_trust` on the          federation only if that is what you mean"
            .to_owned(),
    );

    let federation = serde_json::json!({
        "name": name,
        "upstream": serde_json::Value::Object(upstream),
        "naming": { "tool_prefix": format!("{name}.") },
    });
    let document = serde_json::json!({ "mcp": { "federations": [federation] } });

    let yaml = serde_yaml::to_string(&document)
        .map_err(|e| format!("could not render the config: {e}"))?;

    Ok(GeneratedConfig {
        yaml,
        auth_plan: plan,
        todo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::authlab::AauthPosture;
    use mcpg_mcp_client::auth::BearerChallenge;

    fn spec(url: &str) -> TargetSpec {
        serde_json::from_value(serde_json::json!({ "url": url })).unwrap()
    }

    fn report() -> AuthReport {
        AuthReport {
            probe_status: 200,
            answered_without_credential: true,
            www_authenticate: None,
            challenge: None,
            discovery: Vec::new(),
            resource: None,
            token_endpoint: None,
            discovery_error: None,
            aauth: None,
            verdict: String::new(),
        }
    }

    #[test]
    fn an_open_server_needs_no_auth_block() {
        let out = generate(
            &spec("https://api.example.com/mcp"),
            &report(),
            "2026-07-28",
        )
        .unwrap();
        assert_eq!(out.auth_plan, AuthPlan::None);
        assert!(out.yaml.contains("mode: none"), "{}", out.yaml);
        assert!(out.yaml.contains("2026-07-28"), "{}", out.yaml);
        assert!(
            out.todo.iter().any(|t| t.contains("trust floor")),
            "even an open server carries the trust-floor note: {:?}",
            out.todo
        );
    }

    /// A discovered authorization server is the whole point: the audience,
    /// resource and token endpoint go straight into the credential config
    /// the issuer plugin consumes.
    #[test]
    fn a_discovered_authorization_server_becomes_credential_config() {
        let mut r = report();
        r.probe_status = 401;
        r.resource = Some("https://api.example.com/mcp".to_owned());
        r.token_endpoint = Some("https://as.example.com/token".to_owned());
        r.challenge = Some(BearerChallenge {
            scope: Some("mcp:read".to_owned()),
            ..Default::default()
        });
        let out = generate(&spec("https://api.example.com/mcp"), &r, "2025-11-25").unwrap();
        assert_eq!(out.auth_plan, AuthPlan::OauthClientCredentials);
        assert!(
            out.yaml.contains("mode: oauth_client_credentials"),
            "{}",
            out.yaml
        );
        assert!(
            out.yaml
                .contains("redeem_token_url: https://as.example.com/token"),
            "{}",
            out.yaml
        );
        assert!(
            out.yaml.contains("audience: https://api.example.com/mcp"),
            "{}",
            out.yaml
        );
        assert!(out.yaml.contains("scope: mcp:read"), "{}", out.yaml);
        assert!(out.yaml.contains("2025-11-25"), "{}", out.yaml);
        // The issuer is the operator's choice; a plausible-looking invented
        // id would produce config that reads as finished and does not boot.
        assert!(out.yaml.contains("CHANGEME"), "{}", out.yaml);
        assert_eq!(out.todo.len(), 2, "issuer + trust floor: {:?}", out.todo);
    }

    /// Challenged, but nothing readable behind it. Forwarding the caller's
    /// own credential is the only thing mcpg can honestly do.
    #[test]
    fn a_challenge_with_no_discoverable_server_becomes_pass_through() {
        let mut r = report();
        r.probe_status = 401;
        r.challenge = Some(BearerChallenge::default());
        let out = generate(&spec("https://api.example.com/mcp"), &r, "2026-07-28").unwrap();
        assert_eq!(out.auth_plan, AuthPlan::PassThrough);
        assert!(out.yaml.contains("mode: pass_through"), "{}", out.yaml);
        assert!(
            out.todo.iter().any(|t| t.contains("caller must")),
            "{:?}",
            out.todo
        );
    }

    /// AAuth is an identity plugin, not an upstream auth mode — emitting
    /// `mode: aauth` would be config that never validates.
    #[test]
    fn an_aauth_server_says_it_needs_the_plugin() {
        let mut r = report();
        r.aauth = Some(AauthPosture {
            resource_metadata: true,
            ..Default::default()
        });
        let out = generate(&spec("https://api.example.com/mcp"), &r, "2026-07-28").unwrap();
        assert_eq!(out.auth_plan, AuthPlan::Aauth);
        assert!(out.yaml.contains("mode: none"), "{}", out.yaml);
        assert!(
            out.todo
                .iter()
                .any(|t| t.contains("dev.mcpg.identity.aauth")),
            "{:?}",
            out.todo
        );
    }

    /// A loopback http target needs both safety opt-ins, or the generated
    /// config is refused by the very gateway it was written for.
    #[test]
    fn a_loopback_http_target_carries_its_safety_opt_ins() {
        let out = generate(&spec("http://127.0.0.1:8787/mcp"), &report(), "2026-07-28").unwrap();
        assert!(
            out.yaml.contains("allow_private_backends: true"),
            "{}",
            out.yaml
        );
        assert!(
            out.yaml.contains("allow_insecure_http: true"),
            "{}",
            out.yaml
        );
    }

    #[test]
    fn names_come_from_the_host_and_are_usable_as_a_prefix() {
        assert_eq!(federation_name("https://api.notion.com/mcp"), "notion");
        assert_eq!(federation_name("https://mcp.stripe.com/"), "stripe");
        assert_eq!(federation_name("https://example.io/mcp"), "example");
        // Nothing usable is better as an obvious placeholder than as
        // something that looks right and is not.
        assert_eq!(federation_name("http://127.0.0.1:8787/mcp"), "upstream");
        assert_eq!(federation_name("not a url"), "upstream");
    }

    #[test]
    fn a_stdio_target_is_refused_with_the_reason() {
        let spec: TargetSpec =
            serde_json::from_value(serde_json::json!({"command": "sh", "args": []})).unwrap();
        let err = generate(&spec, &report(), "2025-11-25").unwrap_err();
        assert!(err.contains("upstream.command"), "{err}");
    }

    /// Headers travel, but the operator is told to move secrets out before
    /// this lands in a repository.
    #[test]
    fn headers_are_carried_with_a_warning() {
        let mut s = spec("https://api.example.com/mcp");
        s.headers.insert("x-api-key".into(), "secret".into());
        let out = generate(&s, &report(), "2026-07-28").unwrap();
        assert!(out.yaml.contains("x-api-key"), "{}", out.yaml);
        assert!(
            out.todo.iter().any(|t| t.contains("${env.NAME}")),
            "{:?}",
            out.todo
        );
    }
}
