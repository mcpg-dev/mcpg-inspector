//! The auth lab: what a server wants, and why the chain stopped where
//! it did.
//!
//! Pointing an inspector at a real MCP server and getting a 401 is the
//! common first experience. This turns that into an answer: probe the
//! endpoint, read the `WWW-Authenticate` challenge, walk the RFC 9728 →
//! RFC 8414 discovery chain, and report every step — including the one
//! that failed. The discovery walk is the gateway's own
//! (`mcpg-mcp-client`), so what the lab reports is what the gateway
//! would do.

use mcpg_mcp_client::auth::{
    BearerChallenge, DiscoveredOauth, DiscoveryPolicy, DiscoveryStep, IdJagSupport,
    discover_oauth_traced,
};
use serde::Serialize;

use super::target::{TargetKind, TargetSpec};

/// What the lab found out about a target's authorization.
#[derive(Debug, Default, Serialize)]
pub struct AuthReport {
    /// HTTP status the bare probe got back.
    pub probe_status: u16,
    /// The endpoint answered the credential-free probe with a 2xx. A
    /// 401/403 is a challenge and anything else is an error — neither
    /// is "open", so neither sets this.
    pub answered_without_credential: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub www_authenticate: Option<String>,
    /// The `WWW-Authenticate: DPoP` challenge, verbatim, when the resource
    /// sends one beside the Bearer challenge (RFC 9449 §7.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<BearerChallenge>,
    pub discovery: Vec<DiscoveryStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    /// The AS issuer: the hop-1 `audience` an ID-JAG must carry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types_supported: Vec<String>,
    /// Lists `urn:ietf:params:oauth:grant-profile:id-jag` when the AS
    /// redeems ID-JAGs (enterprise-managed authorization).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_grant_profiles_supported: Vec<String>,
    /// How far the AS commits to redeeming ID-JAGs: `advertised` (the
    /// id-jag grant profile), `jwt-bearer-only` (the grant without the
    /// profile) or `unsupported`. Absent when no AS metadata was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_managed_authorization: Option<&'static str>,
    /// Where a browser sign-in starts. Absent on an AS that issues tokens
    /// machine to machine only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub client_id_metadata_document_supported: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// RFC 9449: the proof algorithms the AS accepts; empty when it binds
    /// no token to a key.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// RFC 9396: the `authorization_details` types the AS takes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_details_types_supported: Vec<String>,
    /// RFC 9207: the AS names itself in every authorization response.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub authorization_response_iss_parameter_supported: bool,
    /// What the protected resource metadata says about the tokens the
    /// resource takes, when it says anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_token_requirements: Option<ResourceTokenRequirements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_error: Option<String>,
    /// AAuth posture, when the target shows any sign of speaking it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aauth: Option<AauthPosture>,
    /// What an operator should do next, in one line.
    pub verdict: String,
}

/// RFC 9728 §2 members about the tokens a resource takes.
#[derive(Debug, Default, Serialize)]
pub struct ResourceTokenRequirements {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// Only DPoP-bound tokens are accepted; a bearer token is refused.
    pub dpop_bound_access_tokens_required: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_details_types_supported: Vec<String>,
}

impl ResourceTokenRequirements {
    fn of(found: &DiscoveredOauth) -> Option<Self> {
        let requirements = Self {
            dpop_signing_alg_values_supported: found
                .resource_dpop_signing_alg_values_supported
                .clone(),
            dpop_bound_access_tokens_required: found.resource_dpop_bound_access_tokens_required,
            authorization_details_types_supported: found
                .resource_authorization_details_types_supported
                .clone(),
        };
        (requirements.dpop_bound_access_tokens_required
            || !requirements.dpop_signing_alg_values_supported.is_empty()
            || !requirements
                .authorization_details_types_supported
                .is_empty())
        .then_some(requirements)
    }
}

/// What a target says about AAuth.
///
/// AAuth deliberately does not use `WWW-Authenticate` — the draft is explicit
/// that it never conveys its requirements there — so a server can be fully
/// AAuth-protected while the OAuth chain above finds nothing at all. Reporting
/// only the OAuth side would tell an operator "no metadata advertised" about a
/// server that is in fact saying precisely what it wants.
#[derive(Debug, Default, Serialize)]
pub struct AauthPosture {
    /// `AAuth-Requirement`, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<String>,
    /// `Signature-Error`, verbatim: why the signature was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_error: Option<String>,
    /// `Accept-Signature` (deployed) or the `-08` split
    /// `Accept-Signature-Scheme` / `Accept-Signature-Alg`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<String>,
    /// `/.well-known/aauth-resource.json` was served.
    pub resource_metadata: bool,
    /// `access_mode` from that document; absent means the default,
    /// `agent-token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<String>,
    /// `signature_window` in seconds; the profile default is 60.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_window: Option<u64>,
    /// Components the resource requires beyond the mandated four.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_signature_components: Vec<String>,
    /// Problems found in the metadata document itself.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
}

impl AauthPosture {
    /// Whether anything at all pointed at AAuth.
    fn observed(&self) -> bool {
        self.requirement.is_some()
            || self.signature_error.is_some()
            || !self.accept.is_empty()
            || self.resource_metadata
    }
}

/// Probe a target's authorization posture.
pub async fn inspect(spec: &TargetSpec) -> Result<AuthReport, String> {
    let TargetKind::Http { url } = &spec.kind else {
        return Err(
            "auth applies to http targets; a stdio server has no HTTP challenge".to_owned(),
        );
    };

    // A deliberately credential-free POST: the point is to see what an
    // unauthenticated caller is told. It runs WITHOUT a connected session, so
    // it never inherits the connect path's egress guard and has to carry its
    // own — otherwise "what does this target require for auth" is a working
    // read of anything the process can reach.
    let client = mcpg_mcp_client::auth::guarded_client(
        url,
        DiscoveryPolicy {
            allow_private: spec.allow_private,
            allow_insecure_http: url.starts_with("http://"),
        },
        std::time::Duration::from_secs(10),
    )
    .await?;
    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
        .send()
        .await
        .map_err(|e| format!("probe request to {url} failed: {e}"))?;

    let probe_status = resp.status().as_u16();
    // A resource may challenge once per scheme (RFC 9449 §7.1): the Bearer
    // challenge is the one discovery reads; a DPoP one is reported as sent.
    let challenges: Vec<String> = resp
        .headers()
        .get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let is_dpop = |value: &&String| {
        value
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("dpop "))
    };
    let dpop_challenge = challenges.iter().find(is_dpop).cloned();
    let www_authenticate = challenges
        .iter()
        .find(|value| !is_dpop(value))
        .or(challenges.first())
        .cloned();
    let challenge = www_authenticate.as_deref().and_then(BearerChallenge::parse);
    let resp_headers = resp.headers().clone();

    // Loopback targets are the normal case for an inspector, so the
    // walk permits private addresses and plain http when the target
    // itself is plain http — refusing to discover the server the user
    // just asked about would be theatre.
    let policy = DiscoveryPolicy {
        allow_private: spec.allow_private,
        allow_insecure_http: url.starts_with("http://"),
    };
    // A challenge naming its metadata document wins over the derived
    // well-known URL (RFC 9728 §5.1); otherwise derive from the target.
    let discovery_base = challenge
        .as_ref()
        .and_then(|c| c.resource_metadata.clone())
        .map(|metadata| strip_well_known(&metadata))
        .unwrap_or_else(|| url.clone());
    let (discovery, outcome) = discover_oauth_traced(&discovery_base, policy).await;

    let (found, discovery_error) = match outcome {
        Ok(found) => (Some(found), None),
        Err(e) => (None, Some(e)),
    };

    let aauth = aauth_posture(&client, url, resp_headers).await;

    let mut verdict = verdict(
        probe_status,
        challenge.as_ref(),
        found.as_ref().map(|f| f.token_endpoint.as_str()),
        &discovery,
        aauth.as_ref(),
    );
    if let Some(found) = &found {
        verdict.push_str(&oauth_hints(found));
    }

    let mut report = AuthReport {
        probe_status,
        answered_without_credential: (200..300).contains(&probe_status),
        www_authenticate,
        dpop_challenge,
        challenge,
        discovery,
        discovery_error,
        aauth,
        verdict,
        ..Default::default()
    };
    if let Some(found) = found {
        report.enterprise_managed_authorization = Some(match found.id_jag_support() {
            IdJagSupport::Advertised => "advertised",
            IdJagSupport::JwtBearerOnly => "jwt-bearer-only",
            IdJagSupport::Unsupported => "unsupported",
        });
        report.resource_token_requirements = ResourceTokenRequirements::of(&found);
        report.resource = Some(found.resource);
        report.token_endpoint = Some(found.token_endpoint);
        report.issuer = Some(found.issuer);
        report.grant_types_supported = found.grant_types_supported;
        report.authorization_grant_profiles_supported =
            found.authorization_grant_profiles_supported;
        report.authorization_endpoint = found.authorization_endpoint;
        report.registration_endpoint = found.registration_endpoint;
        report.client_id_metadata_document_supported = found.client_id_metadata_document_supported;
        report.token_endpoint_auth_methods_supported = found.token_endpoint_auth_methods_supported;
        report.dpop_signing_alg_values_supported = found.dpop_signing_alg_values_supported;
        report.authorization_details_types_supported = found.authorization_details_types_supported;
        report.authorization_response_iss_parameter_supported =
            found.authorization_response_iss_parameter_supported;
    }
    Ok(report)
}

/// What else the verdict says about a discovered authorization server:
/// which logins it takes, and whether its tokens must be DPoP-bound.
fn oauth_hints(found: &DiscoveredOauth) -> String {
    let mut logins = Vec::new();
    if found.authorization_endpoint.is_some() {
        logins.push("a browser sign-in (`login`)");
    }
    match found.id_jag_support() {
        IdJagSupport::Advertised => {
            logins.push("an ID-JAG from your IdP (`login --idp-token-url`, enterprise-managed)")
        }
        IdJagSupport::JwtBearerOnly => logins.push(
            "an ID-JAG from your IdP (`login --idp-token-url`; the jwt-bearer grant is listed, \
             the id-jag profile is not)",
        ),
        IdJagSupport::Unsupported => {}
    }
    let mut hints = String::new();
    if !logins.is_empty() {
        hints.push_str(&format!("; it takes {}", logins.join(" or ")));
    }
    if found.resource_dpop_bound_access_tokens_required {
        hints.push_str("; its tokens must be DPoP-bound (`--dpop-key`)");
    } else if !found.dpop_signing_alg_values_supported.is_empty() {
        hints.push_str("; it binds tokens to a DPoP key on request (`--dpop-key`)");
    }
    hints
}

/// Read the target's AAuth posture: the challenge headers it just sent, plus
/// its resource metadata.
///
/// The metadata fetch is same-origin with the probe that already ran, so it
/// reaches nothing the caller has not already asked the inspector to dial.
async fn aauth_posture(
    client: &reqwest::Client,
    url: &str,
    headers: reqwest::header::HeaderMap,
) -> Option<AauthPosture> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let mut posture = AauthPosture {
        requirement: header("aauth-requirement"),
        signature_error: header("signature-error"),
        accept: [
            "accept-signature",
            "accept-signature-scheme",
            "accept-signature-alg",
        ]
        .iter()
        .filter_map(|name| header(name).map(|v| format!("{name}: {v}")))
        .collect(),
        ..Default::default()
    };

    let origin = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.join("/.well-known/aauth-resource.json").ok())?;
    let metadata_url = origin.to_string();
    if let Ok(resp) = client.get(origin).send().await
        && resp.status().is_success()
        && let Ok(doc) = resp.json::<serde_json::Value>().await
    {
        posture.resource_metadata = true;
        posture.access_mode = doc
            .get("access_mode")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        posture.signature_window = doc.get("signature_window").and_then(|v| v.as_u64());
        posture.additional_signature_components = doc
            .get("additional_signature_components")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        // The draft makes this check mandatory before trusting anything in
        // the document: `issuer` must equal the URL it was fetched from,
        // minus the well-known suffix, compared byte for byte.
        let expected = metadata_url.trim_end_matches("/.well-known/aauth-resource.json");
        match doc.get("issuer").and_then(|v| v.as_str()) {
            None => posture
                .findings
                .push("resource metadata has no `issuer` member (required)".to_owned()),
            Some(issuer) if issuer != expected => posture.findings.push(format!(
                "resource metadata `issuer` is {issuer:?} but the document was served \
                 from {expected:?}; a verifier must reject this"
            )),
            Some(_) => {}
        }
    }

    posture.observed().then_some(posture)
}

/// A `resource_metadata` URL points at the document; discovery derives
/// that URL itself from the resource identifier, so strip the
/// well-known segment back off to recover the identifier.
fn strip_well_known(metadata_url: &str) -> String {
    match metadata_url.split_once("/.well-known/oauth-protected-resource") {
        Some((origin, path)) => format!("{origin}{path}"),
        None => metadata_url.to_owned(),
    }
}

/// One line telling the operator what to do next.
///
/// Every branch is stated from what was actually observed. In
/// particular a half-walked chain — the resource document read, its
/// authorization server unreachable — must not read as "no OAuth
/// here": the server plainly advertises OAuth, and the operator's
/// problem is the AS, which is a different fix entirely.
fn verdict(
    status: u16,
    challenge: Option<&BearerChallenge>,
    token_endpoint: Option<&str>,
    discovery: &[DiscoveryStep],
    aauth: Option<&AauthPosture>,
) -> String {
    let scope_hint = challenge
        .and_then(|c| c.scope.as_deref())
        .map(|scope| format!(" with scope {scope:?}"))
        .unwrap_or_default();
    let advertises_oauth = discovery
        .iter()
        .any(|s| s.step == "protected-resource-metadata" && s.ok);
    let stalled = discovery
        .iter()
        .find(|s| !s.ok)
        .and_then(|s| s.detail.clone())
        .unwrap_or_else(|| "no reason given".to_owned());

    let posture = match status {
        401 | 403 if challenge.is_some() => "server challenged for a bearer token".to_owned(),
        401 | 403 => "server refused the request but sent no WWW-Authenticate challenge, \
                      so it does not say which credential it wants"
            .to_owned(),
        s if (200..300).contains(&s) => "server answered without a credential".to_owned(),
        s => format!("server rejected the credential-free probe with HTTP {s}"),
    };

    // AAuth is reported before the OAuth outcome when it is the only thing
    // the server offers, because then the OAuth chain's silence is not the
    // answer — the server did say what it wants, in the other channel.
    let aauth_note = aauth.map(aauth_advice);

    match (token_endpoint, advertises_oauth, aauth_note) {
        (Some(endpoint), _, Some(note)) => {
            format!(
                "{posture}; mint a token at {endpoint}{scope_hint} — and it also speaks AAuth: {note}"
            )
        }
        (Some(endpoint), _, None) => format!("{posture}; mint a token at {endpoint}{scope_hint}"),
        (None, _, Some(note)) => format!("{posture}; it wants AAuth: {note}"),
        (None, true, None) => format!(
            "{posture}; it advertises OAuth, but its authorization server could not be read: {stalled}"
        ),
        (None, false, None) => format!("{posture}; no OAuth metadata advertised ({stalled})"),
    }
}

/// The AAuth half of the verdict: what to do about what the server asked for.
fn aauth_advice(aauth: &AauthPosture) -> String {
    // The requirement is an RFC 8941 Dictionary; the member name is the
    // machine-readable part and the parameters carry the payload.
    let requirement = aauth
        .requirement
        .as_deref()
        .map(|raw| raw.split(';').next().unwrap_or(raw).trim())
        .map(|r| r.trim_start_matches("requirement=").to_owned());

    let mut advice = match requirement.as_deref() {
        Some("agent-token") => "present an agent token — run `aauth-keygen`, publish the two \
             well-known documents, then pass --aauth-key"
            .to_owned(),
        Some("auth-token") => "it needs an auth token from your person server; the inspector \
             signs with an agent token only, so complete that exchange out of band"
            .to_owned(),
        Some("interaction") | Some("approval") | Some("clarification") => {
            "it is deferring to a human approval step, which the inspector does \
             not drive"
                .to_owned()
        }
        Some(other) => format!("it asked for `{other}`, which the inspector does not implement"),
        None if aauth.signature_error.is_some() => {
            "a signature was rejected — see signature_error".to_owned()
        }
        None => "it advertises AAuth resource metadata; sign with --aauth-key".to_owned(),
    };
    if let Some(error) = &aauth.signature_error {
        advice.push_str(&format!(" ({error})"));
    }
    if !aauth.additional_signature_components.is_empty() {
        advice.push_str(&format!(
            "; it also requires these covered components: {}",
            aauth.additional_signature_components.join(", ")
        ));
    }
    advice
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report carries what an ID-JAG client needs from the AS: the
    /// issuer (the hop-1 audience) and the grant profile it advertises.
    #[tokio::test]
    async fn the_report_carries_the_id_jag_metadata() {
        use axum::routing::{get, post};
        use mcpg_mcp_client::auth::{GRANT_PROFILE_ID_JAG, GRANT_TYPE_JWT_BEARER};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let prm = serde_json::json!({
            "resource": format!("{base}/mcp"),
            "authorization_servers": [base],
            "dpop_signing_alg_values_supported": ["ES256"],
            "dpop_bound_access_tokens_required": true,
            "authorization_details_types_supported": ["crm_record"],
        });
        let asm = serde_json::json!({
            "issuer": base,
            "token_endpoint": format!("{base}/oauth/token"),
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "grant_types_supported": [GRANT_TYPE_JWT_BEARER, "authorization_code"],
            "authorization_grant_profiles_supported": [GRANT_PROFILE_ID_JAG],
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"],
            "dpop_signing_alg_values_supported": ["ES256", "EdDSA"],
            "authorization_details_types_supported": ["crm_record"],
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": true,
        });
        let app = axum::Router::new()
            .route(
                "/mcp",
                post(|| async {
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        axum::response::AppendHeaders([
                            ("www-authenticate", "Bearer scope=\"mcp:tools\""),
                            ("www-authenticate", "DPoP algs=\"ES256\""),
                        ]),
                    )
                }),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(move || {
                    let doc = prm.clone();
                    async move { axum::Json(doc) }
                }),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(move || {
                    let doc = asm.clone();
                    async move { axum::Json(doc) }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let spec: TargetSpec =
            serde_json::from_value(serde_json::json!({ "url": format!("{base}/mcp") })).unwrap();
        let report = inspect(&spec).await.expect("report");
        assert_eq!(report.issuer.as_deref(), Some(base.as_str()));
        // Both challenges are kept apart: the Bearer one is parsed, the
        // DPoP one reported as sent.
        assert_eq!(
            report.challenge.as_ref().and_then(|c| c.scope.as_deref()),
            Some("mcp:tools")
        );
        assert_eq!(
            report.dpop_challenge.as_deref(),
            Some("DPoP algs=\"ES256\"")
        );
        assert_eq!(
            report.grant_types_supported,
            vec![GRANT_TYPE_JWT_BEARER, "authorization_code"]
        );
        assert_eq!(
            report.authorization_grant_profiles_supported,
            vec![GRANT_PROFILE_ID_JAG]
        );
        assert_eq!(report.enterprise_managed_authorization, Some("advertised"));
        assert_eq!(
            report.dpop_signing_alg_values_supported,
            vec!["ES256", "EdDSA"]
        );
        assert_eq!(
            report.authorization_details_types_supported,
            vec!["crm_record"]
        );
        assert!(report.authorization_response_iss_parameter_supported);
        assert!(report.client_id_metadata_document_supported);
        let resource = report
            .resource_token_requirements
            .as_ref()
            .expect("resource side");
        assert!(resource.dpop_bound_access_tokens_required);
        assert_eq!(resource.dpop_signing_alg_values_supported, vec!["ES256"]);
        // The verdict names both logins and the DPoP requirement.
        assert!(
            report.verdict.contains("browser sign-in"),
            "{}",
            report.verdict
        );
        assert!(
            report.verdict.contains("--idp-token-url"),
            "{}",
            report.verdict
        );
        assert!(report.verdict.contains("DPoP-bound"), "{}", report.verdict);

        let doc = serde_json::to_value(&report).unwrap();
        assert_eq!(
            doc["authorization_grant_profiles_supported"],
            serde_json::json!([GRANT_PROFILE_ID_JAG])
        );
        assert_eq!(doc["enterprise_managed_authorization"], "advertised");
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            serde_json::json!(["private_key_jwt", "none"])
        );
        assert_eq!(
            doc["resource_token_requirements"]["authorization_details_types_supported"],
            serde_json::json!(["crm_record"])
        );
    }

    /// Nothing about DPoP, RAR or ID-JAG is claimed of a server that says
    /// nothing about them.
    #[test]
    fn a_plain_authorization_server_gets_no_extra_hints() {
        let found = DiscoveredOauth {
            resource: "https://h/mcp".to_owned(),
            token_endpoint: "https://as/token".to_owned(),
            issuer: "https://as".to_owned(),
            ..Default::default()
        };
        assert_eq!(oauth_hints(&found), "");
        assert!(ResourceTokenRequirements::of(&found).is_none());
        let doc = serde_json::to_value(AuthReport::default()).unwrap();
        for absent in [
            "enterprise_managed_authorization",
            "dpop_signing_alg_values_supported",
            "authorization_response_iss_parameter_supported",
            "client_id_metadata_document_supported",
            "resource_token_requirements",
        ] {
            assert!(doc.get(absent).is_none(), "{absent} in {doc}");
        }
    }

    #[test]
    fn strips_the_well_known_segment_back_to_an_identifier() {
        assert_eq!(
            strip_well_known("https://h/.well-known/oauth-protected-resource/mcp"),
            "https://h/mcp"
        );
        assert_eq!(
            strip_well_known("https://h/.well-known/oauth-protected-resource"),
            "https://h"
        );
        // Not a well-known URL: left alone rather than mangled.
        assert_eq!(strip_well_known("https://h/mcp"), "https://h/mcp");
    }

    fn step(step: &'static str, ok: bool) -> DiscoveryStep {
        DiscoveryStep {
            step,
            url: "http://x".to_owned(),
            ok,
            detail: (!ok).then(|| "connection refused".to_owned()),
        }
    }

    #[test]
    fn verdicts_name_the_next_action() {
        let with_scope = BearerChallenge {
            scope: Some("mcp:tools".to_owned()),
            ..Default::default()
        };
        let v = verdict(401, Some(&with_scope), Some("https://as/token"), &[], None);
        assert!(v.contains("challenged"), "{v}");
        assert!(v.contains("https://as/token"), "{v}");
        assert!(v.contains("mcp:tools"), "{v}");

        let v = verdict(401, None, None, &[], None);
        assert!(v.contains("does not say which"), "{v}");

        let v = verdict(200, None, None, &[], None);
        assert!(v.contains("answered without a credential"), "{v}");
    }

    #[test]
    fn a_half_walked_chain_does_not_read_as_no_oauth() {
        // The resource document was read; only its authorization server
        // was unreachable. Reporting "no OAuth metadata" here would send
        // the operator to fix the wrong thing.
        let steps = [
            step("protected-resource-metadata", true),
            step("authorization-server-metadata", false),
        ];
        let v = verdict(401, Some(&BearerChallenge::default()), None, &steps, None);
        assert!(v.contains("advertises OAuth"), "{v}");
        assert!(v.contains("authorization server could not be read"), "{v}");
        assert!(!v.contains("no OAuth metadata"), "{v}");
    }

    #[test]
    fn a_rejected_probe_is_not_an_open_server() {
        // A 400 is neither a challenge nor an answer; calling it
        // "answered without a credential" would be a lie.
        let steps = [step("protected-resource-metadata", false)];
        let v = verdict(400, None, None, &steps, None);
        assert!(
            v.contains("rejected the credential-free probe with HTTP 400"),
            "{v}"
        );
        assert!(!v.contains("answered without a credential"), "{v}");
    }

    fn aauth_requiring(requirement: &str) -> AauthPosture {
        AauthPosture {
            requirement: Some(format!("requirement={requirement}")),
            resource_metadata: true,
            ..Default::default()
        }
    }

    /// A server can be fully AAuth-protected and advertise no OAuth at all.
    /// Saying "no OAuth metadata advertised" would send the operator looking
    /// for a token endpoint that does not exist.
    #[test]
    fn aauth_only_server_is_not_reported_as_having_no_auth() {
        let posture = aauth_requiring("agent-token");
        let v = verdict(401, None, None, &[], Some(&posture));
        assert!(v.contains("wants AAuth"), "{v}");
        assert!(v.contains("--aauth-key"), "{v}");
        assert!(
            !v.contains("no OAuth metadata advertised"),
            "the OAuth chain's silence is not the answer here: {v}"
        );
    }

    /// Both channels can be live at once; the draft says AAuth never uses
    /// `WWW-Authenticate`, so neither report displaces the other.
    #[test]
    fn a_server_speaking_both_reports_both() {
        let posture = aauth_requiring("agent-token");
        let v = verdict(401, None, Some("https://as/token"), &[], Some(&posture));
        assert!(v.contains("mint a token at https://as/token"), "{v}");
        assert!(v.contains("also speaks AAuth"), "{v}");
    }

    #[test]
    fn a_requirement_the_inspector_cannot_satisfy_says_so() {
        let posture = aauth_requiring("auth-token");
        let v = verdict(401, None, None, &[], Some(&posture));
        assert!(v.contains("person server"), "{v}");

        let posture = aauth_requiring("payment");
        let v = verdict(402, None, None, &[], Some(&posture));
        assert!(v.contains("does not implement"), "{v}");
    }

    #[test]
    fn a_rejected_signature_surfaces_the_reason() {
        let posture = AauthPosture {
            signature_error: Some("error=invalid_signature".to_owned()),
            ..Default::default()
        };
        let v = verdict(401, None, None, &[], Some(&posture));
        assert!(v.contains("signature was rejected"), "{v}");
        assert!(v.contains("invalid_signature"), "{v}");
    }

    #[test]
    fn extra_required_components_reach_the_operator() {
        let mut posture = aauth_requiring("agent-token");
        posture.additional_signature_components = vec!["content-digest".into(), "date".into()];
        let v = verdict(401, None, None, &[], Some(&posture));
        assert!(v.contains("content-digest, date"), "{v}");
    }

    #[test]
    fn nothing_aauth_observed_means_no_aauth_section() {
        assert!(!AauthPosture::default().observed());
        assert!(aauth_requiring("agent-token").observed());
    }
}
