//! Enterprise-managed authorization: sign in to an MCP server with an
//! identity the enterprise IdP already holds, and no browser. This is the
//! client half of the MCP extension
//! `io.modelcontextprotocol/enterprise-managed-authorization` (Okta calls
//! it Cross App Access), built on ID-JAG (draft-ietf-oauth-identity-
//! assertion-authz-grant-04 §4):
//!
//! 1. RFC 8693 token exchange at the IdP: the user's ID token (or SAML
//!    assertion, or IdP refresh token) for an ID-JAG whose `audience` is the
//!    MCP server's authorization server, by its issuer identifier, and whose
//!    `resource` is the MCP server.
//! 2. The RFC 7523 JWT bearer grant at that authorization server, with the
//!    ID-JAG as `assertion` and the client authenticated as it is
//!    registered there.
//!
//! An ID-JAG obtained elsewhere skips step 1. Its claims are read, not
//! verified — verifying is the authorization server's job — so that what
//! the server will refuse (another audience, another client) is said
//! before it refuses. The subject token and the ID-JAG are never shown.

use std::sync::Arc;

use mcpg_mcp_client::auth::{DiscoveredOauth, GRANT_TYPE_JWT_BEARER, IdJagSupport};
use serde::Serialize;
use serde_json::Value;

use super::client_auth::ClientCredentials;
use super::dpop::DpopKey;
use super::oauth::{
    Grant, Issued, LoginOutcome, Registration, TokenRequest, dpop_warnings, http_client,
    request_token, require_dpop_key, with_warnings,
};

/// RFC 8693 §2.1 token exchange grant.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// ID-JAG §10.2 token type.
pub const TOKEN_TYPE_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// ID-JAG §3 JWT `typ`.
pub const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
/// RFC 8693 §2.2.1: the `token_type` of an issued token that is not an
/// access token.
const TOKEN_TYPE_NOT_APPLICABLE: &str = "N_A";

/// What the subject token is (ID-JAG §4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum SubjectTokenType {
    /// An OpenID Connect ID token.
    #[default]
    #[value(name = "id_token")]
    IdToken,
    /// A SAML 2.0 assertion.
    #[value(name = "saml2")]
    Saml2,
    /// A refresh token the IdP issued to this client.
    #[value(name = "refresh_token")]
    RefreshToken,
}

impl SubjectTokenType {
    fn urn(self) -> &'static str {
        match self {
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            Self::Saml2 => "urn:ietf:params:oauth:token-type:saml2",
            Self::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
        }
    }
}

/// The token exchange at the enterprise IdP.
pub struct IdpExchange {
    pub token_endpoint: String,
    /// The IdP's issuer identifier, for a client assertion addressed to it.
    pub issuer: Option<String>,
    /// The client as it is registered at the IdP.
    pub client: ClientCredentials,
    pub subject_token: String,
    pub subject_token_type: SubjectTokenType,
}

impl std::fmt::Debug for IdpExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdpExchange")
            .field("token_endpoint", &self.token_endpoint)
            .field("client", &self.client)
            .field("subject_token_type", &self.subject_token_type)
            .finish_non_exhaustive()
    }
}

/// Where the ID-JAG comes from.
pub enum IdJagSource {
    /// Exchanged for at the IdP now.
    Exchange(Box<IdpExchange>),
    /// Obtained elsewhere.
    Supplied(String),
}

pub struct IdJagOptions {
    pub source: IdJagSource,
    /// The client as it is registered at the MCP server's authorization
    /// server: the ID-JAG's `client_id` names it.
    pub client: ClientCredentials,
    /// Scopes to request. Empty asks for what the challenge named, else
    /// none, which leaves the choice to the IdP's policy.
    pub scopes: Vec<String>,
    pub dpop: Option<Arc<DpopKey>>,
    /// RFC 9396 `authorization_details`, a JSON array, sent with both
    /// requests.
    pub authorization_details: Option<String>,
}

/// An ID-JAG, by the claims that decide whether it is redeemed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IdJagSummary {
    /// `exchange` or `supplied`.
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Run the enterprise-managed login against `discovered`.
pub async fn login(
    discovered: &DiscoveredOauth,
    challenge_scope: Option<&str>,
    opts: &IdJagOptions,
) -> Result<LoginOutcome, String> {
    let dpop = opts.dpop.as_deref();
    require_dpop_key(discovered, dpop)?;
    let mut warnings = dpop_warnings(discovered, dpop);
    match discovered.id_jag_support() {
        IdJagSupport::Advertised => {}
        IdJagSupport::JwtBearerOnly => warnings.push(
            "the authorization server lists the jwt-bearer grant but not the id-jag grant \
             profile in authorization_grant_profiles_supported"
                .to_owned(),
        ),
        IdJagSupport::Unsupported => warnings.push(
            "the authorization server advertises neither the id-jag grant profile nor the \
             jwt-bearer grant; the grant is tried anyway"
                .to_owned(),
        ),
    }
    let scopes: Vec<String> = if !opts.scopes.is_empty() {
        opts.scopes.clone()
    } else {
        challenge_scope
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    };
    let scope = (!scopes.is_empty()).then(|| scopes.join(" "));

    let http = http_client()?;
    let (id_jag, source) = match &opts.source {
        IdJagSource::Supplied(id_jag) => (id_jag.trim().to_owned(), "supplied"),
        IdJagSource::Exchange(exchange) => (
            exchange_at_idp(
                &http,
                discovered,
                exchange,
                scope.as_deref(),
                opts.authorization_details.as_deref(),
                &mut warnings,
            )
            .await?,
            "exchange",
        ),
    };
    let summary = inspect(
        &id_jag,
        source,
        discovered,
        opts.client.client_id(),
        &mut warnings,
    );

    let mut form = vec![
        ("grant_type", GRANT_TYPE_JWT_BEARER.to_owned()),
        ("assertion", id_jag.clone()),
        // MCP authorization: the resource goes on every token request, and
        // it is what the issued token's audience is bound to.
        ("resource", discovered.resource.clone()),
    ];
    if let Some(scope) = &scope {
        form.push(("scope", scope.clone()));
    }
    if let Some(details) = &opts.authorization_details {
        form.push(("authorization_details", details.clone()));
    }
    let mut secrets = vec![id_jag.as_str()];
    secrets.extend(opts.client.secret());
    if let IdJagSource::Exchange(exchange) = &opts.source {
        secrets.push(&exchange.subject_token);
        secrets.extend(exchange.client.secret());
    }
    let tokens = request_token(
        &http,
        TokenRequest {
            what: "token endpoint",
            endpoint: &discovered.token_endpoint,
            issuer: Some(&discovered.issuer),
            form,
            client: &opts.client,
            dpop,
            secrets,
        },
    )
    .await
    .map_err(|e| with_warnings(e, &warnings))?;
    if tokens.refresh_token.is_some() {
        warnings.push(
            "the authorization server issued a refresh token for an ID-JAG, which ID-JAG \
             §4.4.3 says it should not: the IdP cannot revoke what that token renews"
                .to_owned(),
        );
    }
    Ok(Issued {
        tokens,
        client: &opts.client,
        registration: Registration::of_client_id(opts.client.client_id()),
        discovered,
        grant: Grant::IdJag,
        dpop,
        warnings,
        id_jag: Some(summary),
    }
    .outcome())
}

/// Step 1: the subject token for an ID-JAG at the IdP (ID-JAG §4.3).
async fn exchange_at_idp(
    http: &reqwest::Client,
    discovered: &DiscoveredOauth,
    exchange: &IdpExchange,
    scope: Option<&str>,
    authorization_details: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<String, String> {
    check_secret_destination(&exchange.token_endpoint)?;
    let mut form = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE.to_owned()),
        ("requested_token_type", TOKEN_TYPE_ID_JAG.to_owned()),
        ("subject_token", exchange.subject_token.clone()),
        (
            "subject_token_type",
            exchange.subject_token_type.urn().to_owned(),
        ),
        // ID-JAG §4.3: the authorization server's issuer exactly as its
        // own metadata states it — the server compares `aud` byte for byte.
        ("audience", discovered.issuer.clone()),
        ("resource", discovered.resource.clone()),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope.to_owned()));
    }
    if let Some(details) = authorization_details {
        form.push(("authorization_details", details.to_owned()));
    }
    let mut secrets = vec![exchange.subject_token.as_str()];
    secrets.extend(exchange.client.secret());
    let issued = request_token(
        http,
        TokenRequest {
            what: "IdP token endpoint",
            endpoint: &exchange.token_endpoint,
            issuer: exchange.issuer.as_deref(),
            form,
            client: &exchange.client,
            dpop: None,
            secrets,
        },
    )
    .await?;
    match issued.issued_token_type.as_deref() {
        Some(TOKEN_TYPE_ID_JAG) => {}
        Some(other) => {
            return Err(format!(
                "the IdP issued a token of type {other}, not an ID-JAG ({TOKEN_TYPE_ID_JAG})"
            ));
        }
        None => warnings.push(
            "the IdP's answer has no issued_token_type, which RFC 8693 §2.2.1 requires; \
             its access_token is read as the ID-JAG"
                .to_owned(),
        ),
    }
    if let Some(token_type) = issued.token_type.as_deref()
        && !token_type.eq_ignore_ascii_case(TOKEN_TYPE_NOT_APPLICABLE)
    {
        warnings.push(format!(
            "the IdP answered token_type {token_type:?} for the ID-JAG; ID-JAG §4.3.4 has N_A"
        ));
    }
    Ok(issued.access_token)
}

/// Refuse to send a subject token or a client secret in the clear to
/// anything but this machine.
fn check_secret_destination(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| format!("{url:?} is not a URL"))?;
    match (parsed.scheme(), parsed.host()) {
        ("https", _) => Ok(()),
        ("http", Some(url::Host::Domain("localhost"))) => Ok(()),
        ("http", Some(url::Host::Ipv4(ip))) if ip.is_loopback() => Ok(()),
        ("http", Some(url::Host::Ipv6(ip))) if ip.is_loopback() => Ok(()),
        (scheme, _) => Err(format!(
            "the IdP token endpoint {url} is {scheme}://, and the subject token goes over \
             https (or plain http to this machine) only"
        )),
    }
}

/// Read the ID-JAG's header and claims and note what the authorization
/// server will refuse.
fn inspect(
    id_jag: &str,
    source: &'static str,
    discovered: &DiscoveredOauth,
    client_id: &str,
    warnings: &mut Vec<String>,
) -> IdJagSummary {
    let mut summary = IdJagSummary {
        source,
        ..Default::default()
    };
    let decode = |part: &str| -> Option<Value> {
        let bytes = mcpg_aauth_core::b64::decode(part).ok()?;
        serde_json::from_slice::<Value>(&bytes)
            .ok()
            .filter(Value::is_object)
    };
    let mut parts = id_jag.split('.');
    let (Some(header), Some(claims), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        warnings.push("the ID-JAG is not a compact JWT".to_owned());
        return summary;
    };
    let (Some(header), Some(claims)) = (decode(header), decode(claims)) else {
        warnings.push("the ID-JAG's header or claims are not base64url JSON objects".to_owned());
        return summary;
    };
    let text =
        |value: &Value, name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    summary.typ = text(&header, "typ");
    summary.iss = text(&claims, "iss");
    summary.aud = claims.get("aud").cloned();
    summary.client_id = text(&claims, "client_id");
    summary.resource = claims.get("resource").cloned();
    summary.scope = text(&claims, "scope");
    summary.expires_at = claims.get("exp").and_then(Value::as_u64);

    if summary.typ.as_deref() != Some(ID_JAG_TYP) {
        warnings.push(format!(
            "the ID-JAG's typ is {:?}, and ID-JAG §3 requires {ID_JAG_TYP:?}",
            summary.typ.as_deref().unwrap_or("absent")
        ));
    }
    let audiences: Vec<&str> = match &summary.aud {
        Some(Value::String(aud)) => vec![aud.as_str()],
        Some(Value::Array(auds)) => auds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if audiences != [discovered.issuer.as_str()] {
        warnings.push(format!(
            "the ID-JAG's aud is {}, and the authorization server accepts only its issuer {:?}",
            summary
                .aud
                .as_ref()
                .map_or_else(|| "absent".to_owned(), Value::to_string),
            discovered.issuer
        ));
    }
    if summary.client_id.as_deref() != Some(client_id) {
        warnings.push(format!(
            "the ID-JAG names client {:?}, and it is redeemed as {client_id:?}; the server \
             refuses a client_id that is not the authenticated client (ID-JAG §4.4.1)",
            summary.client_id.as_deref().unwrap_or("absent")
        ));
    }
    if let Some(resource) = &summary.resource {
        let resources: Vec<&str> = match resource {
            Value::String(r) => vec![r.as_str()],
            Value::Array(rs) => rs.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !resources.contains(&discovered.resource.as_str()) {
            warnings.push(format!(
                "the ID-JAG's resource {resource} does not name this server, {:?}",
                discovered.resource
            ));
        }
    }
    if summary
        .expires_at
        .is_some_and(|exp| exp <= mcpg_aauth_core::now_unix())
    {
        warnings.push("the ID-JAG has expired".to_owned());
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::keys::{SigningAlg, SigningKey};
    use serde_json::json;

    fn discovered() -> DiscoveredOauth {
        DiscoveredOauth {
            resource: "https://gw.example/mcp".to_owned(),
            token_endpoint: "https://gw.example/oauth/token".to_owned(),
            issuer: "https://gw.example".to_owned(),
            ..Default::default()
        }
    }

    fn id_jag(header: Value, claims: Value) -> String {
        SigningKey::generate(SigningAlg::Es256)
            .unwrap()
            .sign_jws(&header, &claims)
            .unwrap()
    }

    fn good_claims() -> Value {
        json!({
            "iss": "https://idp.example",
            "sub": "u-1",
            "aud": "https://gw.example",
            "client_id": "mcp-client",
            "resource": "https://gw.example/mcp",
            "scope": "mcp:tools",
            "exp": mcpg_aauth_core::now_unix() + 300,
        })
    }

    #[test]
    fn a_well_formed_id_jag_draws_no_warning() {
        let mut warnings = Vec::new();
        let summary = inspect(
            &id_jag(json!({"typ": ID_JAG_TYP}), good_claims()),
            "supplied",
            &discovered(),
            "mcp-client",
            &mut warnings,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(summary.client_id.as_deref(), Some("mcp-client"));
        assert_eq!(summary.aud, Some(json!("https://gw.example")));
        let shown = serde_json::to_value(&summary).unwrap();
        assert!(shown.get("sub").is_none(), "the subject is not repeated");
    }

    /// What an authorization server refuses is named before it refuses:
    /// another audience (a trailing slash is another issuer), another
    /// client, another resource, the wrong `typ`, an expired grant.
    #[test]
    fn what_the_server_will_refuse_is_named() {
        let mut claims = good_claims();
        claims["aud"] = json!("https://gw.example/");
        claims["client_id"] = json!("someone-else");
        claims["resource"] = json!(["https://other.example/mcp"]);
        claims["exp"] = json!(1);
        let mut warnings = Vec::new();
        inspect(
            &id_jag(json!({"typ": "JWT"}), claims),
            "supplied",
            &discovered(),
            "mcp-client",
            &mut warnings,
        );
        let all = warnings.join("\n");
        for expected in [
            "typ",
            "accepts only its issuer",
            "someone-else",
            "does not name this server",
            "expired",
        ] {
            assert!(all.contains(expected), "missing {expected:?} in {all}");
        }
    }

    #[test]
    fn a_non_jwt_is_named_and_not_repeated() {
        let mut warnings = Vec::new();
        inspect(
            "opaque-grant-value",
            "supplied",
            &discovered(),
            "c",
            &mut warnings,
        );
        assert_eq!(warnings, ["the ID-JAG is not a compact JWT"]);
    }

    #[test]
    fn a_subject_token_goes_over_https_or_loopback_only() {
        assert!(check_secret_destination("https://idp.example/token").is_ok());
        assert!(check_secret_destination("http://127.0.0.1:9/token").is_ok());
        assert!(check_secret_destination("http://[::1]:9/token").is_ok());
        assert!(check_secret_destination("http://localhost:9/token").is_ok());
        let err = check_secret_destination("http://idp.example/token").unwrap_err();
        assert!(err.contains("https"), "{err}");
    }
}
