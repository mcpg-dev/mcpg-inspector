//! Driving an MCP server's OAuth login, so the auth lab can hand back a
//! token instead of a diagnosis.
//!
//! `auth` reports the chain; this walks it. Given a discovered
//! authorization server it registers a client (RFC 7591) when the server
//! offers it, runs an authorization-code grant with PKCE (RFC 7636) against
//! a loopback redirect, and exchanges the code for a token the caller can
//! pass straight back as `--bearer`.
//!
//! Two things separate this from a stock OIDC login, and both come from the
//! MCP authorization spec:
//!
//! - **Resource indicators (RFC 8707).** MCP requires the `resource`
//!   parameter on both the authorization request and the token exchange, so
//!   the issued token is audience-bound to *this* MCP server and cannot be
//!   replayed at another resource that trusts the same authorization server.
//! - **Dynamic client registration.** An MCP client cannot pre-register with
//!   every server it might meet, so when the AS advertises a registration
//!   endpoint we use it rather than requiring the operator to find a
//!   `client_id`.
//!
//! A registered client may be confidential ([`ClientAuthOptions`]), the
//! authorization response's `iss` is checked (RFC 9207), and with a DPoP key
//! the code is bound to that key and the token request carries a proof
//! (RFC 9449). The token request itself ([`request_token`]) is shared with
//! the enterprise-managed login in [`super::idjag`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcpg_mcp_client::auth::{DiscoveredOauth, IdJagSupport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::client_auth::{AssertionKey, ClientAuthMethod, ClientCredentials};
use super::dpop::{DPOP_HEADER, DPOP_NONCE_HEADER, DpopKey, TOKEN_TYPE_DPOP, USE_DPOP_NONCE};

/// How long to wait for the human to finish signing in.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-request timeout at a token or registration endpoint.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest token-endpoint response read.
const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;
/// Longest server-supplied error text repeated in a message.
const MAX_ERROR_TEXT_CHARS: usize = 300;

/// Receives the authorization URL, for whoever can actually visit it.
pub type UrlSink = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

/// Where this instance serves its OAuth client-metadata document. The URL
/// *is* the `client_id` when a server supports it, which is why the path is
/// fixed rather than configurable.
pub const CLIENT_METADATA_PATH: &str = "/.well-known/oauth-client-metadata";

/// The client-metadata document, for an instance reachable at `public_url`.
///
/// A client with a public origin can be identified by a URL that resolves to
/// this document, so there is nothing to register: no per-server `client_id`,
/// no registration endpoint, no state. The local inspector has no public
/// origin and therefore cannot use it — see the registration order in
/// [`login`].
pub fn client_metadata(public_url: &str) -> serde_json::Value {
    let public_url = public_url.trim_end_matches('/');
    serde_json::json!({
        "client_id": format!("{public_url}{CLIENT_METADATA_PATH}"),
        "client_name": "mcpg Inspector",
        "client_uri": public_url,
        "redirect_uris": [format!("{public_url}/oauth/callback")],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile email",
    })
}

/// How a client the operator names authenticates at the token endpoint.
/// Empty is a public client.
#[derive(Clone, Default)]
pub struct ClientAuthOptions {
    pub method: Option<ClientAuthMethod>,
    pub secret: Option<String>,
    pub key: Option<AssertionKey>,
}

impl std::fmt::Debug for ClientAuthOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuthOptions")
            .field("method", &self.method)
            .field("secret", &self.secret.as_ref().map(|_| "[set]"))
            .field("key", &self.key.as_ref().map(|_| "[set]"))
            .finish()
    }
}

impl ClientAuthOptions {
    pub fn is_empty(&self) -> bool {
        self.method.is_none() && self.secret.is_none() && self.key.is_none()
    }

    /// The credentials `client_id` presents at `discovered`'s token
    /// endpoint. `label` names the flags in errors.
    pub fn credentials(
        &self,
        label: &str,
        client_id: String,
        discovered: &DiscoveredOauth,
    ) -> Result<ClientCredentials, String> {
        ClientCredentials::build(
            label,
            client_id,
            self.method,
            self.secret.clone(),
            self.key.clone(),
            &discovered.token_endpoint_auth_methods_supported,
        )
    }
}

#[derive(Default)]
pub struct LoginOptions {
    /// Pre-registered client, or the URL of the client's metadata document.
    /// Absent means register dynamically, which fails cleanly if the server
    /// does not offer it.
    pub client_id: Option<String>,
    /// How `client_id` authenticates; a registered client is public.
    pub client_auth: ClientAuthOptions,
    /// RFC 7591 §3 initial access token for dynamic registration.
    pub registration_token: Option<String>,
    /// Public origin of this instance, when it has one. Present, and with a
    /// server that supports it, the client-metadata document's URL is used
    /// as `client_id` and registration is skipped entirely.
    pub public_url: Option<String>,
    /// Scopes to request. Empty asks for whatever the challenge named, then
    /// whatever the AS advertises, then nothing.
    pub scopes: Vec<String>,
    /// Print the URL rather than opening a browser.
    pub no_browser: bool,
    /// Where the authorization URL goes. `None` opens a browser on this
    /// machine, which is right for the CLI and wrong everywhere else — a
    /// served inspector has to hand the URL to the person at the other end
    /// of the HTTP connection, not to the host it runs on.
    pub visit: Option<UrlSink>,
    /// Bind the code and the token to this key (RFC 9449).
    pub dpop: Option<Arc<DpopKey>>,
    /// RFC 9396 `authorization_details`, a JSON array, for the
    /// authorization request.
    pub authorization_details: Option<String>,
}

/// Which grant produced the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Grant {
    /// A browser sign-in: authorization code with PKCE.
    AuthorizationCode,
    /// Enterprise-managed authorization: an ID-JAG redeemed with the JWT
    /// bearer grant.
    IdJag,
}

/// A token, and enough about how it was obtained to explain it.
#[derive(Serialize)]
pub struct LoginOutcome {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub client_id: String,
    /// How the client identified itself.
    pub registration: Registration,
    /// How the client authenticated at the token endpoint.
    pub client_auth: ClientAuthMethod,
    pub resource: String,
    pub grant: Grant,
    /// The RFC 7638 thumbprint of the key a DPoP-bound token is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    /// RFC 9396 details the token is limited to, as the server granted them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Value>,
    /// The ID-JAG the token was redeemed from, by its claims only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_jag: Option<super::idjag::IdJagSummary>,
    /// Things the servers did that a conformant client would not rely on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for LoginOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginOutcome")
            .field("token_type", &self.token_type)
            .field("client_id", &self.client_id)
            .field("registration", &self.registration)
            .field("grant", &self.grant)
            .field("dpop_jkt", &self.dpop_jkt)
            .field("warnings", &self.warnings)
            .finish_non_exhaustive()
    }
}

/// How the client came by its `client_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Registration {
    /// Supplied by the operator.
    PreRegistered,
    /// The URL of this instance's client-metadata document.
    ClientIdMetadata,
    /// RFC 7591, registered for this login.
    Dynamic,
}

impl Registration {
    /// A `client_id` that is an `https://` URL names its metadata document.
    pub fn of_client_id(client_id: &str) -> Self {
        if client_id.starts_with("https://") {
            Self::ClientIdMetadata
        } else {
            Self::PreRegistered
        }
    }
}

/// A token response: RFC 6749 §5.1, with the RFC 8693 §2.2.1 and RFC 9396
/// §7 members.
#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default, deserialize_with = "seconds")]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub issued_token_type: Option<String>,
    #[serde(default)]
    pub authorization_details: Option<Value>,
}

/// `expires_in` as a number, or as the numeric string some servers send.
fn seconds<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    Ok(match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    })
}

/// One token request: its form, how the client authenticates, and whether
/// it carries a DPoP proof.
pub(crate) struct TokenRequest<'a> {
    /// What the endpoint is, as a message names it.
    pub what: &'static str,
    pub endpoint: &'a str,
    /// The server's issuer identifier, for an assertion addressed to it.
    pub issuer: Option<&'a str>,
    pub form: Vec<(&'static str, String)>,
    pub client: &'a ClientCredentials,
    pub dpop: Option<&'a DpopKey>,
    /// Every secret the request carries. None of them may reach a message,
    /// whatever the server echoes.
    pub secrets: Vec<&'a str>,
}

/// An HTTP client for token and registration endpoints: no redirects,
/// which would carry a credential to wherever the server points.
pub(crate) fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("client build failed: {e}"))
}

/// Post a token request. A DPoP proof refused for want of a server nonce
/// is retried once with the nonce the server sent (RFC 9449 §8).
pub(crate) async fn request_token(
    http: &reqwest::Client,
    request: TokenRequest<'_>,
) -> Result<TokenResponse, String> {
    let what = request.what;
    let endpoint = request.endpoint;
    let mut nonce: Option<String> = None;
    for attempt in 0..2 {
        let mut form = request.form.clone();
        let mut builder = http
            .post(endpoint)
            .header(reqwest::header::ACCEPT, "application/json");
        builder = request
            .client
            .authenticate(builder, &mut form, endpoint, request.issuer)?;
        if let Some(key) = request.dpop {
            builder = builder.header(
                DPOP_HEADER,
                key.proof("POST", endpoint, nonce.as_deref(), None)?,
            );
        }
        let response = builder
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("{what} request to {endpoint} failed: {e}"))?;
        let status = response.status();
        let server_nonce = response
            .headers()
            .get(DPOP_NONCE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("no content type")
            .to_owned();
        let body = read_capped(response, MAX_TOKEN_RESPONSE_BYTES)
            .await
            .map_err(|e| format!("{what} at {endpoint}: {e}"))?;
        if status.is_success() {
            // The body holds the token, and a serde message can quote the
            // value it choked on: say what is wrong, never what was there.
            let problem = match serde_json::from_slice::<Value>(&body) {
                Err(_) => "the body is not JSON".to_owned(),
                Ok(value) if !value.get("access_token").is_some_and(Value::is_string) => {
                    "the body has no access_token".to_owned()
                }
                Ok(value) => match serde_json::from_value::<TokenResponse>(value) {
                    Ok(tokens) => return Ok(tokens),
                    Err(e) => format!("a member has the wrong type ({:?})", e.classify()),
                },
            };
            return Err(format!(
                "{what} at {endpoint} answered {status} without a token response: {problem}"
            ));
        }
        let error = OAuthErrorBody::read(&body);
        if attempt == 0
            && request.dpop.is_some()
            && error.as_ref().is_some_and(|e| e.error == USE_DPOP_NONCE)
            && server_nonce.is_some()
        {
            nonce = server_nonce;
            continue;
        }
        let detail = match error {
            Some(error) => error.describe(),
            None => format!("a {content_type} body of {} bytes", body.len()),
        };
        return Err(format!(
            "{what} at {endpoint} returned HTTP {status}: {}",
            scrub(&detail, &request.secrets)
        ));
    }
    Err(format!(
        "{what} at {endpoint} asked for a new DPoP nonce twice"
    ))
}

/// An RFC 6749 §5.2 error response.
struct OAuthErrorBody {
    error: String,
    description: Option<String>,
}

impl OAuthErrorBody {
    fn read(body: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(body).ok()?;
        Some(Self {
            error: value.get("error")?.as_str()?.to_owned(),
            description: value
                .get("error_description")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    fn describe(&self) -> String {
        match &self.description {
            Some(description) => format!("{}: {description}", self.error),
            None => self.error.clone(),
        }
    }
}

/// `error`, followed by what the client noticed before the server refused,
/// which is often why it refused.
pub(crate) fn with_warnings(error: String, warnings: &[String]) -> String {
    if warnings.is_empty() {
        error
    } else {
        format!("{error} (noticed before sending: {})", warnings.join("; "))
    }
}

/// `text` without any of `secrets`, and no longer than a message needs.
pub(crate) fn scrub(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_owned();
    for secret in secrets.iter().filter(|s| s.len() >= 4) {
        out = out.replace(secret, "[redacted]");
    }
    if out.chars().count() > MAX_ERROR_TEXT_CHARS {
        out = out.chars().take(MAX_ERROR_TEXT_CHARS).collect::<String>() + "…";
    }
    out
}

/// Read at most `cap` bytes of a response body.
async fn read_capped(mut response: reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("body read failed: {e}"))?
    {
        if body.len() + chunk.len() > cap {
            return Err(format!("response exceeded {cap} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Refuse up front a login whose token the resource could not accept: one
/// that takes only DPoP-bound tokens, with no key to bind them to.
pub(crate) fn require_dpop_key(
    discovered: &DiscoveredOauth,
    dpop: Option<&DpopKey>,
) -> Result<(), String> {
    if discovered.resource_dpop_bound_access_tokens_required && dpop.is_none() {
        return Err(
            "this server takes only DPoP-bound tokens (dpop_bound_access_tokens_required); \
             pass --dpop-key PATH, which is created when it does not exist"
                .to_owned(),
        );
    }
    Ok(())
}

/// Warnings about a DPoP key the authorization server will not bind to.
pub(crate) fn dpop_warnings(discovered: &DiscoveredOauth, dpop: Option<&DpopKey>) -> Vec<String> {
    let Some(key) = dpop else {
        return Vec::new();
    };
    let accepted = &discovered.dpop_signing_alg_values_supported;
    if accepted.is_empty() {
        vec![
            "the authorization server advertises no dpop_signing_alg_values_supported; \
             a proof is sent, and the token is bound only if the server takes it"
                .to_owned(),
        ]
    } else if !accepted.iter().any(|a| a == key.alg_name()) {
        vec![format!(
            "the DPoP key signs {}, which the authorization server does not list ({})",
            key.alg_name(),
            accepted.join(", ")
        )]
    } else {
        Vec::new()
    }
}

/// Assemble the outcome of a token response.
pub(crate) struct Issued<'a> {
    pub tokens: TokenResponse,
    pub client: &'a ClientCredentials,
    pub registration: Registration,
    pub discovered: &'a DiscoveredOauth,
    pub grant: Grant,
    pub dpop: Option<&'a DpopKey>,
    pub warnings: Vec<String>,
    pub id_jag: Option<super::idjag::IdJagSummary>,
}

impl Issued<'_> {
    pub(crate) fn outcome(self) -> LoginOutcome {
        let mut warnings = self.warnings;
        let token_type = self
            .tokens
            .token_type
            .clone()
            .unwrap_or_else(|| "Bearer".to_owned());
        let bound = token_type.eq_ignore_ascii_case(TOKEN_TYPE_DPOP);
        let dpop_jkt = match self.dpop {
            Some(key) if bound => Some(key.thumbprint().to_owned()),
            Some(_) => {
                warnings.push(format!(
                    "a DPoP proof was sent and the token came back as `{token_type}`: it is \
                     not bound to the key"
                ));
                None
            }
            None => None,
        };
        LoginOutcome {
            access_token: self.tokens.access_token,
            refresh_token: self.tokens.refresh_token,
            token_type,
            expires_in: self.tokens.expires_in,
            scope: self.tokens.scope,
            client_id: self.client.client_id().to_owned(),
            registration: self.registration,
            client_auth: self.client.method(),
            resource: self.discovered.resource.clone(),
            grant: self.grant,
            dpop_jkt,
            authorization_details: self.tokens.authorization_details,
            id_jag: self.id_jag,
            warnings,
        }
    }
}

/// The PKCE pair. The verifier stays local until the token exchange; only
/// its hash goes out with the authorization request.
struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    fn generate() -> Self {
        let verifier = random_b64url(32);
        let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

fn b64url(bytes: &[u8]) -> String {
    mcpg_aauth_core::b64::encode(bytes)
}

fn random_b64url(len: usize) -> String {
    let mut buf = vec![0u8; len];
    mcpg_aauth_core::rand_bytes(&mut buf);
    b64url(&buf)
}

/// Why there is no browser login at `discovered`, and which login there is
/// when the server redeems ID-JAGs.
fn no_interactive_login(discovered: &DiscoveredOauth) -> String {
    let mut message = "the authorization server advertises no authorization_endpoint, so there \
                       is no interactive login to drive — it issues tokens machine-to-machine only"
        .to_owned();
    if discovered.id_jag_support() != IdJagSupport::Unsupported {
        message.push_str(
            "; it redeems ID-JAGs: log in with --idp-token-url and --subject-token-file, or \
             redeem an ID-JAG you hold with --id-jag-file",
        );
    }
    message
}

/// Run the login. Returns the token, or why it could not be obtained.
pub async fn login(
    discovered: &DiscoveredOauth,
    challenge_scope: Option<&str>,
    opts: &LoginOptions,
) -> Result<LoginOutcome, String> {
    let authorization_endpoint = discovered
        .authorization_endpoint
        .as_deref()
        .ok_or_else(|| no_interactive_login(discovered))?;
    // S256 is the only method worth sending. An AS that lists methods
    // without it is either plain-only (forbidden for public clients) or
    // misconfigured; say which rather than failing at the exchange.
    if !discovered.code_challenge_methods_supported.is_empty()
        && !discovered
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
    {
        return Err(format!(
            "authorization server does not support PKCE S256 (it lists {:?}); \
             the inspector will not fall back to `plain`",
            discovered.code_challenge_methods_supported
        ));
    }
    let dpop = opts.dpop.as_deref();
    require_dpop_key(discovered, dpop)?;
    let mut warnings = dpop_warnings(discovered, dpop);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("cannot bind a loopback redirect listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("listener has no address: {e}"))?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", addr.port());

    let http = http_client()?;

    // Registration order, most to least preferred: a client the operator
    // already registered (or its metadata document URL); this instance's
    // client-metadata document, if it has a public origin and the server
    // takes one; then RFC 7591 dynamic registration. Each earlier option
    // leaves less state behind.
    let (client, registration) = match (&opts.client_id, &opts.public_url) {
        (Some(id), _) => {
            let registration = Registration::of_client_id(id);
            if registration == Registration::ClientIdMetadata
                && !discovered.client_id_metadata_document_supported
            {
                warnings.push(
                    "the client_id is a URL, and the authorization server does not advertise \
                     client_id_metadata_document_supported"
                        .to_owned(),
                );
            }
            (
                opts.client_auth
                    .credentials("--client", id.clone(), discovered)?,
                registration,
            )
        }
        (None, _) if !opts.client_auth.is_empty() => {
            return Err(
                "--client-secret, --client-key and --client-auth describe a client you \
                 registered; name it with --client-id"
                    .to_owned(),
            );
        }
        (None, Some(public))
            if discovered.client_id_metadata_document_supported && !public.is_empty() =>
        {
            (
                ClientCredentials::public(format!(
                    "{}{CLIENT_METADATA_PATH}",
                    public.trim_end_matches('/')
                )),
                Registration::ClientIdMetadata,
            )
        }
        (None, _) => {
            let endpoint = discovered.registration_endpoint.as_deref().ok_or(
                "no --client-id given and the authorization server offers neither \
                 client-ID metadata documents nor dynamic client registration; \
                 register the inspector manually and pass its id",
            )?;
            let registration = ClientRegistration {
                redirect_uri: &redirect_uri,
                initial_access_token: opts.registration_token.as_deref(),
                dpop_bound: dpop.is_some(),
            };
            (
                ClientCredentials::public(register(&http, endpoint, &registration).await?),
                Registration::Dynamic,
            )
        }
    };

    // Scope preference: what the challenge asked for, else what the AS
    // advertises, else none — an empty `scope` parameter is worse than an
    // absent one at several providers.
    let scopes: Vec<String> = if !opts.scopes.is_empty() {
        opts.scopes.clone()
    } else if let Some(scope) = challenge_scope {
        scope.split_whitespace().map(str::to_owned).collect()
    } else {
        discovered.scopes_supported.clone()
    };

    let pkce = Pkce::generate();
    let state = random_b64url(16);

    let mut authorize = url::Url::parse(authorization_endpoint)
        .map_err(|e| format!("authorization_endpoint is not a URL: {e}"))?;
    {
        let mut q = authorize.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client.client_id());
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("state", &state);
        q.append_pair("code_challenge", &pkce.challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("resource", &discovered.resource);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
        // RFC 9449 §10: the code is issued for this key only.
        if let Some(key) = dpop {
            q.append_pair("dpop_jkt", key.thumbprint());
        }
        if let Some(details) = &opts.authorization_details {
            q.append_pair("authorization_details", details);
        }
    }

    match &opts.visit {
        Some(sink) => sink(authorize.as_str()),
        None if opts.no_browser => eprintln!("open this URL to sign in:\n  {authorize}"),
        None => {
            eprintln!("opening a browser to sign in…");
            if let Err(e) = webbrowser::open(authorize.as_str()) {
                eprintln!("  browser open failed ({e}); open this URL manually:\n  {authorize}");
            }
        }
    }

    let params = tokio::time::timeout(CALLBACK_TIMEOUT, await_callback(listener))
        .await
        .map_err(|_| {
            format!(
                "timed out after {}s waiting for the authorization redirect",
                CALLBACK_TIMEOUT.as_secs()
            )
        })??;

    // Checked before the code is touched: a mismatched `state` means this
    // redirect is not the one we started, and the code with it is not ours.
    if params.get("state").map(String::as_str) != Some(state.as_str()) {
        return Err("authorization redirect carried the wrong `state` — \
                    refusing to exchange a code that may not be ours"
            .to_owned());
    }
    // RFC 9207 §2.4: a response from another authorization server — a
    // mix-up — names that server, or none where this one promised to.
    match params.get("iss") {
        Some(iss) if *iss != discovered.issuer => {
            return Err(format!(
                "authorization redirect names issuer {iss:?}, not {:?} — refusing a response \
                 from another authorization server (RFC 9207)",
                discovered.issuer
            ));
        }
        None if discovered.authorization_response_iss_parameter_supported => {
            return Err(
                "authorization redirect carries no `iss`, which this authorization server \
                 promises in every response (RFC 9207) — refusing it"
                    .to_owned(),
            );
        }
        _ => {}
    }
    if let Some(error) = params.get("error") {
        let description = params
            .get("error_description")
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        return Err(format!(
            "authorization server refused: {error}{description}"
        ));
    }
    let code = params
        .get("code")
        .ok_or("authorization redirect carried neither a code nor an error")?;

    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("code_verifier", pkce.verifier.clone()),
        // Repeated at the exchange, not only at the authorization request:
        // RFC 8707 §2.2 is what binds the issued token's audience.
        ("resource", discovered.resource.clone()),
    ];
    if !scopes.is_empty() {
        form.push(("scope", scopes.join(" ")));
    }
    let tokens = request_token(
        &http,
        TokenRequest {
            what: "token endpoint",
            endpoint: &discovered.token_endpoint,
            issuer: Some(&discovered.issuer),
            form,
            client: &client,
            dpop,
            secrets: [Some(code.as_str()), client.secret()]
                .into_iter()
                .flatten()
                .collect(),
        },
    )
    .await
    .map_err(|e| with_warnings(e, &warnings))?;

    Ok(Issued {
        tokens,
        client: &client,
        registration,
        discovered,
        grant: Grant::AuthorizationCode,
        dpop,
        warnings,
        id_jag: None,
    }
    .outcome())
}

/// What a dynamic registration asks for.
struct ClientRegistration<'a> {
    redirect_uri: &'a str,
    /// RFC 7591 §3: the operator's initial access token, when the server
    /// does not take anonymous registrations.
    initial_access_token: Option<&'a str>,
    /// RFC 9449 §5.2: the client always uses DPoP.
    dpop_bound: bool,
}

/// RFC 7591 dynamic client registration for a public client.
async fn register(
    http: &reqwest::Client,
    endpoint: &str,
    registration: &ClientRegistration<'_>,
) -> Result<String, String> {
    let mut body = serde_json::json!({
        "client_name": "mcpg-inspector",
        "redirect_uris": [registration.redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        // Public client: the secret would live in a CLI a user can read,
        // which is what PKCE exists to make unnecessary.
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    });
    if registration.dpop_bound {
        body["dpop_bound_access_tokens"] = serde_json::json!(true);
    }
    let mut request = http.post(endpoint).json(&body);
    if let Some(token) = registration.initial_access_token {
        request = request.bearer_auth(token);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| format!("client registration at {endpoint} failed: {e}"))?;
    let status = resp.status();
    let text = read_capped(resp, MAX_TOKEN_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("client registration at {endpoint}: {e}"))?;
    let secrets: Vec<&str> = registration.initial_access_token.into_iter().collect();
    if !status.is_success() {
        let detail = OAuthErrorBody::read(&text)
            .map(|e| e.describe())
            .unwrap_or_else(|| String::from_utf8_lossy(&text).trim().to_owned());
        return Err(format!(
            "client registration returned HTTP {status}: {}",
            scrub(&detail, &secrets)
        ));
    }
    serde_json::from_slice::<Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("client_id")
                .and_then(|c| c.as_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| "client registration response has no client_id".to_owned())
}

/// Accept exactly one request on the loopback listener and return its query
/// parameters.
///
/// Hand-rolled rather than an axum server: this handles one request, on a
/// socket bound for one purpose, and then the listener is dropped. It reads
/// only the request line, which is where the query lives.
async fn await_callback(
    listener: tokio::net::TcpListener,
) -> Result<HashMap<String, String>, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("redirect listener failed: {e}"))?;
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await.is_err() {
            continue;
        }
        // `GET /callback?code=…&state=… HTTP/1.1`
        let Some(target) = request_line.split_whitespace().nth(1) else {
            continue;
        };
        // Browsers ask for /favicon.ico on the same origin; answering the
        // first request that arrives would lose the redirect.
        if !target.starts_with("/callback") {
            let mut stream = reader.into_inner();
            let _ = stream
                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                .await;
            continue;
        }
        let params: HashMap<String, String> = url::Url::parse(&format!("http://127.0.0.1{target}"))
            .map_err(|e| format!("callback URL unparseable: {e}"))?
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let mut stream = reader.into_inner();
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\n\
                     content-length: {}\r\n\r\n{DONE_HTML}",
                    DONE_HTML.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = stream.flush().await;
        return Ok(params);
    }
}

const DONE_HTML: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
<style>body{font-family:system-ui;max-width:26rem;margin:5rem auto;text-align:center}\
.ok{color:#0a8;font-size:3rem}</style>\
<div class=ok>OK</div><h1>Signed in</h1>\
<p>You can close this tab and return to your terminal.</p>";

#[cfg(test)]
mod tests {
    use super::*;

    fn discovered() -> DiscoveredOauth {
        DiscoveredOauth {
            resource: "https://gw.example/mcp".to_owned(),
            token_endpoint: "https://as.example/token".to_owned(),
            issuer: "https://as.example".to_owned(),
            authorization_endpoint: Some("https://as.example/authorize".to_owned()),
            registration_endpoint: Some("https://as.example/register".to_owned()),
            scopes_supported: vec!["mcp:read".to_owned()],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            ..Default::default()
        }
    }

    fn options() -> LoginOptions {
        LoginOptions {
            client_id: Some("cid".to_owned()),
            no_browser: true,
            ..Default::default()
        }
    }

    /// RFC 7636 §4: `challenge = BASE64URL(SHA256(ASCII(verifier)))`,
    /// unpadded. The published example vector pins both halves.
    #[test]
    fn pkce_challenge_matches_the_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            b64url(&Sha256::digest(verifier.as_bytes())),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn pkce_verifier_is_fresh_each_time() {
        let a = Pkce::generate();
        let b = Pkce::generate();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
        // RFC 7636 §4.1 requires 43..=128 characters.
        assert!(
            (43..=128).contains(&a.verifier.len()),
            "{}",
            a.verifier.len()
        );
    }

    #[tokio::test]
    async fn refuses_an_authorization_server_with_no_authorize_endpoint() {
        let mut d = discovered();
        d.authorization_endpoint = None;
        let err = login(&d, None, &options()).await.unwrap_err();
        assert!(err.contains("no authorization_endpoint"), "{err}");
        assert!(!err.contains("--idp-token-url"), "{err}");
    }

    /// A server that redeems ID-JAGs and signs no one in through a browser
    /// is reached with the ID-JAG login, which the refusal names.
    #[tokio::test]
    async fn an_id_jag_only_server_points_at_the_id_jag_login() {
        let mut d = discovered();
        d.authorization_endpoint = None;
        d.grant_types_supported = vec!["urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned()];
        d.authorization_grant_profiles_supported =
            vec!["urn:ietf:params:oauth:grant-profile:id-jag".to_owned()];
        let err = login(&d, None, &options()).await.unwrap_err();
        assert!(err.contains("--idp-token-url"), "{err}");
        assert!(err.contains("--id-jag-file"), "{err}");
    }

    /// Falling back to `plain` would defeat the point; an AS that cannot do
    /// S256 gets a refusal naming what it offered.
    #[tokio::test]
    async fn refuses_to_downgrade_from_s256() {
        let mut d = discovered();
        d.code_challenge_methods_supported = vec!["plain".to_owned()];
        let err = login(&d, None, &options()).await.unwrap_err();
        assert!(err.contains("S256"), "{err}");
        assert!(err.contains("plain"), "{err}");
    }

    /// An AS that lists nothing is not asserting it lacks S256 — RFC 8414
    /// makes the field optional — so absence must not be read as refusal.
    #[tokio::test]
    async fn an_unlisted_method_set_is_not_a_refusal() {
        let mut d = discovered();
        d.code_challenge_methods_supported = vec![];
        d.authorization_endpoint = None; // stop before the browser opens
        let err = login(&d, None, &options()).await.unwrap_err();
        assert!(err.contains("no authorization_endpoint"), "{err}");
    }

    #[tokio::test]
    async fn without_a_client_id_or_registration_it_says_which_is_missing() {
        let mut d = discovered();
        d.registration_endpoint = None;
        let mut opts = options();
        opts.client_id = None;
        let err = login(&d, None, &opts).await.unwrap_err();
        assert!(err.contains("--client-id"), "{err}");
        assert!(err.contains("dynamic client registration"), "{err}");
    }

    /// A stub authorization server: registration, and a token endpoint that
    /// records what it was sent. `authorize` is never called — a browser
    /// would, and the test plays that part directly (see `fake_browser`).
    mod stub {
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        pub struct Seen {
            pub registration: Option<serde_json::Value>,
            pub registration_auth: Option<String>,
            pub token_form: Option<std::collections::HashMap<String, String>>,
            pub token_headers: Option<axum::http::HeaderMap>,
            pub token_calls: usize,
        }

        pub struct Stub {
            pub base: String,
            pub seen: Arc<Mutex<Seen>>,
        }

        /// Spawn the stub on a loopback port. `issue` is the token JSON the
        /// exchange returns; `None` makes the endpoint 400.
        pub async fn spawn(issue: Option<serde_json::Value>) -> Stub {
            use axum::{Json, Router, extract::State, routing::post};

            let seen = Arc::new(Mutex::new(Seen::default()));
            let state = (seen.clone(), issue);

            let app = Router::new()
                .route(
                    "/register",
                    post(
                        |State((seen, _)): State<(Arc<Mutex<Seen>>, Option<serde_json::Value>)>,
                         headers: axum::http::HeaderMap,
                         Json(body): Json<serde_json::Value>| async move {
                            let mut seen = seen.lock().unwrap();
                            seen.registration = Some(body);
                            seen.registration_auth = headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);
                            Json(serde_json::json!({ "client_id": "registered-client" }))
                        },
                    ),
                )
                .route(
                    "/token",
                    post(
                        |State((seen, issue)): State<(
                            Arc<Mutex<Seen>>,
                            Option<serde_json::Value>,
                        )>,
                         headers: axum::http::HeaderMap,
                         body: String| async move {
                            let form: std::collections::HashMap<String, String> =
                                url::form_urlencoded::parse(body.as_bytes())
                                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                    .collect();
                            let mut record = seen.lock().unwrap();
                            record.token_form = Some(form);
                            record.token_headers = Some(headers);
                            record.token_calls += 1;
                            drop(record);
                            match issue {
                                Some(doc) => (axum::http::StatusCode::OK, Json(doc)),
                                None => (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    Json(serde_json::json!({"error": "invalid_grant"})),
                                ),
                            }
                        },
                    ),
                )
                .with_state(state);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Stub { base, seen }
        }
    }

    /// Play the browser: read `state` and `redirect_uri` out of the
    /// authorization URL and hit the redirect the way a real one would.
    fn fake_browser(code: &'static str) -> UrlSink {
        std::sync::Arc::new(move |url: &str| {
            let parsed = url::Url::parse(url).expect("authorize URL");
            let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
            let redirect = q.get("redirect_uri").expect("redirect_uri").to_string();
            let state = q.get("state").expect("state").to_string();
            tokio::spawn(async move {
                let target = format!("{redirect}?code={code}&state={state}");
                let _ = reqwest::Client::new().get(&target).send().await;
            });
        })
    }

    fn live(base: &str) -> DiscoveredOauth {
        DiscoveredOauth {
            resource: "https://gw.example/mcp".to_owned(),
            token_endpoint: format!("{base}/token"),
            issuer: base.to_owned(),
            authorization_endpoint: Some(format!("{base}/authorize")),
            registration_endpoint: Some(format!("{base}/register")),
            scopes_supported: vec!["mcp:read".to_owned()],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            ..Default::default()
        }
    }

    /// Play the browser as [`fake_browser`] does, adding `extra` to the
    /// redirect's query.
    fn fake_browser_with(code: &'static str, extra: String) -> UrlSink {
        std::sync::Arc::new(move |url: &str| {
            let parsed = url::Url::parse(url).expect("authorize URL");
            let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
            let redirect = q.get("redirect_uri").expect("redirect_uri").to_string();
            let state = q.get("state").expect("state").to_string();
            let extra = extra.clone();
            tokio::spawn(async move {
                let target = format!("{redirect}?code={code}&state={state}{extra}");
                let _ = reqwest::Client::new().get(&target).send().await;
            });
        })
    }

    /// The whole grant: register, authorize, redirect, exchange. The
    /// assertions on the token form are the point — they are what a real
    /// authorization server checks, and getting any of them wrong yields a
    /// login that fails only against a real provider.
    #[tokio::test]
    async fn completes_the_authorization_code_grant() {
        let stub = stub::spawn(Some(serde_json::json!({
            "access_token": "at-123",
            "token_type": "Bearer",
            "refresh_token": "rt-456",
            "expires_in": 3600,
            "scope": "mcp:read",
        })))
        .await;

        let opts = LoginOptions {
            visit: Some(fake_browser("the-code")),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");

        assert_eq!(outcome.access_token, "at-123");
        assert_eq!(outcome.refresh_token.as_deref(), Some("rt-456"));
        assert_eq!(outcome.expires_in, Some(3600));
        assert_eq!(outcome.client_id, "registered-client");
        assert_eq!(outcome.registration, Registration::Dynamic);

        let seen = stub.seen.lock().unwrap();
        let form = seen.token_form.as_ref().expect("token endpoint called");
        assert_eq!(form.get("grant_type").unwrap(), "authorization_code");
        assert_eq!(form.get("code").unwrap(), "the-code");
        assert_eq!(form.get("client_id").unwrap(), "registered-client");
        // RFC 8707: the audience binding has to be on the exchange too, not
        // only on the authorization request.
        assert_eq!(form.get("resource").unwrap(), "https://gw.example/mcp");
        // RFC 7636: the verifier — never the challenge — goes to the token
        // endpoint.
        let verifier = form.get("code_verifier").expect("code_verifier sent");
        assert!((43..=128).contains(&verifier.len()));
        assert!(form.get("code_challenge").is_none());
        assert_eq!(form.get("scope").unwrap(), "mcp:read");

        // Public client: PKCE is the proof, so no secret is invented.
        let registration = seen.registration.as_ref().expect("registered");
        assert_eq!(registration["token_endpoint_auth_method"], "none");
        assert_eq!(registration["client_name"], "mcpg-inspector");
        assert!(
            registration["redirect_uris"][0]
                .as_str()
                .unwrap()
                .starts_with("http://127.0.0.1:")
        );
    }

    /// The challenge's scope is used when the caller names none, so a login
    /// asks for what the server actually said it wanted.
    #[tokio::test]
    async fn the_challenge_scope_is_requested() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let opts = LoginOptions {
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        login(&live(&stub.base), Some("tools:call tools:list"), &opts)
            .await
            .expect("login");
        let seen = stub.seen.lock().unwrap();
        assert_eq!(
            seen.token_form.as_ref().unwrap().get("scope").unwrap(),
            "tools:call tools:list"
        );
    }

    /// A redirect carrying someone else's `state` must not be exchanged —
    /// the code in it is not ours.
    #[tokio::test]
    async fn a_mismatched_state_is_refused() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let forged: UrlSink = std::sync::Arc::new(|url: &str| {
            let parsed = url::Url::parse(url).unwrap();
            let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
            let redirect = q.get("redirect_uri").unwrap().to_string();
            tokio::spawn(async move {
                let target = format!("{redirect}?code=stolen&state=not-the-one");
                let _ = reqwest::Client::new().get(&target).send().await;
            });
        });
        let opts = LoginOptions {
            visit: Some(forged),
            ..Default::default()
        };
        let err = login(&live(&stub.base), None, &opts).await.unwrap_err();
        assert!(err.contains("wrong `state`"), "{err}");
        assert!(
            stub.seen.lock().unwrap().token_form.is_none(),
            "the code must never reach the token endpoint"
        );
    }

    /// An `error` in the redirect is the server's answer, not a missing code.
    #[tokio::test]
    async fn an_error_redirect_is_reported_as_the_server_said_it() {
        let stub = stub::spawn(None).await;
        let denied: UrlSink = std::sync::Arc::new(|url: &str| {
            let parsed = url::Url::parse(url).unwrap();
            let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
            let redirect = q.get("redirect_uri").unwrap().to_string();
            let state = q.get("state").unwrap().to_string();
            tokio::spawn(async move {
                let target = format!(
                    "{redirect}?error=access_denied&error_description=user%20said%20no&state={state}"
                );
                let _ = reqwest::Client::new().get(&target).send().await;
            });
        });
        let opts = LoginOptions {
            visit: Some(denied),
            ..Default::default()
        };
        let err = login(&live(&stub.base), None, &opts).await.unwrap_err();
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("user said no"), "{err}");
    }

    /// A browser asks for /favicon.ico on the same origin. Answering the
    /// first request that arrives would consume the listener and lose the
    /// redirect.
    #[tokio::test]
    async fn an_unrelated_request_does_not_consume_the_callback() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let noisy: UrlSink = std::sync::Arc::new(|url: &str| {
            let parsed = url::Url::parse(url).unwrap();
            let q: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
            let redirect = q.get("redirect_uri").unwrap().to_string();
            let state = q.get("state").unwrap().to_string();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let origin = redirect.trim_end_matches("/callback").to_owned();
                let _ = client.get(format!("{origin}/favicon.ico")).send().await;
                let _ = client
                    .get(format!("{redirect}?code=late&state={state}"))
                    .send()
                    .await;
            });
        });
        let opts = LoginOptions {
            visit: Some(noisy),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");
        assert_eq!(outcome.access_token, "at");
    }

    /// A token endpoint that refuses must surface its body, not a generic
    /// parse failure.
    #[tokio::test]
    async fn a_refused_exchange_reports_what_the_server_returned() {
        let stub = stub::spawn(None).await;
        let opts = LoginOptions {
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let err = login(&live(&stub.base), None, &opts).await.unwrap_err();
        assert!(err.contains("400"), "{err}");
        assert!(err.contains("invalid_grant"), "{err}");
    }

    /// A server that takes a client-metadata-document URL needs no
    /// registration at all — the document *is* the client id.
    #[tokio::test]
    async fn a_public_origin_uses_its_metadata_document_as_the_client_id() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let mut d = live(&stub.base);
        d.client_id_metadata_document_supported = true;
        let opts = LoginOptions {
            public_url: Some("https://inspector.mcpg.cloud".to_owned()),
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&d, None, &opts).await.expect("login");
        assert_eq!(outcome.registration, Registration::ClientIdMetadata);
        assert_eq!(
            outcome.client_id,
            "https://inspector.mcpg.cloud/.well-known/oauth-client-metadata"
        );
        assert!(
            stub.seen.lock().unwrap().registration.is_none(),
            "nothing should have been registered"
        );
    }

    /// Without a public origin there is no document to point at, so the
    /// same instance falls back to registering.
    #[tokio::test]
    async fn a_local_instance_falls_back_to_dynamic_registration() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let mut d = live(&stub.base);
        d.client_id_metadata_document_supported = true;
        let opts = LoginOptions {
            public_url: None,
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&d, None, &opts).await.expect("login");
        assert_eq!(outcome.registration, Registration::Dynamic);
    }

    /// A server that does not advertise the capability gets registration
    /// even from an instance that has a public origin.
    #[tokio::test]
    async fn a_server_without_the_capability_still_gets_registration() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let opts = LoginOptions {
            public_url: Some("https://inspector.mcpg.cloud".to_owned()),
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");
        assert_eq!(outcome.registration, Registration::Dynamic);
    }

    /// An operator-supplied client wins over both.
    #[tokio::test]
    async fn a_pre_registered_client_wins() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "Bearer"}),
        ))
        .await;
        let mut d = live(&stub.base);
        d.client_id_metadata_document_supported = true;
        let opts = LoginOptions {
            client_id: Some("ours".to_owned()),
            public_url: Some("https://inspector.mcpg.cloud".to_owned()),
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&d, None, &opts).await.expect("login");
        assert_eq!(outcome.registration, Registration::PreRegistered);
        assert_eq!(outcome.client_id, "ours");
    }

    /// The document must name itself: a server fetches the `client_id` URL
    /// and checks that the document it gets back claims that same id.
    #[test]
    fn the_metadata_document_names_its_own_url() {
        let doc = client_metadata("https://inspector.mcpg.cloud/");
        assert_eq!(
            doc["client_id"],
            "https://inspector.mcpg.cloud/.well-known/oauth-client-metadata"
        );
        assert_eq!(doc["token_endpoint_auth_method"], "none");
        assert_eq!(doc["client_uri"], "https://inspector.mcpg.cloud");
    }

    fn bearer_token() -> serde_json::Value {
        serde_json::json!({"access_token": "at", "token_type": "Bearer"})
    }

    /// RFC 9207: a redirect naming another issuer is a mix-up, and its code
    /// never reaches this server's token endpoint.
    #[tokio::test]
    async fn a_redirect_from_another_issuer_is_refused() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let opts = LoginOptions {
            visit: Some(fake_browser_with(
                "c",
                "&iss=https%3A%2F%2Fevil.example".to_owned(),
            )),
            ..Default::default()
        };
        let err = login(&live(&stub.base), None, &opts).await.unwrap_err();
        assert!(err.contains("RFC 9207"), "{err}");
        assert!(err.contains("evil.example"), "{err}");
        assert!(stub.seen.lock().unwrap().token_form.is_none());
    }

    /// A server that promises `iss` and leaves it out is refused too.
    #[tokio::test]
    async fn a_promised_iss_that_is_missing_is_refused() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let mut d = live(&stub.base);
        d.authorization_response_iss_parameter_supported = true;
        let opts = LoginOptions {
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let err = login(&d, None, &opts).await.unwrap_err();
        assert!(err.contains("no `iss`"), "{err}");
    }

    #[tokio::test]
    async fn the_right_iss_is_accepted() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let mut d = live(&stub.base);
        d.authorization_response_iss_parameter_supported = true;
        let iss: String = url::form_urlencoded::byte_serialize(stub.base.as_bytes()).collect();
        let opts = LoginOptions {
            visit: Some(fake_browser_with("c", format!("&iss={iss}"))),
            ..Default::default()
        };
        let outcome = login(&d, None, &opts).await.expect("login");
        assert_eq!(outcome.grant, Grant::AuthorizationCode);
    }

    /// A static confidential client authenticates at the exchange; with
    /// `client_secret_basic` the secret goes in the header, not the form.
    #[tokio::test]
    async fn a_confidential_client_authenticates_at_the_exchange() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let opts = LoginOptions {
            client_id: Some("static-client".to_owned()),
            client_auth: ClientAuthOptions {
                secret: Some("s3cret-value".to_owned()),
                ..Default::default()
            },
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");
        assert_eq!(outcome.client_auth, ClientAuthMethod::ClientSecretBasic);
        let seen = stub.seen.lock().unwrap();
        let form = seen.token_form.as_ref().unwrap();
        assert!(form.get("client_secret").is_none());
        assert!(form.get("client_id").is_none());
        let auth = seen.token_headers.as_ref().unwrap()["authorization"]
            .to_str()
            .unwrap();
        assert!(auth.starts_with("Basic "), "{auth}");
    }

    #[tokio::test]
    async fn client_credentials_without_a_client_id_are_refused() {
        let opts = LoginOptions {
            client_auth: ClientAuthOptions {
                secret: Some("s".to_owned()),
                ..Default::default()
            },
            no_browser: true,
            ..Default::default()
        };
        let err = login(&discovered(), None, &opts).await.unwrap_err();
        assert!(err.contains("--client-id"), "{err}");
    }

    /// A URL client id is a metadata document, and says so when the server
    /// does not advertise that it resolves one.
    #[tokio::test]
    async fn a_url_client_id_is_a_metadata_document() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let opts = LoginOptions {
            client_id: Some("https://tools.example/inspector.json".to_owned()),
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");
        assert_eq!(outcome.registration, Registration::ClientIdMetadata);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.contains("client_id_metadata_document_supported")),
            "{:?}",
            outcome.warnings
        );
        assert!(stub.seen.lock().unwrap().registration.is_none());
    }

    /// RFC 7591 §3: the initial access token authorizes the registration,
    /// and a DPoP client says it always uses DPoP.
    #[tokio::test]
    async fn registration_carries_the_initial_access_token() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let opts = LoginOptions {
            registration_token: Some("iat-0123456789".to_owned()),
            dpop: Some(Arc::new(
                DpopKey::generate(crate::engine::keys::SigningAlg::Es256).unwrap(),
            )),
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        login(&live(&stub.base), None, &opts).await.expect("login");
        let seen = stub.seen.lock().unwrap();
        assert_eq!(
            seen.registration_auth.as_deref(),
            Some("Bearer iat-0123456789")
        );
        let registration = seen.registration.as_ref().unwrap();
        assert_eq!(registration["dpop_bound_access_tokens"], true);
        assert_eq!(registration["application_type"], "native");
    }

    /// With a key, the code is bound to it (`dpop_jkt`), the exchange
    /// carries a proof of the token endpoint, and a DPoP token reports the
    /// key it is bound to.
    #[tokio::test]
    async fn a_dpop_login_binds_the_code_and_the_token_to_the_key() {
        let stub = stub::spawn(Some(
            serde_json::json!({"access_token": "at", "token_type": "DPoP"}),
        ))
        .await;
        let key = Arc::new(DpopKey::generate(crate::engine::keys::SigningAlg::Es256).unwrap());
        let seen_url = Arc::new(std::sync::Mutex::new(String::new()));
        let browser = fake_browser("c");
        let record = seen_url.clone();
        let visit: UrlSink = Arc::new(move |url: &str| {
            *record.lock().unwrap() = url.to_owned();
            browser(url);
        });
        let mut d = live(&stub.base);
        d.dpop_signing_alg_values_supported = vec!["ES256".to_owned()];
        let opts = LoginOptions {
            client_id: Some("cid".to_owned()),
            dpop: Some(key.clone()),
            visit: Some(visit),
            ..Default::default()
        };
        let outcome = login(&d, None, &opts).await.expect("login");
        assert_eq!(outcome.token_type, "DPoP");
        assert_eq!(outcome.dpop_jkt.as_deref(), Some(key.thumbprint()));
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);

        let authorize = url::Url::parse(&seen_url.lock().unwrap()).unwrap();
        let jkt = authorize
            .query_pairs()
            .find(|(k, _)| k == "dpop_jkt")
            .map(|(_, v)| v.into_owned());
        assert_eq!(jkt.as_deref(), Some(key.thumbprint()));

        let seen = stub.seen.lock().unwrap();
        let proof = seen.token_headers.as_ref().unwrap()["dpop"]
            .to_str()
            .unwrap()
            .to_owned();
        let header = jsonwebtoken::decode_header(&proof).unwrap();
        let jwk = header.jwk.unwrap();
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<serde_json::Value>(
            &proof,
            &jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], d.token_endpoint);
        assert!(claims.get("ath").is_none(), "no token yet to hash");
    }

    /// A bearer token back for a proof is reported, not passed off as bound.
    #[tokio::test]
    async fn an_unbound_token_for_a_proof_is_a_warning() {
        let stub = stub::spawn(Some(bearer_token())).await;
        let opts = LoginOptions {
            client_id: Some("cid".to_owned()),
            dpop: Some(Arc::new(
                DpopKey::generate(crate::engine::keys::SigningAlg::EdDsa).unwrap(),
            )),
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");
        assert!(outcome.dpop_jkt.is_none());
        assert!(
            outcome.warnings.iter().any(|w| w.contains("not bound")),
            "{:?}",
            outcome.warnings
        );
    }

    /// A resource that takes only DPoP-bound tokens is not worth a browser
    /// round trip without a key.
    #[tokio::test]
    async fn a_dpop_only_resource_needs_a_key_before_the_browser_opens() {
        let mut d = discovered();
        d.resource_dpop_bound_access_tokens_required = true;
        let err = login(&d, None, &options()).await.unwrap_err();
        assert!(err.contains("--dpop-key"), "{err}");
    }

    /// Some servers send `expires_in` as a string; it is read either way.
    #[tokio::test]
    async fn a_string_expires_in_is_read() {
        let stub = stub::spawn(Some(serde_json::json!({
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": "3600",
        })))
        .await;
        let opts = LoginOptions {
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let outcome = login(&live(&stub.base), None, &opts).await.expect("login");
        assert_eq!(outcome.expires_in, Some(3600));
    }

    /// A success answer that is not a token response is described, not
    /// repeated: whatever it holds may be a credential.
    #[tokio::test]
    async fn a_malformed_token_response_is_described_not_repeated() {
        let stub = stub::spawn(Some(serde_json::json!({"token": "leaky-value-1"}))).await;
        let opts = LoginOptions {
            visit: Some(fake_browser("c")),
            ..Default::default()
        };
        let err = login(&live(&stub.base), None, &opts).await.unwrap_err();
        assert!(err.contains("no access_token"), "{err}");
        assert!(!err.contains("leaky-value-1"), "{err}");
    }

    #[test]
    fn scrub_removes_every_secret_and_caps_the_length() {
        let text = format!("bad secret-value-1 and {}", "x".repeat(1000));
        let out = scrub(&text, &["secret-value-1"]);
        assert!(!out.contains("secret-value-1"));
        assert!(out.contains("[redacted]"));
        assert!(out.chars().count() <= MAX_ERROR_TEXT_CHARS + 1);
    }

    #[test]
    fn the_outcome_debug_hides_the_tokens() {
        let outcome = LoginOutcome {
            access_token: "at-secret-1".to_owned(),
            refresh_token: Some("rt-secret-2".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_in: None,
            scope: None,
            client_id: "c".to_owned(),
            registration: Registration::PreRegistered,
            client_auth: ClientAuthMethod::None,
            resource: "https://gw.example/mcp".to_owned(),
            grant: Grant::AuthorizationCode,
            dpop_jkt: None,
            authorization_details: None,
            id_jag: None,
            warnings: Vec::new(),
        };
        let shown = format!("{outcome:?}");
        assert!(!shown.contains("at-secret-1"), "{shown}");
        assert!(!shown.contains("rt-secret-2"), "{shown}");
    }
}
