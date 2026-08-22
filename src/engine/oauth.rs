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

use std::collections::HashMap;
use std::time::Duration;

use mcpg_mcp_client::auth::DiscoveredOauth;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How long to wait for the human to finish signing in.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

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

#[derive(Default)]
pub struct LoginOptions {
    /// Pre-registered client. Absent means register dynamically, which
    /// fails cleanly if the server does not offer it.
    pub client_id: Option<String>,
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
}

/// A token, and enough about how it was obtained to explain it.
#[derive(Debug, Serialize)]
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
    pub resource: String,
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

/// RFC 6749 §5.1 token response.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
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

/// Run the login. Returns the token, or why it could not be obtained.
pub async fn login(
    discovered: &DiscoveredOauth,
    challenge_scope: Option<&str>,
    opts: &LoginOptions,
) -> Result<LoginOutcome, String> {
    let authorization_endpoint = discovered.authorization_endpoint.as_deref().ok_or(
        "the authorization server advertises no authorization_endpoint, so there is \
         no interactive login to drive — it issues tokens machine-to-machine only",
    )?;
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("cannot bind a loopback redirect listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("listener has no address: {e}"))?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", addr.port());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("client build failed: {e}"))?;

    // Registration order, most to least preferred: a client the operator
    // already registered; this instance's client-metadata document, if it
    // has a public origin and the server takes one; then RFC 7591 dynamic
    // registration. Each earlier option leaves less state behind.
    let (client_id, registration) = match (&opts.client_id, &opts.public_url) {
        (Some(id), _) => (id.clone(), Registration::PreRegistered),
        (None, Some(public))
            if discovered.client_id_metadata_document_supported && !public.is_empty() =>
        {
            (
                format!("{}{CLIENT_METADATA_PATH}", public.trim_end_matches('/')),
                Registration::ClientIdMetadata,
            )
        }
        (None, _) => {
            let endpoint = discovered.registration_endpoint.as_deref().ok_or(
                "no --client-id given and the authorization server offers neither \
                 client-ID metadata documents nor dynamic client registration; \
                 register the inspector manually and pass its id",
            )?;
            (
                register(&client, endpoint, &redirect_uri).await?,
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
        q.append_pair("client_id", &client_id);
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("state", &state);
        q.append_pair("code_challenge", &pkce.challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("resource", &discovered.resource);
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
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

    let joined_scopes = scopes.join(" ");
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", client_id.as_str()),
        ("code_verifier", pkce.verifier.as_str()),
        // Repeated at the exchange, not only at the authorization request:
        // RFC 8707 §2.2 is what binds the issued token's audience.
        ("resource", discovered.resource.as_str()),
    ];
    if !joined_scopes.is_empty() {
        form.push(("scope", joined_scopes.as_str()));
    }

    let resp = client
        .post(&discovered.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token request to {} failed: {e}", discovered.token_endpoint))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "token endpoint returned HTTP {status}: {}",
            body.trim()
        ));
    }
    let tokens: TokenResponse = serde_json::from_str(&body).map_err(|e| {
        format!(
            "token response is not a token response ({e}): {}",
            body.trim()
        )
    })?;

    Ok(LoginOutcome {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type.unwrap_or_else(|| "Bearer".to_owned()),
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        client_id,
        registration,
        resource: discovered.resource.clone(),
    })
}

/// RFC 7591 dynamic client registration for a public client.
async fn register(
    client: &reqwest::Client,
    endpoint: &str,
    redirect_uri: &str,
) -> Result<String, String> {
    let body = serde_json::json!({
        "client_name": "mcpg-inspector",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        // Public client: the secret would live in a CLI a user can read,
        // which is what PKCE exists to make unnecessary.
        "token_endpoint_auth_method": "none",
    });
    let resp = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("client registration at {endpoint} failed: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "client registration returned HTTP {status}: {}",
            text.trim()
        ));
    }
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("client_id")
                .and_then(|c| c.as_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            format!(
                "client registration response has no client_id: {}",
                text.trim()
            )
        })
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
            client_id_metadata_document_supported: false,
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
            pub token_form: Option<std::collections::HashMap<String, String>>,
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
                         Json(body): Json<serde_json::Value>| async move {
                            seen.lock().unwrap().registration = Some(body);
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
                         body: String| async move {
                            let form: std::collections::HashMap<String, String> =
                                url::form_urlencoded::parse(body.as_bytes())
                                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                    .collect();
                            seen.lock().unwrap().token_form = Some(form);
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
            client_id_metadata_document_supported: false,
        }
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
}
