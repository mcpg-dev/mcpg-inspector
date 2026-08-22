//! Session-token auth and origin validation.
//!
//! Order matters: origin is checked before the token, so a browser
//! driven by a hostile page is refused on the origin regardless of
//! whether it guessed a token. A request with no `Origin` header
//! (curl, CI, the TUI) passes the origin gate and is stopped by the
//! token instead.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::ApiState;

/// How this instance authenticates callers.
pub enum AuthPolicy {
    /// A per-boot (or operator-pinned) bearer token, required on every
    /// route. The allow-listed origins are derived from the bind.
    Token {
        token: String,
        allowed_origins: Vec<String>,
    },
    /// No auth. Only reachable when the listener is bound to loopback —
    /// `serve` refuses the combination otherwise.
    None { allowed_origins: Vec<String> },
    /// OIDC, the hosted profile. Identity comes from the provider, and
    /// each subject gets its own workspace — see [`super::hosted`].
    Oidc {
        hosted: Arc<super::hosted::HostedAuth>,
        allowed_origins: Vec<String>,
    },
}

impl AuthPolicy {
    pub fn token(token: String, bind: SocketAddr) -> Self {
        Self::Token {
            token,
            allowed_origins: default_allowed_origins(bind),
        }
    }

    pub fn none(bind: SocketAddr) -> Self {
        Self::None {
            allowed_origins: default_allowed_origins(bind),
        }
    }

    /// The hosted profile: identity from an OIDC provider, origins
    /// derived from the public URL rather than from the bind (the bind is
    /// behind a proxy and is never what a browser sends).
    pub fn oidc(hosted: Arc<super::hosted::HostedAuth>) -> Self {
        let allowed_origins = vec![hosted.public_url().to_owned()];
        Self::Oidc {
            hosted,
            allowed_origins,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::None { .. } => "none",
            Self::Oidc { .. } => "oidc",
        }
    }

    pub fn hosted(&self) -> Option<&Arc<super::hosted::HostedAuth>> {
        match self {
            Self::Oidc { hosted, .. } => Some(hosted),
            _ => None,
        }
    }

    fn allowed_origins(&self) -> &[String] {
        match self {
            Self::Token {
                allowed_origins, ..
            }
            | Self::None { allowed_origins }
            | Self::Oidc {
                allowed_origins, ..
            } => allowed_origins,
        }
    }

    fn expected_token(&self) -> Option<&str> {
        match self {
            Self::Token { token, .. } => Some(token),
            Self::None { .. } | Self::Oidc { .. } => None,
        }
    }
}

/// Origins a browser may legitimately carry when talking to this
/// instance. `localhost` resolves to either IP family, so all three
/// loopback spellings are listed; a wildcard bind adds the spellings a
/// browser would actually send for it. An empty list means deny — never
/// allow-all (the fail-open branch that made the official tool's
/// middleware sharp).
fn default_allowed_origins(bind: SocketAddr) -> Vec<String> {
    let port = bind.port();
    if bind.ip().is_loopback() || bind.ip().is_unspecified() {
        return vec![
            format!("http://localhost:{port}"),
            format!("http://127.0.0.1:{port}"),
            format!("http://[::1]:{port}"),
        ];
    }
    vec![format!("http://{bind}")]
}

/// Reject a browser request whose `Origin` is not allow-listed, then a
/// request without a valid token. Runs on every `/api` route and on the
/// SPA itself.
pub async fn guard(
    State(state): State<ApiState>,
    headers: HeaderMap,
    // `Option<ConnectInfo<…>>` does not satisfy axum 0.8's
    // `OptionalFromRequestParts`; ConnectInfo rides the request
    // extensions, so it is extracted as an optional Extension — the
    // same shape the gateway's transports use for the same reason.
    peer: Option<axum::extract::Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Rate limiting comes first: a limiter that only counts requests
    // which already passed auth does not limit the traffic that costs
    // the most to reject.
    if state.limiter.enabled()
        && let Some(peer) = peer
        && !state.limiter.check(client_ip(&headers, peer.0.0))
    {
        return refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many requests from this address — slow down",
        );
    }

    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok())
        && !state
            .auth
            .allowed_origins()
            .iter()
            .any(|allowed| allowed == origin)
    {
        return refuse(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "request blocked to prevent DNS-rebinding attacks",
        );
    }

    if let Some(expected) = state.auth.expected_token() {
        let presented = bearer(&headers).or_else(|| query_token(request.uri().query()));
        let ok = presented
            .as_deref()
            .is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()));
        if !ok {
            return refuse(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or invalid session token",
            );
        }
    }

    // Hosted: resolve the caller, but do not require one.
    //
    // A hosted inspector is a public tool. The page, the pre-wired targets
    // and everything readable are open to anyone — a sign-up wall on a tool
    // whose first job is a first impression is the wrong trade. Signing in
    // buys exactly one thing: asking the service to dial an address the
    // caller chose. Handlers enforce that boundary; the guard only
    // establishes who is asking.
    let mut request = request;
    if let Some(hosted) = state.auth.hosted() {
        let cookie = headers.get("cookie").and_then(|v| v.to_str().ok());
        let session = match super::hosted::session_from_cookies(cookie) {
            Some(id) => hosted.lookup(&id),
            None => match bearer(&headers) {
                Some(token) => hosted.lookup_bearer(&token).await,
                None => None,
            },
        };
        match session {
            Some(session) => {
                request.extensions_mut().insert(Arc::clone(&session.engine));
                request
                    .extensions_mut()
                    .insert(Identity::User(Arc::clone(&session)));
                request.extensions_mut().insert(session);
            }
            None => {
                // Anonymous callers share the workspace holding whatever the
                // operator pre-wired. Adding to it needs an identity, so one
                // anonymous caller cannot change what another sees.
                request.extensions_mut().insert(Arc::clone(&state.engine));
                request.extensions_mut().insert(Identity::Anonymous);
            }
        }
    } else {
        request.extensions_mut().insert(Identity::Operator);
        request.extensions_mut().insert(Arc::clone(&state.engine));
    }

    next.run(request).await
}

/// Who is making a request, as the guard resolved them.
///
/// Local runs have exactly one caller and every surface is theirs. A hosted
/// instance has two kinds, and the difference between them is deliberately
/// narrow: an anonymous caller may read anything the operator published, and
/// may not make the service dial an address of their choosing.
#[derive(Clone)]
pub enum Identity {
    /// A local run: the operator who already holds the session token.
    Operator,
    /// A hosted caller who has not signed in.
    Anonymous,
    /// A hosted caller with a provider-verified identity.
    User(Arc<super::hosted::UserSession>),
}

impl Identity {
    /// Whether this caller may have the service dial a target they supplied.
    ///
    /// This is the abuse surface, and the only thing signing in buys: an
    /// outbound dialer on a public origin, driveable by anyone, is what
    /// turns a developer tool into someone else's proxy.
    pub fn may_dial_arbitrary_targets(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    /// The OIDC subject, when there is one.
    pub fn subject(&self) -> Option<&str> {
        match self {
            Self::User(session) => Some(&session.subject),
            Self::Operator | Self::Anonymous => None,
        }
    }
}

/// The address to charge a request to. `X-Forwarded-For` is honoured
/// only in hosted mode, where an edge proxy fronts the service and
/// every socket peer would otherwise be that proxy; trusting it on a
/// local bind would let any caller spoof its own bucket.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> std::net::IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| peer.ip())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::to_owned)
}

/// `?token=…` exists because an `EventSource` cannot set headers and
/// the first page load has no token yet. Loopback-only by construction:
/// the origin gate already refused any cross-origin caller.
fn query_token(query: Option<&str>) -> Option<String> {
    query?.split('&').find_map(|pair| {
        pair.strip_prefix("token=")
            .map(|v| percent_decode(v).unwrap_or_else(|| v.to_owned()))
    })
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn refuse(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_bind_allows_all_three_spellings() {
        let origins = default_allowed_origins(addr("127.0.0.1:7846"));
        assert!(origins.contains(&"http://localhost:7846".to_owned()));
        assert!(origins.contains(&"http://127.0.0.1:7846".to_owned()));
        assert!(origins.contains(&"http://[::1]:7846".to_owned()));
    }

    #[test]
    fn wildcard_and_explicit_binds_have_origins_too() {
        // A wildcard bind is reached *as* loopback by a local browser.
        assert!(
            default_allowed_origins(addr("0.0.0.0:7846"))
                .contains(&"http://127.0.0.1:7846".to_owned())
        );
        // An explicit non-loopback bind allows exactly itself — never
        // an empty list, which the guard would have to treat as deny.
        let origins = default_allowed_origins(addr("10.1.2.3:7846"));
        assert_eq!(origins, vec!["http://10.1.2.3:7846".to_owned()]);
    }

    #[test]
    fn token_comparison_is_length_and_content_exact() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn query_token_extracts_and_decodes() {
        assert_eq!(query_token(Some("token=abc")), Some("abc".to_owned()));
        assert_eq!(
            query_token(Some("since=3&token=a%2Bb")),
            Some("a+b".to_owned())
        );
        assert_eq!(query_token(Some("since=3")), None);
        assert_eq!(query_token(None), None);
    }
}
