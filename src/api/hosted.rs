//! Hosted-mode authentication and per-user isolation.
//!
//! The local inspector serves one operator on loopback behind a per-boot
//! token. A hosted instance serves strangers who do not know each other, so
//! two things change:
//!
//! - **Who you are** comes from an OIDC provider rather than from possessing
//!   a token printed on someone's terminal. The SPA gets a login redirect and
//!   an `HttpOnly` cookie; an API client presents the IdP's access token as a
//!   bearer, verified against the IdP's JWKS.
//! - **What you can see** is scoped to you. Each authenticated subject gets
//!   its own [`Engine`], so targets — and the credentials attached to them —
//!   never appear in another user's list. Nothing is persisted: sessions live
//!   in memory and die with the process, which is the property that keeps
//!   this deployment free of a database, of tenant-scoped rows, and of a
//!   secret at rest.
//!
//! The OIDC client is `mcpg-cli-core`'s, the same one the control plane and
//! `mcpg login` use, so a token this accepts is a token those accept.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use mcpg_cli_core::oidc::{OidcClient, PkcePair, random_state};

use crate::engine::registry::{Engine, Mode};

/// How long an unfinished login may sit before its PKCE verifier is dropped.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// How long a session survives without a request.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(12 * 3600);
/// Cookie carrying the session id.
pub const SESSION_COOKIE: &str = "mcpg_inspector_session";

/// One signed-in user and the workspace that belongs to them.
pub struct UserSession {
    pub id: String,
    /// OIDC `sub`. Stable for the user at this issuer, and the identity
    /// everything else keys on.
    pub subject: String,
    pub email: Option<String>,
    pub engine: Arc<Engine>,
    pub created: Instant,
    last_seen: Mutex<Instant>,
}

impl UserSession {
    fn touch(&self) {
        *self.last_seen.lock().expect("last_seen lock") = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_seen.lock().expect("last_seen lock").elapsed()
    }
}

/// A login in flight: the PKCE verifier the callback will need, held under
/// the `state` value the provider will echo back.
struct Pending {
    pkce: PkcePair,
    created: Instant,
    /// Where to send the browser once the exchange succeeds. Same-origin
    /// path only — never an absolute URL, or the login becomes an open
    /// redirect.
    next: String,
}

pub struct HostedAuth {
    client: OidcClient,
    /// Public origin this instance is reached at, e.g.
    /// `https://inspector.mcpg.cloud`. The redirect URI and the cookie's
    /// `Secure` attribute both derive from it.
    public_url: String,
    sessions: RwLock<HashMap<String, Arc<UserSession>>>,
    pending: Mutex<HashMap<String, Pending>>,
    frame_buffer: usize,
    max_sessions: usize,
    max_targets: usize,
}

/// Why a login could not be completed. The wording is what a stranger sees,
/// so it says what happened without describing the internals.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    UnknownState,
    Exchange(String),
    Capacity,
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownState => write!(
                f,
                "this sign-in link is no longer valid — start again from the home page"
            ),
            Self::Exchange(detail) => write!(f, "sign-in failed: {detail}"),
            Self::Capacity => write!(f, "the service is at capacity — try again in a few minutes"),
        }
    }
}

impl HostedAuth {
    pub fn new(
        issuer: url::Url,
        client_id: String,
        client_secret: Option<String>,
        public_url: String,
        frame_buffer: usize,
        max_sessions: usize,
        max_targets: usize,
    ) -> Self {
        let public_url = public_url.trim_end_matches('/').to_owned();
        let redirect_uri = format!("{public_url}/auth/callback");
        Self {
            client: OidcClient::new(issuer, client_id, client_secret, redirect_uri),
            public_url,
            sessions: RwLock::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            frame_buffer,
            max_sessions,
            max_targets,
        }
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    /// `Secure` is set for an https origin and omitted otherwise, because a
    /// browser silently drops a `Secure` cookie on plain http and the
    /// session would appear to succeed and then not exist.
    fn cookie_secure(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    /// Begin a login: mint PKCE + state, remember them, and return the URL
    /// to send the browser to.
    pub async fn begin(&self, next: &str) -> Result<String, LoginError> {
        self.sweep();
        let pkce = PkcePair::generate();
        let state = random_state();
        let url = self
            .client
            .authorize_url(&pkce, &state, &["openid", "email", "profile"])
            .await
            .map_err(|e| LoginError::Exchange(e.to_string()))?;
        self.pending.lock().expect("pending lock").insert(
            state,
            Pending {
                pkce,
                created: Instant::now(),
                next: safe_next(next),
            },
        );
        Ok(url.to_string())
    }

    /// Finish a login. Returns the new session and where to send the browser.
    ///
    /// The `state` lookup is a take, not a read: a code may be redeemed once,
    /// and a replayed callback must find nothing.
    pub async fn complete(
        &self,
        code: &str,
        state: &str,
    ) -> Result<(Arc<UserSession>, String), LoginError> {
        let pending = self
            .pending
            .lock()
            .expect("pending lock")
            .remove(state)
            .ok_or(LoginError::UnknownState)?;
        if pending.created.elapsed() > PENDING_TTL {
            return Err(LoginError::UnknownState);
        }

        let tokens = self
            .client
            .exchange_code(code, &pending.pkce.verifier)
            .await
            .map_err(|e| LoginError::Exchange(e.to_string()))?;
        // Verified, not merely decoded: the id_token is checked against the
        // issuer's JWKS before any of its claims becomes an identity.
        let claims = self
            .client
            .verify_id_token(&tokens.id_token)
            .await
            .map_err(|e| LoginError::Exchange(e.to_string()))?;

        let session = self.open_session(claims.sub.clone(), Some(claims.resolved_email()))?;
        Ok((session, pending.next))
    }

    /// Create (or reuse) the session for a subject.
    ///
    /// One session per subject: signing in twice from two browsers shares a
    /// workspace rather than silently doubling a user's quota.
    fn open_session(
        &self,
        subject: String,
        email: Option<String>,
    ) -> Result<Arc<UserSession>, LoginError> {
        self.sweep();
        let mut sessions = self.sessions.write().expect("sessions lock");
        if let Some(existing) = sessions.values().find(|s| s.subject == subject) {
            existing.touch();
            return Ok(Arc::clone(existing));
        }
        if self.max_sessions > 0 && sessions.len() >= self.max_sessions {
            return Err(LoginError::Capacity);
        }
        let id = mcpg_aauth_core::rand_token(256);
        let session = Arc::new(UserSession {
            id: id.clone(),
            subject,
            email,
            engine: Arc::new(
                Engine::new(Mode::Hosted, self.frame_buffer).with_max_targets(self.max_targets),
            ),
            created: Instant::now(),
            last_seen: Mutex::new(Instant::now()),
        });
        sessions.insert(id, Arc::clone(&session));
        Ok(session)
    }

    /// Resolve a session id, refreshing its idle clock.
    pub fn lookup(&self, id: &str) -> Option<Arc<UserSession>> {
        let session = self
            .sessions
            .read()
            .expect("sessions lock")
            .get(id)
            .cloned()?;
        if session.idle_for() > SESSION_IDLE_TTL {
            return None;
        }
        session.touch();
        Some(session)
    }

    /// Resolve an IdP access token to a session, for API clients that cannot
    /// hold a cookie. The token is verified against the issuer's JWKS, and
    /// its `sub` names the same workspace the browser flow would open.
    pub async fn lookup_bearer(&self, token: &str) -> Option<Arc<UserSession>> {
        #[derive(serde::Deserialize)]
        struct Sub {
            sub: String,
            #[serde(default)]
            email: Option<String>,
        }
        // Audience is not constrained here: the deployment's IdP client is
        // the audience by construction, and the CP applies the same posture.
        let claims: Sub = self
            .client
            .verify_signed_claims(token, &[], false)
            .await
            .ok()?;
        self.open_session(claims.sub, claims.email).ok()
    }

    /// Open a session without a provider round trip.
    ///
    /// Test-only, and named so: it is how an integration test gets a caller
    /// past the sign-in boundary without standing up an IdP. It cannot be
    /// reached from a request — nothing routes to it.
    #[doc(hidden)]
    pub fn open_session_for_test(&self, subject: String) -> Arc<UserSession> {
        self.open_session(subject, None)
            .expect("test session within capacity")
    }

    pub fn end(&self, id: &str) {
        self.sessions.write().expect("sessions lock").remove(id);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().expect("sessions lock").len()
    }

    /// Drop expired logins-in-flight and idle sessions.
    ///
    /// Called on the login paths rather than from a timer: this process has
    /// no background reaper, and the moments that matter — a new login, a new
    /// session — are exactly when the maps grow.
    fn sweep(&self) {
        self.pending
            .lock()
            .expect("pending lock")
            .retain(|_, p| p.created.elapsed() <= PENDING_TTL);
        self.sessions
            .write()
            .expect("sessions lock")
            .retain(|_, s| s.idle_for() <= SESSION_IDLE_TTL);
    }

    /// `Set-Cookie` for a freshly opened session.
    pub fn session_cookie(&self, id: &str) -> String {
        let secure = if self.cookie_secure() { "; Secure" } else { "" };
        // SameSite=Lax, not None: the cookie must survive the top-level
        // redirect back from the provider, and must not ride a cross-site
        // subrequest.
        format!(
            "{SESSION_COOKIE}={id}; HttpOnly{secure}; SameSite=Lax; Path=/; Max-Age={}",
            SESSION_IDLE_TTL.as_secs()
        )
    }

    pub fn clearing_cookie(&self) -> String {
        let secure = if self.cookie_secure() { "; Secure" } else { "" };
        format!("{SESSION_COOKIE}=; HttpOnly{secure}; SameSite=Lax; Path=/; Max-Age=0")
    }
}

/// Read the session id out of a `Cookie` header.
pub fn session_from_cookies(header: Option<&str>) -> Option<String> {
    header?.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == SESSION_COOKIE).then(|| value.trim().to_owned())
    })
}

/// Constrain a post-login redirect to a same-origin path.
///
/// Anything that could leave this origin — an absolute URL, a
/// scheme-relative `//host`, a backslash some browsers normalize to `/` — is
/// replaced by `/`. A login endpoint that forwards to an attacker-supplied
/// URL is an open redirect, and it is worth more here than usual because the
/// user has just been asked to trust the page.
fn safe_next(next: &str) -> String {
    let candidate = next.trim();
    if candidate.starts_with('/')
        && !candidate.starts_with("//")
        && !candidate.starts_with("/\\")
        && !candidate.contains('\\')
    {
        return candidate.to_owned();
    }
    "/".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> HostedAuth {
        HostedAuth::new(
            "https://idp.example".parse().unwrap(),
            "mcpg-inspector".to_owned(),
            None,
            "https://inspector.mcpg.cloud".to_owned(),
            64,
            2,
            3,
        )
    }

    #[test]
    fn each_subject_gets_its_own_workspace() {
        let auth = auth();
        let a = auth.open_session("user-a".into(), None).unwrap();
        let b = auth.open_session("user-b".into(), None).unwrap();
        assert_ne!(a.id, b.id);

        let spec: crate::engine::target::TargetSpec =
            serde_json::from_value(serde_json::json!({"url": "https://one.example/mcp"})).unwrap();
        assert!(a.engine.add_target(spec).is_ok());
        assert_eq!(a.engine.list().len(), 1);
        assert_eq!(
            b.engine.list().len(),
            0,
            "one user's targets must not appear in another's workspace"
        );
    }

    #[test]
    fn signing_in_twice_reuses_the_workspace() {
        let auth = auth();
        let first = auth.open_session("user-a".into(), None).unwrap();
        let second = auth.open_session("user-a".into(), None).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(auth.session_count(), 1);
    }

    #[test]
    fn capacity_is_refused_rather_than_exceeded() {
        let auth = auth();
        auth.open_session("a".into(), None).unwrap();
        auth.open_session("b".into(), None).unwrap();
        assert!(matches!(
            auth.open_session("c".into(), None),
            Err(LoginError::Capacity)
        ));
    }

    #[test]
    fn a_workspace_caps_its_targets() {
        let auth = auth();
        let session = auth.open_session("a".into(), None).unwrap();
        for n in 0..3 {
            let spec: crate::engine::target::TargetSpec = serde_json::from_value(
                serde_json::json!({"url": format!("https://s{n}.example/mcp")}),
            )
            .unwrap();
            assert!(session.engine.add_target(spec).is_ok());
        }
        let spec: crate::engine::target::TargetSpec =
            serde_json::from_value(serde_json::json!({"url": "https://over.example/mcp"})).unwrap();
        let err = match session.engine.add_target(spec) {
            Err(e) => e,
            Ok(_) => panic!("the cap must refuse a fourth target"),
        };
        assert!(err.contains("target limit reached"), "{err}");
    }

    /// Hosted workspaces inherit the locked-down profile — a per-session
    /// engine that forgot its mode would re-open stdio spawning.
    #[test]
    fn a_workspace_is_hosted_mode() {
        let auth = auth();
        let session = auth.open_session("a".into(), None).unwrap();
        assert_eq!(session.engine.mode(), Mode::Hosted);
        let spec: crate::engine::target::TargetSpec =
            serde_json::from_value(serde_json::json!({"command": "sh", "args": ["-c", "echo"]}))
                .unwrap();
        assert!(session.engine.add_target(spec).is_err());
    }

    #[test]
    fn a_session_can_be_looked_up_and_ended() {
        let auth = auth();
        let session = auth.open_session("a".into(), None).unwrap();
        assert!(auth.lookup(&session.id).is_some());
        auth.end(&session.id);
        assert!(auth.lookup(&session.id).is_none());
        assert!(auth.lookup("not-a-session").is_none());
    }

    #[test]
    fn the_cookie_is_httponly_and_scoped() {
        let auth = auth();
        let cookie = auth.session_cookie("abc");
        assert!(cookie.starts_with("mcpg_inspector_session=abc"));
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
        assert!(auth.clearing_cookie().contains("Max-Age=0"));
    }

    /// A `Secure` cookie is dropped by the browser over plain http, which
    /// would look like a login that succeeded and then did not exist.
    #[test]
    fn plain_http_origins_omit_secure() {
        let auth = HostedAuth::new(
            "https://idp.example".parse().unwrap(),
            "id".into(),
            None,
            "http://localhost:7846".into(),
            64,
            0,
            0,
        );
        assert!(!auth.session_cookie("abc").contains("Secure"));
    }

    #[test]
    fn cookies_are_parsed_out_of_a_crowded_header() {
        assert_eq!(
            session_from_cookies(Some("a=1; mcpg_inspector_session=xyz; b=2")).as_deref(),
            Some("xyz")
        );
        assert_eq!(
            session_from_cookies(Some("mcpg_inspector_session=only")).as_deref(),
            Some("only")
        );
        assert_eq!(session_from_cookies(Some("other=1")), None);
        assert_eq!(session_from_cookies(None), None);
    }

    /// The post-login redirect is attacker-influenced, so anything that
    /// could leave this origin collapses to `/`.
    #[test]
    fn the_post_login_redirect_cannot_leave_this_origin() {
        assert_eq!(safe_next("/targets/1"), "/targets/1");
        assert_eq!(safe_next("/"), "/");
        for hostile in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/redirect\\evil",
            "javascript:alert(1)",
            "",
        ] {
            assert_eq!(safe_next(hostile), "/", "{hostile} must not survive");
        }
    }
}
