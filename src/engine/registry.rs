//! The engine's target registry: what the API, and later the TUI,
//! drive. Owns one entry per target — its spec, its frame log, and its
//! live session — and the state machine connecting them.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::Serialize;
use serde_json::{Value, json};

use super::eventlog::EventLog;
use super::responders::{Responder, ResponderPolicy};
use super::session::{Session, SessionError};
use super::target::TargetSpec;

/// Where a target's session is in its lifecycle.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum SessionState {
    Idle,
    Connecting,
    Ready { negotiated_version: String },
    Failed { message: String },
}

/// One inspectable target and everything attached to it.
pub struct TargetEntry {
    pub id: String,
    pub spec: TargetSpec,
    pub events: Arc<EventLog>,
    /// Outlives any one session: a request queued by the last connect
    /// is still answerable after a reconnect.
    pub responder: Arc<Responder>,
    session: tokio::sync::Mutex<Option<Arc<Session>>>,
    state: RwLock<SessionState>,
}

impl TargetEntry {
    fn new(id: String, spec: TargetSpec, frame_buffer: usize, policy: ResponderPolicy) -> Self {
        Self {
            id,
            spec,
            events: Arc::new(EventLog::new(frame_buffer)),
            responder: Arc::new(Responder::new(policy)),
            session: tokio::sync::Mutex::new(None),
            state: RwLock::new(SessionState::Idle),
        }
    }

    pub fn state(&self) -> SessionState {
        self.state.read().expect("state lock").clone()
    }

    fn set_state(&self, state: SessionState) {
        *self.state.write().expect("state lock") = state;
    }

    /// Connect (or re-connect) this target, installing its event log as
    /// the frame tap so the whole conversation — including the version
    /// probe — is recorded from the first byte.
    pub async fn connect(&self) -> Result<SessionState, SessionError> {
        let mut slot = self.session.lock().await;
        if let Some(existing) = slot.take() {
            existing.close().await;
        }
        self.set_state(SessionState::Connecting);
        let tap: mcpg_mcp_client::tap::SharedTap = Arc::clone(&self.events) as _;
        match Session::connect(
            &self.spec,
            Some(tap),
            Arc::clone(&self.responder),
            Some(&self.events),
        )
        .await
        {
            Ok(session) => {
                let state = SessionState::Ready {
                    negotiated_version: session.negotiated_version().to_owned(),
                };
                *slot = Some(Arc::new(session));
                self.set_state(state.clone());
                Ok(state)
            }
            Err(e) => {
                self.set_state(SessionState::Failed {
                    message: e.to_string(),
                });
                Err(e)
            }
        }
    }

    pub async fn disconnect(&self) {
        if let Some(session) = self.session.lock().await.take() {
            session.close().await;
        }
        self.set_state(SessionState::Idle);
    }

    /// The live session, or `None` when this target is not connected.
    pub async fn session(&self) -> Option<Arc<Session>> {
        self.session.lock().await.clone()
    }

    /// The target as the API reports it. Credentials never appear: the bearer,
    /// the AAuth signing key and the AAuth token are each replaced with a
    /// presence flag, and header values whose names look credential-bearing are
    /// masked. A caller that already holds the credential learns nothing new; a
    /// screenshot, screen-share or exported log leaks nothing.
    ///
    /// Redaction is by field name, so a new secret added to `TargetSpec` is
    /// emitted verbatim until it is named here. The test below pins that.
    pub fn describe(&self) -> Value {
        let mut spec = serde_json::to_value(&self.spec).unwrap_or_else(|_| json!({}));
        if let Some(obj) = spec.as_object_mut() {
            let had_bearer = obj.remove("bearer").is_some();
            obj.insert("bearerConfigured".to_owned(), json!(had_bearer));
            if let Some(headers) = obj.get_mut("headers").and_then(Value::as_object_mut) {
                for (name, value) in headers.iter_mut() {
                    if is_credential_header(name) {
                        *value = json!("***");
                    }
                }
            }
            // `aauth.key` is an Ed25519 private seed and `aauth.token` is a
            // bearer credential. Redacted by name rather than by a serde
            // attribute because the same struct is persisted to the target
            // store, where both must survive a round-trip.
            if let Some(aauth) = obj.get_mut("aauth").and_then(Value::as_object_mut) {
                let had_key = aauth.remove("key").is_some();
                aauth.insert("keyConfigured".to_owned(), json!(had_key));
                let had_token = aauth.remove("token").is_some();
                aauth.insert("tokenConfigured".to_owned(), json!(had_token));
            }
        }
        json!({
            "id": self.id,
            "name": self.spec.name.clone().unwrap_or_else(|| self.id.clone()),
            "spec": spec,
            "session": self.state(),
        })
    }
}

/// Header names that carry credentials. Mirrors the key list the
/// shared `mcpg-sensitive` redactor uses; kept local so the inspector
/// takes no dependency on the gateway's crate for four strings.
fn is_credential_header(name: &str) -> bool {
    const KEYS: &[&str] = &[
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "api-key",
    ];
    let lower = name.to_ascii_lowercase();
    KEYS.contains(&lower.as_str()) || lower.contains("token") || lower.contains("secret")
}

/// Whether this process may spawn processes and reach private
/// addresses. Hosted mode is the locked-down profile from the RFC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Local,
    Hosted,
}

pub struct Engine {
    targets: RwLock<BTreeMap<String, Arc<TargetEntry>>>,
    frame_buffer: usize,
    mode: Mode,
    /// Cap on concurrently registered targets. `0` is unlimited, which
    /// is right for a local operator and wrong for a shared deployment
    /// where each target is memory and an outbound connection.
    max_targets: usize,
}

impl Engine {
    pub fn new(mode: Mode, frame_buffer: usize) -> Self {
        Self {
            targets: RwLock::new(BTreeMap::new()),
            frame_buffer,
            mode,
            max_targets: 0,
        }
    }

    /// Cap concurrently registered targets. Hosted deployments set this;
    /// a local run leaves it unlimited.
    pub fn with_max_targets(mut self, max_targets: usize) -> Self {
        self.max_targets = max_targets;
        self
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Register a target. The id is its name when it has one (the
    /// supervisor names what it pre-wires), else `target-<n>`.
    pub fn add_target(&self, mut spec: TargetSpec) -> Result<Arc<TargetEntry>, String> {
        if self.mode == Mode::Hosted {
            if spec.is_stdio() {
                return Err("stdio targets are not available in hosted mode".to_owned());
            }
            // Hosted treats every target URL as hostile. `allow_private`
            // is OVERRIDDEN, not validated: a rejection would only teach
            // the caller to omit the field, and the field is the one
            // thing standing between a shared deployment and the cloud
            // metadata endpoint. Same reason the responder cannot park
            // a request on a queue nobody is watching.
            spec.allow_private = false;
        }
        let mut targets = self.targets.write().expect("targets lock");
        if self.max_targets > 0 && targets.len() >= self.max_targets {
            return Err(format!(
                "target limit reached ({} of {}) — remove one before adding another",
                targets.len(),
                self.max_targets
            ));
        }
        let id = match &spec.name {
            Some(name) if !targets.contains_key(name) => name.clone(),
            Some(name) => return Err(format!("target '{name}' already exists")),
            None => {
                let mut n = targets.len() + 1;
                loop {
                    let candidate = format!("target-{n}");
                    if !targets.contains_key(&candidate) {
                        break candidate;
                    }
                    n += 1;
                }
            }
        };
        let policy = spec.responder.clone();
        let entry = Arc::new(TargetEntry::new(
            id.clone(),
            spec,
            self.frame_buffer,
            policy,
        ));
        targets.insert(id, Arc::clone(&entry));
        Ok(entry)
    }

    pub fn get(&self, id: &str) -> Option<Arc<TargetEntry>> {
        self.targets.read().expect("targets lock").get(id).cloned()
    }

    pub fn list(&self) -> Vec<Arc<TargetEntry>> {
        self.targets
            .read()
            .expect("targets lock")
            .values()
            .cloned()
            .collect()
    }

    /// Remove a target, closing its session. The frame log goes with
    /// it — nothing is persisted anywhere else.
    pub async fn remove(&self, id: &str) -> bool {
        let entry = self.targets.write().expect("targets lock").remove(id);
        match entry {
            Some(entry) => {
                entry.disconnect().await;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_spec(name: Option<&str>) -> TargetSpec {
        let mut spec = TargetSpec::parse_cli("http://127.0.0.1:9/mcp").unwrap();
        spec.name = name.map(str::to_owned);
        spec
    }

    #[test]
    fn ids_come_from_names_then_counter() {
        let engine = Engine::new(Mode::Local, 16);
        assert_eq!(
            engine.add_target(http_spec(Some("gateway"))).unwrap().id,
            "gateway"
        );
        assert_eq!(engine.add_target(http_spec(None)).unwrap().id, "target-2");
        // A duplicate name is a conflict, not a silent overwrite.
        assert!(engine.add_target(http_spec(Some("gateway"))).is_err());
        assert_eq!(engine.list().len(), 2);
    }

    #[test]
    fn hosted_mode_refuses_stdio_targets() {
        let engine = Engine::new(Mode::Hosted, 16);
        let spec = TargetSpec::parse_cli("stdio:some-server").unwrap();
        assert!(engine.add_target(spec).is_err());
        // …and still takes HTTP targets.
        assert!(engine.add_target(http_spec(None)).is_ok());
    }

    #[test]
    fn hosted_mode_overrides_a_caller_asking_for_private_egress() {
        // The request explicitly asks to reach a private range — which
        // in a shared deployment means the cloud metadata endpoint and
        // everything else on the internal network.
        let engine = Engine::new(Mode::Hosted, 16);
        let mut spec = http_spec(Some("evil"));
        spec.allow_private = true;
        let entry = engine.add_target(spec).unwrap();
        assert!(
            !entry.spec.allow_private,
            "hosted mode must override allow_private, not trust it"
        );

        // Local mode is the operator's own machine: inspecting a server
        // on 127.0.0.1 is the primary use, so the flag is honoured.
        let local = Engine::new(Mode::Local, 16);
        let mut spec = http_spec(Some("mine"));
        spec.allow_private = true;
        assert!(local.add_target(spec).unwrap().spec.allow_private);
    }

    /// The AAuth `key` is an Ed25519 private seed. It reached
    /// `GET /api/v1/targets`, `POST /connect` and recording export verbatim,
    /// because redaction is by field name and nothing named it.
    #[test]
    fn describe_never_leaks_the_aauth_signing_key() {
        let engine = Engine::new(Mode::Local, 16);
        let mut spec = http_spec(Some("agent-gw"));
        spec.aauth = Some(crate::engine::aauth::AauthSpec {
            key: "SEED-THAT-MUST-NEVER-BE-SERIALISED".to_owned(),
            token: Some("TOKEN-THAT-MUST-NEVER-BE-SERIALISED".to_owned()),
            issuer: Some("https://sandbox.agentprovider.dev".to_owned()),
            agent: Some("aauth:k7q3p9n2@sandbox.agentprovider.dev".to_owned()),
            person_server: None,
            credential: None,
            scopes: None,
            present: None,
            save_credential: None,
            consent_timeout_secs: 180,
            cover: Vec::new(),
            content_digest: false,
        });
        let entry = engine.add_target(spec).unwrap();

        let rendered = entry.describe().to_string();
        assert!(
            !rendered.contains("SEED-THAT-MUST-NEVER-BE-SERIALISED"),
            "aauth signing key must not appear: {rendered}"
        );
        assert!(
            !rendered.contains("TOKEN-THAT-MUST-NEVER-BE-SERIALISED"),
            "aauth token must not appear: {rendered}"
        );
        assert!(
            rendered.contains("keyConfigured"),
            "presence flag must replace the key: {rendered}"
        );
        // Non-secret identifiers stay visible — the point is redaction, not
        // hiding which provider a target uses.
        assert!(rendered.contains("sandbox.agentprovider.dev"));
    }

    #[test]
    fn describe_never_leaks_credentials() {
        let engine = Engine::new(Mode::Local, 16);
        let mut spec = http_spec(Some("gw"));
        spec.bearer = Some("super-secret-token".to_owned());
        spec.headers
            .insert("X-Api-Key".to_owned(), "another-secret".to_owned());
        spec.headers
            .insert("X-Env".to_owned(), "staging".to_owned());
        let entry = engine.add_target(spec).unwrap();

        let described = entry.describe();
        let rendered = described.to_string();
        assert!(
            !rendered.contains("super-secret-token"),
            "bearer must not appear: {rendered}"
        );
        assert!(
            !rendered.contains("another-secret"),
            "credential header must not appear: {rendered}"
        );
        assert_eq!(
            described["spec"]["bearerConfigured"],
            serde_json::json!(true)
        );
        assert_eq!(described["spec"]["headers"]["X-Api-Key"], "***");
        // A non-credential header is still readable — the point is
        // debugging, so only the secrets are masked.
        assert_eq!(described["spec"]["headers"]["X-Env"], "staging");
    }

    #[test]
    fn credential_header_names_are_recognized() {
        assert!(is_credential_header("Authorization"));
        assert!(is_credential_header("x-api-key"));
        assert!(is_credential_header("X-Session-Token"));
        assert!(is_credential_header("client-secret"));
        assert!(!is_credential_header("X-Env"));
        assert!(!is_credential_header("content-type"));
    }

    #[tokio::test]
    async fn remove_reports_whether_it_removed_anything() {
        let engine = Engine::new(Mode::Local, 16);
        engine.add_target(http_spec(Some("a"))).unwrap();
        assert!(engine.remove("a").await);
        assert!(!engine.remove("a").await);
        assert!(engine.get("a").is_none());
    }
}
