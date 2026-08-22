//! AAuth client identity — signing outbound MCP requests.
//!
//! AAuth (`draft-hardt-oauth-aauth-protocol`) gives an agent a portable
//! cryptographic identity, `aauth:local@domain`, bound to an Ed25519 key.
//! Every request carries an RFC 9421 signature, so the credential is
//! proof-of-possession: a captured token is inert without the key.
//!
//! There is no MCP binding in the AAuth drafts and none is needed — AAuth
//! signs at the HTTP layer and leaves JSON-RPC untouched. The inspector
//! implements the **identity-based** access mode (the agent token *is* the
//! credential), which is the mode mcpg's `dev.mcpg.identity.aauth` plugin
//! verifies. The consent-bearing modes (resource-managed, PS-asserted,
//! federated) are surfaced as diagnostics by the auth lab rather than driven,
//! because they need a person server and an interactive approval.
//!
//! Crypto and wire format come from `mcpg-aauth-core`, the same crate the
//! gateway plugin verifies with, so a signature this module produces and a
//! signature that plugin accepts are built from one implementation.

use std::sync::Mutex;

use mcpg_aauth_core as aauth;
use mcpg_mcp_client::signer::{RequestSigner, SigningRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Agent-token lifetime when the inspector self-issues, and the margin
/// before expiry at which it re-mints.
const SELF_ISSUED_TTL_SECS: u64 = 600;
const REFRESH_MARGIN_SECS: u64 = 60;

/// AAuth identity for one target.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AauthSpec {
    /// Ed25519 private key as an unpadded base64url 32-byte seed. Required:
    /// the signature is only meaningful with the key the token names.
    pub key: String,
    /// A pre-minted `aa-agent+jwt` from an agent provider. When absent the
    /// inspector self-issues one (the spec's self-hosted-agent bootstrap),
    /// which requires `issuer` and `agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Agent provider URL, e.g. `https://agents.example.com`. Self-issued
    /// tokens claim this as `iss`, and a verifier resolves the JWKS under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Agent identifier `aauth:local@domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The agent's person server, claimed as `ps` in a self-issued agent
    /// token and dialled for person / auth tokens when `credential` asks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_server: Option<String>,
    /// Which AAuth credential to present in `Signature-Key`:
    /// `agent` (default — the agent token, identity-based access),
    /// `person` (a person token from `person_server` for the target,
    /// person-identity access), or `auth` (a person token, then a resource
    /// token from the target's authorization endpoint for `scopes`, then an
    /// auth token from `person_server` — PS-authorization access). The
    /// consent-bearing modes may defer: the inspector prints the interaction
    /// URL and code and polls until the person decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<AauthCredential>,
    /// Space-separated scope values to request when `credential: auth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<String>,
    /// A person or auth token obtained earlier, presented as-is in place of
    /// acquiring one (its `cnf.jwk` must be this key). Skips the person
    /// server entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<String>,
    /// After acquiring a person / auth token, also write it to this file
    /// (mode 0600), so a later run can `present` it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_credential: Option<std::path::PathBuf>,
    /// How long to wait for a deferred (consent) answer, seconds.
    #[serde(default = "default_consent_timeout_secs")]
    pub consent_timeout_secs: u64,
    /// Additional header names to cover in the signature, beyond the four
    /// the profile mandates plus the body-integrity headers. A resource
    /// advertises these in `additional_signature_components`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cover: Vec<String>,
    /// Send and cover `Content-Digest` on requests with a body.
    ///
    /// On by default, and it matters more for MCP than for a REST API:
    /// every JSON-RPC call is `POST /mcp`, so without the digest the
    /// signature base for `tools/list` and for a `tools/call` of a
    /// destructive tool are byte-identical — the signature would say
    /// nothing about which call was made.
    ///
    /// This commits the *agent* to a body. It does not by itself stop a
    /// transplant: the digest only bites where the receiver checks it
    /// against the bytes it read, and an MCP identity resolver never sees
    /// the body. Signing it correctly is the half a client can own.
    #[serde(default = "default_true")]
    pub content_digest: bool,
}

fn default_true() -> bool {
    true
}

fn default_consent_timeout_secs() -> u64 {
    180
}

/// The AAuth credential presented in `Signature-Key`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AauthCredential {
    #[default]
    Agent,
    Person,
    Auth,
}

impl std::str::FromStr for AauthCredential {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "agent" => Ok(Self::Agent),
            "person" => Ok(Self::Person),
            "auth" => Ok(Self::Auth),
            other => Err(format!(
                "aauth credential must be agent, person, or auth (got {other:?})"
            )),
        }
    }
}

/// Whether the presented agent token was supplied or minted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TokenOrigin {
    Provided,
    SelfIssued,
}

/// What the inspector will present to a target, for display in the UI. The
/// key never appears here.
#[derive(Clone, Debug, Serialize)]
pub struct AauthIdentity {
    pub agent: String,
    pub issuer: Option<String>,
    pub thumbprint: String,
    /// The JOSE `alg` of the presented token. Fixed: AAuth -10 §5.2.2 admits
    /// exactly one fully-specified identifier this build can produce.
    pub alg: String,
    pub origin: TokenOrigin,
    pub covers: Vec<String>,
    /// Which credential kind is presented.
    pub credential: AauthCredential,
    /// The `typ` of the token currently presented, once acquired.
    pub presented_typ: Option<String>,
}

/// A token obtained from a person server (person or auth), presented in
/// place of the agent token.
struct PresentedToken {
    jwt: String,
    typ: String,
}

/// A self-issued token and the moment it stops being usable.
struct MintedToken {
    jwt: String,
    expires_at: u64,
}

pub struct AauthSigner {
    key: aauth::jwk::SigningKey,
    jwk: aauth::jwk::Jwk,
    thumbprint: String,
    /// Set when the operator supplied a token; then nothing is minted.
    provided: Option<String>,
    issuer: Option<String>,
    agent: String,
    person_server: Option<String>,
    credential: AauthCredential,
    scopes: Option<String>,
    save_credential: Option<std::path::PathBuf>,
    consent_timeout: std::time::Duration,
    cover: Vec<String>,
    content_digest: bool,
    minted: Mutex<Option<MintedToken>>,
    presented: Mutex<Option<PresentedToken>>,
}

impl std::fmt::Debug for AauthSigner {
    /// Hand-written so no future derive can print the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AauthSigner")
            .field("agent", &self.agent)
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

impl AauthSigner {
    pub fn new(spec: &AauthSpec) -> Result<Self, String> {
        let seed: [u8; 32] = aauth::b64::decode_fixed(spec.key.trim())
            .map_err(|e| format!("aauth.key is not a base64url 32-byte Ed25519 seed: {e}"))?;
        let key = aauth::jwk::SigningKey::from_bytes(&seed);
        let jwk = aauth::jwk::Jwk::from_verifying_key(&key.verifying_key());
        let thumbprint = jwk
            .thumbprint()
            .map_err(|e| format!("aauth key thumbprint: {e}"))?;

        // The agent identity is whatever the presented token asserts; only
        // when self-issuing does the operator get to name it.
        let agent = match (&spec.token, &spec.agent) {
            (Some(token), _) => {
                let decoded = aauth::jwt::decode(token)
                    .map_err(|e| format!("aauth.token is not a well-formed JWT: {e}"))?;
                let sub = decoded
                    .payload
                    .get("sub")
                    .and_then(|v| v.as_str())
                    .ok_or("aauth.token has no `sub` claim")?
                    .to_owned();
                // A token whose `cnf.jwk` names a different key would be
                // rejected by every verifier; catching it here says why.
                if let Some(cnf) = decoded.payload.pointer("/cnf/jwk")
                    && let Ok(bound) = serde_json::from_value::<aauth::jwk::Jwk>(cnf.clone())
                    && bound.thumbprint().ok().as_deref() != Some(thumbprint.as_str())
                {
                    return Err("aauth.token is bound to a different key than aauth.key".to_owned());
                }
                sub
            }
            (None, Some(agent)) => {
                aauth::ident::AgentId::parse(agent).map_err(|e| format!("aauth.agent: {e}"))?;
                agent.clone()
            }
            (None, None) => {
                return Err("aauth needs either `token` or `agent` + `issuer`".to_owned());
            }
        };
        if spec.token.is_none() && spec.issuer.is_none() {
            return Err("aauth.issuer is required when self-issuing an agent token".to_owned());
        }
        let credential = spec.credential.unwrap_or_default();
        if credential != AauthCredential::Agent && spec.person_server.is_none() {
            return Err(
                "aauth.credential person/auth needs aauth.person_server (the person server \
                 that issues person and auth tokens)"
                    .to_owned(),
            );
        }
        if credential == AauthCredential::Auth
            && spec
                .scopes
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
        {
            return Err(
                "aauth.credential auth needs aauth.scopes (the scope values to request)".to_owned(),
            );
        }
        if let Some(ps) = &spec.person_server {
            aauth::ident::validate_server_identifier(ps, true)
                .map_err(|e| format!("aauth.person_server: {e:?}"))?;
        }
        // A pre-obtained person / auth token: presented verbatim, bound to
        // this key.
        let presented = match &spec.present {
            Some(jwt) => {
                let decoded = aauth::jwt::decode(jwt)
                    .map_err(|e| format!("aauth.present is not a well-formed JWT: {e}"))?;
                let typ = decoded
                    .header
                    .typ
                    .clone()
                    .ok_or("aauth.present has no typ")?;
                if typ != aauth::tokens::TYP_PERSON && typ != aauth::tokens::TYP_AUTH {
                    return Err(format!(
                        "aauth.present must be an aa-person+jwt or aa-auth+jwt (got {typ})"
                    ));
                }
                if let Some(cnf) = decoded.payload.pointer("/cnf/jwk")
                    && let Ok(bound) = serde_json::from_value::<aauth::jwk::Jwk>(cnf.clone())
                    && bound.thumbprint().ok().as_deref() != Some(thumbprint.as_str())
                {
                    return Err(
                        "aauth.present is bound to a different key than aauth.key".to_owned()
                    );
                }
                Some(PresentedToken {
                    jwt: jwt.clone(),
                    typ,
                })
            }
            None => None,
        };

        Ok(Self {
            key,
            jwk,
            thumbprint,
            provided: spec.token.clone(),
            issuer: spec.issuer.clone(),
            agent,
            person_server: spec.person_server.clone(),
            credential,
            scopes: spec.scopes.clone(),
            save_credential: spec.save_credential.clone(),
            consent_timeout: std::time::Duration::from_secs(spec.consent_timeout_secs.max(1)),
            cover: spec.cover.iter().map(|s| s.to_lowercase()).collect(),
            content_digest: spec.content_digest,
            minted: Mutex::new(None),
            presented: Mutex::new(presented),
        })
    }

    /// What this signer presents, for the UI. Never includes the key.
    pub fn identity(&self) -> AauthIdentity {
        AauthIdentity {
            agent: self.agent.clone(),
            issuer: self.issuer.clone(),
            thumbprint: self.thumbprint.clone(),
            alg: aauth::jwt::ALG_ED25519.to_owned(),
            origin: match self.provided {
                Some(_) => TokenOrigin::Provided,
                None => TokenOrigin::SelfIssued,
            },
            covers: {
                let mut c: Vec<String> = aauth::sig::REQUIRED_COMPONENTS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect();
                if self.content_digest {
                    c.push("content-digest".into());
                }
                c.extend(self.cover.iter().cloned());
                c
            },
            credential: self.credential,
            presented_typ: self
                .presented
                .lock()
                .ok()
                .and_then(|p| p.as_ref().map(|t| t.typ.clone())),
        }
    }

    /// The token to put in `Signature-Key`: the acquired person/auth token
    /// when the credential mode asks for one and it has been obtained, else
    /// the agent token.
    fn presented_token(&self, now: u64) -> Result<String, String> {
        if let Ok(p) = self.presented.lock()
            && let Some(t) = p.as_ref()
        {
            return Ok(t.jwt.clone());
        }
        self.agent_token(now)
    }

    /// The agent token to present, minting or re-minting as needed.
    fn agent_token(&self, now: u64) -> Result<String, String> {
        if let Some(token) = &self.provided {
            return Ok(token.clone());
        }
        let mut slot = self
            .minted
            .lock()
            .map_err(|_| "aauth token lock poisoned")?;
        if let Some(minted) = slot.as_ref()
            && minted.expires_at > now + REFRESH_MARGIN_SECS
        {
            return Ok(minted.jwt.clone());
        }
        let issuer = self.issuer.as_ref().ok_or("aauth.issuer missing")?;
        let claims = aauth::tokens::AgentTokenClaims {
            iss: issuer.clone(),
            dwk: "aauth-agent.json".to_owned(),
            sub: self.agent.clone(),
            jti: aauth::rand_token(128),
            cnf: aauth::tokens::Cnf {
                jwk: self.jwk.clone(),
            },
            iat: now,
            exp: now + SELF_ISSUED_TTL_SECS,
            ps: self.person_server.clone(),
            parent_agent: None,
        };
        let payload = serde_json::to_value(&claims).map_err(|e| e.to_string())?;
        let jwt = aauth::jwt::sign(
            aauth::tokens::TYP_AGENT,
            Some(&self.thumbprint),
            None,
            &payload,
            &self.key,
        );
        *slot = Some(MintedToken {
            jwt: jwt.clone(),
            expires_at: claims.exp,
        });
        Ok(jwt)
    }
}

/// Split a URL into the `@authority`, `@path` and `@query` RFC 9421 derived
/// components. Authority is lowercased with the scheme's default port
/// omitted; path is the wire-form path, defaulting to `/`; query is the raw
/// string **without** the leading `?`, empty when there is none.
fn derived_components(url: &str) -> Result<(String, String, String), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("target URL: {e}"))?;
    let host = parsed.host_str().ok_or("target URL has no host")?;
    let authority = match parsed.port() {
        Some(port) => format!("{}:{port}", host.to_lowercase()),
        None => host.to_lowercase(),
    };
    let path = parsed.path();
    let path = if path.is_empty() { "/" } else { path };
    Ok((
        authority,
        path.to_owned(),
        parsed.query().unwrap_or_default().to_owned(),
    ))
}

impl RequestSigner for AauthSigner {
    fn sign(&self, req: &SigningRequest<'_>) -> Result<Vec<(String, String)>, String> {
        let now = aauth::now_unix();
        let token = self.presented_token(now)?;
        let (authority, path, query) = derived_components(req.url)?;

        // Everything the signature covers must be a header value already
        // fixed, so the digest is computed before the base is built and
        // returned alongside the signature.
        let mut added: Vec<(String, String)> = Vec::new();
        let mut extra: Vec<String> = Vec::new();
        if self.content_digest
            && let Some(body) = req.body
        {
            let digest = Sha256::digest(body);
            added.push((
                "content-digest".to_owned(),
                format!("sha-256=:{}:", aauth::b64::encode_std(&digest)),
            ));
            extra.push("content-digest".to_owned());
        }
        for name in &self.cover {
            if extra.iter().any(|e| e == name) {
                continue;
            }
            // Derived components (`@query`, …) have no header to look up;
            // they resolve from the request itself. A covered *header* the
            // request does not carry would make the base unbuildable, so
            // skipping it keeps a stale `cover` list from wedging every
            // request.
            if name.starts_with('@') || req.header(name).is_some() {
                extra.push(name.clone());
            }
        }

        let resolve = |name: &str| -> Option<String> {
            added
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .or_else(|| req.header(name).map(str::to_owned))
        };
        let extra_refs: Vec<&str> = extra.iter().map(String::as_str).collect();
        let signed = aauth::sig::sign_request(
            req.method,
            &authority,
            &path,
            &query,
            &extra_refs,
            &resolve,
            &aauth::sigkey::serialize_jwt(&token),
            &self.key,
            now,
        )
        .map_err(|e| format!("{e}"))?;

        added.push(("signature-key".to_owned(), signed.signature_key));
        added.push(("signature-input".to_owned(), signed.signature_input));
        added.push(("signature".to_owned(), signed.signature));
        Ok(added)
    }
}

// ---------------------------------------------------------------------------
// Person-server flows: person tokens and auth tokens
// ---------------------------------------------------------------------------

/// A signed HTTP call the acquisition flows make (to the person server or
/// the resource's authorization endpoint): JSON body, `content-type` and
/// `content-digest` covered as the protocol requires of PS requests.
struct SignedCall {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// One AAuth-side answer from a deferred endpoint.
enum Deferred {
    Done(serde_json::Value),
    Pending {
        location: String,
        retry_after: u64,
        interaction: Option<(String, String)>,
        status: String,
    },
}

impl AauthSigner {
    /// The AAuth server identifier of a target URL — scheme + host, plus the
    /// port only when non-default. This is what a person token's `aud` names.
    pub fn resource_identifier(target_url: &str) -> Result<String, String> {
        let parsed = url::Url::parse(target_url).map_err(|e| format!("target URL: {e}"))?;
        let host = parsed
            .host_str()
            .ok_or("target URL has no host")?
            .to_lowercase();
        Ok(match parsed.port() {
            Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        })
    }

    /// Obtain the credential `credential` names for `target_url` and hold it
    /// for [`RequestSigner::sign`]. A no-op for `agent`. Deferred answers
    /// (`202` + `AAuth-Requirement: requirement=interaction`) print the
    /// interaction URL and code to stderr and poll until the person decides
    /// or `consent_timeout` elapses.
    pub async fn acquire(&self, target_url: &str) -> Result<(), String> {
        if self.credential == AauthCredential::Agent {
            return Ok(());
        }
        if self.presented.lock().map(|p| p.is_some()).unwrap_or(false) {
            // A pre-obtained token is presented as-is.
            return Ok(());
        }
        let ps = self
            .person_server
            .clone()
            .ok_or("aauth.person_server is required for this credential")?;
        let resource = Self::resource_identifier(target_url)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| format!("http client: {e}"))?;

        let ps_meta = fetch_json(&client, &format!("{ps}/.well-known/aauth-person.json")).await?;
        let person_endpoint = ps_meta
            .get("person_token_endpoint")
            .and_then(|v| v.as_str())
            .ok_or("person server metadata has no person_token_endpoint")?
            .to_owned();

        // 1. Person token for the resource, signed with the agent token.
        let body = serde_json::json!({ "resource": resource }).to_string();
        let answer = self
            .call_deferred(
                &client,
                &person_endpoint,
                body.as_bytes(),
                None,
                "person token",
            )
            .await?;
        let person_jwt = answer
            .get("person_token")
            .and_then(|v| v.as_str())
            .ok_or("person server answered without person_token")?
            .to_owned();
        eprintln!("aauth: person token obtained from {ps} for {resource}");
        if self.credential == AauthCredential::Person {
            self.present(person_jwt, aauth::tokens::TYP_PERSON);
            return Ok(());
        }

        // 2. Resource token from the resource's authorization endpoint,
        //    signed with the person token.
        let res_meta = fetch_json(
            &client,
            &format!("{resource}/.well-known/aauth-resource.json"),
        )
        .await?;
        let authorize = res_meta
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .ok_or(
                "resource metadata has no authorization_endpoint (does it issue resource tokens?)",
            )?
            .to_owned();
        let scope = self.scopes.clone().unwrap_or_default();
        let body = serde_json::json!({ "scope": scope }).to_string();
        let answer = self
            .call_deferred(
                &client,
                &authorize,
                body.as_bytes(),
                Some(&person_jwt),
                "resource token",
            )
            .await?;
        let resource_token = answer
            .get("resource_token")
            .and_then(|v| v.as_str())
            .ok_or("authorization endpoint answered without resource_token")?
            .to_owned();

        // 3. Auth token from the person server, signed with the agent token.
        let auth_endpoint = ps_meta
            .get("auth_token_endpoint")
            .and_then(|v| v.as_str())
            .ok_or("person server metadata has no auth_token_endpoint")?
            .to_owned();
        let body = serde_json::json!({ "resource_token": resource_token }).to_string();
        let answer = self
            .call_deferred(&client, &auth_endpoint, body.as_bytes(), None, "auth token")
            .await?;
        let auth_jwt = answer
            .get("auth_token")
            .and_then(|v| v.as_str())
            .ok_or("person server answered without auth_token")?
            .to_owned();
        eprintln!("aauth: auth token obtained from {ps} for {resource} (scope: {scope})");
        self.present(auth_jwt, aauth::tokens::TYP_AUTH);
        Ok(())
    }

    fn present(&self, jwt: String, typ: &str) {
        if let Some(path) = &self.save_credential {
            use std::io::Write;
            let write = || -> std::io::Result<()> {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let mut f = opts.open(path)?;
                f.write_all(jwt.as_bytes())?;
                f.write_all(b"\n")
            };
            if let Err(e) = write() {
                eprintln!(
                    "aauth: could not save credential to {}: {e}",
                    path.display()
                );
            }
        }
        if let Ok(mut p) = self.presented.lock() {
            *p = Some(PresentedToken {
                jwt,
                typ: typ.to_owned(),
            });
        }
    }

    /// Sign a JSON POST (or bodyless GET) with `token` (the agent token when
    /// `None`), covering `content-type` + `content-digest` on bodies.
    fn sign_call(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        token: Option<&str>,
    ) -> Result<SignedCall, String> {
        let now = aauth::now_unix();
        let token = match token {
            Some(t) => t.to_owned(),
            None => self.agent_token(now)?,
        };
        let (authority, path, query) = derived_components(url)?;
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut extra: Vec<&str> = Vec::new();
        if let Some(b) = body {
            headers.push(("content-type".to_owned(), "application/json".to_owned()));
            headers.push((
                "content-digest".to_owned(),
                aauth::sig::content_digest_sha256(b),
            ));
            extra.push("content-type");
            extra.push("content-digest");
        }
        let lookup = |name: &str| -> Option<String> {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let signed = aauth::sig::sign_request(
            method,
            &authority,
            &path,
            &query,
            &extra,
            &lookup,
            &aauth::sigkey::serialize_jwt(&token),
            &self.key,
            now,
        )
        .map_err(|e| format!("{e}"))?;
        let mut all = headers;
        all.push(("signature-key".to_owned(), signed.signature_key));
        all.push(("signature-input".to_owned(), signed.signature_input));
        all.push(("signature".to_owned(), signed.signature));
        Ok(SignedCall {
            headers: all,
            body: body.map(<[u8]>::to_vec).unwrap_or_default(),
        })
    }

    /// POST to a deferred-capable endpoint and follow the AAuth
    /// deferred-response state machine until a terminal answer.
    async fn call_deferred(
        &self,
        client: &reqwest::Client,
        url: &str,
        body: &[u8],
        token: Option<&str>,
        what: &str,
    ) -> Result<serde_json::Value, String> {
        let call = self.sign_call("POST", url, Some(body), token)?;
        let mut req = client.post(url).header("prefer", "wait=45");
        for (n, v) in &call.headers {
            req = req.header(n, v);
        }
        let resp = req
            .body(call.body)
            .send()
            .await
            .map_err(|e| format!("{what}: request to {url} failed: {e}"))?;
        let mut answer = classify(resp, what).await?;
        let deadline = std::time::Instant::now() + self.consent_timeout;
        let mut announced = false;
        loop {
            match answer {
                Deferred::Done(v) => return Ok(v),
                Deferred::Pending {
                    location,
                    retry_after,
                    interaction,
                    status,
                } => {
                    if let Some((iurl, code)) = &interaction
                        && !announced
                    {
                        eprintln!(
                            "aauth: {what} needs the person's consent — open {iurl}?code={code} \
                             (code {code}); waiting up to {}s",
                            self.consent_timeout.as_secs()
                        );
                        announced = true;
                    }
                    if status == "interacting" && announced {
                        eprintln!("aauth: the person is at the consent screen");
                        announced = false; // print again only if a new URL arrives
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "{what}: no decision within {}s (pending at {location})",
                            self.consent_timeout.as_secs()
                        ));
                    }
                    if retry_after > 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(retry_after.min(30)))
                            .await;
                    }
                    let poll = self.sign_call("GET", &location, None, token)?;
                    let mut req = client.get(&location).header("prefer", "wait=45");
                    for (n, v) in &poll.headers {
                        req = req.header(n, v);
                    }
                    let resp = req
                        .send()
                        .await
                        .map_err(|e| format!("{what}: poll of {location} failed: {e}"))?;
                    answer = classify(resp, what).await?;
                }
            }
        }
    }
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value, String> {
    let resp = client
        .get(url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: HTTP {}", resp.status().as_u16()));
    }
    resp.json()
        .await
        .map_err(|e| format!("GET {url}: not JSON: {e}"))
}

/// Read a response from a deferred-capable endpoint into the state machine's
/// terms: `200` is done, `202` is pending (with `Location`, `Retry-After`,
/// and any `AAuth-Requirement` interaction), everything else is an error
/// carrying the problem body's `error` / `detail`.
async fn classify(resp: reqwest::Response, what: &str) -> Result<Deferred, String> {
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    match status.as_u16() {
        200 => Ok(Deferred::Done(json)),
        202 => {
            let location = headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or(format!("{what}: 202 without Location"))?
                .to_owned();
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(5);
            let interaction = headers
                .get("aauth-requirement")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_interaction);
            let status_field = json
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("pending")
                .to_owned();
            Ok(Deferred::Pending {
                location,
                retry_after,
                interaction,
                status: status_field,
            })
        }
        code => {
            let error = json.get("error").and_then(|v| v.as_str()).unwrap_or("");
            let detail = json.get("detail").and_then(|v| v.as_str()).unwrap_or("");
            let sig_err = headers
                .get("signature-error")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            Err(format!("{what}: HTTP {code} {error} {detail} {sig_err}",)
                .trim_end()
                .to_owned())
        }
    }
}

/// `requirement=interaction; url="…"; code="…"` → `(url, code)`.
fn parse_interaction(value: &str) -> Option<(String, String)> {
    let dict = aauth::sfv::parse_dictionary(value).ok()?;
    let (_, member) = dict.iter().find(|(k, _)| k == "requirement")?;
    let aauth::sfv::MemberValue::Item(aauth::sfv::BareItem::Token(t), params) = &member.value
    else {
        return None;
    };
    if t != "interaction" {
        return None;
    }
    let url = aauth::sfv::param(params, "url")?.as_str()?.to_owned();
    let code = aauth::sfv::param(params, "code")?.as_str()?.to_owned();
    Some((url, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic seed so the assertions below are stable.
    const SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn spec() -> AauthSpec {
        AauthSpec {
            key: SEED.to_owned(),
            token: None,
            issuer: Some("https://agents.example".to_owned()),
            agent: Some("aauth:inspector@agents.example".to_owned()),
            person_server: None,
            credential: None,
            scopes: None,
            present: None,
            save_credential: None,
            consent_timeout_secs: 180,
            cover: vec![],
            content_digest: true,
        }
    }

    fn sign_post(signer: &AauthSigner, body: &[u8]) -> Vec<(String, String)> {
        let headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        signer
            .sign(&SigningRequest {
                method: "POST",
                url: "https://Example.COM:443/mcp?session=1",
                headers: &headers,
                body: Some(body),
            })
            .expect("sign")
    }

    fn verify_policy() -> aauth::sig::VerifyPolicy {
        aauth::sig::VerifyPolicy {
            now: aauth::now_unix(),
            window_secs: 60,
            extra_required: vec![],
        }
    }

    fn value_of<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    #[test]
    fn emits_the_three_signature_headers_plus_digest() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let out = sign_post(&signer, br#"{"method":"tools/list"}"#);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "content-digest",
                "signature-key",
                "signature-input",
                "signature"
            ]
        );
        assert!(value_of(&out, "signature-key").starts_with("sig=jwt;jwt=\""));
        assert!(value_of(&out, "signature").starts_with("sig=:"));
    }

    /// The profile forbids `alg` and discourages `keyid` as signature
    /// parameters — the key is named by `Signature-Key`, not by the label.
    #[test]
    fn signature_input_carries_only_created() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let out = sign_post(&signer, b"{}");
        let input = value_of(&out, "signature-input");
        assert!(input.contains(";created="), "{input}");
        assert!(!input.contains("alg="), "{input}");
        assert!(!input.contains("keyid="), "{input}");
        assert!(!input.contains("nonce="), "{input}");
    }

    #[test]
    fn covers_the_four_mandated_components_and_the_digest() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let out = sign_post(&signer, b"{}");
        let input = value_of(&out, "signature-input");
        for c in ["@method", "@authority", "@path", "signature-key"] {
            assert!(
                input.contains(&format!("\"{c}\"")),
                "{c} not covered: {input}"
            );
        }
        assert!(input.contains("\"content-digest\""), "{input}");
    }

    /// Two different JSON-RPC calls to the same `POST /mcp` must not share a
    /// signature. Without `Content-Digest` they would, because the mandated
    /// components say nothing about the body.
    #[test]
    fn body_is_bound_by_the_digest() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let list = sign_post(&signer, br#"{"method":"tools/list"}"#);
        let call = sign_post(&signer, br#"{"method":"tools/call","name":"rm"}"#);
        assert_ne!(
            value_of(&list, "content-digest"),
            value_of(&call, "content-digest")
        );
        assert_ne!(value_of(&list, "signature"), value_of(&call, "signature"));

        let mut unbound = spec();
        unbound.content_digest = false;
        let signer = AauthSigner::new(&unbound).unwrap();
        let list = sign_post(&signer, br#"{"method":"tools/list"}"#);
        let call = sign_post(&signer, br#"{"method":"tools/call","name":"rm"}"#);
        assert_eq!(
            value_of(&list, "signature"),
            value_of(&call, "signature"),
            "without the digest the body is outside the signature — \
             this is why content_digest defaults on"
        );
    }

    /// A signature the inspector produces is one the gateway's identity
    /// plugin accepts: same parse, same required components, same key.
    #[test]
    fn verifies_against_the_gateway_verify_path() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let body = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let out = sign_post(&signer, body);
        let mut headers: std::collections::HashMap<String, String> =
            out.iter().map(|(n, v)| (n.clone(), v.clone())).collect();
        headers.insert("content-type".into(), "application/json".into());

        let lookup = |name: &str| headers.get(name).cloned();
        let parts = aauth::sig::RequestParts {
            method: "POST",
            authority: "example.com",
            path: "/mcp",
            query: "",
            header: &lookup,
        };
        let parsed = aauth::sig::parse_request_signature(&parts, &verify_policy()).expect("parse");
        let token = match &parsed.scheme {
            aauth::sigkey::SigKeyScheme::Jwt(t) => t.clone(),
            other => panic!("expected the jwt scheme, got {other:?}"),
        };
        let decoded = aauth::jwt::decode(&token).unwrap();
        let jwk: aauth::jwk::Jwk =
            serde_json::from_value(decoded.payload.pointer("/cnf/jwk").unwrap().clone()).unwrap();
        aauth::jwt::verify_with_jwk(&decoded, &jwk).expect("self-issued token verifies");
        aauth::sig::verify_parsed(&parsed, &jwk).expect("request signature verifies");
    }

    /// AAuth -10 §5.2.2 admits exactly one fully-specified identifier this
    /// build can produce, and requires the confirmation key to name it too.
    /// A token failing either is refused by the gateway's identity plugin,
    /// which validates through this same code.
    #[test]
    fn self_issued_token_is_fully_specified_end_to_end() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let now = aauth::now_unix();
        let token = signer.agent_token(now).unwrap();
        let decoded = aauth::jwt::decode(&token).unwrap();
        assert_eq!(decoded.header.alg, "Ed25519");
        assert_eq!(
            decoded
                .payload
                .pointer("/cnf/jwk/alg")
                .and_then(|v| v.as_str()),
            Some("Ed25519"),
        );
        let claims = aauth::tokens::validate_agent_token(&decoded, now, false)
            .expect("the gateway's agent-token validation must accept what we mint");
        assert_eq!(claims.sub, "aauth:inspector@agents.example");
        assert_eq!(signer.identity().alg, "Ed25519");
    }

    /// The signature must not survive a change of method, host, path or
    /// body — those are exactly what the mandated components pin.
    #[test]
    fn rejects_replay_onto_a_different_request() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let out = sign_post(&signer, b"{}");
        let mut headers: std::collections::HashMap<String, String> =
            out.iter().map(|(n, v)| (n.clone(), v.clone())).collect();
        headers.insert("content-type".into(), "application/json".into());
        let lookup = |name: &str| headers.get(name).cloned();

        let jwk = aauth::jwk::Jwk::from_verifying_key(
            &aauth::jwk::SigningKey::from_bytes(&aauth::b64::decode_fixed::<32>(SEED).unwrap())
                .verifying_key(),
        );
        for (method, authority, path) in [
            ("DELETE", "example.com", "/mcp"),
            ("POST", "evil.example", "/mcp"),
            ("POST", "example.com", "/admin"),
            // The default port is omitted from `@authority`; spelling it
            // out is a different string and must not verify.
            ("POST", "example.com:443", "/mcp"),
        ] {
            let parts = aauth::sig::RequestParts {
                method,
                authority,
                path,
                query: "",
                header: &lookup,
            };
            let parsed =
                aauth::sig::parse_request_signature(&parts, &verify_policy()).expect("parse");
            assert!(
                aauth::sig::verify_parsed(&parsed, &jwk).is_err(),
                "{method} {authority}{path} must not verify"
            );
        }
    }

    #[test]
    fn self_issued_token_is_reused_until_it_nears_expiry() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let now = aauth::now_unix();
        let first = signer.agent_token(now).unwrap();
        assert_eq!(signer.agent_token(now).unwrap(), first, "reused");
        let past_refresh = now + SELF_ISSUED_TTL_SECS - REFRESH_MARGIN_SECS + 1;
        assert_ne!(
            signer.agent_token(past_refresh).unwrap(),
            first,
            "re-minted before it expires"
        );
    }

    #[test]
    fn token_bound_to_another_key_is_rejected() {
        let other = aauth::jwk::generate_signing_key();
        let other_jwk = aauth::jwk::Jwk::from_verifying_key(&other.verifying_key());
        let claims = serde_json::json!({
            "iss": "https://agents.example",
            "sub": "aauth:someone@agents.example",
            "cnf": {"jwk": other_jwk},
        });
        let token = aauth::jwt::sign("aa-agent+jwt", None, None, &claims, &other);
        let mut s = spec();
        s.token = Some(token);
        let err = AauthSigner::new(&s).unwrap_err();
        assert!(err.contains("bound to a different key"), "{err}");
    }

    #[test]
    fn a_provided_token_names_the_agent() {
        let sk = aauth::jwk::SigningKey::from_bytes(&aauth::b64::decode_fixed::<32>(SEED).unwrap());
        let jwk = aauth::jwk::Jwk::from_verifying_key(&sk.verifying_key());
        let claims = serde_json::json!({
            "iss": "https://ap.example",
            "sub": "aauth:from-ap@ap.example",
            "cnf": {"jwk": jwk},
        });
        let mut s = spec();
        s.token = Some(aauth::jwt::sign("aa-agent+jwt", None, None, &claims, &sk));
        s.agent = Some("aauth:ignored@agents.example".to_owned());
        let signer = AauthSigner::new(&s).unwrap();
        assert_eq!(signer.identity().agent, "aauth:from-ap@ap.example");
        assert_eq!(signer.identity().origin, TokenOrigin::Provided);
    }

    #[test]
    fn authority_is_lowercased_and_the_path_excludes_the_query() {
        assert_eq!(
            derived_components("https://Example.COM/mcp?x=1").unwrap(),
            (
                "example.com".to_owned(),
                "/mcp".to_owned(),
                "x=1".to_owned()
            )
        );
        assert_eq!(
            derived_components("http://host:8080").unwrap(),
            ("host:8080".to_owned(), "/".to_owned(), String::new())
        );
        // Default ports are omitted, per RFC 9421 §2.2.3.
        assert_eq!(derived_components("https://h:443/x").unwrap().0, "h");
        assert_eq!(derived_components("http://h:80/x").unwrap().0, "h");
    }

    #[test]
    fn a_bad_key_is_rejected_at_construction() {
        let mut s = spec();
        s.key = "not-base64url!".to_owned();
        assert!(AauthSigner::new(&s).unwrap_err().contains("aauth.key"));
    }

    #[test]
    fn self_issuing_requires_an_issuer() {
        let mut s = spec();
        s.issuer = None;
        assert!(AauthSigner::new(&s).unwrap_err().contains("aauth.issuer"));
    }

    #[test]
    fn debug_does_not_print_the_key() {
        let signer = AauthSigner::new(&spec()).unwrap();
        let rendered = format!("{signer:?}");
        assert!(!rendered.contains(SEED), "{rendered}");
    }

    /// A resource may require `@query` via `additional_signature_components`.
    /// Derived components have no header to look up, so a header-presence
    /// check would silently drop them and the request would be rejected by
    /// the very server that asked for them.
    #[test]
    fn a_derived_component_can_be_covered() {
        let mut s = spec();
        s.cover = vec!["@query".to_owned()];
        let signer = AauthSigner::new(&s).unwrap();
        let out = sign_post(&signer, b"{}");
        let input = value_of(&out, "signature-input");
        assert!(input.contains("\"@query\""), "{input}");
    }

    /// And the query it commits to must be the real one, not the empty
    /// string — otherwise the verifier builds a different base.
    #[test]
    fn a_covered_query_signs_the_actual_query() {
        let mut s = spec();
        s.cover = vec!["@query".to_owned()];
        let signer = AauthSigner::new(&s).unwrap();
        let headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        let sign_at = |url: &str| {
            signer
                .sign(&SigningRequest {
                    method: "POST",
                    url,
                    headers: &headers,
                    body: Some(b"{}"),
                })
                .expect("sign")
        };
        let a = sign_at("https://example.com/mcp?session=1");
        let b = sign_at("https://example.com/mcp?session=2");
        assert_ne!(
            value_of(&a, "signature"),
            value_of(&b, "signature"),
            "the covered @query must reach the signature base"
        );
    }

    /// A covered header the request does not carry cannot be resolved, so it
    /// is skipped rather than failing every request.
    #[test]
    fn an_absent_covered_header_is_skipped() {
        let mut s = spec();
        s.cover = vec!["x-not-sent".to_owned()];
        let signer = AauthSigner::new(&s).unwrap();
        let out = sign_post(&signer, b"{}");
        assert!(!value_of(&out, "signature-input").contains("x-not-sent"));
    }
}
