//! How the inspector authenticates as an OAuth client at a token endpoint
//! (RFC 6749 §2.3): `none`, `client_secret_basic`, `client_secret_post` or
//! `private_key_jwt` (an RFC 7523 §2.2 client assertion).
//!
//! The same client authenticates at an enterprise IdP (the RFC 8693
//! exchange that yields an ID-JAG) and at an MCP server's authorization
//! server. A secret is sent and never shown: `Debug` and every error name
//! the method and the client, not the credential.

use std::sync::Arc;

use serde::Serialize;
use serde_json::json;

use super::keys::SigningKey;

/// `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE_JWT: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Lifetime of a client assertion. It is a bearer credential, so it stays
/// short.
const ASSERTION_LIFETIME_SECS: u64 = 120;

/// A client authentication method, spelled as RFC 8414 metadata spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// A public client: `client_id` in the form, no credential.
    #[value(name = "none")]
    None,
    #[value(name = "client_secret_basic")]
    ClientSecretBasic,
    #[value(name = "client_secret_post")]
    ClientSecretPost,
    #[value(name = "private_key_jwt")]
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }
}

/// The `aud` of a client assertion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum AssertionAudience {
    /// The authorization server's issuer identifier (rfc7523bis).
    #[default]
    Issuer,
    /// The URL of the token endpoint the assertion is posted to, which
    /// Okta expects.
    TokenEndpoint,
}

/// The signing half of `private_key_jwt`.
#[derive(Clone, Debug)]
pub struct AssertionKey {
    pub key: Arc<SigningKey>,
    pub key_id: Option<String>,
    pub audience: AssertionAudience,
}

/// One client's identity and credential at one token endpoint.
#[derive(Clone)]
pub struct ClientCredentials {
    client_id: String,
    method: ClientAuthMethod,
    secret: Option<String>,
    assertion: Option<AssertionKey>,
}

impl std::fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("client_id", &self.client_id)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl ClientCredentials {
    /// A public client.
    pub fn public(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            method: ClientAuthMethod::None,
            secret: None,
            assertion: None,
        }
    }

    /// Settle how `client_id` authenticates. `method` absent is chosen from
    /// what was given: a key means `private_key_jwt`, a secret the method
    /// of the two secret methods the server lists (`client_secret_basic`
    /// when it lists neither or both), nothing a public client. `label`
    /// names the flags in errors (`--client` or `--idp-client`).
    pub fn build(
        label: &str,
        client_id: String,
        method: Option<ClientAuthMethod>,
        secret: Option<String>,
        assertion: Option<AssertionKey>,
        server_methods: &[String],
    ) -> Result<Self, String> {
        let secret = secret.filter(|s| !s.is_empty());
        let method = method.unwrap_or_else(|| match (&assertion, &secret) {
            (Some(_), _) => ClientAuthMethod::PrivateKeyJwt,
            (None, Some(_)) => {
                let lists = |m: ClientAuthMethod| server_methods.iter().any(|s| s == m.as_str());
                if lists(ClientAuthMethod::ClientSecretPost)
                    && !lists(ClientAuthMethod::ClientSecretBasic)
                {
                    ClientAuthMethod::ClientSecretPost
                } else {
                    ClientAuthMethod::ClientSecretBasic
                }
            }
            (None, None) => ClientAuthMethod::None,
        });
        match method {
            ClientAuthMethod::None if secret.is_some() || assertion.is_some() => Err(format!(
                "{label}-auth none sends no credential; drop {label}-secret and {label}-key"
            )),
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost
                if secret.is_none() =>
            {
                Err(format!(
                    "{label}-auth {} needs {label}-secret",
                    method.as_str()
                ))
            }
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost
                if assertion.is_some() =>
            {
                Err(format!(
                    "{label}-key signs private_key_jwt assertions; it does not go with {label}-auth {}",
                    method.as_str()
                ))
            }
            ClientAuthMethod::PrivateKeyJwt if assertion.is_none() => {
                Err(format!("{label}-auth private_key_jwt needs {label}-key"))
            }
            ClientAuthMethod::PrivateKeyJwt if secret.is_some() => Err(format!(
                "{label}-secret does not go with {label}-auth private_key_jwt"
            )),
            _ => Ok(Self {
                client_id,
                method,
                secret,
                assertion,
            }),
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn method(&self) -> ClientAuthMethod {
        self.method
    }

    /// The long-lived secret this client sends, for scrubbing it out of
    /// anything a server answers.
    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }

    /// Attach this client's credential to a token request posted to
    /// `token_endpoint`. `issuer` is the server's issuer identifier, which
    /// an assertion addressed to the issuer needs.
    pub fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        form: &mut Vec<(&'static str, String)>,
        token_endpoint: &str,
        issuer: Option<&str>,
    ) -> Result<reqwest::RequestBuilder, String> {
        match self.method {
            ClientAuthMethod::None => {
                form.push(("client_id", self.client_id.clone()));
                Ok(request)
            }
            ClientAuthMethod::ClientSecretPost => {
                form.push(("client_id", self.client_id.clone()));
                form.push(("client_secret", self.secret.clone().unwrap_or_default()));
                Ok(request)
            }
            // RFC 6749 §2.3.1: both halves are form-encoded before they go
            // into the Basic header.
            ClientAuthMethod::ClientSecretBasic => Ok(request.basic_auth(
                form_encode(&self.client_id),
                Some(form_encode(self.secret.as_deref().unwrap_or_default())),
            )),
            ClientAuthMethod::PrivateKeyJwt => {
                let key = self
                    .assertion
                    .as_ref()
                    .ok_or("private_key_jwt has no key")?;
                let audience = match key.audience {
                    AssertionAudience::TokenEndpoint => token_endpoint,
                    AssertionAudience::Issuer => issuer.ok_or(
                        "the client assertion is addressed to the issuer, and no issuer is known",
                    )?,
                };
                let assertion = self.sign_assertion(key, audience)?;
                form.push(("client_id", self.client_id.clone()));
                form.push((
                    "client_assertion_type",
                    CLIENT_ASSERTION_TYPE_JWT.to_owned(),
                ));
                form.push(("client_assertion", assertion));
                Ok(request)
            }
        }
    }

    /// A fresh assertion: `iss` = `sub` = the client, one `aud`, a new
    /// `jti` and a short life.
    fn sign_assertion(&self, key: &AssertionKey, audience: &str) -> Result<String, String> {
        let now = mcpg_aauth_core::now_unix();
        let mut header = json!({ "typ": "JWT" });
        if let Some(kid) = &key.key_id {
            header["kid"] = json!(kid);
        }
        let claims = json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": audience,
            "jti": uuid::Uuid::new_v4().to_string(),
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
        });
        key.key
            .sign_jws(&header, &claims)
            .map_err(|e| format!("client assertion for {}: {e}", self.client_id))
    }
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::keys::{SigningAlg, tests::verify};

    const TOKEN_URL: &str = "https://idp.example/oauth2/v1/token";

    fn form_of(
        client: &ClientCredentials,
        issuer: Option<&str>,
    ) -> (reqwest::Request, Vec<(&'static str, String)>) {
        let mut form = Vec::new();
        let request = client
            .authenticate(
                reqwest::Client::new().post(TOKEN_URL),
                &mut form,
                TOKEN_URL,
                issuer,
            )
            .unwrap()
            .build()
            .unwrap();
        (request, form)
    }

    fn field<'a>(form: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        form.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    fn key(audience: AssertionAudience) -> AssertionKey {
        AssertionKey {
            key: Arc::new(SigningKey::generate(SigningAlg::Es256).unwrap()),
            key_id: Some("kid-1".to_owned()),
            audience,
        }
    }

    #[test]
    fn the_method_follows_what_was_given() {
        let public = ClientCredentials::build("--client", "c".into(), None, None, None, &[]);
        assert_eq!(public.unwrap().method(), ClientAuthMethod::None);
        let basic =
            ClientCredentials::build("--client", "c".into(), None, Some("s".into()), None, &[]);
        assert_eq!(basic.unwrap().method(), ClientAuthMethod::ClientSecretBasic);
        // A server that lists only the post method gets the post method.
        let post = ClientCredentials::build(
            "--client",
            "c".into(),
            None,
            Some("s".into()),
            None,
            &[
                "client_secret_post".to_owned(),
                "private_key_jwt".to_owned(),
            ],
        );
        assert_eq!(post.unwrap().method(), ClientAuthMethod::ClientSecretPost);
        let jwt = ClientCredentials::build(
            "--client",
            "c".into(),
            None,
            None,
            Some(key(AssertionAudience::Issuer)),
            &[],
        );
        assert_eq!(jwt.unwrap().method(), ClientAuthMethod::PrivateKeyJwt);
    }

    #[test]
    fn contradictions_are_refused_by_flag_name() {
        let err = ClientCredentials::build(
            "--idp-client",
            "c".into(),
            Some(ClientAuthMethod::ClientSecretPost),
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(err.contains("--idp-client-secret"), "{err}");
        let err = ClientCredentials::build(
            "--client",
            "c".into(),
            Some(ClientAuthMethod::PrivateKeyJwt),
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert!(err.contains("--client-key"), "{err}");
        let err = ClientCredentials::build(
            "--client",
            "c".into(),
            Some(ClientAuthMethod::None),
            Some("s".into()),
            None,
            &[],
        )
        .unwrap_err();
        assert!(err.contains("none"), "{err}");
    }

    #[test]
    fn basic_form_encodes_both_halves() {
        let client = ClientCredentials::build(
            "--client",
            "a b".into(),
            Some(ClientAuthMethod::ClientSecretBasic),
            Some("p:w".into()),
            None,
            &[],
        )
        .unwrap();
        let (request, form) = form_of(&client, None);
        assert!(form.is_empty(), "nothing in the body: {form:?}");
        let header = request.headers()["authorization"].to_str().unwrap();
        // base64("a+b:p%3Aw")
        assert_eq!(header, "Basic YStiOnAlM0F3");
    }

    #[test]
    fn post_and_none_put_the_client_in_the_form() {
        let client = ClientCredentials::build(
            "--client",
            "c".into(),
            Some(ClientAuthMethod::ClientSecretPost),
            Some("s".into()),
            None,
            &[],
        )
        .unwrap();
        let (_, form) = form_of(&client, None);
        assert_eq!(field(&form, "client_id"), Some("c"));
        assert_eq!(field(&form, "client_secret"), Some("s"));

        let (request, form) = form_of(&ClientCredentials::public("pub"), None);
        assert_eq!(field(&form, "client_id"), Some("pub"));
        assert!(field(&form, "client_secret").is_none());
        assert!(request.headers().get("authorization").is_none());
    }

    #[test]
    fn private_key_jwt_signs_a_fresh_assertion_for_the_chosen_audience() {
        for (audience, expected) in [
            (AssertionAudience::Issuer, "https://idp.example"),
            (AssertionAudience::TokenEndpoint, TOKEN_URL),
        ] {
            let key = key(audience);
            let signing = key.key.clone();
            let client =
                ClientCredentials::build("--client", "agent-1".into(), None, None, Some(key), &[])
                    .unwrap();
            let (_, form) = form_of(&client, Some("https://idp.example"));
            assert_eq!(field(&form, "client_id"), Some("agent-1"));
            assert_eq!(
                field(&form, "client_assertion_type"),
                Some(CLIENT_ASSERTION_TYPE_JWT)
            );
            let assertion = field(&form, "client_assertion").unwrap();
            let claims = verify(assertion, &signing);
            assert_eq!(claims["iss"], "agent-1");
            assert_eq!(claims["sub"], "agent-1");
            assert_eq!(claims["aud"], expected);
            let lifetime = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
            assert!(lifetime <= 300);
            let (_, again) = form_of(&client, Some("https://idp.example"));
            assert_ne!(
                field(&again, "client_assertion"),
                Some(assertion),
                "a new jti each time"
            );
        }
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let client = ClientCredentials::build(
            "--client",
            "c".into(),
            None,
            Some("hunter2-not-real".into()),
            None,
            &[],
        )
        .unwrap();
        assert!(!format!("{client:?}").contains("hunter2"));
    }
}
