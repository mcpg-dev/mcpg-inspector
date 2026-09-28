//! DPoP (RFC 9449): the key a sender-constrained token is bound to, the
//! proofs signed with it, and the signer that presents such a token on
//! every MCP request.
//!
//! A DPoP-bound token is useless without its key, and the CLI runs one
//! process per command, so the key lives in a file the operator names
//! (`--dpop-key`): `login` creates it (owner-only) when it does not exist,
//! and every later command reads it. Nothing here prints a key, a proof or
//! a token.

use std::path::Path;
use std::sync::{Arc, Mutex};

use mcpg_aauth_core as aauth;
use mcpg_mcp_client::signer::{RequestSigner, SigningRequest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::keys::{SigningAlg, SigningKey, write_private_file};

/// Request header that carries a proof.
pub const DPOP_HEADER: &str = "DPoP";
/// Response header that carries a server nonce (RFC 9449 §8, §9).
pub const DPOP_NONCE_HEADER: &str = "dpop-nonce";
/// `token_type` of a token bound to a key (RFC 9449 §5).
pub const TOKEN_TYPE_DPOP: &str = "DPoP";
/// `error` of a token or resource request that needs a server nonce.
pub const USE_DPOP_NONCE: &str = "use_dpop_nonce";
/// `typ` of a proof.
const PROOF_TYP: &str = "dpop+jwt";
/// The algorithms the inspector signs proofs with, most preferred first.
const SIGNED_ALGS: [SigningAlg; 2] = [SigningAlg::Es256, SigningAlg::EdDsa];

/// A key proofs are signed with.
#[derive(Debug)]
pub struct DpopKey {
    key: SigningKey,
    public_jwk: Value,
    thumbprint: String,
}

impl DpopKey {
    fn wrap(key: SigningKey) -> Result<Self, String> {
        if !SIGNED_ALGS.contains(&key.alg()) {
            return Err(format!(
                "a DPoP key signs ES256 or EdDSA here, and this key is {}",
                key.alg().name()
            ));
        }
        let mut public_jwk = serde_json::to_value(key.public_jwk()?)
            .map_err(|_| "the DPoP key has no public JWK".to_owned())?;
        // The proof header carries the bare public key: RFC 9449 §4.2
        // forbids private members, and `alg` already sits in the header.
        if let Some(object) = public_jwk.as_object_mut() {
            object.retain(|name, _| matches!(name.as_str(), "kty" | "crv" | "x" | "y"));
        }
        let thumbprint = key.thumbprint()?;
        Ok(Self {
            key,
            public_jwk,
            thumbprint,
        })
    }

    /// A new key for `alg`.
    pub fn generate(alg: SigningAlg) -> Result<Self, String> {
        Self::wrap(SigningKey::generate(alg)?)
    }

    /// The key in `path`: a private JWK or a PKCS#8 PEM.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        Self::wrap(SigningKey::from_file(path, None)?)
    }

    /// The key in `path`, or, when there is no file there, a new key of an
    /// algorithm `accepted` lists (any, when it lists none), written to
    /// `path` owner-only. Returns the key and whether it is new.
    pub fn load_or_create(path: &Path, accepted: &[String]) -> Result<(Self, bool), String> {
        if path.exists() {
            let key = Self::from_file(path)?;
            if !accepted.is_empty() && !accepted.iter().any(|a| a == key.alg_name()) {
                return Err(format!(
                    "the DPoP key in {} is {}, and the server accepts only {}",
                    path.display(),
                    key.alg_name(),
                    accepted.join(", ")
                ));
            }
            return Ok((key, false));
        }
        let key = Self::generate(choose_alg(accepted)?)?;
        let jwk = key
            .key
            .private_jwk()
            .ok_or("a generated DPoP key has a private JWK")?;
        let text = serde_json::to_string_pretty(&jwk).unwrap_or_default();
        write_private_file(path, format!("{text}\n").as_bytes(), false)?;
        Ok((key, true))
    }

    pub fn alg_name(&self) -> &'static str {
        self.key.alg().name()
    }

    /// The RFC 7638 thumbprint a bound token names in `cnf.jkt`.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// A proof of a `method` request to `url` (RFC 9449 §4.2). `nonce` is
    /// the server's latest; `access_token` is the token the request
    /// presents, which the proof names by hash as `ath`.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<String, String> {
        let mut claims = json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "htm": method,
            "htu": htu(url)?,
            "iat": aauth::now_unix(),
        });
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        if let Some(token) = access_token {
            claims["ath"] = json!(aauth::b64::encode(&Sha256::digest(token.as_bytes())));
        }
        let header = json!({ "typ": PROOF_TYP, "jwk": self.public_jwk });
        self.key.sign_jws(&header, &claims)
    }
}

/// The algorithm to sign proofs with, from the ones a server accepts
/// (any, when it lists none).
pub fn choose_alg(accepted: &[String]) -> Result<SigningAlg, String> {
    if accepted.is_empty() {
        return Ok(SIGNED_ALGS[0]);
    }
    SIGNED_ALGS
        .into_iter()
        .find(|alg| accepted.iter().any(|a| a == alg.name()))
        .ok_or_else(|| {
            format!(
                "the server accepts DPoP proofs signed with {} only, and the inspector signs \
                 with ES256 or EdDSA",
                accepted.join(", ")
            )
        })
}

/// RFC 9449 §4.2: the target URI without its query and fragment.
fn htu(url: &str) -> Result<String, String> {
    let mut parsed = url::Url::parse(url).map_err(|_| format!("{url:?} is not a URL"))?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// Presents a DPoP-bound access token: `Authorization: DPoP <token>` and a
/// fresh proof on every request.
pub struct DpopSigner {
    key: Arc<DpopKey>,
    access_token: String,
    nonce: Mutex<Option<String>>,
}

impl std::fmt::Debug for DpopSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopSigner")
            .field("jkt", &self.key.thumbprint())
            .finish_non_exhaustive()
    }
}

impl DpopSigner {
    pub fn new(key: Arc<DpopKey>, access_token: String) -> Self {
        Self {
            key,
            access_token,
            nonce: Mutex::new(None),
        }
    }

    /// Use `nonce` in every later proof.
    pub fn set_nonce(&self, nonce: String) {
        if let Ok(mut current) = self.nonce.lock() {
            *current = Some(nonce);
        }
    }

    fn headers(&self, method: &str, url: &str) -> Result<Vec<(String, String)>, String> {
        let nonce = self.nonce.lock().ok().and_then(|n| n.clone());
        let proof = self
            .key
            .proof(method, url, nonce.as_deref(), Some(&self.access_token))?;
        Ok(vec![
            (
                "authorization".to_owned(),
                format!("{TOKEN_TYPE_DPOP} {}", self.access_token),
            ),
            (DPOP_HEADER.to_ascii_lowercase(), proof),
        ])
    }

    /// Ask the resource at `url` for a nonce: a request whose proof carries
    /// none is answered 401 `use_dpop_nonce` with a fresh `DPoP-Nonce` by a
    /// resource that requires one (RFC 9449 §9). Returns whether one was
    /// learned.
    pub async fn learn_nonce(&self, client: &reqwest::Client, url: &str) -> bool {
        let Ok(headers) = self.headers("POST", url) else {
            return false;
        };
        let mut request = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .body(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let Ok(response) = request.send().await else {
            return false;
        };
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return false;
        }
        let asks_for_nonce = response
            .headers()
            .get_all(reqwest::header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.contains(USE_DPOP_NONCE));
        let nonce = response
            .headers()
            .get(DPOP_NONCE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match nonce {
            Some(nonce) if asks_for_nonce => {
                self.set_nonce(nonce);
                true
            }
            _ => false,
        }
    }
}

impl RequestSigner for DpopSigner {
    fn sign(&self, req: &SigningRequest<'_>) -> Result<Vec<(String, String)>, String> {
        self.headers(req.method, req.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{DecodingKey, Validation};

    fn decode_proof(proof: &str) -> (Value, Value) {
        let header = jsonwebtoken::decode_header(proof).unwrap();
        assert_eq!(header.typ.as_deref(), Some("dpop+jwt"));
        let jwk: Jwk = header.jwk.clone().expect("the proof carries its key");
        let key = DecodingKey::from_jwk(&jwk).unwrap();
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<Value>(proof, &key, &validation)
            .expect("the proof verifies under the key it carries")
            .claims;
        (serde_json::to_value(&jwk).unwrap(), claims)
    }

    #[test]
    fn a_proof_names_the_request_and_verifies_under_its_own_key() {
        for alg in SIGNED_ALGS {
            let key = DpopKey::generate(alg).unwrap();
            let proof = key
                .proof(
                    "POST",
                    "https://gw.example/oauth/token?x=1#frag",
                    Some("n-1"),
                    None,
                )
                .unwrap();
            let (jwk, claims) = decode_proof(&proof);
            assert!(jwk.get("d").is_none(), "no private member in the header");
            assert_eq!(claims["htm"], "POST");
            assert_eq!(claims["htu"], "https://gw.example/oauth/token");
            assert_eq!(claims["nonce"], "n-1");
            assert!(claims.get("ath").is_none());
            assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
            let jwk: Jwk = serde_json::from_value(jwk).unwrap();
            assert_eq!(
                jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
                    .unwrap(),
                key.thumbprint()
            );
        }
    }

    /// RFC 9449 §4.2: `ath` is the base64url SHA-256 of the access token.
    #[test]
    fn a_resource_proof_carries_the_token_hash() {
        let key = DpopKey::generate(SigningAlg::Es256).unwrap();
        let proof = key
            .proof("GET", "https://gw.example/mcp", None, Some("the-token"))
            .unwrap();
        let (_, claims) = decode_proof(&proof);
        assert_eq!(
            claims["ath"],
            aauth::b64::encode(&Sha256::digest(b"the-token"))
        );
    }

    #[test]
    fn the_signer_presents_the_dpop_scheme_and_a_fresh_proof() {
        let key = Arc::new(DpopKey::generate(SigningAlg::EdDsa).unwrap());
        let signer = DpopSigner::new(key, "tok".to_owned());
        let request = SigningRequest {
            method: "POST",
            url: "https://gw.example/mcp",
            headers: &[],
            body: Some(b"{}"),
        };
        let first = signer.sign(&request).unwrap();
        assert_eq!(
            first[0],
            ("authorization".to_owned(), "DPoP tok".to_owned())
        );
        assert_eq!(first[1].0, "dpop");
        signer.set_nonce("n-2".to_owned());
        let second = signer.sign(&request).unwrap();
        assert_ne!(first[1].1, second[1].1, "a new proof per request");
        let (_, claims) = decode_proof(&second[1].1);
        assert_eq!(claims["nonce"], "n-2");
        assert!(!format!("{signer:?}").contains("tok\""));
    }

    #[test]
    fn the_algorithm_follows_what_the_server_accepts() {
        assert_eq!(choose_alg(&[]).unwrap(), SigningAlg::Es256);
        assert_eq!(
            choose_alg(&["RS256".to_owned(), "EdDSA".to_owned()]).unwrap(),
            SigningAlg::EdDsa
        );
        let err = choose_alg(&["PS256".to_owned()]).unwrap_err();
        assert!(err.contains("PS256"), "{err}");
    }

    #[test]
    fn a_key_file_is_created_once_and_read_back() {
        let path = std::env::temp_dir().join(format!("mcpg-dpop-{}.jwk", uuid::Uuid::new_v4()));
        let (key, created) = DpopKey::load_or_create(&path, &["EdDSA".to_owned()]).unwrap();
        assert!(created);
        assert_eq!(key.alg_name(), "EdDSA");
        let (again, created) = DpopKey::load_or_create(&path, &[]).unwrap();
        assert!(!created);
        assert_eq!(again.thumbprint(), key.thumbprint());
        let err = DpopKey::load_or_create(&path, &["ES256".to_owned()]).unwrap_err();
        assert!(err.contains("accepts only ES256"), "{err}");
        let _ = std::fs::remove_file(&path);
    }
}
