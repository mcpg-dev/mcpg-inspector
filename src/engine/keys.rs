//! Private keys the inspector signs with: a client's key for
//! `private_key_jwt` assertions (RFC 7523 §2.2) and the key a DPoP-bound
//! token is bound to (RFC 9449).
//!
//! A key arrives as PEM (PKCS#8, or PKCS#1 for RSA) or as a private JWK
//! (P-256 or Ed25519); a key the inspector generates is written out as a
//! private JWK. No error message and no `Debug` output carries key
//! material.

use std::path::Path;

use jsonwebtoken::jwk::{Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, EncodingKey};
use mcpg_aauth_core as aauth;
use serde_json::{Value, json};

/// PKCS#8 v1 of an Ed25519 key (RFC 8410 §7): this prefix, then the
/// 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// PKCS#8 v1 of a P-256 key whose ECPrivateKey leaves out the optional
/// public key (RFC 5915 §3): this prefix, then the 32-byte private scalar.
/// The public point is derived from the scalar when the key is parsed.
const P256_PKCS8_PREFIX: [u8; 35] = [
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
    0x01, 0x04, 0x20,
];
/// Bytes of a P-256 private scalar and of an Ed25519 seed.
const PRIVATE_BYTES: usize = 32;
/// Largest key file read, in bytes.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// A JWS algorithm a key signs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum SigningAlg {
    #[value(name = "RS256")]
    Rs256,
    #[value(name = "RS384")]
    Rs384,
    #[value(name = "RS512")]
    Rs512,
    #[value(name = "PS256")]
    Ps256,
    #[value(name = "PS384")]
    Ps384,
    #[value(name = "PS512")]
    Ps512,
    #[value(name = "ES256")]
    Es256,
    #[value(name = "ES384")]
    Es384,
    #[value(name = "EdDSA")]
    EdDsa,
}

impl SigningAlg {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::EdDsa => Algorithm::EdDSA,
        }
    }

    fn family(self) -> KeyFamily {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                KeyFamily::Rsa
            }
            Self::Es256 | Self::Es384 => KeyFamily::Ec,
            Self::EdDsa => KeyFamily::Ed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyFamily {
    Rsa,
    Ec,
    Ed,
}

/// A private key and the one algorithm it signs with.
pub struct SigningKey {
    alg: SigningAlg,
    encoding: EncodingKey,
    /// The P-256 scalar or Ed25519 seed, for a key that can be written back
    /// out as a private JWK.
    private: Option<Vec<u8>>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("alg", &self.alg.name())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A new key for `alg`, which must be `ES256` or `EdDSA`.
    pub fn generate(alg: SigningAlg) -> Result<Self, String> {
        // A random 32-byte string is a valid P-256 scalar unless it is zero
        // or at least the group order, which happens with odds near 2^-32;
        // a few draws make a failure practically impossible.
        for _ in 0..8 {
            let mut private = vec![0u8; PRIVATE_BYTES];
            aauth::rand_bytes(&mut private);
            match Self::from_private_bytes(alg, private) {
                Ok(key) => return Ok(key),
                Err(_) if alg == SigningAlg::Es256 => continue,
                Err(e) => return Err(e),
            }
        }
        Err("could not generate a P-256 key".to_owned())
    }

    fn from_private_bytes(alg: SigningAlg, private: Vec<u8>) -> Result<Self, String> {
        if private.len() != PRIVATE_BYTES {
            return Err(format!(
                "the private key must be {PRIVATE_BYTES} bytes for {}",
                alg.name()
            ));
        }
        let encoding = match alg {
            SigningAlg::Es256 => {
                EncodingKey::from_ec_der(&[P256_PKCS8_PREFIX.as_slice(), &private].concat())
            }
            SigningAlg::EdDsa => {
                EncodingKey::from_ed_der(&[ED25519_PKCS8_PREFIX.as_slice(), &private].concat())
            }
            other => {
                return Err(format!(
                    "{} keys are not generated here; the inspector makes ES256 and EdDSA keys",
                    other.name()
                ));
            }
        };
        let key = Self {
            alg,
            encoding,
            private: Some(private),
        };
        // Parsing derives the public half; a key that does not parse is not
        // a key.
        key.public_jwk()?;
        Ok(key)
    }

    /// A PEM private key. Without `alg`, the algorithm follows the key:
    /// RS256 for RSA, ES256 or ES384 for P-256 or P-384, EdDSA for Ed25519.
    pub fn from_pem(pem: &str, alg: Option<SigningAlg>) -> Result<Self, String> {
        let pem = normalize_pem(pem);
        let bytes = pem.as_bytes();
        let parsed = [KeyFamily::Rsa, KeyFamily::Ec, KeyFamily::Ed]
            .into_iter()
            .filter(|family| alg.is_none_or(|a| a.family() == *family))
            .find_map(|family| {
                let key = match family {
                    KeyFamily::Rsa => EncodingKey::from_rsa_pem(bytes),
                    KeyFamily::Ec => EncodingKey::from_ec_pem(bytes),
                    KeyFamily::Ed => EncodingKey::from_ed_pem(bytes),
                };
                key.ok().map(|key| (family, key))
            });
        let Some((family, encoding)) = parsed else {
            return Err(match alg {
                Some(alg) => format!(
                    "the key is not a PKCS#8 (or, for RSA, PKCS#1) PEM private key for {}",
                    alg.name()
                ),
                None => "the key is not a PKCS#8 (or, for RSA, PKCS#1) PEM private key".to_owned(),
            });
        };
        let candidates = match (alg, family) {
            (Some(alg), _) => vec![alg],
            (None, KeyFamily::Rsa) => vec![SigningAlg::Rs256],
            (None, KeyFamily::Ec) => vec![SigningAlg::Es256, SigningAlg::Es384],
            (None, KeyFamily::Ed) => vec![SigningAlg::EdDsa],
        };
        for candidate in candidates {
            let key = Self {
                alg: candidate,
                encoding: encoding.clone(),
                private: None,
            };
            if key.sign_jws(&json!({}), &json!({})).is_ok() {
                return Ok(key);
            }
        }
        Err(match alg {
            Some(alg) => format!("the key cannot sign {}", alg.name()),
            None => {
                "the key signs none of RS256, ES256, ES384 or EdDSA; name the algorithm".to_owned()
            }
        })
    }

    /// A private JWK: EC P-256 (ES256) or OKP Ed25519 (EdDSA). Its public
    /// members, when present, must be those of the private key.
    pub fn from_jwk(jwk: &Value) -> Result<Self, String> {
        let member = |name: &str| jwk.get(name).and_then(Value::as_str);
        let alg = match (member("kty"), member("crv")) {
            (Some("EC"), Some("P-256")) => SigningAlg::Es256,
            (Some("OKP"), Some("Ed25519")) => SigningAlg::EdDsa,
            (Some("RSA"), _) => {
                return Err("an RSA key is read as PEM, not as a JWK".to_owned());
            }
            _ => {
                return Err(
                    "a JWK key must be EC P-256 or OKP Ed25519 (kty and crv members)".to_owned(),
                );
            }
        };
        let private = member("d")
            .ok_or("the JWK has no private member `d`")
            .and_then(|d| aauth::b64::decode(d).map_err(|_| "the JWK `d` is not base64url"))?;
        let key = Self::from_private_bytes(alg, private)?;
        let public = serde_json::to_value(key.public_jwk()?).unwrap_or_default();
        for name in ["x", "y"] {
            if let Some(given) = jwk.get(name)
                && public.get(name) != Some(given)
            {
                return Err(format!(
                    "the JWK `{name}` is not the public half of its private key"
                ));
            }
        }
        Ok(key)
    }

    /// A key read from `path`: a private JWK (JSON) or a PEM.
    pub fn from_file(path: &Path, alg: Option<SigningAlg>) -> Result<Self, String> {
        let text = read_key_file(path)?;
        let trimmed = text.trim();
        if trimmed.starts_with('{') {
            let jwk: Value = serde_json::from_str(trimmed)
                .map_err(|_| format!("{} is not a JSON JWK", path.display()))?;
            let key = Self::from_jwk(&jwk).map_err(|e| format!("{}: {e}", path.display()))?;
            if let Some(alg) = alg
                && alg != key.alg
            {
                return Err(format!(
                    "{} is a {} key, not a {} key",
                    path.display(),
                    key.alg.name(),
                    alg.name()
                ));
            }
            return Ok(key);
        }
        Self::from_pem(trimmed, alg).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn alg(&self) -> SigningAlg {
        self.alg
    }

    /// The public key, as a JWK carrying `alg`.
    pub fn public_jwk(&self) -> Result<Jwk, String> {
        Jwk::from_encoding_key(&self.encoding, self.alg.algorithm())
            .map_err(|_| format!("the key is not a usable {} key", self.alg.name()))
    }

    /// The RFC 7638 SHA-256 thumbprint of the public key.
    pub fn thumbprint(&self) -> Result<String, String> {
        self.public_jwk()?
            .thumbprint(ThumbprintHash::SHA256)
            .map_err(|_| "the key has no RFC 7638 thumbprint".to_owned())
    }

    /// The key as a private JWK, for a key generated here or read as one.
    pub fn private_jwk(&self) -> Option<Value> {
        let private = self.private.as_ref()?;
        let mut jwk = serde_json::to_value(self.public_jwk().ok()?).ok()?;
        jwk["d"] = json!(aauth::b64::encode(private));
        Some(jwk)
    }

    /// A compact JWS of `claims` under `header`, with `alg` set to this
    /// key's algorithm.
    pub fn sign_jws(&self, header: &Value, claims: &Value) -> Result<String, String> {
        let mut header = header.clone();
        header["alg"] = json!(self.alg.name());
        let encode = |value: &Value| {
            aauth::b64::encode(serde_json::to_string(value).unwrap_or_default().as_bytes())
        };
        let message = format!("{}.{}", encode(&header), encode(claims));
        let signature =
            jsonwebtoken::crypto::sign(message.as_bytes(), &self.encoding, self.alg.algorithm())
                .map_err(|_| format!("the key cannot sign {}", self.alg.name()))?;
        Ok(format!("{message}.{signature}"))
    }
}

/// A PEM passed through an environment variable or a one-line file often
/// carries literal `\n` escapes in place of line breaks.
fn normalize_pem(pem: &str) -> String {
    let pem = pem.trim();
    if !pem.contains('\n') && pem.contains("\\n") {
        pem.replace("\\n", "\n")
    } else {
        pem.to_owned()
    }
}

fn read_key_file(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .len();
    if size > MAX_KEY_FILE_BYTES {
        return Err(format!(
            "{} is {size} bytes, larger than any key file",
            path.display()
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Write `contents` to `path`, readable by its owner only. With `replace`
/// false an existing file is left alone and the write refused.
pub fn write_private_file(path: &Path, contents: &[u8], replace: bool) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    // The mode above applies only to a file this call creates.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict {}: {e}", path.display()))?;
    }
    file.write_all(contents)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};

    /// Standard base64 with padding, for building PEM fixtures in tests.
    pub(crate) fn pem_of(label: &str, der: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in der.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        let body: Vec<String> = out
            .as_bytes()
            .chunks(64)
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            body.join("\n")
        )
    }

    /// A P-256 PKCS#8 PEM of a fresh key.
    pub(crate) fn p256_pem() -> String {
        let key = SigningKey::generate(SigningAlg::Es256).unwrap();
        let der = [
            P256_PKCS8_PREFIX.as_slice(),
            key.private.as_ref().unwrap().as_slice(),
        ]
        .concat();
        pem_of("PRIVATE KEY", &der)
    }

    /// Verify `jws` against `key`'s public JWK and return its claims.
    pub(crate) fn verify(jws: &str, key: &SigningKey) -> Value {
        let decoding = DecodingKey::from_jwk(&key.public_jwk().unwrap()).unwrap();
        let mut validation = Validation::new(key.alg.algorithm());
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        jsonwebtoken::decode::<Value>(jws, &decoding, &validation)
            .expect("the signature verifies")
            .claims
    }

    #[test]
    fn generated_keys_sign_what_their_public_half_verifies() {
        for alg in [SigningAlg::Es256, SigningAlg::EdDsa] {
            let key = SigningKey::generate(alg).unwrap();
            let jws = key
                .sign_jws(&json!({"typ": "test"}), &json!({"n": 1}))
                .unwrap();
            assert_eq!(verify(&jws, &key)["n"], 1, "{}", alg.name());
            let jwk = serde_json::to_value(key.public_jwk().unwrap()).unwrap();
            assert!(jwk.get("d").is_none(), "the public JWK is public");
            assert_eq!(key.thumbprint().unwrap().len(), 43);
        }
    }

    #[test]
    fn a_private_jwk_round_trips() {
        for alg in [SigningAlg::Es256, SigningAlg::EdDsa] {
            let key = SigningKey::generate(alg).unwrap();
            let jwk = key.private_jwk().unwrap();
            let back = SigningKey::from_jwk(&jwk).unwrap();
            assert_eq!(back.alg(), alg);
            assert_eq!(back.thumbprint().unwrap(), key.thumbprint().unwrap());
        }
    }

    /// A JWK whose public member belongs to another key is refused rather
    /// than silently signing with a key its holder does not expect.
    #[test]
    fn a_jwk_with_a_foreign_public_half_is_refused() {
        let mut jwk = SigningKey::generate(SigningAlg::Es256)
            .unwrap()
            .private_jwk()
            .unwrap();
        let other = SigningKey::generate(SigningAlg::Es256)
            .unwrap()
            .private_jwk()
            .unwrap();
        jwk["x"] = other["x"].clone();
        let err = SigningKey::from_jwk(&jwk).unwrap_err();
        assert!(err.contains("not the public half"), "{err}");
    }

    #[test]
    fn a_pem_key_takes_its_algorithm_from_the_key() {
        let pem = p256_pem();
        let key = SigningKey::from_pem(&pem, None).unwrap();
        assert_eq!(key.alg(), SigningAlg::Es256);
        // Escaped newlines, as an environment variable carries them.
        let escaped = pem.trim().replace('\n', "\\n");
        assert_eq!(
            SigningKey::from_pem(&escaped, None).unwrap().alg(),
            SigningAlg::Es256
        );
        let err = SigningKey::from_pem(&pem, Some(SigningAlg::Rs256)).unwrap_err();
        assert!(err.contains("RS256"), "{err}");
        assert!(!err.contains("PRIVATE KEY"), "no key material: {err}");
    }

    #[test]
    fn errors_never_carry_key_material() {
        let key = SigningKey::generate(SigningAlg::EdDsa).unwrap();
        let d = key.private_jwk().unwrap()["d"].as_str().unwrap().to_owned();
        assert!(!format!("{key:?}").contains(&d));
        let mut jwk = key.private_jwk().unwrap();
        jwk["kty"] = json!("oct");
        let err = SigningKey::from_jwk(&jwk).unwrap_err();
        assert!(!err.contains(&d), "{err}");
    }

    #[test]
    fn a_private_file_is_owner_only_and_not_overwritten() {
        let path = std::env::temp_dir().join(format!("mcpg-key-{}", uuid::Uuid::new_v4()));
        write_private_file(&path, b"one", false).unwrap();
        assert!(write_private_file(&path, b"two", false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        write_private_file(&path, b"three", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"three");
        let _ = std::fs::remove_file(&path);
    }
}
