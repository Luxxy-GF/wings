use crate::hash::Hash32;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ISSUER: &str = "control";
pub const PURPOSE_TUNNEL: &str = "tunnel";
pub const TOKEN_TTL_SECS: u64 = 300;
pub const CLOCK_LEEWAY_SECS: u64 = 60;

const ALGORITHM: Algorithm = Algorithm::EdDSA;

fn install_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

#[inline]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Cnf {
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: compact_str::CompactString,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectClaims {
    #[serde(rename = "iss")]
    pub issuer: compact_str::CompactString,
    #[serde(rename = "sub")]
    pub subject: uuid::Uuid,
    #[serde(rename = "aud")]
    pub audience: uuid::Uuid,
    pub purpose: compact_str::CompactString,

    #[serde(rename = "iat")]
    pub issued_at: u64,
    #[serde(rename = "nbf")]
    pub not_before: u64,
    #[serde(rename = "exp")]
    pub expiration_time: u64,
    pub cnf: Cnf,
}

impl ConnectClaims {
    #[inline]
    pub fn new(src_node: uuid::Uuid, dst_node: uuid::Uuid, client_cert: &Hash32, now: u64) -> Self {
        Self {
            issuer: ISSUER.into(),
            subject: src_node,
            audience: dst_node,
            purpose: PURPOSE_TUNNEL.into(),
            issued_at: now,
            not_before: now,
            expiration_time: now + TOKEN_TTL_SECS,
            cnf: Cnf {
                x5t_s256: B64.encode(client_cert.as_bytes()).into(),
            },
        }
    }

    /// Every check the signature alone does not make: `Validation` is deliberately inert so
    /// the order and the errors stay the ones section 5 of the protocol documents.
    pub fn validate(&self, expect: &Expect, now: u64) -> Result<(), JwtError> {
        if self.issuer != ISSUER {
            return Err(JwtError::WrongIssuer(self.issuer.clone()));
        }
        if self.purpose != PURPOSE_TUNNEL {
            return Err(JwtError::WrongPurpose(self.purpose.clone()));
        }
        if self.audience != expect.audience {
            return Err(JwtError::WrongAudience {
                got: self.audience,
                want: expect.audience,
            });
        }
        if self.subject != expect.subject {
            return Err(JwtError::WrongSubject {
                got: self.subject,
                want: expect.subject,
            });
        }
        if now > self.expiration_time.saturating_add(expect.leeway) {
            return Err(JwtError::Expired {
                exp: self.expiration_time,
                now,
            });
        }
        if now.saturating_add(expect.leeway) < self.not_before {
            return Err(JwtError::NotYetValid {
                nbf: self.not_before,
                now,
            });
        }

        let bound = B64
            .decode(&self.cnf.x5t_s256)
            .map_err(|_| JwtError::CnfMismatch)?;
        if bound != expect.client_cert.as_bytes() {
            return Err(JwtError::CnfMismatch);
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum JwtError {
    Malformed,
    BadHeader,
    BadSignature,
    Expired { exp: u64, now: u64 },
    NotYetValid { nbf: u64, now: u64 },
    WrongIssuer(compact_str::CompactString),
    WrongPurpose(compact_str::CompactString),
    WrongAudience { got: uuid::Uuid, want: uuid::Uuid },
    WrongSubject { got: uuid::Uuid, want: uuid::Uuid },
    CnfMismatch,
}

impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match err.kind() {
            ErrorKind::InvalidSignature => JwtError::BadSignature,
            ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => JwtError::BadHeader,
            _ => JwtError::Malformed,
        }
    }
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Malformed => write!(f, "malformed token"),
            JwtError::BadHeader => write!(f, "unsupported JOSE header"),
            JwtError::BadSignature => write!(f, "signature verification failed"),
            JwtError::Expired { exp, now } => write!(f, "token expired at {exp}, now {now}"),
            JwtError::NotYetValid { nbf, now } => {
                write!(f, "token not valid before {nbf}, now {now}")
            }
            JwtError::WrongIssuer(issuer) => write!(f, "wrong issuer {issuer:?}"),
            JwtError::WrongPurpose(purpose) => write!(f, "wrong purpose {purpose:?}"),
            JwtError::WrongAudience { got, want } => {
                write!(f, "token audience {got} is not this node {want}")
            }
            JwtError::WrongSubject { got, want } => write!(
                f,
                "token subject {got} does not match the peer certificate identity {want}"
            ),
            JwtError::CnfMismatch => write!(
                f,
                "cnf x5t#S256 does not match the presented client certificate"
            ),
        }
    }
}

impl std::error::Error for JwtError {}

#[derive(Debug, PartialEq, Eq)]
pub struct BadKey;

impl std::fmt::Display for BadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not a usable Ed25519 public key")
    }
}

impl std::error::Error for BadKey {}

#[derive(Debug, Clone, Copy)]
pub struct Expect {
    pub audience: uuid::Uuid,
    /// The node identity resolved from the presented client certificate, never from the token.
    pub subject: uuid::Uuid,
    pub client_cert: Hash32,
    pub leeway: u64,
}

/// Signs connect tokens. Only the control plane holds one.
pub struct JwtIssuer {
    encoding_key: EncodingKey,
    header: Header,
}

impl std::fmt::Debug for JwtIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtIssuer").finish_non_exhaustive()
    }
}

impl JwtIssuer {
    /// `der` is an unencrypted PKCS#8 document, v1 or v2.
    pub fn from_pkcs8_der(der: &[u8]) -> Self {
        install_provider();

        Self {
            encoding_key: EncodingKey::from_ed_der(der),
            header: Header::new(ALGORITHM),
        }
    }

    #[inline]
    pub fn create<T: Serialize>(&self, claims: &T) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(&self.header, claims, &self.encoding_key)
    }
}

/// Verifies connect tokens against one snapshot's `jwt_pubkey`. Cheap enough to build per
/// call, which is what callers must do: the key rotates with the snapshot.
#[derive(Debug)]
pub struct JwtClient {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtClient {
    pub fn new(pubkey: &Hash32) -> Result<Self, BadKey> {
        install_provider();

        // jsonwebtoken keeps the raw bytes unchecked and only fails at verification, so the
        // key is screened here instead: dalek rejects a non-canonical point, and a low-order
        // one would make almost every signature verify against almost every message
        let key = ed25519_dalek::VerifyingKey::from_bytes(pubkey.as_bytes()).map_err(|_| BadKey)?;
        if key.is_weak() {
            return Err(BadKey);
        }

        // the temporal and policy claims are checked by `ConnectClaims::validate`, which
        // reports which one failed rather than a single opaque rejection
        let mut validation = Validation::new(ALGORITHM);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        Ok(Self {
            decoding_key: DecodingKey::from_ed_der(pubkey.as_bytes()),
            validation,
        })
    }

    #[inline]
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, JwtError> {
        // checked before decoding so `alg: none` and friends are a header failure rather
        // than whatever the payload happens to fail on first
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::BadHeader)?;
        if header.alg != ALGORITHM {
            return Err(JwtError::BadHeader);
        }

        Ok(jsonwebtoken::decode::<T>(token, &self.decoding_key, &self.validation)?.claims)
    }

    /// The only way to obtain a `ConnectClaims` that every check has run against.
    pub fn validate_connect(
        &self,
        token: &str,
        expect: &Expect,
        now: u64,
    ) -> Result<ConnectClaims, JwtError> {
        let claims: ConnectClaims = self.verify(token)?;
        claims.validate(expect, now)?;

        Ok(claims)
    }
}

/// Never an admission decision: the peer runs `validate_connect` and may still reject the token.
pub fn unverified_expiry(token: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Exp {
        exp: u64,
    }

    jsonwebtoken::dangerous::insecure_decode::<Exp>(token)
        .ok()
        .map(|data| data.claims.exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};

    fn issuer_from(seed: [u8; 32]) -> (JwtIssuer, Hash32) {
        let key = SigningKey::from_bytes(&seed);
        let der = key.to_pkcs8_der().unwrap();

        (
            JwtIssuer::from_pkcs8_der(der.as_bytes()),
            Hash32(key.verifying_key().to_bytes()),
        )
    }

    fn setup() -> (JwtIssuer, JwtClient, uuid::Uuid, uuid::Uuid, Hash32, Expect) {
        let (issuer, pubkey) = issuer_from([7; 32]);
        let src = uuid::Uuid::from_u128(1);
        let dst = uuid::Uuid::from_u128(2);
        let cert = sha256(b"peer cert der");
        let expect = Expect {
            audience: dst,
            subject: src,
            client_cert: cert,
            leeway: CLOCK_LEEWAY_SECS,
        };

        (
            issuer,
            JwtClient::new(&pubkey).unwrap(),
            src,
            dst,
            cert,
            expect,
        )
    }

    // unverified_expiry

    #[test]
    fn unverified_expiry_reads_exp_without_trusting_the_token() {
        let (issuer, _, src, dst, cert, _) = setup();
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &cert, 1000))
            .unwrap();
        assert_eq!(unverified_expiry(&token), Some(1000 + TOKEN_TTL_SECS));

        // a tampered signature still parses
        let tampered = format!("{token}x");
        assert_eq!(unverified_expiry(&tampered), Some(1000 + TOKEN_TTL_SECS));

        assert_eq!(unverified_expiry("not.a.token"), None);
        assert_eq!(unverified_expiry("nodots"), None);
        assert_eq!(unverified_expiry(""), None);
    }

    // JwtClient::new

    #[test]
    fn a_public_key_that_cannot_verify_anything_is_refused_up_front() {
        // not a curve point at all
        assert_eq!(JwtClient::new(&Hash32([2; 32])).unwrap_err(), BadKey);

        // the identity point: low order, so a forgery verifies against almost any message
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(JwtClient::new(&Hash32(identity)).unwrap_err(), BadKey);
    }

    // validate_connect

    #[test]
    fn validate_accepts_a_freshly_issued_token() {
        let (issuer, client, src, dst, cert, expect) = setup();
        let claims = ConnectClaims::new(src, dst, &cert, 1000);
        let token = issuer.create(&claims).unwrap();

        assert_eq!(token.split('.').count(), 3);
        assert_eq!(
            client.validate_connect(&token, &expect, 1000).unwrap(),
            claims
        );
    }

    #[test]
    fn expiry_honours_the_leeway_and_then_rejects() {
        let (issuer, client, src, dst, cert, expect) = setup();
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &cert, 1000))
            .unwrap();
        let exp = 1000 + TOKEN_TTL_SECS;

        assert!(client.validate_connect(&token, &expect, exp).is_ok());
        assert!(
            client
                .validate_connect(&token, &expect, exp + CLOCK_LEEWAY_SECS)
                .is_ok()
        );
        assert_eq!(
            client
                .validate_connect(&token, &expect, exp + CLOCK_LEEWAY_SECS + 1)
                .unwrap_err(),
            JwtError::Expired {
                exp,
                now: exp + CLOCK_LEEWAY_SECS + 1
            }
        );
    }

    #[test]
    fn not_before_honours_the_leeway_and_then_rejects() {
        let (issuer, client, src, dst, cert, expect) = setup();
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &cert, 1000))
            .unwrap();

        assert!(
            client
                .validate_connect(&token, &expect, 1000 - CLOCK_LEEWAY_SECS)
                .is_ok()
        );
        assert_eq!(
            client
                .validate_connect(&token, &expect, 1000 - CLOCK_LEEWAY_SECS - 1)
                .unwrap_err(),
            JwtError::NotYetValid {
                nbf: 1000,
                now: 939
            }
        );
    }

    #[test]
    fn validate_rejects_a_token_for_another_node() {
        let (issuer, client, src, dst, cert, expect) = setup();
        let elsewhere = uuid::Uuid::from_u128(99);
        let token = issuer
            .create(&ConnectClaims::new(src, elsewhere, &cert, 1000))
            .unwrap();

        assert_eq!(
            client.validate_connect(&token, &expect, 1000).unwrap_err(),
            JwtError::WrongAudience {
                got: elsewhere,
                want: dst
            }
        );
    }

    #[test]
    fn validate_rejects_a_token_naming_a_different_source_node() {
        let (issuer, client, _, dst, cert, expect) = setup();
        let impostor = uuid::Uuid::from_u128(42);
        let token = issuer
            .create(&ConnectClaims::new(impostor, dst, &cert, 1000))
            .unwrap();

        assert_eq!(
            client.validate_connect(&token, &expect, 1000).unwrap_err(),
            JwtError::WrongSubject {
                got: impostor,
                want: uuid::Uuid::from_u128(1)
            }
        );
    }

    #[test]
    fn validate_rejects_a_token_bound_to_another_certificate() {
        let (issuer, client, src, dst, _, expect) = setup();
        let other = sha256(b"someone else's cert");
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &other, 1000))
            .unwrap();

        assert_eq!(
            client.validate_connect(&token, &expect, 1000).unwrap_err(),
            JwtError::CnfMismatch
        );
    }

    #[test]
    fn validate_rejects_a_stolen_token_replayed_by_an_attacker() {
        let (issuer, client, src, dst, cert, mut expect) = setup();
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &cert, 1000))
            .unwrap();

        expect.client_cert = sha256(b"attacker cert der");
        assert_eq!(
            client.validate_connect(&token, &expect, 1000).unwrap_err(),
            JwtError::CnfMismatch
        );
    }

    #[test]
    fn validate_rejects_a_token_from_the_wrong_signing_key() {
        let (issuer, _, src, dst, cert, expect) = setup();
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &cert, 1000))
            .unwrap();
        let (_, other) = issuer_from([8; 32]);

        assert_eq!(
            JwtClient::new(&other)
                .unwrap()
                .validate_connect(&token, &expect, 1000)
                .unwrap_err(),
            JwtError::BadSignature
        );
    }

    #[test]
    fn tampering_with_the_payload_invalidates_the_signature() {
        let (issuer, client, src, dst, cert, expect) = setup();
        let token = issuer
            .create(&ConnectClaims::new(src, dst, &cert, 1000))
            .unwrap();

        let mut parts: Vec<_> = token.split('.').collect();
        let forged = ConnectClaims::new(src, dst, &cert, 1000 + 99999);
        let payload = B64.encode(serde_json::to_string(&forged).unwrap());
        parts[1] = &payload;

        assert_eq!(
            client
                .validate_connect(&parts.join("."), &expect, 1000)
                .unwrap_err(),
            JwtError::BadSignature
        );
    }

    #[test]
    fn wrong_issuer_and_purpose_are_rejected() {
        let (issuer, client, src, dst, cert, expect) = setup();

        let mut c = ConnectClaims::new(src, dst, &cert, 1000);
        c.issuer = "someone".into();
        assert_eq!(
            client
                .validate_connect(&issuer.create(&c).unwrap(), &expect, 1000)
                .unwrap_err(),
            JwtError::WrongIssuer("someone".into())
        );

        let mut c = ConnectClaims::new(src, dst, &cert, 1000);
        c.purpose = "transfer".into();
        assert_eq!(
            client
                .validate_connect(&issuer.create(&c).unwrap(), &expect, 1000)
                .unwrap_err(),
            JwtError::WrongPurpose("transfer".into())
        );
    }

    #[test]
    fn validate_rejects_an_alg_none_token() {
        let (_, client, src, dst, cert, expect) = setup();
        let claims = ConnectClaims::new(src, dst, &cert, 1000);
        let forged = format!(
            "{}.{}.",
            B64.encode(r#"{"alg":"none","typ":"JWT"}"#),
            B64.encode(serde_json::to_string(&claims).unwrap())
        );

        assert_eq!(
            client.validate_connect(&forged, &expect, 1000).unwrap_err(),
            JwtError::BadHeader
        );
    }

    #[test]
    fn a_header_written_in_another_order_is_still_accepted() {
        use ed25519_dalek::Signer as _;

        // what every release before this one emitted, and what a third-party control plane
        // may well emit: only `alg` is part of the contract
        let (_, client, src, dst, cert, expect) = setup();
        let claims = ConnectClaims::new(src, dst, &cert, 1000);
        let signing_input = format!(
            "{}.{}",
            B64.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#),
            B64.encode(serde_json::to_string(&claims).unwrap())
        );
        let sig = SigningKey::from_bytes(&[7; 32]).sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", B64.encode(sig.to_bytes()));

        assert_eq!(
            client.validate_connect(&token, &expect, 1000).unwrap(),
            claims
        );
    }

    #[test]
    fn validate_rejects_an_hmac_token_signed_with_the_public_key() {
        let (_, client, src, dst, cert, expect) = setup();
        let (_, pubkey) = issuer_from([7; 32]);
        let claims = ConnectClaims::new(src, dst, &cert, 1000);

        // the classic algorithm-confusion forgery: a public key used as an HMAC secret
        let forged = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(pubkey.as_bytes()),
        )
        .unwrap();

        assert_eq!(
            client.validate_connect(&forged, &expect, 1000).unwrap_err(),
            JwtError::BadHeader
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_without_panicking() {
        let (_, client, _, _, _, expect) = setup();

        for bad in ["", ".", "a.b", "a.b.c.d", "....", "!!!.!!!.!!!"] {
            assert!(client.validate_connect(bad, &expect, 1000).is_err());
        }
    }

    // ConnectClaims

    #[test]
    fn connect_claims_encode_the_certificate_digest_as_base64url() {
        let der = b"a certificate";
        let claims = ConnectClaims::new(uuid::Uuid::nil(), uuid::Uuid::nil(), &sha256(der), 0);

        assert_eq!(claims.cnf.x5t_s256.len(), 43);
        assert!(!claims.cnf.x5t_s256.contains(['+', '/', '=']));
        assert_eq!(
            B64.decode(&claims.cnf.x5t_s256).unwrap(),
            sha256(der).as_bytes()
        );
    }
}
