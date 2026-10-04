use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tundra_common::jwt;

pub const MIN_REMAINING: u64 = 60;

const DIR: &str = "tokens";

#[inline]
fn is_usable(cached: &Cached, now: u64) -> bool {
    cached.exp.saturating_sub(now) >= MIN_REMAINING
}

fn write_private(path: &Path, body: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&tmp)?.write_all(body)?;

    std::fs::rename(&tmp, path)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Cached {
    jwt: String,
    exp: u64,
}

#[derive(Debug)]
pub struct TokenStore {
    dir: PathBuf,
    mem: parking_lot::Mutex<HashMap<uuid::Uuid, Cached>>,
}

impl TokenStore {
    pub fn new(data_dir: &Path) -> Self {
        let dir = data_dir.join(DIR);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            tracing::debug!(
                path = %dir.display(),
                "failed to create the token cache directory: {:?}",
                err
            );
        }

        Self {
            dir,
            mem: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    #[inline]
    fn path(&self, peer: &uuid::Uuid) -> PathBuf {
        self.dir.join(format!("{peer}.json"))
    }

    pub fn store(&self, peer: &uuid::Uuid, token: &str) {
        let Some(exp) = jwt::unverified_expiry(token) else {
            return;
        };

        let cached = Cached {
            jwt: token.to_owned(),
            exp,
        };

        if let Ok(body) = serde_json::to_vec(&cached) {
            let path = self.path(peer);
            if let Err(err) = write_private(&path, &body) {
                tracing::debug!(
                    peer = %peer,
                    path = %path.display(),
                    "failed to persist a connect token: {:?}",
                    err
                );
            }
        }

        self.mem.lock().insert(*peer, cached);
    }

    pub fn get(&self, peer: &uuid::Uuid, now: u64) -> Option<String> {
        if let Some(hit) = self.mem.lock().get(peer).filter(|c| is_usable(c, now)) {
            return Some(hit.jwt.clone());
        }

        let body = std::fs::read(self.path(peer)).ok()?;
        let cached: Cached = serde_json::from_slice(&body).ok()?;
        if !is_usable(&cached, now) {
            return None;
        }

        let jwt = cached.jwt.clone();
        self.mem.lock().insert(*peer, cached);

        Some(jwt)
    }

    #[cfg(test)]
    fn forget(&self, peer: &uuid::Uuid) {
        self.mem.lock().remove(peer);
        let _ = std::fs::remove_file(self.path(peer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    use tundra_common::{
        hash::sha256,
        jwt::{ConnectClaims, JwtIssuer, TOKEN_TTL_SECS},
    };

    fn token(now: u64) -> String {
        let der = SigningKey::from_bytes(&[3; 32]).to_pkcs8_der().unwrap();
        let claims = ConnectClaims::new(
            uuid::Uuid::from_u128(1),
            uuid::Uuid::from_u128(2),
            &sha256(b"c"),
            now,
        );
        JwtIssuer::from_pkcs8_der(der.as_bytes())
            .create(&claims)
            .unwrap()
    }

    fn store() -> (TokenStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "tundra-tokens-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (TokenStore::new(&dir), dir)
    }

    // TokenStore

    #[test]
    fn token_store_reloads_a_stored_token_from_the_same_directory() {
        let (a, dir) = store();
        let peer = uuid::Uuid::from_u128(9);
        a.store(&peer, &token(1000));

        let b = TokenStore::new(&dir);
        assert_eq!(b.get(&peer, 1000).as_deref(), Some(token(1000).as_str()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_store_refuses_a_token_too_close_to_expiry() {
        let (s, dir) = store();
        let peer = uuid::Uuid::from_u128(9);
        s.store(&peer, &token(1000));
        let exp = 1000 + TOKEN_TTL_SECS;

        assert!(s.get(&peer, exp - MIN_REMAINING).is_some());
        assert!(s.get(&peer, exp - MIN_REMAINING + 1).is_none());
        assert!(s.get(&peer, exp + 1).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_store_does_not_persist_an_unparseable_token() {
        let (s, dir) = store();
        let peer = uuid::Uuid::from_u128(9);
        s.store(&peer, "garbage");
        assert!(s.get(&peer, 0).is_none());
        assert!(!s.path(&peer).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forget_clears_both_the_memory_and_the_disk_copy() {
        let (s, dir) = store();
        let peer = uuid::Uuid::from_u128(9);
        s.store(&peer, &token(1000));
        s.forget(&peer);

        assert!(s.get(&peer, 1000).is_none());
        assert!(TokenStore::new(&dir).get(&peer, 1000).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
