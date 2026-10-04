use compact_str::ToCompactString;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}

impl FromStr for Hash32 {
    type Err = HexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0; 32];
        hex::decode_to_slice(s.trim(), &mut out)
            .map_err(|_| HexParseError(s.to_compact_string()))?;

        Ok(Self(out))
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(D::Error::custom)
        } else {
            <[u8; 32]>::deserialize(d).map(Self)
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct HexParseError(compact_str::CompactString);

impl std::fmt::Display for HexParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "expected 64 hex characters, got {:?}", self.0)
    }
}

impl std::error::Error for HexParseError {}

#[inline]
pub fn sha256(bytes: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hash32

    #[test]
    fn hex_roundtrip_and_json_form() {
        let h = sha256(b"tundra");
        assert_eq!(h, h.to_hex().parse().unwrap());

        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", h.to_hex()));
        assert_eq!(h, serde_json::from_str::<Hash32>(&json).unwrap());
    }

    #[test]
    fn binary_form_is_raw_32_bytes() {
        let h = sha256(b"tundra");
        let bin = postcard::to_stdvec(&h).unwrap();
        assert_eq!(bin.len(), 32);
        assert_eq!(bin, h.0);
        assert_eq!(h, postcard::from_bytes::<Hash32>(&bin).unwrap());
    }

    #[test]
    fn hex_parsing_rejects_malformed_input() {
        assert!("zz".parse::<Hash32>().is_err());
        assert!("ab".repeat(31).parse::<Hash32>().is_err());
        assert!(serde_json::from_str::<Hash32>("\"nope\"").is_err());
    }

    #[test]
    fn sha256_matches_a_known_vector() {
        assert_eq!(
            sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
