//! Content hasher abstraction — allows plugging different digest algorithms
//! without duplicating the JSON walking logic.

use core::fmt::Write;
use tiny_keccak::Hasher;

/// Abstraction over the hashing algorithm used for content digests.
///
/// Each implementor defines a two-character prefix and both a byte-level and
/// string-level hash function. The trait is crate-private — the public API
/// exposes only the concrete `digest_data` / `digest_data_blake3` functions.
pub(crate) trait ContentHasher {
    /// Two-character prefix, e.g. `"cj"` (SHA3 json) or `"cm"` (BLAKE3 json).
    const PREFIX: &'static str;

    /// Raw output type (currently `[u8; 32]` for both SHA3-256 and BLAKE3-256).
    type HashOutput: AsRef<[u8]>;

    /// Hash raw content and return the raw digest bytes.
    fn hash_bytes(content: &[u8]) -> Self::HashOutput;

    /// Hash raw content and return the multibase-encoded string (without prefix).
    fn hash(content: &[u8]) -> String {
        multibase::encode(multibase::Base::Base64Url, Self::hash_bytes(content))
    }
}

/// SHA3-256 via `tiny_keccak`.  Legacy behaviour — kept for backward compatibility.
pub(crate) struct Sha3Cj;

impl ContentHasher for Sha3Cj {
    const PREFIX: &'static str = "cj";
    type HashOutput = [u8; 32];

    fn hash_bytes(content: &[u8]) -> [u8; 32] {
        let mut hasher = tiny_keccak::Sha3::v256();
        let mut hash_output = [0u8; 32];
        hasher.update(content);
        hasher.finalize(&mut hash_output);
        hash_output
    }
}

/// BLAKE3-256.  Faster, modern alternative.
pub(crate) struct Blake3Cm;

impl ContentHasher for Blake3Cm {
    const PREFIX: &'static str = "cm";
    type HashOutput = [u8; 32];

    fn hash_bytes(content: &[u8]) -> [u8; 32] {
        let hash = blake3::hash(content);
        *hash.as_bytes()
    }
}

/// A typed, parsed representation of a JSON digest string like `"cjubdcpA0Ff..."` or `"cmursDCff..."`.
///
/// Each variant carries its own hash size — currently both 32 bytes, but future
/// hashers with different output sizes can add variants without changing the public API.
///
/// Round-trips through [`Display`] / [`FromStr`] and supports serde and SCALE codec.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "substrate",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        parity_scale_codec::MaxEncodedLen,
        parity_scale_codec::DecodeWithMemTracking,
        scale_info::TypeInfo
    )
)]
pub enum JsonDigest {
    /// SHA3-256 Merkle-tree hash (prefix `cj`).
    Sha3([u8; 32]),
    /// BLAKE3-256 Merkle-tree hash (prefix `cm`).
    Blake3([u8; 32]),
}

impl JsonDigest {
    /// The single-letter code used in the digest string after the leading `c`.
    pub fn kind_char(self) -> char {
        match self {
            Self::Sha3(_) => 'j',
            Self::Blake3(_) => 'm',
        }
    }

    /// Returns `true` if this is a SHA3-256 json-digest.
    pub fn is_sha3(self) -> bool {
        matches!(self, Self::Sha3(_))
    }

    /// Returns `true` if this is a BLAKE3-256 json-digest.
    pub fn is_blake3(self) -> bool {
        matches!(self, Self::Blake3(_))
    }

    /// Return the raw hash bytes as a slice, regardless of variant.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha3(b) => b,
            Self::Blake3(b) => b,
        }
    }
}

impl core::fmt::Display for JsonDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, bytes): (char, &[u8]) = match self {
            Self::Sha3(b) => ('j', b),
            Self::Blake3(b) => ('m', b),
        };
        f.write_char('c')?;
        f.write_char(kind)?;
        f.write_str(&multibase::encode(multibase::Base::Base64Url, bytes))
    }
}

impl core::str::FromStr for JsonDigest {
    type Err = crate::error::JsonDigestError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let mut chars = s.chars();
        if chars.next() != Some('c') {
            return Err(crate::error::JsonDigestError::Internal(
                "JsonDigest must start with 'c'".into(),
            ));
        }
        let kind = chars.next().ok_or_else(|| {
            crate::error::JsonDigestError::Internal("Missing JsonDigest kind character".into())
        })?;
        let multibase_str = chars.as_str();
        let (_base, bytes) = multibase::decode(multibase_str).map_err(|e| {
            crate::error::JsonDigestError::Internal(format!("Multibase decode error: {e}"))
        })?;
        match kind {
            'j' => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    crate::error::JsonDigestError::Internal(
                        "SHA3 JsonDigest must be 32 bytes".into(),
                    )
                })?;
                Ok(Self::Sha3(arr))
            }
            'm' => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    crate::error::JsonDigestError::Internal(
                        "BLAKE3 JsonDigest must be 32 bytes".into(),
                    )
                })?;
                Ok(Self::Blake3(arr))
            }
            _ => Err(crate::error::JsonDigestError::Internal(format!(
                "Unknown JsonDigest kind '{kind}'"
            ))),
        }
    }
}

impl serde::Serialize for JsonDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for JsonDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_roundtrip_sha3() {
        let digest = JsonDigest::Sha3([0xABu8; 32]);
        let s = digest.to_string();
        assert!(s.starts_with("cj"), "expected cj prefix, got: {s}");
        let parsed: JsonDigest = s.parse().unwrap();
        assert_eq!(parsed, digest);
    }

    #[test]
    fn display_roundtrip_blake3() {
        let digest = JsonDigest::Blake3([0xABu8; 32]);
        let s = digest.to_string();
        assert!(s.starts_with("cm"), "expected cm prefix, got: {s}");
        let parsed: JsonDigest = s.parse().unwrap();
        assert_eq!(parsed, digest);
    }

    #[test]
    fn parse_rejects_missing_c() {
        assert!("jF...".parse::<JsonDigest>().is_err());
    }

    #[test]
    fn parse_rejects_unknown_kind() {
        assert!("cxF...".parse::<JsonDigest>().is_err());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let short = format!("cj{}", multibase::encode(multibase::Base::Base64Url, [0u8; 16]));
        assert!(short.parse::<JsonDigest>().is_err());
    }
}
