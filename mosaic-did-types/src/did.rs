//! DID identifier types for `did:mosaic`.
//!
//! A Mosaic DID is derived from the initial public key:
//! ```text
//! did:mosaic:<multibase(base58btc, BLAKE3-256(initial-public-key))>
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

/// A 32-byte Mosaic DID identifier, derived as `BLAKE3-256(initial_public_key)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "substrate",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        parity_scale_codec::MaxEncodedLen,
        scale_info::TypeInfo,
    )
)]
pub struct Did(pub [u8; 32]);

#[cfg(test)]
impl Did {
    // Public key of Alice
    const PK_ALICE: &[u8; 32] = b"\xd4\x35\x93\xc7\x15\xfd\xd3\x1c\x61\x14\x1a\xbd\x04\xa9\x9f\xd6\x82\x2c\x85\x58\x85\x4c\xcd\xe3\x9a\x56\x84\xe7\xa5\x6d\xa2\x7d";

    pub fn alice() -> Self {
        Self::from_public_key(Self::PK_ALICE)
    }
}

impl Did {
    /// The DID method prefix.
    pub const METHOD_PREFIX: &'static str = "did:mosaic:";

    /// The legacy IOP Morpheus prefix (for migration support).
    pub const LEGACY_MORPHEUS_PREFIX: &'static str = "did:morpheus:";

    /// Derive a DID identifier from a public key using BLAKE3-256.
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let hash = blake3::hash(public_key);
        Did(*hash.as_bytes())
    }

    /// Return the raw 32-byte identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode the DID as a full `did:mosaic:z...` string using multibase base58btc.
    pub fn to_did_string(&self) -> String {
        // Multibase base58btc prefix is 'z'
        let encoded = bs58::encode(&self.0).into_string();
        let mut s = String::with_capacity(Self::METHOD_PREFIX.len() + 1 + encoded.len());
        s.push_str(Self::METHOD_PREFIX);
        s.push('z');
        s.push_str(&encoded);
        s
    }

    /// Parse a `did:mosaic:z...` string back into a Did.
    pub fn from_did_string(s: &str) -> Result<Self, DidParseError> {
        let rest = s.strip_prefix(Self::METHOD_PREFIX).ok_or(DidParseError::InvalidPrefix)?;

        // Expect multibase base58btc prefix 'z'
        let base58_str = rest.strip_prefix('z').ok_or(DidParseError::InvalidMultibase)?;

        let bytes =
            bs58::decode(base58_str).into_vec().map_err(|_| DidParseError::InvalidBase58)?;

        if bytes.len() != 32 {
            return Err(DidParseError::InvalidLength(bytes.len()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Did(arr))
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_did_string())
    }
}

impl From<[u8; 32]> for Did {
    fn from(bytes: [u8; 32]) -> Self {
        Did(bytes)
    }
}

/// Errors that can occur when parsing a DID string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidParseError {
    /// The string doesn't start with `did:mosaic:`.
    InvalidPrefix,
    /// Missing or wrong multibase prefix (expected 'z' for base58btc).
    InvalidMultibase,
    /// Invalid base58 encoding.
    InvalidBase58,
    /// Decoded bytes are not 32 bytes long.
    InvalidLength(usize),
}

impl fmt::Display for DidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "DID must start with '{}'", Did::METHOD_PREFIX),
            Self::InvalidMultibase => write!(f, "expected multibase base58btc prefix 'z'"),
            Self::InvalidBase58 => write!(f, "invalid base58 encoding"),
            Self::InvalidLength(len) => write!(f, "expected 32 bytes, got {len}"),
        }
    }
}

/// Key identifier within a DID document.
///
/// References a specific verification method, e.g. `"key-1"`, `"key-recovery"`.
/// Stored as raw bytes with a maximum length of 64.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "substrate",
    derive(parity_scale_codec::Encode, parity_scale_codec::Decode, scale_info::TypeInfo,)
)]
pub struct KeyRef(Vec<u8>);

impl KeyRef {
    /// Maximum length of a key identifier in bytes.
    pub const MAX_LEN: usize = 64;

    /// Create a new KeyRef from bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() > Self::MAX_LEN {
            return Err("KeyRef exceeds maximum length of 64 bytes");
        }
        Ok(KeyRef(bytes))
    }

    /// Create a KeyRef from a string identifier (e.g. "key-1").
    pub fn from_str_id(s: &str) -> Result<Self, &'static str> {
        Self::new(s.as_bytes().to_vec())
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return as a UTF-8 string if valid.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "0x{}", hex::encode(&self.0)),
        }
    }
}

/// Content identifier for BeforeProof — discriminates hashing strategy.
///
/// Two hashing strategies exist in the ecosystem:
/// - **ByteHash**: BLAKE3-256 of raw binary content (new, Mosaic-native).
/// - **JsonDigest**: SHA3-256 Merkle-tree hash of structured JSON data
///   (legacy Morpheus `cj`-prefix format). Enables selective disclosure
///   of document subtrees — a property flat hashing cannot provide.
///
/// Both variants store a fixed 32-byte hash. The enum discriminant captures
/// *how* the hash was produced, which determines verifiability semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "substrate",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        parity_scale_codec::MaxEncodedLen,
        scale_info::TypeInfo,
    )
)]
pub enum ContentId {
    /// BLAKE3-256 hash of raw binary content.
    ByteHash([u8; 32]),
    /// SHA3-256 json-digest Merkle-tree hash of structured JSON data.
    /// Supports selective disclosure of document subtrees.
    JsonDigest([u8; 32]),
}

impl ContentId {
    /// Compute a ContentId from arbitrary content bytes using BLAKE3.
    pub fn from_content(content: &[u8]) -> Self {
        let hash = blake3::hash(content);
        ContentId::ByteHash(*hash.as_bytes())
    }

    /// Create a ContentId from a pre-computed JSON-digest hash (SHA3-256).
    pub fn from_json_digest_hash(hash: [u8; 32]) -> Self {
        ContentId::JsonDigest(hash)
    }

    /// Return the raw 32-byte hash, regardless of hashing strategy.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            ContentId::ByteHash(h) | ContentId::JsonDigest(h) => h,
        }
    }

    /// Returns `true` if this content ID was produced by json-digest.
    pub fn is_json_digest(&self) -> bool {
        matches!(self, ContentId::JsonDigest(_))
    }
}

impl Default for ContentId {
    fn default() -> Self {
        ContentId::ByteHash([0u8; 32])
    }
}

impl From<[u8; 32]> for ContentId {
    fn from(bytes: [u8; 32]) -> Self {
        ContentId::ByteHash(bytes)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentId::ByteHash(h) => write!(f, "0x{}", hex::encode(h)),
            ContentId::JsonDigest(h) => write!(f, "cj:0x{}", hex::encode(h)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID_ALICE: &str = "did:mosaic:zDmfekcjeeeZKwAgu5pAXS5ZxEZxmkCfKpTs7Upm2sjsN";

    #[test]
    fn did_alice_to_string() {
        let did = Did::alice();
        assert_eq!(&did.to_did_string(), DID_ALICE);
    }

    #[test]
    fn did_alice_from_string() {
        let did1 = Did::alice();
        let did2 = Did::from_did_string(DID_ALICE).expect("constant known to parse correctly");
        assert_eq!(did1, did2);
    }

    #[test]
    fn did_from_public_key_deterministic() {
        let pk = b"test-public-key-ed25519-32bytes!";
        let did1 = Did::from_public_key(pk);
        let did2 = Did::from_public_key(pk);
        assert_eq!(did1, did2);
    }

    #[test]
    fn did_different_keys_different_dids() {
        let did1 = Did::from_public_key(b"key-alice");
        let did2 = Did::from_public_key(b"key-bob");
        assert_ne!(did1, did2);
    }

    #[test]
    fn did_parse_invalid_prefix() {
        let err = Did::from_did_string("did:morpheus:z123").unwrap_err();
        assert_eq!(err, DidParseError::InvalidPrefix);
    }

    #[test]
    fn did_parse_invalid_multibase() {
        let err = Did::from_did_string("did:mosaic:f123").unwrap_err();
        assert_eq!(err, DidParseError::InvalidMultibase);
    }

    #[test]
    fn did_parse_invalid_length() {
        let err = Did::from_did_string("did:mosaic:zqztJ6XX6GDxdSgdiySiT3J").unwrap_err();
        assert!(matches!(err, DidParseError::InvalidLength(_)));
    }

    #[test]
    fn content_id_from_content() {
        let content = b"Hello, Mosaic Trust Network!";
        let cid1 = ContentId::from_content(content);
        let cid2 = ContentId::from_content(content);
        assert_eq!(cid1, cid2);
        assert!(!cid1.is_json_digest());

        let cid3 = ContentId::from_content(b"Different content");
        assert_ne!(cid1, cid3);
    }

    #[test]
    fn content_id_json_digest_variant() {
        let hash = [0xABu8; 32];
        let cid = ContentId::from_json_digest_hash(hash);
        assert!(cid.is_json_digest());
        assert_eq!(cid.as_bytes(), &hash);

        // ByteHash and JsonDigest with same bytes are NOT equal (different variants)
        let byte_cid = ContentId::ByteHash(hash);
        assert_ne!(cid, byte_cid);
    }

    #[test]
    fn content_id_display() {
        let hash = [0x42u8; 32];
        let byte_cid = ContentId::ByteHash(hash);
        assert!(byte_cid.to_string().starts_with("0x"));

        let json_cid = ContentId::JsonDigest(hash);
        assert!(json_cid.to_string().starts_with("cj:0x"));
    }

    #[test]
    fn key_id_from_str() {
        let kid = KeyRef::from_str_id("key-1").unwrap();
        assert_eq!(kid.as_str(), Some("key-1"));
    }

    #[test]
    fn key_id_max_length() {
        let long = vec![b'a'; 65];
        assert!(KeyRef::new(long).is_err());

        let ok = vec![b'a'; 64];
        assert!(KeyRef::new(ok).is_ok());
    }
}
