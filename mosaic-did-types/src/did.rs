//! DID identifier types for `did:mosaic`.
//!
//! A Mosaic DID is derived from the initial public key's multicipher key ID:
//! ```text
//! did:mosaic:<MKeyId>
//! ```
//! where `<MKeyId>` is the Ed25519Blake3 multicipher key ID string (e.g., `iozABC...`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use bounded_collections::{BoundedVec, ConstU32};
use iop_keyvault::ed25519::{Blake3, EdKeyId, EdPublicKey};
use iop_keyvault::multicipher::MKeyId;

/// Maximum key ID size in bytes (for `KeyRef`).
pub const MAX_KEY_REF_LEN: u32 = 64;

/// Maximum SCALE-encoded length of a DID.
///
/// MKeyId strings are at most ~49 UTF-8 bytes (for Ed25519Blake3).
/// SCALE encodes as a length-prefixed `Vec<u8>`: compact(len) + bytes.
/// We use 66 (2-byte compact prefix + 64 bytes) as a conservative bound.
const MAX_DID_ENCODED_LEN: usize = 66;

/// A Mosaic DID identifier, wrapping the multicipher key ID of the initial public key.
///
/// The DID is derived from the initial Ed25519 public key using Blake3 hashing,
/// producing an `Ed25519Blake3` multicipher key ID. The DID string representation
/// is `did:mosaic:<MKeyId>`, e.g. `did:mosaic:iozABC...`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Did {
    /// The multicipher key ID of the initial public key that created this DID.
    pub default_key_id: MKeyId,
}

// ========== SCALE codec (Substrate) ==========

#[cfg(feature = "substrate")]
mod scale_impls {
    use super::*;
    use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, EncodeLike, MaxEncodedLen};
    use scale_info::TypeInfo;

    impl EncodeLike for Did {}

    impl Encode for Did {
        fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
            let bytes = self.default_key_id.to_bytes();
            Encode::encode_to(&bytes, dest);
        }
    }

    impl Decode for Did {
        fn decode<I: parity_scale_codec::Input>(
            input: &mut I,
        ) -> Result<Self, parity_scale_codec::Error> {
            let bytes = Vec::<u8>::decode(input)?;
            let key_id = MKeyId::from_bytes(bytes)
                .map_err(|_| parity_scale_codec::Error::from("invalid MKeyId encoding"))?;
            Ok(Did { default_key_id: key_id })
        }
    }

    impl DecodeWithMemTracking for Did {}

    impl MaxEncodedLen for Did {
        fn max_encoded_len() -> usize {
            MAX_DID_ENCODED_LEN
        }
    }

    impl TypeInfo for Did {
        type Identity = Self;
        fn type_info() -> scale_info::Type {
            scale_info::Type::builder()
                .path(scale_info::Path::new("Did", "mosaic_did_types::did"))
                .composite(
                    scale_info::build::Fields::unnamed()
                        .field(|f| f.ty::<Vec<u8>>().type_name("MKeyId")),
                )
        }
    }
}

// ========== Serde ==========

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;

    impl serde::Serialize for Did {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.to_did_string())
        }
    }

    impl<'de> serde::Deserialize<'de> for Did {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            Did::from_did_string(&s).map_err(serde::de::Error::custom)
        }
    }
}

// ========== Test helpers ==========

#[cfg(test)]
impl Did {
    pub fn alice() -> Self {
        // RFC 8032 test vector 1: pk for secret key = all zeros
        let pk_bytes =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        Self::from_public_key(&pk_bytes).expect("Alice PK is a valid Ed25519 key")
    }

    pub fn bob() -> Self {
        // RFC 8032 test vector 2
        let pk_bytes =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap();
        Self::from_public_key(&pk_bytes).expect("Bob PK is a valid Ed25519 key")
    }
}

// ========== Core API ==========

impl Did {
    /// The DID method prefix.
    pub const METHOD_PREFIX: &'static str = "did:mosaic:";

    /// Derive a DID identifier from a raw Ed25519 public key.
    ///
    /// The bytes must be a valid 32-byte Ed25519 public key on the curve.
    /// Returns `Err` if the bytes are not a valid Ed25519 point.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, DidCreationError> {
        let pk =
            EdPublicKey::from_bytes(public_key).map_err(|_| DidCreationError::InvalidPublicKey)?;
        let key_id = EdKeyId::from_pk::<Blake3>(&pk);
        Ok(Did { default_key_id: MKeyId::Ed25519Blake3(key_id) })
    }

    /// Encode the DID as a full `did:mosaic:<MKeyId>` string.
    pub fn to_did_string(&self) -> String {
        let kid_str = self.default_key_id.to_string();
        let mut s = String::with_capacity(Self::METHOD_PREFIX.len() + kid_str.len());
        s.push_str(Self::METHOD_PREFIX);
        s.push_str(&kid_str);
        s
    }

    /// Parse a `did:mosaic:<MKeyId>` string back into a Did.
    pub fn from_did_string(s: &str) -> Result<Self, DidParseError> {
        let rest = s.strip_prefix(Self::METHOD_PREFIX).ok_or(DidParseError::InvalidPrefix)?;
        let key_id: MKeyId = rest.parse().map_err(|_| DidParseError::InvalidKeyId)?;
        Ok(Did { default_key_id: key_id })
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_did_string())
    }
}

/// Errors that can occur when creating a DID from a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidCreationError {
    /// The public key bytes are not a valid Ed25519 curve point.
    InvalidPublicKey,
}

impl fmt::Display for DidCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
        }
    }
}

/// Errors that can occur when parsing a DID string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidParseError {
    /// The string doesn't start with `did:mosaic:`.
    InvalidPrefix,
    /// The MKeyId portion could not be parsed.
    InvalidKeyId,
}

impl fmt::Display for DidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "DID must start with '{}'", Did::METHOD_PREFIX),
            Self::InvalidKeyId => write!(f, "invalid multicipher key ID"),
        }
    }
}

/// Key identifier within a DID document.
///
/// References a specific verification method, e.g. `"key-1"`, `"key-recovery"`.
/// Stored as bounded bytes with a maximum length of 64.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyRef(BoundedVec<u8, ConstU32<MAX_KEY_REF_LEN>>);

impl KeyRef {
    /// Create a new KeyRef from bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        let bounded =
            BoundedVec::try_from(bytes).map_err(|_| "KeyRef exceeds maximum length of 64 bytes")?;
        Ok(KeyRef(bounded))
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Return as a UTF-8 string if valid.
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.0.as_slice()).ok()
    }

    /// Access the inner BoundedVec directly.
    pub fn as_bounded(&self) -> &BoundedVec<u8, ConstU32<MAX_KEY_REF_LEN>> {
        &self.0
    }
}

impl core::str::FromStr for KeyRef {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.as_bytes().to_vec())
    }
}

// Manual impls for traits that BoundedVec may not derive.

impl PartialOrd for KeyRef {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyRef {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl core::hash::Hash for KeyRef {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "0x{}", hex::encode(self.as_bytes())),
        }
    }
}

/// Content identifier for BeforeProof -- discriminates hashing strategy.
///
/// Two hashing strategies exist in the ecosystem:
/// - **ByteHash**: BLAKE3-256 of raw binary content (new, Mosaic-native).
/// - **JsonDigest**: SHA3-256 Merkle-tree hash of structured JSON data
///   (legacy Morpheus `cj`-prefix format). Enables selective disclosure
///   of document subtrees -- a property flat hashing cannot provide.
///
/// Both variants store a fixed 32-byte hash. The enum discriminant captures
/// *how* the hash was produced, which determines verifiability semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ContentId {
    /// BLAKE3-256 hash of raw binary content.
    ByteHash([u8; 32]),
    /// SHA3-256 json-digest Merkle-tree hash of structured JSON data.
    /// Supports selective disclosure of document subtrees.
    JsonDigest([u8; 32]),
}

impl ContentId {
    /// Compute a ContentId from arbitrary content bytes using BLAKE3.
    pub fn from_bytes(content: &[u8]) -> Self {
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

impl core::str::FromStr for ContentId {
    type Err = ContentIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(hex) = s.strip_prefix("cj:0x") {
            return Ok(ContentId::JsonDigest(decode_hash_hex(hex)?));
        }
        if let Some(hex) = s.strip_prefix("0x") {
            return Ok(ContentId::ByteHash(decode_hash_hex(hex)?));
        }
        Err(ContentIdParseError::InvalidPrefix)
    }
}

fn decode_hash_hex(hex_str: &str) -> Result<[u8; 32], ContentIdParseError> {
    let bytes = hex::decode(hex_str).map_err(|_| ContentIdParseError::InvalidHex)?;
    bytes.try_into().map_err(|_| ContentIdParseError::InvalidLength)
}

/// Errors that can occur when parsing a displayed [`ContentId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentIdParseError {
    /// The string was not in `0x...` or `cj:0x...` form.
    InvalidPrefix,
    /// The hash payload was not valid hexadecimal.
    InvalidHex,
    /// The decoded hash was not exactly 32 bytes.
    InvalidLength,
}

impl fmt::Display for ContentIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "ContentId must start with '0x' or 'cj:0x'"),
            Self::InvalidHex => write!(f, "ContentId hash must be valid hexadecimal"),
            Self::InvalidLength => write!(f, "ContentId hash must be exactly 32 bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    /// Pinned: Alice = RFC 8032 test vector 1 pk → Blake3 MKeyId
    const DID_ALICE: &str = "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";

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
        let pk = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap();
        let did1 = Did::from_public_key(&pk).unwrap();
        let did2 = Did::from_public_key(&pk).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn did_different_keys_different_dids() {
        let did1 = Did::alice();
        let did2 = Did::bob();
        assert_ne!(did1, did2);
    }

    #[test]
    fn did_from_invalid_public_key() {
        // Not a valid Ed25519 curve point
        let err = Did::from_public_key(b"this-is-not-an-ed25519-key-at!!");
        assert!(err.is_err());
    }

    #[test]
    fn did_parse_invalid_prefix() {
        let err = Did::from_did_string("did:morpheus:iozABC").unwrap_err();
        assert_eq!(err, DidParseError::InvalidPrefix);
    }

    #[test]
    fn did_parse_invalid_key_id() {
        let err = Did::from_did_string("did:mosaic:garbage").unwrap_err();
        assert_eq!(err, DidParseError::InvalidKeyId);
    }

    #[test]
    fn did_string_roundtrip() {
        let did = Did::alice();
        let s = did.to_did_string();
        let parsed = Did::from_did_string(&s).unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn content_id_from_content() {
        let content = b"Hello, Mosaic Trust Network!";
        let cid1 = ContentId::from_bytes(content);
        let cid2 = ContentId::from_bytes(content);
        assert_eq!(cid1, cid2);
        assert!(!cid1.is_json_digest());

        let cid3 = ContentId::from_bytes(b"Different content");
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
    fn content_id_display_roundtrip() {
        let hash = [0x42u8; 32];

        let byte_cid = ContentId::ByteHash(hash);
        let parsed_byte = byte_cid.to_string().parse::<ContentId>().unwrap();
        assert_eq!(parsed_byte, byte_cid);

        let json_cid = ContentId::JsonDigest(hash);
        let parsed_json = json_cid.to_string().parse::<ContentId>().unwrap();
        assert_eq!(parsed_json, json_cid);
    }

    #[test]
    fn content_id_parse_rejects_bad_inputs() {
        assert_eq!(
            "cjuFoobar".parse::<ContentId>().unwrap_err(),
            ContentIdParseError::InvalidPrefix
        );
        assert_eq!("0xnot-hex".parse::<ContentId>().unwrap_err(), ContentIdParseError::InvalidHex);
        assert_eq!("cj:0x42".parse::<ContentId>().unwrap_err(), ContentIdParseError::InvalidLength);
    }

    #[test]
    fn key_id_from_str() {
        let kid = KeyRef::from_str("key-1").unwrap();
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
