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
use json_digest::JsonDigest;

use bounded_collections::{BoundedVec, ConstU32};
use mosaic_keyvault::ed25519::{Blake3, EdKeyId, EdPublicKey};
use mosaic_keyvault::multicipher::MKeyId;

/// Maximum key ID size in bytes (for `KeyRef`).
pub const MAX_KEY_REF_LEN: u32 = 64;

/// Maximum SCALE-encoded length of a DID.
///
/// MKeyId strings are at most ~49 UTF-8 bytes (for Ed25519Blake3).
/// SCALE encodes as a length-prefixed `Vec<u8>`: compact(len) + bytes.
/// We use 66 (2-byte compact prefix + 64 bytes) as a conservative bound.
#[cfg(feature = "substrate")]
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
/// References a specific verification method, e.g. `"ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH"`.
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
#[derive(serde::Serialize, serde::Deserialize)]
/// A key reference (document-fragment identifier) within a DID document.
///
/// # Convention
///
/// `KeyRef` SHOULD be the **string representation of an `MKeyId`** (multicipher
/// key ID). Multicipher key IDs use the format `i<suite>z<base58btc-bytes>`:
///
/// | Position | Meaning | Examples |
/// |---|---|---|
/// | `i` | key-ID prefix (distinguishes from `p` public key and `s` signature) | always `i` |
/// | `<suite>` | cipher suite | `e` = Ed25519, `o` = Ed25519Blake3, `s` = secp256k1 |
/// | `z` | multibase base58btc prefix | always `z` |
/// | `<bytes>` | inner key-ID bytes in base58btc | 32-byte blake3 hash for `o`, 20-byte ripemd160 for `s` |
///
/// The `Authentication` type carried by `DidOperation::AddKey` wraps the
/// `MKeyId`, so callers derive the `KeyRef` from that. The pallet extracts
/// the `MKeyId` from the `PublicKey` variant (currently the only supported
/// variant; `keyvault-plan.md` describes future `KeyId`-variant registration
/// where the public key is not revealed on-chain immediately).
///
/// `KeyRef` does NOT enforce the MKeyId convention at the type level — it is
/// a bounded byte vector (`BoundedVec<u8, 64>`) that accepts any bytes. This
/// flexibility is intentional:
/// - It lets the indexer reconstruct `KeyRef` values from SCALE-encoded events
///   without depending on `mosaic_keyvault`.
/// - It keeps `mosaic-did-types` independent of specific cipher-suite formats.
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

/// Content identifier — discriminates hashing strategy and structure (flat vs. Merkle tree).
///
/// # Variants
///
/// | Prefix | Variant | Algorithm | Structure | Hash size |
/// |--------|---------|-----------|-----------|-----------|
/// | `cb` | `Blake3Flat` | BLAKE3-256 | flat bytes | 32 |
/// | `cB` | `Blake2bFlat` | BLAKE2b-512 | flat bytes | 64 |
/// | `cj` | `Structured` | SHA3-256 | json-digest | 32 |
/// | `cm` | `Structured` | BLAKE3-256 | json-digest | 32 |
///
/// Flat hashes use **Base58Btc** encoding. Structured hashes use the standard
/// `json_digest::JsonDigest` format (multibase Base64Url).
///
/// # Size note
///
/// `Blake2bFlat` carries a 64-byte hash — the large-enum-variant warning is expected
/// and acceptable. All other variants use 32-byte hashes.
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
#[allow(clippy::large_enum_variant)] // Blake2bFlat is intentionally 64 bytes
pub enum ContentId {
    /// BLAKE3-256 of raw binary content (32 bytes). Prefix `cb`.
    Blake3Flat([u8; 32]),
    /// BLAKE2b-512 of raw binary content (64 bytes). Prefix `cB`.
    Blake2bFlat([u8; 64]),
    /// Structured JSON Merkle-tree hash (SHA3-256 or BLAKE3-256).
    /// The inner `JsonDigest` carries the algorithm kind.
    Structured(JsonDigest),
}

impl ContentId {
    /// Compute a `Blake3Flat` content ID from arbitrary raw bytes.
    pub fn from_bytes(content: &[u8]) -> Self {
        ContentId::Blake3Flat(*blake3::hash(content).as_bytes())
    }

    /// Create a `Structured` content ID from a pre-computed json-digest (SHA3-256, legacy).
    pub fn from_json_digest_hash(hash: [u8; 32]) -> Self {
        ContentId::Structured(JsonDigest::Sha3(hash))
    }

    /// Create a `Structured` content ID from a typed [`JsonDigest`].
    pub fn from_json_digest(digest: JsonDigest) -> Self {
        ContentId::Structured(digest)
    }

    /// Return the raw hash bytes as a slice, regardless of variant.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ContentId::Blake3Flat(h) => h,
            ContentId::Blake2bFlat(h) => h,
            ContentId::Structured(d) => d.as_bytes(),
        }
    }

    /// Returns `true` if this content ID is a structured JSON digest.
    pub fn is_json_digest(&self) -> bool {
        matches!(self, ContentId::Structured(_))
    }
}

impl Default for ContentId {
    fn default() -> Self {
        ContentId::Blake3Flat([0u8; 32])
    }
}

impl From<[u8; 32]> for ContentId {
    fn from(bytes: [u8; 32]) -> Self {
        ContentId::Blake3Flat(bytes)
    }
}

impl From<JsonDigest> for ContentId {
    fn from(digest: JsonDigest) -> Self {
        ContentId::Structured(digest)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentId::Blake3Flat(h) => {
                write!(f, "cb{}", multibase::encode(multibase::Base::Base58Btc, h))
            }
            ContentId::Blake2bFlat(h) => {
                write!(f, "cB{}", multibase::encode(multibase::Base::Base58Btc, h))
            }
            ContentId::Structured(d) => fmt::Display::fmt(d, f),
        }
    }
}

impl core::str::FromStr for ContentId {
    type Err = ContentIdParseError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let mut chars = s.chars();
        if chars.next() != Some('c') {
            return Err(ContentIdParseError::InvalidPrefix);
        }
        let kind = chars.next().ok_or(ContentIdParseError::InvalidPrefix)?;
        let payload = chars.as_str();
        match kind {
            'b' => {
                let (_base, bytes) =
                    multibase::decode(payload).map_err(|_| ContentIdParseError::InvalidBase58)?;
                let arr: [u8; 32] =
                    bytes.try_into().map_err(|_| ContentIdParseError::InvalidLength)?;
                Ok(ContentId::Blake3Flat(arr))
            }
            'B' => {
                let (_base, bytes) =
                    multibase::decode(payload).map_err(|_| ContentIdParseError::InvalidBase58)?;
                let arr: [u8; 64] =
                    bytes.try_into().map_err(|_| ContentIdParseError::InvalidLength)?;
                Ok(ContentId::Blake2bFlat(arr))
            }
            'j' | 'm' => {
                // Re-parse through JsonDigest::from_str for structured variants.
                let digest: JsonDigest =
                    s.parse().map_err(|_| ContentIdParseError::InvalidJsonDigest)?;
                Ok(ContentId::Structured(digest))
            }
            _ => Err(ContentIdParseError::InvalidPrefix),
        }
    }
}

/// Errors that can occur when parsing a displayed [`ContentId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentIdParseError {
    /// The string does not start with `c` followed by a known variant letter.
    InvalidPrefix,
    /// The Base58Btc payload could not be decoded.
    InvalidBase58,
    /// The decoded hash bytes had the wrong length for the variant.
    InvalidLength,
    /// The structured JSON digest string could not be parsed.
    InvalidJsonDigest,
}

impl fmt::Display for ContentIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => {
                write!(f, "ContentId must start with 'c' followed by b/B/j/m")
            }
            Self::InvalidBase58 => write!(f, "ContentId payload is not valid Base58Btc"),
            Self::InvalidLength => write!(f, "ContentId hash has wrong length for its variant"),
            Self::InvalidJsonDigest => write!(f, "ContentId structured digest could not be parsed"),
        }
    }
}

impl serde::Serialize for ContentId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for ContentId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
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
        assert_eq!(cid.as_bytes(), &hash[..]);

        // Blake3Flat and Structured with same bytes are NOT equal (different variants)
        let flat_cid = ContentId::Blake3Flat(hash);
        assert_ne!(cid, flat_cid);
    }

    #[test]
    fn content_id_display() {
        let hash = [0x42u8; 32];
        let flat_cid = ContentId::Blake3Flat(hash);
        assert!(flat_cid.to_string().starts_with("cb"));

        let json_cid = ContentId::from_json_digest_hash(hash);
        assert!(json_cid.to_string().starts_with("cj"));
    }

    #[test]
    fn content_id_display_roundtrip() {
        let hash = [0x42u8; 32];

        let flat_cid = ContentId::Blake3Flat(hash);
        let parsed_flat = flat_cid.to_string().parse::<ContentId>().unwrap();
        assert_eq!(parsed_flat, flat_cid);

        let json_cid = ContentId::from_json_digest_hash(hash);
        let parsed_json = json_cid.to_string().parse::<ContentId>().unwrap();
        assert_eq!(parsed_json, json_cid);

        // BLAKE3 structured roundtrip
        let blake3_cid = ContentId::Structured(JsonDigest::Blake3(hash));
        let s = blake3_cid.to_string();
        assert!(s.starts_with("cm"), "expected cm prefix, got {s}");
        let parsed = s.parse::<ContentId>().unwrap();
        assert_eq!(parsed, blake3_cid);
    }

    #[test]
    fn content_id_parse_rejects_bad_inputs() {
        assert_eq!(
            "not-a-content-id".parse::<ContentId>().unwrap_err(),
            ContentIdParseError::InvalidPrefix
        );
        assert_eq!("cxF...".parse::<ContentId>().unwrap_err(), ContentIdParseError::InvalidPrefix);
        // Wrong length for Blake3Flat variant
        let short = format!("cb{}", multibase::encode(multibase::Base::Base58Btc, [0u8; 16]));
        assert_eq!(short.parse::<ContentId>().unwrap_err(), ContentIdParseError::InvalidLength);
    }

    #[test]
    fn content_id_blake2b_roundtrip() {
        // 64 bytes of dummy hash
        let hash = [0x7Fu8; 64];
        let cid = ContentId::Blake2bFlat(hash);
        let s = cid.to_string();
        assert!(s.starts_with("cB"), "expected cB prefix, got {s}");
        let parsed = s.parse::<ContentId>().unwrap();
        assert_eq!(parsed, cid);
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
