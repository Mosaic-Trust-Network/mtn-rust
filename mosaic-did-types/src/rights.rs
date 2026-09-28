//! Off-chain rights document types.
//!
//! A rights document maps keys to the set of off-chain rights they hold.
//! It is canonicalized via `json_digest` (BLAKE3-256 Merkle tree) and its content
//! ID is committed on-chain. The full document stays private — carried by
//! presenters in Verifiable Presentations.
//!
//! # Two-Phase Design
//!
//! - `UnsafeRightsDocument` / `UnsafeRightEntry` — raw wire format, derive-deserialized
//!   from JSON with zero semantic validation.
//! - `RightsDocument` (schema-gated enum) / `RightsDocumentV1` / `RightEntryV1` —
//!   validated domain types constructed via `TryFrom<UnsafeRightsDocument>`.
//! - The document declares its `hashAlgorithm` inside the hashed preimage, so a
//!   verifier dispatches on the declaration instead of assuming an algorithm.
//! - `key: Authentication` supports either `MKeyId` (compact hash reference) or
//!   `MPublicKey` (self-contained verifiable key). The issuer chooses the revelation level.

use alloc::{string::String, string::ToString, vec::Vec};

use crate::{auth::Authentication, did::ContentId, did::Did};

/// Schema URI for V1 rights documents.
///
/// A v1 document declares its hashing algorithm in `hashAlgorithm`, inside the
/// hashed preimage. The algorithm set is closed at consensus — see
/// [`ContentId::is_supported_commitment_algorithm`] — but a new algorithm is a
/// new [`ContentHashAlgorithm`] value, not a new schema: the declaration is
/// already part of the preimage, so adding one does not change the field set.
pub const RIGHTS_DOCUMENT_V1_SCHEMA: &str = "https://mosaic-trust.net/ns/did-rights/v1";

/// The hashing algorithm a rights document declares in its preimage.
///
/// # Why this is self-describing
///
/// The verifier has to hash a presented document *before* it knows whether the
/// result matches, so the algorithm cannot be read off the expected on-chain
/// value — that value is a claim, not an input. Something has to be
/// authoritative, and there are two candidates:
///
/// - **Consensus** (`ContentId::is_supported_commitment_algorithm`) fixes the
///   permitted set, so a chain never holds an unverifiable commitment.
/// - **The document** (this type) says which algorithm produced the digest.
///
/// Both are needed. Consensus alone would force a runtime upgrade to introduce
/// an algorithm; this field alone would let a publisher pick any algorithm at
/// will, including one the chain refuses. Declaring the algorithm *inside* the
/// preimage also means the declaration is covered by the digest, so a document
/// cannot claim one algorithm and be hashed with another — and since a
/// declaration produces a differently tagged content ID, a downgraded document
/// can never match an on-chain value produced with a stronger algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentHashAlgorithm {
    /// BLAKE3-256 over the canonical JSON Merkle tree. The pinned algorithm.
    #[serde(rename = "blake3-canonical-json")]
    Blake3CanonicalJson,
    /// SHA3-256 over the canonical JSON Merkle tree.
    ///
    /// Permitted as a commitment algorithm alongside BLAKE3: both hash the
    /// canonical JSON Merkle tree, so a document declaring either can be
    /// reproduced and checked — see
    /// [`ContentId::is_supported_commitment_algorithm`]. A document declaring
    /// this produces a `cj` content ID.
    #[serde(rename = "sha3-canonical-json")]
    Sha3CanonicalJson,
}

// ========== Wire Format (untrusted, derive‑deserialized) ==========

/// Raw, untrusted wire-format entry. Every field is a plain `String`.
/// Zero semantic validation — accepts anything structurally valid JSON.
///
/// Unknown fields are **rejected**: this type is part of the digest preimage,
/// so a field an implementation ignores would change the digest it computes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsafeRightEntry {
    /// The key this entry applies to (serialized as `"keyRef"` in JSON).
    ///
    /// A reference to a key the on-chain state knows — normally an `MKeyId`.
    /// The full `MPublicKey` is also accepted, and
    /// [`RightsDocument::grants_right_by_key_ref`] matches the two forms
    /// transparently.
    #[serde(rename = "keyRef")]
    pub key: String,
    /// The set of off-chain rights granted to this key.
    pub rights: Vec<String>,
}

/// Raw, untrusted wire-format rights document.
///
/// Deserialized from JSON without semantic checks. Convert to [`RightsDocument`]
/// via `TryFrom` to validate the schema, DID, key, and right-name fields.
///
/// # Wire field names
///
/// Multi-word fields are camelCase (`previousCommitment`, `hashAlgorithm`),
/// matching the `contentId` / `publishedAtHeight` spelling the commitment
/// service uses inside a DID document. One convention across the protocol: a
/// document that mixed the two would be hashed differently by implementations
/// that each picked a spelling.
///
/// # Unknown fields
///
/// Unknown fields are **rejected**, not ignored. This document is a digest
/// preimage: an implementation that drops a field it does not recognise would
/// hash different bytes than one that honours it. Rejecting keeps every
/// implementation hashing the same bytes.
///
/// The `$schema` discriminator is checked before any field is interpreted, so a
/// document naming a schema this build does not know is rejected with
/// `UnknownSchema` rather than hashed under guessed rules. Within a schema the
/// field set is fixed: adding a field changes the preimage and therefore
/// requires a new schema URI, while adding a *hash algorithm* is a new
/// [`ContentHashAlgorithm`] value, because the declaration is already part of
/// the preimage.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsafeRightsDocument {
    /// Schema identifier for versioning.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// The DID this rights document belongs to (string form, validated later).
    pub did: String,
    /// Monotonic sequence number matching the on-chain commitment.
    pub sequence: u64,
    /// Content ID of the previous rights document; `null` at a chain start.
    ///
    /// Always serialized, including the `null`, because the field is part of
    /// the preimage: the explicit `null` is the canonical spelling of "no
    /// predecessor", so a chain-start document has exactly one preimage.
    #[serde(rename = "previousCommitment")]
    pub previous_commitment: Option<ContentId>,
    /// The hashing algorithm used to produce this document's content ID.
    ///
    /// Mandatory and part of the preimage. It cannot be omitted or ignored:
    /// hashing needs an algorithm before the result can be compared, so every
    /// implementation must read it from the document rather than assume one.
    /// The declaration also tags the resulting content ID (`cm` for BLAKE3,
    /// `cj` for SHA3), so a document that declares a weaker algorithm can never
    /// match a commitment published with a stronger one.
    #[serde(rename = "hashAlgorithm")]
    pub hash_algorithm: ContentHashAlgorithm,
    /// Key-to-rights mappings.
    pub rights: Vec<UnsafeRightEntry>,
}

impl UnsafeRightsDocument {
    /// Compute the typed content ID for this rights document.
    ///
    /// The digest function is chosen by the document's own
    /// [`hash_algorithm`](Self::hash_algorithm) field. The declaration is part
    /// of the serialized preimage, so it is covered by the digest — a document
    /// cannot declare one algorithm and be hashed with another. Because a
    /// declaration also changes the content ID's algorithm tag, a downgraded
    /// document cannot match a commitment published with a stronger algorithm.
    pub fn compute_content_id(&self) -> Result<ContentId, ContentIdError> {
        let digest = match self.hash_algorithm {
            ContentHashAlgorithm::Blake3CanonicalJson => json_digest::digest_data_blake3(self),
            ContentHashAlgorithm::Sha3CanonicalJson => json_digest::digest_data(self),
        }
        .map_err(|e| ContentIdError::Digest(e.to_string()))?;

        digest.parse().map_err(|_| ContentIdError::MalformedDigest(digest))
    }

    /// String rendering of [`Self::compute_content_id`].
    ///
    /// For wire output and display. Prefer [`Self::compute_content_id`]
    /// wherever the value is compared, so a digest failure stays an error
    /// rather than becoming a string that failed to parse.
    pub fn compute_hash(&self) -> Result<String, String> {
        self.compute_content_id().map(|cid| cid.to_string()).map_err(|e| e.to_string())
    }

    /// Check whether this document grants `right` to `holder_key_ref`.
    pub fn grants_right(&self, holder_key_ref: &str, right: &str) -> bool {
        self.rights.iter().any(|e| e.key == holder_key_ref && e.rights.iter().any(|r| r == right))
    }
}

// ========== Domain Types (validated, parsed) ==========

/// A validated rights document.
///
/// This enum gates on the schema version. Variants are added as new schema
/// versions are introduced. Each variant owns its own field set and validation
/// rules — no conditional logic needed at call sites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RightsDocument {
    /// Schema [`RIGHTS_DOCUMENT_V1_SCHEMA`].
    V1(RightsDocumentV1),
}

/// Validated V1 rights document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RightsDocumentV1 {
    /// The DID this rights document belongs to.
    pub did: Did,
    /// Monotonic sequence number (must be > 0).
    pub sequence: u64,
    /// Content ID of the previous rights document.
    pub previous_commitment: Option<ContentId>,
    /// The declared hashing algorithm, covered by the digest.
    pub hash_algorithm: ContentHashAlgorithm,
    /// Validated key-to-rights mappings.
    pub rights: Vec<RightEntryV1>,
}

/// Validated V1 rights entry.
///
/// `key` is an [`Authentication`] — the issuer chooses whether to reveal
/// the full `MPublicKey` or just the `MKeyId` hash reference.
/// `rights` strings must be non-empty and contain only `[a-zA-Z0-9@\-+/]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RightEntryV1 {
    /// The key: either `MKeyId` or `MPublicKey`.
    pub key: Authentication,
    /// The set of off-chain rights granted to this key.
    pub rights: Vec<String>,
}

// ========== Conversions ==========

// Domain → wire (lossless, for serialization / hashing).
impl From<RightEntryV1> for UnsafeRightEntry {
    fn from(e: RightEntryV1) -> Self {
        UnsafeRightEntry { key: e.key.to_string(), rights: e.rights }
    }
}

impl From<RightsDocumentV1> for UnsafeRightsDocument {
    fn from(v1: RightsDocumentV1) -> Self {
        UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: v1.did.to_did_string(),
            sequence: v1.sequence,
            previous_commitment: v1.previous_commitment,
            hash_algorithm: v1.hash_algorithm,
            rights: v1.rights.into_iter().map(UnsafeRightEntry::from).collect(),
        }
    }
}

impl From<RightsDocument> for UnsafeRightsDocument {
    fn from(doc: RightsDocument) -> Self {
        match doc {
            RightsDocument::V1(v1) => UnsafeRightsDocument::from(v1),
        }
    }
}

/// Errors that can occur when converting an [`UnsafeRightsDocument`] into a
/// validated [`RightsDocument`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RightsDocumentError {
    /// The `$schema` field is empty or not a recognized schema URI.
    #[error("unknown rights document schema: {0:?}")]
    UnknownSchema(String),
    /// The `did` field could not be parsed as a valid `did:mosaic` DID.
    #[error("invalid DID: {0:?}")]
    InvalidDid(String),
    /// The `sequence` field must be greater than zero.
    #[error("sequence must be > 0, got {0}")]
    InvalidSequence(u64),
    /// A `key` field could not be parsed as an [`Authentication`] value.
    #[error("invalid key, expected 'ioz' or 'poz' prefix: {0:?}")]
    InvalidKey(String),
    /// A right name in the `rights` array is empty or contains invalid characters.
    #[error("invalid right name: {0:?}")]
    InvalidRightName(String),
}

/// Failure to compute a rights document's content ID.
///
/// The variants separate a canonicalization failure from a malformed digest,
/// so a digest problem is never mistaken for a document that merely does not
/// match the commitment.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContentIdError {
    /// Canonicalization or digest computation failed.
    #[error("content digest computation failed: {0}")]
    Digest(String),
    /// The canonicalizer produced a string that is not a valid content ID.
    ///
    /// An internal invariant violation: the `c`-prefixed output of
    /// `json_digest` must always parse. Never expected, and never safe to
    /// treat as "no match".
    #[error("canonicalizer produced a malformed content ID: {0}")]
    MalformedDigest(String),
}

// ========== Presentation set ==========

/// Why a [`RightsDocumentSet`] could not be built.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RightsDocumentSetError {
    /// Two or more documents claim the same sequence number.
    #[error("two rights documents claim sequence {sequence}")]
    DuplicateSequence { sequence: u64 },
    /// Sequences are not in strictly increasing order.
    #[error(
        "rights document sequence {sequence} does not follow {previous}; \
         documents must be ordered by strictly increasing sequence"
    )]
    NotStrictlyIncreasing { sequence: u64, previous: u64 },
}

/// The rights documents a presenter supplied, indexed by sequence.
///
/// Construction rejects duplicate and out-of-order sequences, so two
/// properties hold for every instance:
///
/// - **A sequence resolves to one document.** No two documents can claim the
///   same sequence, so lookup never depends on presentation order.
/// - **The index cannot disagree with the document.** The sequence used for
///   lookup is the one the document declares, never a caller-supplied value.
///
/// Ordering is strictly increasing rather than merely unique, so a
/// presentation has one canonical order across implementations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RightsDocumentSet<'a> {
    documents: Vec<&'a RightsDocument>,
}

impl<'a> RightsDocumentSet<'a> {
    /// Build a set from presenter-supplied documents.
    ///
    /// Documents must be ordered by strictly increasing [`RightsDocument::sequence`].
    pub fn new(documents: Vec<&'a RightsDocument>) -> Result<Self, RightsDocumentSetError> {
        let mut previous: Option<u64> = None;
        for doc in &documents {
            let sequence = doc.sequence();
            match previous {
                Some(prev) if sequence == prev => {
                    return Err(RightsDocumentSetError::DuplicateSequence { sequence });
                }
                Some(prev) if sequence < prev => {
                    return Err(RightsDocumentSetError::NotStrictlyIncreasing {
                        sequence,
                        previous: prev,
                    });
                }
                _ => {}
            }
            previous = Some(sequence);
        }
        Ok(Self { documents })
    }

    /// The document presented for `sequence`, if any.
    pub fn get(&self, sequence: u64) -> Option<&'a RightsDocument> {
        let index = self.documents.binary_search_by_key(&sequence, |doc| doc.sequence()).ok()?;
        self.documents.get(index).copied()
    }

    /// Iterate over the documents in ascending sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &'a RightsDocument> + '_ {
        self.documents.iter().copied()
    }

    /// Number of documents in the set.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

// ========== TryFrom Conversions ==========

impl RightsDocument {
    /// Check whether this document grants `right` to `key`.
    ///
    /// `key` is compared using [`Authentication`]'s cross-variant `PartialEq` —
    /// a `KeyId` matches its corresponding `PublicKey` transparently.
    pub fn grants_right(&self, key: &Authentication, right: &str) -> bool {
        match self {
            RightsDocument::V1(v1) => v1.grants_right(key, right),
        }
    }

    /// Check whether this document grants `right` to a key referenced by string
    /// (e.g. a `KeyRef` as-str).
    ///
    /// The `key_ref` is parsed into an [`Authentication`] and compared with the
    /// cross-variant `PartialEq`, so an entry that reveals the **full public
    /// key** matches the bare key id the chain stores. A `key_ref` that is not
    /// a key reference at all matches nothing.
    pub fn grants_right_by_key_ref(&self, key_ref: &str, right: &str) -> bool {
        let Ok(target) = key_ref.parse::<Authentication>() else {
            return false;
        };
        self.rights().iter().any(|e| e.key == target && e.rights.iter().any(|r| r == right))
    }

    fn rights(&self) -> &[RightEntryV1] {
        match self {
            RightsDocument::V1(v1) => &v1.rights,
        }
    }

    /// Return the DID this rights document belongs to.
    pub fn did(&self) -> &Did {
        match self {
            RightsDocument::V1(v1) => &v1.did,
        }
    }

    /// Return the previous commitment content ID, if any.
    pub fn previous_commitment(&self) -> Option<&ContentId> {
        match self {
            RightsDocument::V1(v1) => v1.previous_commitment.as_ref(),
        }
    }

    /// Return the sequence number declared by this document.
    pub fn sequence(&self) -> u64 {
        match self {
            RightsDocument::V1(v1) => v1.sequence,
        }
    }

    /// Compute the typed content ID for this rights document.
    ///
    /// The declared [`ContentHashAlgorithm`] selects the digest function, so
    /// the algorithm is read from the document rather than assumed.
    ///
    /// This is the authoritative operation; [`Self::compute_hash`] is a thin
    /// string rendering of it. Verifiers must compare [`ContentId`] values,
    /// never strings, so a digest that fails to compute is reported rather than
    /// collapsed into a plain "no match".
    pub fn compute_content_id(&self) -> Result<ContentId, ContentIdError> {
        let wire: UnsafeRightsDocument = self.clone().into();
        wire.compute_content_id()
    }

    /// String rendering of [`Self::compute_content_id`].
    pub fn compute_hash(&self) -> Result<String, String> {
        self.compute_content_id().map(|cid| cid.to_string()).map_err(|e| e.to_string())
    }
}

impl RightsDocumentV1 {
    /// Check whether this document grants `right` to `key`.
    pub fn grants_right(&self, key: &Authentication, right: &str) -> bool {
        self.rights.iter().any(|e| &e.key == key && e.rights.iter().any(|r| r == right))
    }
}

impl TryFrom<UnsafeRightsDocument> for RightsDocument {
    type Error = RightsDocumentError;

    fn try_from(raw: UnsafeRightsDocument) -> Result<Self, Self::Error> {
        match raw.schema.as_str() {
            RIGHTS_DOCUMENT_V1_SCHEMA => Ok(RightsDocument::V1(RightsDocumentV1::try_from(raw)?)),
            other => Err(RightsDocumentError::UnknownSchema(if other.is_empty() {
                "(empty)".into()
            } else {
                other.to_string()
            })),
        }
    }
}

impl TryFrom<UnsafeRightsDocument> for RightsDocumentV1 {
    type Error = RightsDocumentError;

    fn try_from(raw: UnsafeRightsDocument) -> Result<Self, Self::Error> {
        let did = Did::from_did_string(&raw.did)
            .map_err(|_| RightsDocumentError::InvalidDid(raw.did.clone()))?;

        if raw.sequence == 0 {
            return Err(RightsDocumentError::InvalidSequence(raw.sequence));
        }

        let rights: Result<Vec<RightEntryV1>, _> =
            raw.rights.into_iter().map(TryFrom::try_from).collect();
        let rights = rights?;

        Ok(RightsDocumentV1 {
            did,
            sequence: raw.sequence,
            previous_commitment: raw.previous_commitment,
            hash_algorithm: raw.hash_algorithm,
            rights,
        })
    }
}

impl TryFrom<UnsafeRightEntry> for RightEntryV1 {
    type Error = RightsDocumentError;

    fn try_from(raw: UnsafeRightEntry) -> Result<Self, Self::Error> {
        let key: Authentication =
            raw.key.parse().map_err(|_| RightsDocumentError::InvalidKey(raw.key.clone()))?;

        let rights = validate_right_names(raw.rights)?;

        Ok(RightEntryV1 { key, rights })
    }
}

/// Validate that all right names are non-empty and contain only `[a-zA-Z0-9@\-+/]`.
fn validate_right_names(names: Vec<String>) -> Result<Vec<String>, RightsDocumentError> {
    for name in &names {
        if name.is_empty() {
            return Err(RightsDocumentError::InvalidRightName("(empty)".into()));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '@' || c == '-' || c == '+' || c == '/')
        {
            return Err(RightsDocumentError::InvalidRightName(name.clone()));
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_rights_document_structure() {
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };

        assert_eq!(doc.schema, RIGHTS_DOCUMENT_V1_SCHEMA);
        assert_eq!(doc.did, "did:mosaic:iozABC");
        assert_eq!(doc.sequence, 1);
        assert_eq!(doc.previous_commitment, None);
        assert_eq!(doc.rights.len(), 1);
        assert_eq!(doc.rights[0].key, "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH");
        assert_eq!(doc.rights[0].rights, alloc::vec!["impersonate".to_string()]);
    }

    #[test]
    fn unsafe_rights_document_with_previous_commitment() {
        let previous = ContentId::from_bytes(b"test content");
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 2,
            previous_commitment: Some(previous),
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![],
        };

        assert_eq!(doc.previous_commitment, Some(previous));
        assert!(doc.rights.is_empty());
    }

    #[test]
    fn unsafe_rights_document_json_roundtrip() {
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"$schema\""));
        assert!(json.contains("\"sequence\":1"));
        assert!(json.contains("\"ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH\""));

        let parsed: UnsafeRightsDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc);
    }

    /// `previousCommitment` is always serialized: an explicit `null` marks a
    /// chain start. It is part of the preimage, and an omitted field would let
    /// an implementation that drops it and one that emits the `null` hash the
    /// same logical document differently.
    #[test]
    fn unsafe_rights_document_serializes_explicit_null_previous_commitment() {
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"previousCommitment\":null"), "got: {json}");

        let parsed: UnsafeRightsDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc, "the explicit null must round-trip");
    }

    // ===== TryFrom validation tests =====

    #[test]
    fn try_from_rejects_empty_schema() {
        let raw = UnsafeRightsDocument {
            schema: "".into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "empty $schema must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("schema"), "error should mention schema, got: {err}");
    }

    #[test]
    fn try_from_rejects_unknown_schema() {
        let raw = UnsafeRightsDocument {
            schema: "https://example.com/some-future-schema/v42".into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "unknown $schema must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("schema"), "error should mention schema, got: {err}");
    }

    #[test]
    fn try_from_rejects_invalid_did() {
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "not-a-did".into(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "invalid DID must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DID"), "error should mention DID, got: {err}");
    }

    #[test]
    fn try_from_rejects_zero_sequence() {
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 0,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "zero sequence must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("sequence"), "error should mention sequence, got: {err}");
    }

    #[test]
    fn try_from_rejects_empty_key() {
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "empty key must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("key"), "error should mention key, got: {err}");
    }

    #[test]
    fn try_from_rejects_empty_right_name() {
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["".into()],
            }],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "empty right name must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("right name"), "error should mention right name, got: {err}");
    }

    #[test]
    fn try_from_rejects_invalid_right_name_chars() {
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["bad name!".into()],
            }],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_err(), "right name with '!' must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("right name"), "error should mention right name, got: {err}");
    }

    #[test]
    fn try_from_successful_conversion() {
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["impersonate".into(), "sign-trade".into()],
            }],
        };
        let doc: RightsDocument = raw.try_into().expect("valid document should convert");
        match doc {
            RightsDocument::V1(v1) => {
                assert_eq!(v1.sequence, 1);
                assert_eq!(v1.rights.len(), 1);
                assert_eq!(v1.rights[0].rights.len(), 2);
                assert_eq!(v1.rights[0].rights[0], "impersonate");
                assert_eq!(v1.rights[0].rights[1], "sign-trade");
            }
        }
    }

    #[test]
    fn try_from_accepts_valid_right_name_chars() {
        // All characters in [a-zA-Z0-9@\-+/] should be accepted
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["abcXYZ012@-+/".into()],
            }],
        };
        let result: Result<RightsDocument, _> = raw.try_into();
        assert!(result.is_ok(), "valid right name chars must be accepted, got: {result:?}");
    }

    // ===== RightsDocument methods =====

    #[test]
    fn rights_document_grants_right_matches_key_and_right() {
        use mosaic_keyvault::multicipher::MKeyId;

        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        let holder = Authentication::KeyId(kid.clone());

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(kid),
                rights: alloc::vec!["impersonate".into(), "sign-trade".into()],
            }],
        });

        assert!(doc.grants_right(&holder, "impersonate"));
        assert!(doc.grants_right(&holder, "sign-trade"));
        assert!(!doc.grants_right(&holder, "admin"));
    }

    #[test]
    fn rights_document_grants_right_rejects_wrong_key() {
        use mosaic_keyvault::multicipher::MKeyId;

        let holder: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        let other: MKeyId = "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB".parse().unwrap();

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(holder),
                rights: alloc::vec!["impersonate".into()],
            }],
        });

        assert!(!doc.grants_right(&Authentication::KeyId(other), "impersonate"));
    }

    #[test]
    fn rights_document_compute_hash_is_deterministic() {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(kid),
                rights: alloc::vec!["impersonate".into()],
            }],
        });

        let hash1 = doc.compute_hash().expect("compute_hash should succeed");
        let hash2 = doc.compute_hash().expect("compute_hash should succeed");
        assert_eq!(hash1, hash2, "hash must be deterministic");
        assert!(hash1.starts_with("cm"), "hash must have cm prefix, got: {hash1}");
    }

    #[test]
    fn compute_hash_matches_json_digest_structured_blake3() {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(kid),
                rights: alloc::vec!["impersonate".into()],
            }],
        });

        // compute_hash must produce the same result as the structured
        // json_digest::digest_data_blake3 pipeline that the verifier/SMT uses.
        let from_compute = doc.compute_hash().expect("compute_hash should succeed");

        let wire: UnsafeRightsDocument = doc.into();
        let from_digest =
            json_digest::digest_data_blake3(&wire).expect("digest_data_blake3 should succeed");

        assert_eq!(
            from_compute, from_digest,
            "compute_hash must use structured json_digest pipeline (BLAKE3 Merkle tree), not flat BLAKE3"
        );
    }

    #[test]
    fn wire_domain_roundtrip_preserves_hash() {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();

        let wire = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: kid.to_string(),
                rights: alloc::vec!["impersonate".into(), "sign-trade".into()],
            }],
        };

        let original_hash = wire.compute_hash().expect("wire compute_hash should succeed");

        let domain: RightsDocument = wire.try_into().expect("valid wire must convert to domain");
        let domain_hash = domain.compute_hash().expect("domain compute_hash should succeed");

        assert_eq!(
            original_hash, domain_hash,
            "wire → domain → compute_hash must match wire → compute_hash"
        );
    }

    fn test_v1_document() -> RightsDocument {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(kid),
                rights: alloc::vec!["impersonate".into()],
            }],
        })
    }

    #[test]
    fn compute_content_id_returns_typed_structured_blake3_digest() {
        use json_digest::JsonDigest;
        let doc = test_v1_document();

        let cid = doc.compute_content_id().expect("compute_content_id should succeed");

        assert!(
            matches!(cid, ContentId::Structured(JsonDigest::Blake3(_))),
            "v1 documents must produce a structured BLAKE3 content ID, got {cid:?}"
        );
    }

    #[test]
    fn compute_content_id_agrees_with_compute_hash_string() {
        let doc = test_v1_document();

        let typed = doc.compute_content_id().expect("compute_content_id should succeed");
        let parsed: ContentId = doc
            .compute_hash()
            .expect("compute_hash should succeed")
            .parse()
            .expect("compute_hash output must be a valid ContentId");

        assert_eq!(
            typed, parsed,
            "compute_hash must be a thin string rendering of compute_content_id"
        );
        assert_eq!(typed.to_string(), doc.compute_hash().unwrap());
    }

    #[test]
    fn unsafe_rights_document_rejects_unknown_field() {
        // A lenient parser that ignores `admin` and one that honors it compute
        // different preimages for the same document, so two implementations
        // disagree on the digest. This is the "browsers fixing invalid HTML in
        // different ways" failure: reject instead of interpret.
        let json = r#"{
            "$schema": "https://mosaic-trust.net/ns/did-rights/v1",
            "did": "did:mosaic:iozABC",
            "sequence": 1,
            "hashAlgorithm": "blake3-canonical-json",
            "rights": [],
            "admin": true
        }"#;

        let err = serde_json::from_str::<UnsafeRightsDocument>(json)
            .expect_err("unknown top-level fields must be rejected");
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn unsafe_right_entry_rejects_unknown_field() {
        // Nested fields are part of the same preimage, so the same
        // cross-implementation divergence applies one level down.
        let json = r#"{
            "keyRef": "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH",
            "rights": ["impersonate"],
            "wildcard": true
        }"#;

        let err = serde_json::from_str::<UnsafeRightEntry>(json)
            .expect_err("unknown nested fields must be rejected");
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    // ===== Preimage coverage guards =====
    //
    // The DID and sequence bindings in the verifier are *derived* from the
    // digest rather than checked field-by-field: a presented document is bound
    // to a DID and a chain position only because those fields are inside the
    // hashed preimage. Nothing in the type system enforces that, and every
    // caller builds documents through `compute_content_id`, so a change that
    // narrowed the preimage would disable the binding while leaving every
    // other test green.
    //
    // These tests are the executable form of that invariant.

    fn wire_from_json(json: &str) -> UnsafeRightsDocument {
        serde_json::from_str(json).expect("fixture must parse")
    }

    #[test]
    fn preimage_covers_did() {
        let a = wire_from_json(
            r#"{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozAAA","sequence":1,
                "hashAlgorithm":"blake3-canonical-json","rights":[]}"#,
        );
        let b = wire_from_json(
            r#"{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozBBB","sequence":1,
                "hashAlgorithm":"blake3-canonical-json","rights":[]}"#,
        );

        assert_ne!(
            a.compute_content_id().unwrap(),
            b.compute_content_id().unwrap(),
            "the DID must be inside the hashed preimage, otherwise a document \
             can be replayed under a different DID"
        );
    }

    #[test]
    fn preimage_covers_sequence() {
        let a = wire_from_json(
            r#"{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozAAA","sequence":1,
                "hashAlgorithm":"blake3-canonical-json","rights":[]}"#,
        );
        let b = wire_from_json(
            r#"{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozAAA","sequence":2,
                "hashAlgorithm":"blake3-canonical-json","rights":[]}"#,
        );

        assert_ne!(
            a.compute_content_id().unwrap(),
            b.compute_content_id().unwrap(),
            "the sequence must be inside the hashed preimage, otherwise a document \
             can be replayed at a different position in the chain"
        );
    }

    #[test]
    fn preimage_covers_previous_commitment() {
        let base = r#"{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozAAA","sequence":2,
                "hashAlgorithm":"blake3-canonical-json","rights":[]}"#;
        let with_prev = wire_from_json(&format!(
            r#"{{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozAAA","sequence":2,
                "hashAlgorithm":"blake3-canonical-json",
                "previousCommitment":"{}","rights":[]}}"#,
            ContentId::from_bytes(b"previous document")
        ));
        let without_prev = wire_from_json(base);

        assert_eq!(
            with_prev.previous_commitment,
            Some(ContentId::from_bytes(b"previous document")),
            "fixture must carry the previous commitment"
        );
        assert_ne!(
            with_prev.compute_content_id().unwrap(),
            without_prev.compute_content_id().unwrap(),
            "previous_commitment must be inside the hashed preimage, otherwise the \
             chain link can be altered without changing the document digest"
        );
    }

    #[test]
    fn explicit_null_previous_commitment_round_trips() {
        // The companion to the guard above: a chain start must serialize the
        // `null` explicitly and round-trip through it, so the canonical
        // preimage has one spelling of "no predecessor".
        let doc = wire_from_json(
            r#"{"$schema":"https://mosaic-trust.net/ns/did-rights/v1",
                "did":"did:mosaic:iozAAA","sequence":1,
                "hashAlgorithm":"blake3-canonical-json","rights":[]}"#,
        );

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"previousCommitment\":null"), "got: {json}");
        assert_eq!(
            doc.compute_content_id().unwrap(),
            wire_from_json(&json).compute_content_id().unwrap(),
            "the explicit null form must round-trip without perturbing the digest"
        );
    }

    // ===== Presentation set: duplicate sequences must be unrepresentable =====

    fn doc_at_sequence(seq: u64) -> RightsDocument {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: seq,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(kid),
                rights: alloc::vec!["impersonate".into()],
            }],
        })
    }

    #[test]
    fn rights_document_set_rejects_duplicate_sequence() {
        let a = doc_at_sequence(1);
        let b = doc_at_sequence(1);

        let err = RightsDocumentSet::new(alloc::vec![&a, &b])
            .expect_err("two documents for one sequence must be rejected at construction");
        assert_eq!(err, RightsDocumentSetError::DuplicateSequence { sequence: 1 });
    }

    #[test]
    fn rights_document_set_requires_strictly_increasing_sequence() {
        let a = doc_at_sequence(2);
        let b = doc_at_sequence(1);

        let err = RightsDocumentSet::new(alloc::vec![&a, &b])
            .expect_err("out-of-order sequences must be rejected at construction");
        assert_eq!(err, RightsDocumentSetError::NotStrictlyIncreasing { sequence: 1, previous: 2 });
    }

    #[test]
    fn rights_document_set_looks_up_by_the_documents_own_sequence() {
        let a = doc_at_sequence(1);
        let b = doc_at_sequence(7);

        let set =
            RightsDocumentSet::new(alloc::vec![&a, &b]).expect("strictly increasing is valid");

        assert_eq!(set.get(1), Some(&a));
        assert_eq!(set.get(7), Some(&b));
        assert_eq!(set.get(2), None, "absent sequences must resolve to None, not panic");
        assert_eq!(set.len(), 2);
    }

    // ===== Self-describing hash algorithm =====

    fn doc_json(algorithm: &str) -> String {
        alloc::format!(
            r#"{{"$schema":"{RIGHTS_DOCUMENT_V1_SCHEMA}","did":"{}","sequence":1,
                "hashAlgorithm":"{algorithm}","rights":[]}}"#,
            Did::alice().to_did_string()
        )
    }

    /// A document must declare the algorithm that produced its digest: the
    /// verifier has to hash the document before it can compare anything, so it
    /// cannot read the algorithm off the expected on-chain value — that value
    /// is the claim, not the input.
    #[test]
    fn document_without_hash_algorithm_is_rejected() {
        let json = alloc::format!(
            r#"{{"$schema":"{RIGHTS_DOCUMENT_V1_SCHEMA}","did":"{}","sequence":1,"rights":[]}}"#,
            Did::alice().to_did_string()
        );

        let err = serde_json::from_str::<UnsafeRightsDocument>(&json)
            .expect_err("a document without a hashAlgorithm declaration must be rejected");
        assert!(
            err.to_string().contains("hashAlgorithm"),
            "expected a missing-field error naming hashAlgorithm, got: {err}"
        );
    }

    /// A declaration of the pinned algorithm is accepted and produces a
    /// structured BLAKE3 content ID — the only algorithm the pallet accepts as
    /// a commitment.
    #[test]
    fn blake3_declaration_produces_a_supported_commitment() {
        let wire: UnsafeRightsDocument = serde_json::from_str(&doc_json("blake3-canonical-json"))
            .expect("a declared document must parse");
        let doc: RightsDocument = wire.try_into().expect("valid document");

        assert!(matches!(doc, RightsDocument::V1(_)));
        let cid = doc.compute_content_id().unwrap();
        assert!(
            cid.is_supported_commitment_algorithm(),
            "the pinned declaration must produce a supported commitment"
        );
        assert!(cid.to_string().starts_with("cm"), "got {cid}");
    }

    /// The declared algorithm is inside the preimage, so it is bound by the
    /// digest: a document cannot claim one algorithm and be hashed with
    /// another. Removing the declaration from the serialized form must change
    /// the digest — if the field were skipped during serialization, the two
    /// would be identical.
    #[test]
    fn hash_algorithm_declaration_is_inside_the_preimage() {
        let doc: UnsafeRightsDocument =
            serde_json::from_str(&doc_json("blake3-canonical-json")).expect("fixture must parse");
        let json = serde_json::to_string(&doc).unwrap();
        assert!(
            json.contains("hashAlgorithm"),
            "the declaration must be serialized into the preimage, got: {json}"
        );

        let mut stripped: serde_json::Value = serde_json::to_value(&doc).unwrap();
        stripped.as_object_mut().unwrap().remove("hashAlgorithm");
        assert_ne!(
            doc.compute_content_id().unwrap().to_string(),
            json_digest::digest_data_blake3(&stripped).unwrap(),
            "the declared algorithm must be covered by the digest"
        );
    }

    /// A SHA3 declaration dispatches to SHA3 and produces a permitted `cj`
    /// commitment — the same structured-preimage property as BLAKE3, with the
    /// algorithm named by the document.
    #[test]
    fn sha3_declaration_is_dispatched_and_supported() {
        let doc: RightsDocument = TryInto::try_into(
            serde_json::from_str::<UnsafeRightsDocument>(&doc_json("sha3-canonical-json"))
                .expect("the declaration is well formed"),
        )
        .expect("the declaration is well formed");

        let cid = doc.compute_content_id().unwrap();
        assert!(
            cid.is_supported_commitment_algorithm(),
            "a structured SHA3 content ID is a permitted commitment algorithm"
        );
        assert!(
            cid.to_string().starts_with("cj"),
            "a SHA3 declaration must actually dispatch to SHA3, got {cid}"
        );
    }

    /// An unrecognised algorithm name is rejected rather than ignored — an
    /// ignored field would let two implementations disagree about the preimage.
    #[test]
    fn unknown_hash_algorithm_is_rejected() {
        let err = serde_json::from_str::<UnsafeRightsDocument>(&doc_json("rot13"))
            .expect_err("an unknown algorithm must not be dropped");
        assert!(
            err.to_string().contains("unknown variant"),
            "expected an unknown-variant error, got: {err}"
        );
    }

    // ===== JSON field naming =====

    /// Every multi-word field on the wire is camelCase, matching the
    /// `contentId` / `publishedAtHeight` / `publishedBy` spelling of the
    /// commitment service inside a DID document. One convention across the
    /// protocol means one preimage for a document.
    #[test]
    fn rights_document_wire_uses_camel_case_field_names() {
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 2,
            previous_commitment: Some(ContentId::from_bytes(b"prev")),
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };

        let json = serde_json::to_string(&doc).unwrap();

        assert!(json.contains("\"previousCommitment\""), "got: {json}");
        assert!(json.contains("\"hashAlgorithm\""), "got: {json}");
        assert!(!json.contains("previous_commitment"), "snake_case leaked: {json}");
        assert!(!json.contains("\"hash_algorithm\""), "snake_case leaked: {json}");

        // And the names must round-trip, or the digest would differ between
        // the two spellings of the same document.
        let parsed: UnsafeRightsDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc);
    }

    /// The entry's key field is `keyRef`.
    ///
    /// The value is a reference to a key the on-chain state knows — normally
    /// an `MKeyId` — so the name states that the key material itself is not
    /// carried here. A `key` field is unknown and rejected.
    #[test]
    fn rights_entry_wire_uses_key_ref_field_name() {
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"keyRef\""), "got: {json}");
        assert!(!json.contains("\"key\""), "the wire field must be `keyRef`, got: {json}");

        let parsed: UnsafeRightsDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc, "the field must round-trip");

        // `deny_unknown_fields` makes `key` a hard parse error, so the two
        // spellings cannot be hashed to different digests by different
        // implementations.
        let key_field = r#"{"key":"ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH","rights":["impersonate"]}"#;
        assert!(
            serde_json::from_str::<UnsafeRightEntry>(key_field).is_err(),
            "a `key` field must be rejected"
        );
    }

    // ===== Schema-gated upgrade path =====

    /// The `$schema` discriminator is what routes a document, and it is checked
    /// before any field is interpreted.
    ///
    /// This is the upgrade path for `deny_unknown_fields`. Because a document
    /// is routed by its schema URI, a verifier that predates a schema rejects a
    /// new document with `UnknownSchema` — it never reaches the point of
    /// interpreting fields it does not know. So verifiers may be deployed
    /// first, and a presenter that starts emitting a newer schema before
    /// verifiers are upgraded gets a clean rejection rather than a document two
    /// implementations hash differently.
    #[test]
    fn unknown_schema_is_rejected_before_fields_are_interpreted() {
        let json = alloc::format!(
            r#"{{"$schema":"https://mosaic-trust.net/ns/did-rights/v99",
                "did":"{}","sequence":1,"hashAlgorithm":"blake3-canonical-json",
                "rights":[],"aFieldNoVerifierKnows":true}}"#,
            Did::alice().to_did_string()
        );

        // The wire layer rejects the unknown field...
        let wire_err = serde_json::from_str::<UnsafeRightsDocument>(&json)
            .expect_err("an unknown field must be rejected outright");
        assert!(
            wire_err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {wire_err}"
        );

        // ...and without that field, the schema is what rejects it.
        let no_extra = alloc::format!(
            r#"{{"$schema":"https://mosaic-trust.net/ns/did-rights/v99",
                "did":"{}","sequence":1,"hashAlgorithm":"blake3-canonical-json","rights":[]}}"#,
            Did::alice().to_did_string()
        );
        let err = TryInto::<RightsDocument>::try_into(
            serde_json::from_str::<UnsafeRightsDocument>(&no_extra).unwrap(),
        )
        .expect_err("an unknown schema must be rejected");
        assert!(
            matches!(err, RightsDocumentError::UnknownSchema(_)),
            "expected UnknownSchema, got {err:?}"
        );
    }

    // ===== Cross-variant key matching =====

    /// A document entry that reveals the **full public key** matches an
    /// on-chain `KeyRef`, which is a bare key id, because the lookup compares
    /// parsed [`Authentication`] values rather than their string forms.
    #[test]
    fn grants_right_by_key_ref_matches_a_full_public_key_entry() {
        use core::str::FromStr as _;
        use mosaic_keyvault::PrivateKey as _;
        use mosaic_keyvault::PublicKey as _;
        use mosaic_keyvault::ed25519::EdPrivateKey;
        use mosaic_keyvault::multicipher::{MKeyId, MPublicKey};

        let mut seed = [0u8; 32];
        seed[0] = 7;
        let pk = MPublicKey::Ed25519(EdPrivateKey::from_bytes(seed).unwrap().public_key());
        // The on-chain KeyRef for that key is the derived key id.
        let key_ref_str = pk.key_id().to_string();
        assert_eq!(
            MKeyId::from_str(&key_ref_str).map(|k| k.to_string()).ok(),
            Some(key_ref_str.clone()),
            "the key ref must round-trip as a key id"
        );
        assert!(
            !key_ref_str.starts_with(MPublicKey::PREFIX),
            "a key ref must be the key id, not the public key: {key_ref_str}"
        );

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                // The revealing form: a full public key, not a key id.
                key: Authentication::PublicKey(pk),
                rights: alloc::vec!["impersonate".into()],
            }],
        });

        assert!(
            doc.grants_right_by_key_ref(&key_ref_str, "impersonate"),
            "a public-key entry must match the key ref derived from that same key"
        );
        assert!(
            !doc.grants_right_by_key_ref(&key_ref_str, "issue"),
            "the right name must still be honoured"
        );
    }

    /// A key-ref string that is not a key reference at all must not match, and
    /// must not panic.
    #[test]
    fn grants_right_by_key_ref_rejects_a_non_key_ref_string() {
        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(
                    "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb".parse().unwrap(),
                ),
                rights: alloc::vec!["impersonate".into()],
            }],
        });

        assert!(!doc.grants_right_by_key_ref("", "impersonate"));
        assert!(!doc.grants_right_by_key_ref("not-a-key-ref", "impersonate"));
    }
}
