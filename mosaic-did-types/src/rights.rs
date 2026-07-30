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
//! - `RightsDocument` (enum) / `RightsDocumentV1` / `RightEntryV1` — validated domain
//!   types constructed via `TryFrom<UnsafeRightsDocument>`.
//! - `key: Authentication` supports either `MKeyId` (compact hash reference) or
//!   `MPublicKey` (self-contained verifiable key). The issuer chooses the revelation level.

use alloc::{format, string::String, string::ToString, vec::Vec};

use crate::{auth::Authentication, did::ContentId, did::Did};

/// Schema URI for V1 rights documents.
pub const RIGHTS_DOCUMENT_V1_SCHEMA: &str = "https://mosaic-trust.net/ns/did-rights/v1";

// ========== Wire Format (untrusted, derive‑deserialized) ==========

/// Raw, untrusted wire-format entry. Every field is a plain `String`.
/// Zero semantic validation — accepts anything structurally valid JSON.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnsafeRightEntry {
    /// The key this entry applies to (serialized as `"key"` in JSON).
    pub key: String,
    /// The set of off-chain rights granted to this key.
    pub rights: Vec<String>,
}

/// Raw, untrusted wire-format rights document.
///
/// Deserialized from JSON without semantic checks. Convert to [`RightsDocument`]
/// via `TryFrom` to validate the schema, DID, key, and right-name fields.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnsafeRightsDocument {
    /// Schema identifier for versioning.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// The DID this rights document belongs to (string form, validated later).
    pub did: String,
    /// Monotonic sequence number matching the on-chain commitment.
    pub sequence: u64,
    /// Content ID of the previous rights document (None at sequence 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_commitment: Option<ContentId>,
    /// Key-to-rights mappings.
    pub rights: Vec<UnsafeRightEntry>,
}

impl UnsafeRightsDocument {
    /// Compute the `cm`-prefixed content ID for this rights document.
    ///
    /// Uses BLAKE3-256 of the canonical JSON representation, matching the
    /// commitment stored on-chain in `CommitmentVersion.commitment`.
    pub fn compute_hash(&self) -> Result<String, String> {
        let json = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let canonical = json_digest::canonical_json(&json).map_err(|e| e.to_string())?;
        let hash_bytes = blake3::hash(canonical.as_bytes());
        let encoded = bs58::encode(hash_bytes.as_bytes()).into_string();
        Ok(format!("cm{encoded}"))
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RightsDocumentError {
    /// The `$schema` field is empty or not a recognized schema URI.
    UnknownSchema(String),
    /// The `did` field could not be parsed as a valid `did:mosaic` DID.
    InvalidDid(String),
    /// The `sequence` field must be greater than zero.
    InvalidSequence(u64),
    /// A `key` field could not be parsed as an [`Authentication`] value.
    InvalidKey(String),
    /// A right name in the `rights` array is empty or contains invalid characters.
    InvalidRightName(String),
}

impl core::fmt::Display for RightsDocumentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownSchema(s) => write!(f, "unknown rights document schema: {s:?}"),
            Self::InvalidDid(s) => write!(f, "invalid DID: {s:?}"),
            Self::InvalidSequence(n) => write!(f, "sequence must be > 0, got {n}"),
            Self::InvalidKey(s) => write!(f, "invalid key, expected 'ioz' or 'poz' prefix: {s:?}"),
            Self::InvalidRightName(s) => write!(f, "invalid right name: {s:?}"),
        }
    }
}

impl core::error::Error for RightsDocumentError {}

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

    /// Compute the `cm`-prefixed content ID for this rights document.
    ///
    /// Converts back to the wire format and hashes its canonical JSON.
    /// Uses BLAKE3-256, matching the commitment stored on-chain in
    /// `CommitmentVersion.commitment`.
    pub fn compute_hash(&self) -> Result<String, String> {
        let wire: UnsafeRightsDocument = self.clone().into();
        wire.compute_hash()
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

    #[test]
    fn unsafe_rights_document_json_omits_null_previous_commitment() {
        let doc = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            rights: alloc::vec![],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(!json.contains("previousCommitment"));
    }

    // ===== TryFrom validation tests =====

    #[test]
    fn try_from_rejects_empty_schema() {
        let raw = UnsafeRightsDocument {
            schema: "".into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
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
        use iop_keyvault::multicipher::MKeyId;

        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        let holder = Authentication::KeyId(kid.clone());

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
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
        use iop_keyvault::multicipher::MKeyId;

        let holder: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        let other: MKeyId = "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB".parse().unwrap();

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
            rights: alloc::vec![RightEntryV1 {
                key: Authentication::KeyId(holder),
                rights: alloc::vec!["impersonate".into()],
            }],
        });

        assert!(!doc.grants_right(&Authentication::KeyId(other), "impersonate"));
    }

    #[test]
    fn rights_document_compute_hash_is_deterministic() {
        use iop_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();

        let doc = RightsDocument::V1(RightsDocumentV1 {
            did: Did::alice(),
            sequence: 1,
            previous_commitment: None,
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
    fn wire_domain_roundtrip_preserves_hash() {
        use iop_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();

        let wire = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: Did::alice().to_did_string(),
            sequence: 1,
            previous_commitment: None,
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
}
