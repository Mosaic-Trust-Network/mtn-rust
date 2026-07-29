//! Off-chain rights document types.
//!
//! A rights document maps key references to the set of off-chain rights they hold.
//! It is canonicalized via `json_digest` (BLAKE3-256 Merkle tree) and its content
//! ID is committed on-chain. The full document stays private — carried by
//! presenters in Verifiable Presentations.

use alloc::{string::String, vec::Vec};

use crate::did::ContentId;

/// A single entry mapping a key reference to its granted rights.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RightEntry {
    /// The key reference this entry applies to.
    pub key_ref: String,
    /// The set of off-chain rights granted to this key.
    pub rights: Vec<String>,
}

/// An off-chain rights document committed on-chain by the DID controller.
///
/// Each document is a full replacement of the previous one (not a delta).
/// The `previousCommitment` field chains documents together, and the
/// `sequence` number must match the on-chain commitment sequence (gapless).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RightsDocument {
    /// Schema identifier for versioning.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// The DID this rights document belongs to.
    pub did: String,
    /// Monotonic sequence number matching the on-chain commitment.
    pub sequence: u64,
    /// Content ID of the previous rights document (None at sequence 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_commitment: Option<ContentId>,
    /// Key-reference-to-rights mappings.
    pub rights: Vec<RightEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_document_structure() {
        let doc = RightsDocument {
            schema: "https://mosaic-trust.net/ns/did-rights/v1".into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            rights: alloc::vec![RightEntry {
                key_ref: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };

        assert_eq!(doc.schema, "https://mosaic-trust.net/ns/did-rights/v1");
        assert_eq!(doc.did, "did:mosaic:iozABC");
        assert_eq!(doc.sequence, 1);
        assert_eq!(doc.previous_commitment, None);
        assert_eq!(doc.rights.len(), 1);
        assert_eq!(doc.rights[0].key_ref, "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH");
        assert_eq!(doc.rights[0].rights, alloc::vec!["impersonate".to_string()]);
    }

    #[test]
    fn rights_document_with_previous_commitment() {
        let previous = ContentId::from_bytes(b"test content");
        let doc = RightsDocument {
            schema: "https://mosaic-trust.net/ns/did-rights/v1".into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 2,
            previous_commitment: Some(previous),
            rights: alloc::vec![],
        };

        assert_eq!(doc.previous_commitment, Some(previous));
        assert!(doc.rights.is_empty());
    }

    #[test]
    fn rights_document_json_roundtrip() {
        let doc = RightsDocument {
            schema: "https://mosaic-trust.net/ns/did-rights/v1".into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            rights: alloc::vec![RightEntry {
                key_ref: "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"$schema\""));
        assert!(json.contains("\"sequence\":1"));
        assert!(json.contains("\"ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH\""));

        let parsed: RightsDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn rights_document_json_omits_null_previous_commitment() {
        let doc = RightsDocument {
            schema: "https://mosaic-trust.net/ns/did-rights/v1".into(),
            did: "did:mosaic:iozABC".into(),
            sequence: 1,
            previous_commitment: None,
            rights: alloc::vec![],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(!json.contains("previousCommitment"));
    }
}
