//! Off-chain verifier for `did:mosaic` DID Documents.
//!
//! The verifier operates offline on a `DidDocument` produced by the indexer
//! at a specific `?versionId`. It checks on-chain rights from the document's
//! verification relationship arrays and off-chain rights from presenter-
//! supplied `RightsDocument`s whose hashes match the commitment timeline.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use crate::document::DidDocument;
#[cfg(feature = "serde")]
use crate::rights::RightsDocument;

/// Result of a right-verification attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    /// Whether the right was confirmed.
    pub valid: bool,
    /// The proof strength that was satisfied.
    pub strength: ProofStrength,
    /// Issues encountered during verification (warnings + errors).
    pub issues: Vec<String>,
}

/// The strength of proof the presenter provided.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProofStrength {
    /// Any matching commitment — proves the right existed at some point.
    Minimal,
    /// Full time-bounded proof — right held continuously across the window.
    /// All timeline versions must have matching documents, all grant the right,
    /// and the hash chain must be intact.
    Finalized,
}

/// A specific verification failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The DID is tombstoned / deactivated.
    DidDeactivated,
    /// The holder key does not appear in the DID document.
    KeyNotFound,
    /// The rights-document hash does not match any version in the commitment timeline.
    CommitmentHashMismatch,
    /// The rights document does not grant the required right to this key.
    RightNotGranted,
    /// The DID document has no commitment service endpoint.
    NoCommitmentService,
    /// JSON digest computation failed.
    DigestError(String),
    /// A timeline version is missing a corresponding rights document (Finalized only).
    MissingCommitmentDocument,
    /// The `previousCommitment` hash chain between consecutive rights documents is broken.
    CommitmentChainBroken,
}

#[cfg(feature = "serde")]
impl DidDocument {
    /// Compute the `cm`-prefixed content ID for a rights document.
    fn compute_hash(doc: &RightsDocument) -> Result<String, String> {
        let json = serde_json::to_value(doc).map_err(|e| e.to_string())?;
        let canonical = json_digest::canonical_json(&json).map_err(|e| e.to_string())?;
        let hash_bytes = blake3::hash(canonical.as_bytes());
        let encoded = bs58::encode(hash_bytes.as_bytes()).into_string();
        Ok(format!("cm{encoded}"))
    }

    /// Verify that `holder_key_ref` has `right` at the document's resolution height.
    ///
    /// On-chain rights are checked against the DID document's verification
    /// relationship arrays. Off-chain rights require presenter-supplied
    /// `RightsDocument`s, keyed by their sequence number.
    ///
    /// # Proof strengths
    ///
    /// - **Minimal**: any provided document matches a timeline version and grants
    ///   the right. Proves the right existed *at some point*.
    /// - **Finalized**: documents must be provided for *all* versions in the
    ///   commitment timeline. Every one must grant the right and its hash must
    ///   match. The `previousCommitment` chain is verified between consecutive
    ///   documents.
    pub fn verify_right(
        &self, holder_key_ref: &str, right: &str, rights_documents: &[(u64, &RightsDocument)],
        strength: ProofStrength,
    ) -> Result<VerificationResult, VerificationError> {
        if self.deactivated {
            return Err(VerificationError::DidDeactivated);
        }

        // Check that the key appears in verificationMethod
        let key_fragment = format!("#{holder_key_ref}");
        let key_in_doc = self.verification_method.iter().any(|vm| vm.id.ends_with(&key_fragment));
        if !key_in_doc {
            return Err(VerificationError::KeyNotFound);
        }

        // Check on-chain rights via verification relationship arrays
        let in_list = |list: &[String]| list.iter().any(|id| id.ends_with(&key_fragment));

        let onchain_granted = match right {
            "update" => in_list(&self.capability_invocation),
            "delegate" => in_list(&self.capability_delegation),
            "impersonate" | "issue" => in_list(&self.assertion_method),
            _ => false,
        };

        if onchain_granted {
            return Ok(VerificationResult {
                valid: true,
                strength: ProofStrength::Finalized,
                issues: Vec::new(),
            });
        }

        // Off-chain: resolve the commitment timeline
        let commitment_service =
            self.service.iter().find(|s| s.type_ == "MosaicCommitmentTimeline2026");

        let Some(commitment_service) = commitment_service else {
            // No service and no documents → right not granted
            if rights_documents.is_empty() {
                return Err(VerificationError::RightNotGranted);
            }
            return Err(VerificationError::NoCommitmentService);
        };

        let versions = commitment_service
            .service_endpoint
            .get("versions")
            .and_then(|v| v.as_array())
            .ok_or(VerificationError::NoCommitmentService)?;

        // Build a lookup: sequence → expected hash
        let timeline: Vec<(u64, &str)> = versions
            .iter()
            .filter_map(|v| {
                let seq = v.get("sequence")?.as_u64()?;
                let cid = v.get("contentId")?.as_str()?;
                Some((seq, cid))
            })
            .collect();

        match strength {
            ProofStrength::Minimal => {
                // Any matching document grants the right
                for (seq, doc) in rights_documents {
                    let doc_hash =
                        Self::compute_hash(doc).map_err(VerificationError::DigestError)?;
                    if timeline.iter().any(|(s, h)| *s == *seq && *h == doc_hash)
                        && doc.rights.iter().any(|e| {
                            e.key_ref == holder_key_ref && e.rights.iter().any(|r| r == right)
                        })
                    {
                        return Ok(VerificationResult {
                            valid: true,
                            strength: ProofStrength::Minimal,
                            issues: Vec::new(),
                        });
                    }
                }
                Err(VerificationError::RightNotGranted)
            }
            ProofStrength::Finalized => {
                // Every version in the timeline MUST have a matching document
                let doc_by_seq: Vec<Option<&RightsDocument>> = timeline
                    .iter()
                    .map(|(seq, _expected_hash)| {
                        rights_documents.iter().find(|(s, _)| s == seq).map(|(_, doc)| *doc)
                    })
                    .collect();

                for (i, maybe_doc) in doc_by_seq.iter().enumerate() {
                    let (seq, expected_hash) = &timeline[i];
                    let doc = maybe_doc.ok_or(VerificationError::MissingCommitmentDocument)?;

                    // Hash must match
                    let doc_hash =
                        Self::compute_hash(doc).map_err(VerificationError::DigestError)?;
                    if doc_hash != *expected_hash {
                        return Err(VerificationError::CommitmentHashMismatch);
                    }

                    // Right must be granted in every version
                    let granted = doc.rights.iter().any(|e| {
                        e.key_ref == holder_key_ref && e.rights.iter().any(|r| r == right)
                    });
                    if !granted {
                        return Err(VerificationError::RightNotGranted);
                    }

                    // Hash chain: D_i.previousCommitment must equal blake3(canonical(D_{i-1}))
                    if i > 0 {
                        let prev_doc = doc_by_seq[i - 1].expect("previous doc must exist");
                        let prev_hash =
                            Self::compute_hash(prev_doc).map_err(VerificationError::DigestError)?;
                        let expected_prev = crate::did::ContentId::from_bytes(prev_hash.as_bytes());
                        let chain_ok =
                            doc.previous_commitment.as_ref().is_some_and(|pc| *pc == expected_prev);
                        if !chain_ok {
                            return Err(VerificationError::CommitmentChainBroken);
                        }
                    }
                }

                Ok(VerificationResult {
                    valid: true,
                    strength: ProofStrength::Finalized,
                    issues: Vec::new(),
                })
            }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::document::{DidDocument, DidDocumentService, DidDocumentVerificationMethod};

    fn make_test_document() -> DidDocument {
        let key_ref = "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB";
        let did = "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";
        DidDocument {
            context: alloc::vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://mosaic-trust.net/ns/did/v1".into(),
            ],
            id: did.into(),
            controller: None,
            also_known_as: None,
            verification_method: alloc::vec![DidDocumentVerificationMethod {
                id: format!("{did}#{key_ref}"),
                type_: "Ed25519VerificationKey2020".into(),
                controller: did.into(),
                public_key_multibase: "z4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi".into(),
            }],
            authentication: alloc::vec![format!("{did}#{key_ref}")],
            assertion_method: alloc::vec![format!("{did}#{key_ref}")],
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            deactivated: false,
            created_at_height: Some(10),
            last_modified_at_height: Some(100),
            tombstoned_at_height: None,
        }
    }

    fn make_rights_doc(seq: u64, previous_hash: Option<&str>, right: &str) -> RightsDocument {
        RightsDocument {
            schema: "https://mosaic-trust.net/ns/did-rights/v1".into(),
            did: "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb".into(),
            sequence: seq,
            previous_commitment: previous_hash
                .map(|h| crate::did::ContentId::from_bytes(h.as_bytes())),
            rights: alloc::vec![crate::rights::RightEntry {
                key_ref: "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB".into(),
                rights: alloc::vec![right.into()],
            }],
        }
    }

    fn set_timeline(doc: &mut DidDocument, versions: &[(u64, &str)]) {
        let items: Vec<serde_json::Value> = versions
            .iter()
            .map(|(seq, hash)| {
                serde_json::json!({
                    "sequence": seq,
                    "contentId": hash,
                    "publishedAtHeight": seq * 100,
                    "publishedBy": "#iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                })
            })
            .collect();
        doc.service = alloc::vec![DidDocumentService {
            id: format!("{}#rights-commitment", doc.id),
            type_: "MosaicCommitmentTimeline2026".into(),
            service_endpoint: serde_json::json!({ "versions": items }),
        }];
    }

    // ===== On-chain tests =====

    #[test]
    fn verify_right_with_key_in_document() {
        let doc = make_test_document();
        let result = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[],
                ProofStrength::Minimal,
            )
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Finalized);
    }

    #[test]
    fn verify_right_with_key_not_in_document() {
        let doc = make_test_document();
        let err = doc
            .verify_right(
                "iozUNKNOWN0000000000000000000000000000000",
                "impersonate",
                &[],
                ProofStrength::Minimal,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::KeyNotFound);
    }

    #[test]
    fn verify_right_with_on_chain_impersonate() {
        let doc = make_test_document();
        let result = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[],
                ProofStrength::Minimal,
            )
            .unwrap();
        assert!(result.valid);
    }

    #[test]
    fn verify_right_with_deactivated_did() {
        let mut doc = make_test_document();
        doc.deactivated = true;
        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[],
                ProofStrength::Minimal,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::DidDeactivated);
    }

    #[test]
    fn verify_right_rejected_when_right_not_in_on_chain_relationships() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[],
                ProofStrength::Minimal,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    // ===== Minimal proof tests =====

    #[test]
    fn minimal_any_matching_document_passes() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        let rights_doc = make_rights_doc(1, None, "impersonate");
        let hash = DidDocument::compute_hash(&rights_doc).unwrap();
        set_timeline(&mut doc, &[(1, &hash)]);

        let result = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &rights_doc)],
                ProofStrength::Minimal,
            )
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Minimal);
    }

    #[test]
    fn minimal_hash_mismatch_fails() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        let rights_doc = make_rights_doc(1, None, "impersonate");
        set_timeline(&mut doc, &[(1, "cmWRONG_HASH_0000000000000000000000000000")]);

        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &rights_doc)],
                ProofStrength::Minimal,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    #[test]
    fn minimal_wrong_right_fails() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        let rights_doc = make_rights_doc(1, None, "issue"); // grants issue, not impersonate
        let hash = DidDocument::compute_hash(&rights_doc).unwrap();
        set_timeline(&mut doc, &[(1, &hash)]);

        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &rights_doc)],
                ProofStrength::Minimal,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    // ===== Finalized proof tests =====

    #[test]
    fn finalized_full_chain_passes() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();

        // Two versions with chain: D1 → D2
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = DidDocument::compute_hash(&d1).unwrap();
        let d2 = make_rights_doc(2, Some(&h1), "impersonate");
        let h2 = DidDocument::compute_hash(&d2).unwrap();
        set_timeline(&mut doc, &[(1, &h1), (2, &h2)]);

        let result = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &d1), (2, &d2)],
                ProofStrength::Finalized,
            )
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Finalized);
    }

    #[test]
    fn finalized_missing_document_fails() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();

        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = DidDocument::compute_hash(&d1).unwrap();
        set_timeline(&mut doc, &[(1, &h1), (2, "cmDUMMY_0000000000000000000000000000000000")]);

        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &d1)], // missing doc for version 2
                ProofStrength::Finalized,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::MissingCommitmentDocument);
    }

    #[test]
    fn finalized_chain_broken_fails() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();

        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = DidDocument::compute_hash(&d1).unwrap();
        // d2's previousCommitment points to a different hash → chain broken
        let d2 =
            make_rights_doc(2, Some("cmWRONG_CHAIN_HASH_0000000000000000000000"), "impersonate");
        let h2 = DidDocument::compute_hash(&d2).unwrap();
        set_timeline(&mut doc, &[(1, &h1), (2, &h2)]);

        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &d1), (2, &d2)],
                ProofStrength::Finalized,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::CommitmentChainBroken);
    }

    #[test]
    fn finalized_mid_chain_revocation_fails() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();

        // D1 grants Impersonate, D2 does not → fails at D2
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = DidDocument::compute_hash(&d1).unwrap();
        let d2 = make_rights_doc(2, Some(&h1), "issue");
        let h2 = DidDocument::compute_hash(&d2).unwrap();
        set_timeline(&mut doc, &[(1, &h1), (2, &h2)]);

        let err = doc
            .verify_right(
                "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB",
                "impersonate",
                &[(1, &d1), (2, &d2)],
                ProofStrength::Finalized,
            )
            .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }
}
