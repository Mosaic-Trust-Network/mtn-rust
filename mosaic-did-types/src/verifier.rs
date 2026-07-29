//! Off-chain verifier for `did:mosaic` DID Documents.
//!
//! The verifier operates offline on a `DidDocument` produced by the indexer
//! at a specific `?versionId`. It checks on-chain rights from the document's
//! verification relationship arrays and off-chain rights from presenter-
//! supplied `RightsDocument`s whose hashes match the commitment timeline.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::Right;
use crate::did::{ContentId, KeyRef};
use crate::document::DidDocument;
use crate::history::{CommitmentVersion, DidHistory};
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
    /// Lower time-bound proof — the key had the right from `H_start` (derived
    /// from an `AfterProof` anchor) through the present. Key validity, DID
    /// liveness, and commitment continuity are checked across the window.
    AfterProof,
    /// Full time-bounded proof — right held continuously across `[H_start, H_end]`.
    /// Both bounds are cryptographically anchored. All timeline versions must
    /// have matching documents, all grant the right, and the hash chain must
    /// be intact.
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

/// Compute the `cm`-prefixed content ID for a rights document.
///
/// Uses BLAKE3-256 of the canonical JSON representation, matching the
/// commitment stored on-chain in `CommitmentVersion.commitment`.
pub fn compute_rights_document_hash(doc: &RightsDocument) -> Result<String, String> {
    let json = serde_json::to_value(doc).map_err(|e| e.to_string())?;
    let canonical = json_digest::canonical_json(&json).map_err(|e| e.to_string())?;
    let hash_bytes = blake3::hash(canonical.as_bytes());
    let encoded = bs58::encode(hash_bytes.as_bytes()).into_string();
    Ok(format!("cm{encoded}"))
}

impl DidDocument {
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
                    let doc_hash = compute_rights_document_hash(doc)
                        .map_err(VerificationError::DigestError)?;
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
            ProofStrength::AfterProof | ProofStrength::Finalized => {
                // Every version in the timeline MUST have a matching document
                let doc_by_seq: Vec<Option<&RightsDocument>> = timeline
                    .iter()
                    .map(|(seq, _expected_hash)| {
                        rights_documents.iter().find(|(s, _)| s == seq).map(|(_, doc)| *doc)
                    })
                    .collect();

                for (i, maybe_doc) in doc_by_seq.iter().enumerate() {
                    let (_seq, expected_hash) = &timeline[i];
                    let doc = maybe_doc.ok_or(VerificationError::MissingCommitmentDocument)?;

                    // Hash must match
                    let doc_hash = compute_rights_document_hash(doc)
                        .map_err(VerificationError::DigestError)?;
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
                        let prev_hash = compute_rights_document_hash(prev_doc)
                            .map_err(VerificationError::DigestError)?;
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

/// Compute the [`ContentId`] for a rights document (hash + wrap).
fn doc_hash_cid(doc: &RightsDocument) -> Result<ContentId, VerificationError> {
    let hash = compute_rights_document_hash(doc).map_err(VerificationError::DigestError)?;
    Ok(ContentId::from_bytes(hash.as_bytes()))
}

/// Check whether a rights document grants `right` to `holder_key_ref`.
fn doc_grants_right(doc: &RightsDocument, holder_key_ref: &str, right: &str) -> bool {
    doc.rights.iter().any(|e| e.key_ref == holder_key_ref && e.rights.iter().any(|r| r == right))
}

/// Look up a rights document by sequence number.
fn doc_by_seq<'a>(
    rights_documents: &'a [(u64, &'a RightsDocument)], seq: u64,
) -> Result<&'a RightsDocument, VerificationError> {
    rights_documents
        .iter()
        .find(|(s, _)| *s == seq)
        .map(|(_, d)| *d)
        .ok_or(VerificationError::MissingCommitmentDocument)
}

/// Verify that a holder key had a specific right across a time window `[start, end]`.
///
/// This is the core verification function supporting all proof strengths.
/// Unlike [`DidDocument::verify_right`] (which works from a resolved DID document
/// at a single height), this function takes a [`DidHistory`] and explicit window
/// bounds to support per-height checks required by `AfterProof` and `Finalized`
/// strengths.
///
/// # Parameters
///
/// * `history` — The DID history (events reconstructed) for the target DID.
/// * `holder_key_ref` — The key reference to check (e.g. `"ioz..."`).
/// * `right` — The right to verify as a string (`"impersonate"`, `"issue"`, etc.).
/// * `start` — Window start height (inclusive). For `AfterProof` this is
///   `H_start = after_proof.block_height + 1`.
/// * `end` — Window end height (inclusive). Typically the current block height.
/// * `rights_documents` — Presenter-supplied rights documents, keyed by sequence number.
/// * `strength` — Required proof strength.
///
/// # Proof strengths
///
/// | Strength | What it checks |
/// |----------|----------------|
/// | `Minimal` | Any one presenter-supplied document matches a timeline version and grants the right. No time window checks. |
/// | `AfterProof` | The right was held continuously from `start` to `end`. Key validity, DID liveness, and the commitment timeline (every version active in the window must grant the right) are all checked. |
/// | `Finalized` | All `AfterProof` checks **plus** the `previousCommitment` hash chain between consecutive rights documents must be intact. |
pub fn verify_right_windowed(
    history: &DidHistory, holder_key_ref: &str, right: &str, start: u32, end: u32,
    rights_documents: &[(u64, &RightsDocument)], strength: ProofStrength,
) -> Result<VerificationResult, VerificationError> {
    // --- Step 1: DID liveness across [start, end] ---
    if !history.is_alive_across(start, end) {
        return Err(VerificationError::DidDeactivated);
    }

    // --- Step 2: Key validity across [start, end] ---
    let key_ref = KeyRef::new(holder_key_ref.as_bytes().to_vec())
        .map_err(|_| VerificationError::KeyNotFound)?;
    if !history.is_key_valid_across(&key_ref, start, end) {
        return Err(VerificationError::KeyNotFound);
    }

    // --- Step 3: Check on-chain rights (continuous across window) ---
    let right_enum: Right = right.parse().map_err(|_| VerificationError::RightNotGranted)?;
    let onchain_continuous = history.rights.iter().any(|rg| {
        rg.key_ref == key_ref
            && rg.right == right_enum
            && rg.is_active_at(start)
            && rg.revoked_at_height.map_or(true, |h| h > end)
            && rg.expires_at_height.map_or(true, |h| h > end)
    });
    if onchain_continuous {
        return Ok(VerificationResult { valid: true, strength, issues: Vec::new() });
    }

    // --- Step 4: Off-chain commitment path ---
    match strength {
        ProofStrength::Minimal => {
            // Any matching document in any timeline version grants the right.
            for (seq, doc) in rights_documents {
                let doc_cid = doc_hash_cid(doc)?;
                if history
                    .commitments
                    .iter()
                    .any(|cv| cv.sequence == *seq && cv.commitment == doc_cid)
                    && doc_grants_right(doc, holder_key_ref, right)
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
        ProofStrength::AfterProof | ProofStrength::Finalized => {
            // Find the commitment active at `start`.
            let _active_at_start =
                history.commitment_at(start).ok_or(VerificationError::RightNotGranted)?;

            // Collect all commitments from the one active at `start` through `end`.
            let start_idx = history
                .commitments
                .iter()
                .rposition(|cv| cv.published_at_height <= start)
                .unwrap_or(0);

            let relevant_commitments: Vec<&CommitmentVersion> = history.commitments[start_idx..]
                .iter()
                .take_while(|cv| cv.published_at_height <= end)
                .collect();

            if relevant_commitments.is_empty() {
                return Err(VerificationError::RightNotGranted);
            }

            // Every commitment active in the window must have a matching
            // presenter-supplied document that grants the right.
            for &cv in &relevant_commitments {
                let doc = doc_by_seq(rights_documents, cv.sequence)?;
                if cv.commitment != doc_hash_cid(doc)? {
                    return Err(VerificationError::CommitmentHashMismatch);
                }
                if !doc_grants_right(doc, holder_key_ref, right) {
                    return Err(VerificationError::RightNotGranted);
                }
            }

            // For Finalized: verify the previousCommitment hash chain.
            if strength == ProofStrength::Finalized && relevant_commitments.len() > 1 {
                for i in 1..relevant_commitments.len() {
                    let prev_doc =
                        doc_by_seq(rights_documents, relevant_commitments[i - 1].sequence)?;
                    let curr_doc = doc_by_seq(rights_documents, relevant_commitments[i].sequence)?;
                    let expected_prev = doc_hash_cid(prev_doc)?;
                    let chain_ok = curr_doc
                        .previous_commitment
                        .as_ref()
                        .is_some_and(|pc| *pc == expected_prev);
                    if !chain_ok {
                        return Err(VerificationError::CommitmentChainBroken);
                    }
                }
            }

            Ok(VerificationResult { valid: true, strength, issues: Vec::new() })
        }
    }
}

#[cfg(test)]
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
        let hash = compute_rights_document_hash(&rights_doc).unwrap();
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
        let hash = compute_rights_document_hash(&rights_doc).unwrap();
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
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let d2 = make_rights_doc(2, Some(&h1), "impersonate");
        let h2 = compute_rights_document_hash(&d2).unwrap();
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
        let h1 = compute_rights_document_hash(&d1).unwrap();
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
        let h1 = compute_rights_document_hash(&d1).unwrap();
        // d2's previousCommitment points to a different hash → chain broken
        let d2 =
            make_rights_doc(2, Some("cmWRONG_CHAIN_HASH_0000000000000000000000"), "impersonate");
        let h2 = compute_rights_document_hash(&d2).unwrap();
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
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let d2 = make_rights_doc(2, Some(&h1), "issue");
        let h2 = compute_rights_document_hash(&d2).unwrap();
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

    // ===== Windowed verification helpers =====

    /// A test key reference reused across windowed tests.
    const TEST_KEY_REF: &str = "iozA69ACNfFj2h2vRpyN8r9rVGYVGXerUTjKQhaUgBU73XQB";
    /// A test DID reused across windowed tests.
    const TEST_DID_STR: &str = "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";

    fn history_with_key(
        key_added_at: u32, revoked_at: Option<u32>, expires_at: Option<u32>,
    ) -> DidHistory {
        DidHistory {
            did: crate::did::Did::from_did_string(TEST_DID_STR).unwrap(),
            commitments: Vec::new(),
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: KeyRef::new(TEST_KEY_REF.as_bytes().to_vec()).unwrap(),
                key_type: crate::operation::KeyType::Ed25519,
                controller: crate::did::Did::from_did_string(TEST_DID_STR).unwrap(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: key_added_at,
                expires_at_height: expires_at,
                revoked_at_height: revoked_at,
            }],
            rights: Vec::new(),
            tombstoned_at: None,
        }
    }

    fn add_commitment(mut history: DidHistory, seq: u64, at_height: u32) -> DidHistory {
        history.commitments.push(crate::history::CommitmentVersion {
            sequence: seq,
            commitment: crate::did::ContentId::from_bytes(b"placeholder"),
            published_at_height: at_height,
            signer_key_ref: KeyRef::new(TEST_KEY_REF.as_bytes().to_vec()).unwrap(),
        });
        history
    }

    fn replace_commitment_hash(
        mut history: DidHistory, seq: u64, content_id: ContentId,
    ) -> DidHistory {
        if let Some(cv) = history.commitments.iter_mut().find(|cv| cv.sequence == seq) {
            cv.commitment = content_id;
        }
        history
    }

    // ===== AfterProof tests =====

    #[test]
    fn after_proof_happy_path() {
        // Key added at height 10. Commitment published at height 100 grants impersonate.
        // AfterProof: H_start = 100, end = 200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let result = verify_right_windowed(
            &history,
            TEST_KEY_REF,
            "impersonate",
            100,
            200,
            &[(1, &d1)],
            ProofStrength::AfterProof,
        )
        .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::AfterProof);
    }

    #[test]
    fn after_proof_fails_when_key_added_after_h_start() {
        // Key added at height 120. H_start = 100. Key not valid at H_start.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(120, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let err = verify_right_windowed(
            &history,
            TEST_KEY_REF,
            "impersonate",
            100, // H_start before key was added
            200,
            &[(1, &d1)],
            ProofStrength::AfterProof,
        )
        .unwrap_err();
        assert_eq!(err, VerificationError::KeyNotFound);
    }

    #[test]
    fn after_proof_fails_when_key_revoked_before_end() {
        // Key added at 10, revoked at 150. H_start = 100, end = 200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, Some(150), None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let err = verify_right_windowed(
            &history,
            TEST_KEY_REF,
            "impersonate",
            100,
            200, // end after key revoked
            &[(1, &d1)],
            ProofStrength::AfterProof,
        )
        .unwrap_err();
        assert_eq!(err, VerificationError::KeyNotFound);
    }

    #[test]
    fn after_proof_fails_when_did_tombstoned_during_window() {
        // DID tombstoned at 180. H_start = 100, end = 200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let mut history = add_commitment(history_with_key(10, None, None), 1, 100);
        history = replace_commitment_hash(history, 1, cid);
        history.tombstoned_at = Some(180);

        let err = verify_right_windowed(
            &history,
            TEST_KEY_REF,
            "impersonate",
            100,
            200,
            &[(1, &d1)],
            ProofStrength::AfterProof,
        )
        .unwrap_err();
        assert_eq!(err, VerificationError::DidDeactivated);
    }

    #[test]
    fn after_proof_fails_when_commitment_omits_right_mid_window() {
        // Two commitments:
        //   D1 at height 100 grants impersonate
        //   D2 at height 150 grants issue (no impersonate)
        // H_start = 100, end = 180 — D2 is in the window and does NOT grant.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let cid1 = ContentId::from_bytes(h1.as_bytes());
        let d2 = make_rights_doc(2, Some(&h1), "issue");
        let h2 = compute_rights_document_hash(&d2).unwrap();
        let cid2 = ContentId::from_bytes(h2.as_bytes());

        let history = history_with_key(10, None, None);
        let history = add_commitment(history, 1, 100);
        let history = replace_commitment_hash(history, 1, cid1);
        let history = add_commitment(history, 2, 150);
        let history = replace_commitment_hash(history, 2, cid2);

        let err = verify_right_windowed(
            &history,
            TEST_KEY_REF,
            "impersonate",
            100,
            180,
            &[(1, &d1), (2, &d2)],
            ProofStrength::AfterProof,
        )
        .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    #[test]
    fn after_proof_fails_when_no_commitment_at_h_start() {
        // Commitment published at height 100, but H_start = 50.
        // No commitment active at H_start → no off-chain right.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = compute_rights_document_hash(&d1).unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let err = verify_right_windowed(
            &history,
            TEST_KEY_REF,
            "impersonate",
            50,
            80, // end is also before commitment
            &[(1, &d1)],
            ProofStrength::AfterProof,
        )
        .unwrap_err();
        // No commitment active at H_start=50 → off-chain right not granted
        assert_eq!(err, VerificationError::RightNotGranted);
    }
}
