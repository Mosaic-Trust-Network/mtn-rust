//! Off-chain verifier for `did:mosaic` DID Documents.
//!
//! The verifier operates offline on a `DidDocument` produced by the indexer
//! at a specific `?versionId`. It checks on-chain rights from the document's
//! verification relationship arrays and off-chain rights from presenter-
//! supplied `RightsDocument`s whose hashes match the commitment timeline.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::did::{ContentId, KeyRef};
use crate::document::DidDocument;
use crate::history::{CommitmentVersion, DidHistory};
use crate::operation::Right;
use crate::rights::RightsDocument;
use crate::signed::{AfterEnvelope, Signed, SmtContent};
use crate::smt;

/// A single checkpoint in the verification pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepResult {
    /// Name of the verification step (e.g. `"did_liveness"`, `"key_validity"`).
    pub step: &'static str,
    /// Whether the step passed.
    pub passed: bool,
    /// Optional detail (e.g. which heights were checked).
    pub detail: Option<String>,
}

/// Result of a right-verification attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    /// Whether the right was confirmed.
    pub valid: bool,
    /// The proof strength that was satisfied.
    pub strength: ProofStrength,
    /// Issues encountered during verification (warnings + errors).
    pub issues: Vec<String>,
    /// Detailed per-step results for debugging.
    pub steps: Vec<StepResult>,
}

/// The strength of proof the presenter provided.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    /// The achieved proof strength is below the policy minimum.
    InsufficientProofStrength,
    /// SMT inclusion proof verification failed (recomputed root does not match
    /// the BeforeProof content ID, or the leaf hash does not match the
    /// signed-envelope fingerprint).
    SmtInclusionProofFailed,
    /// The BeforeProof anchor could not be verified at the claimed block height.
    BeforeProofVerificationFailed,
    /// The time window is invalid: H_start >= H_end (BeforeProof block height
    /// must be strictly greater than AfterProof block height + 1).
    WindowBoundsInvalid,
}

/// Policy controlling the minimum acceptable [`ProofStrength`].
///
/// # Examples
///
/// ```
/// use mosaic_did_types::verifier::{VerifierPolicy, ProofStrength};
///
/// let policy = VerifierPolicy::b2b_invoice();
/// assert!(policy.check(ProofStrength::AfterProof).is_ok());
/// assert!(policy.check(ProofStrength::Minimal).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierPolicy {
    /// The minimum proof strength required.
    pub min_strength: ProofStrength,
}

impl VerifierPolicy {
    /// Chat apps and low-risk contexts — any matching proof is sufficient.
    pub fn chat() -> Self {
        Self { min_strength: ProofStrength::Minimal }
    }
    /// B2B invoices and standard business — requires a lower time-bound (`AfterProof`).
    pub fn b2b_invoice() -> Self {
        Self { min_strength: ProofStrength::AfterProof }
    }
    /// Notarization and high-assurance — full cryptographic window (`Finalized`).
    pub fn notarization() -> Self {
        Self { min_strength: ProofStrength::Finalized }
    }

    /// Check whether `achieved` meets the policy minimum.
    pub fn check(&self, achieved: ProofStrength) -> Result<(), VerificationError> {
        if achieved >= self.min_strength {
            Ok(())
        } else {
            Err(VerificationError::InsufficientProofStrength)
        }
    }
}

// ===== BeforeProof Verifier Trait =====

/// Trait for verifying that a BeforeProof anchor exists on-chain.
///
/// A BeforeProof proves that a content ID (the SMT root) was anchored at a
/// specific block height on-chain. The verifier calls this trait to confirm
/// that the anchor exists. The caller provides an implementation that reads
/// pallet storage or queries an indexer.
///
/// # Example (test)
///
/// ```
/// use mosaic_did_types::verifier::BeforeProofVerifier;
///
/// struct TestVerifier;
/// impl BeforeProofVerifier for TestVerifier {
///     fn verify_before_proof(&self, _height: u32, _content_id: &str) -> bool { true }
/// }
/// ```
pub trait BeforeProofVerifier {
    /// Verify that `content_id` was anchored on-chain at `block_height`.
    fn verify_before_proof(&self, block_height: u32, content_id: &str) -> bool;
}

/// Input data for verifying a `FinalizedProof` (full time-window with SMT
/// inclusion).
///
/// A FinalizedProof bundles:
/// - A `Signed<AfterEnvelope<SmtContent>>` providing the cryptographic lower
///   time-bound (`H_start = after_proof.block_height + 1`).
/// - An SMT inclusion proof linking the signed envelope's fingerprint to an
///   on-chain anchored root.
/// - The BeforeProof anchor data providing the cryptographic upper time-bound
///   (`H_end = before_proof_block_height`).
///
/// The verifier recomputes the SMT root from the leaf hash and siblings,
/// checks it matches `before_proof_content_id`, and uses the derived bounds
/// for window verification.
#[derive(Clone, Debug)]
pub struct FinalizedProofInput {
    /// The signed AfterEnvelope containing the SMT batch root and the
    /// AfterProof (lower time-bound).
    pub signed_envelope: Signed<AfterEnvelope<SmtContent>>,
    /// SMT inclusion proof linking the signed envelope to the anchored root.
    pub inclusion_proof: smt::InclusionProof,
    /// Block height at which the BeforeProof was anchored on-chain (`H_end`).
    pub before_proof_block_height: u32,
    /// The SMT root hash that was anchored (must match recomputed root).
    pub before_proof_content_id: String,
}

// ===== Extension trait: entry point on DidHistory =====

/// Extension trait that adds a `.check_right()` entry point to [`DidHistory`].
///
/// This is the most natural way to start a verification chain:
///
/// ```text
/// history.check_right(key, "impersonate")
///     .during(100, 200)
///     .with_documents(&docs)
///     .require(ProofStrength::AfterProof)
///     .verify()?;
/// ```
pub trait DidHistoryCheckRight {
    /// Start a verification chain for `right` on `holder_key_ref` against
    /// this DID history.
    fn check_right<'a>(&'a self, holder_key_ref: &'a str, right: &'a str) -> Identity<'a>;
}

impl DidHistoryCheckRight for DidHistory {
    fn check_right<'a>(&'a self, holder_key_ref: &'a str, right: &'a str) -> Identity<'a> {
        Identity { history: self, holder_key_ref, right }
    }
}

// ===== Type-state phase structs for the verification request builder =====

/// Phase 1: identity — the DID history, holder key reference, and right are known.
///
/// Fields are private; construct via [`DidHistoryCheckRight::check_right`] on a
/// [`DidHistory`], not directly. Transition via [`Identity::during`].
pub struct Identity<'a> {
    // DID history (events reconstructed) for the target DID.
    history: &'a DidHistory,
    // Key reference to check (e.g. `"ioz..."`).
    holder_key_ref: &'a str,
    // The right to verify as a string (`"impersonate"`, `"issue"`, etc.).
    right: &'a str,
}

/// Phase 2: window — the verification time window is set.
///
/// Construct via [`Identity::during`], then call [`Window::with_documents`].
pub struct Window<'a> {
    // Previous phase data.
    prev: Identity<'a>,
    // Window start height (inclusive).
    start: u32,
    // Window end height (inclusive).
    end: u32,
}

/// Phase 3: documents — rights documents are supplied.
///
/// Construct via [`Window::with_documents`], then call [`Documents::require`].
pub struct Documents<'a> {
    // Previous phase data.
    prev: Window<'a>,
    // Presenter-provided rights documents, keyed by sequence number.
    rights_documents: &'a [(u64, &'a RightsDocument)],
}

/// Phase 4: ready — all required fields are set.
///
/// Construct via [`Documents::require`], then optionally configure with
/// [`Ready::with_policy`], [`Ready::with_finalized_proof`], or
/// [`Ready::with_before_proof_verifier`]. Call [`Ready::verify`] to execute.
pub struct Ready<'a> {
    // Previous phase data.
    prev: Documents<'a>,
    // Required proof strength.
    strength: ProofStrength,
    // Optional verifier policy that gates the result on a minimum proof strength.
    policy: Option<&'a VerifierPolicy>,
    // Optional finalized proof data (SMT inclusion + BeforeProof) for
    // Finalized strength verification.
    finalized_proof: Option<FinalizedProofInput>,
    // Optional BeforeProof verifier to confirm on-chain anchors.
    before_proof_verifier: Option<&'a dyn BeforeProofVerifier>,
}

// ---------------------------------------------------------------------------
// Phase 1: Identity
// ---------------------------------------------------------------------------
impl<'a> Identity<'a> {
    /// Start building a verification request with the DID history and the
    /// identity to verify.
    /// Set the verification time window `[start, end]` (inclusive).
    pub fn during(self, start: u32, end: u32) -> Window<'a> {
        Window { prev: self, start, end }
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Window
// ---------------------------------------------------------------------------
impl<'a> Window<'a> {
    /// Supply the presenter-provided rights documents.
    pub fn with_documents(
        self, rights_documents: &'a [(u64, &'a RightsDocument)],
    ) -> Documents<'a> {
        Documents { prev: self, rights_documents }
    }
}

// ---------------------------------------------------------------------------
// Phase 3: Documents
// ---------------------------------------------------------------------------
impl<'a> Documents<'a> {
    /// Set the minimum required proof strength.
    pub fn require(self, strength: ProofStrength) -> Ready<'a> {
        Ready {
            prev: self,
            strength,
            policy: None,
            finalized_proof: None,
            before_proof_verifier: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4: Ready — verification may execute
// ---------------------------------------------------------------------------
impl<'a> Ready<'a> {
    /// Optionally attach a verifier policy that gates the result on a minimum
    /// proof strength.
    pub fn with_policy(mut self, policy: &'a VerifierPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Attach a [`FinalizedProofInput`] for SMT inclusion + BeforeProof
    /// verification. When provided, the window bounds `H_start` and `H_end`
    /// are derived from the proof data and override any values set via
    /// `.during()`.
    pub fn with_finalized_proof(mut self, proof: FinalizedProofInput) -> Self {
        self.finalized_proof = Some(proof);
        self
    }

    /// Attach a [`BeforeProofVerifier`] to check that a BeforeProof anchor
    /// exists on-chain at the claimed block height.
    pub fn with_before_proof_verifier(mut self, verifier: &'a dyn BeforeProofVerifier) -> Self {
        self.before_proof_verifier = Some(verifier);
        self
    }

    /// Execute the verification and return a [`VerificationResult`].
    pub fn verify(self) -> Result<VerificationResult, VerificationError> {
        // Destructure all phases into local variables for flat access.
        let Ready {
            prev:
                Documents {
                    prev: Window { prev: Identity { history, holder_key_ref, right }, start, end },
                    rights_documents,
                },
            strength,
            policy,
            finalized_proof,
            before_proof_verifier,
        } = self;

        let mut steps: Vec<StepResult> = Vec::new();

        // --- Step 0: Classify proof bundle and derive time bounds ---
        // If a FinalizedProof is provided, derive H_start and H_end from it.
        // The SMT inclusion proof must be verified first to ensure the bounds
        // are cryptographically sound.
        let (h_start, h_end) = if let Some(fp) = &finalized_proof {
            // Derive H_start from the AfterProof inside the signed envelope.
            let after_proof_h = fp.signed_envelope.content.proof.block_height;
            let derived_start = after_proof_h + 1;
            let derived_end = fp.before_proof_block_height;

            // --- Step 1: Verify SMT inclusion proof ---
            // a. Compute fingerprint of the signed envelope.
            let fingerprint = json_digest::digest_data(&fp.signed_envelope)
                .map_err(|e| VerificationError::DigestError(e.to_string()))?;

            // b. Check fingerprint matches leaf_hash.
            if fingerprint != fp.inclusion_proof.leaf_hash.as_str() {
                return Err(VerificationError::SmtInclusionProofFailed);
            }
            steps.push(StepResult { step: "smt_leaf_hash_match", passed: true, detail: None });

            // c. Recompute SMT root from leaf + siblings.
            let recomputed_root = fp.inclusion_proof.compute_root();

            // d. Check recomputed root matches before_proof_content_id.
            if recomputed_root.as_str() != fp.before_proof_content_id {
                return Err(VerificationError::SmtInclusionProofFailed);
            }
            steps.push(StepResult { step: "smt_root_match", passed: true, detail: None });

            // e. Verify BeforeProof anchor via the verifier trait.
            if let Some(bpv) = before_proof_verifier {
                if !bpv
                    .verify_before_proof(fp.before_proof_block_height, &fp.before_proof_content_id)
                {
                    return Err(VerificationError::BeforeProofVerificationFailed);
                }
                steps.push(StepResult { step: "before_proof_anchor", passed: true, detail: None });
            }

            // f. Validate window bounds: H_start < H_end.
            if derived_start >= derived_end {
                return Err(VerificationError::WindowBoundsInvalid);
            }
            steps.push(StepResult {
                step: "window_bounds",
                passed: true,
                detail: Some(alloc::format!("H_start={derived_start}, H_end={derived_end}")),
            });

            (derived_start, derived_end)
        } else {
            (start, end)
        };

        // --- Step 2: DID liveness across [h_start, h_end] ---
        if !history.is_alive_across(h_start, h_end) {
            return Err(VerificationError::DidDeactivated);
        }
        steps.push(StepResult { step: "did_liveness", passed: true, detail: None });

        // --- Step 3: Key validity across [h_start, h_end] ---
        let key_ref = KeyRef::new(holder_key_ref.as_bytes().to_vec())
            .map_err(|_| VerificationError::KeyNotFound)?;
        if !history.is_key_valid_across(&key_ref, h_start, h_end) {
            return Err(VerificationError::KeyNotFound);
        }
        steps.push(StepResult { step: "key_validity", passed: true, detail: None });

        // --- Step 4: Check on-chain rights (continuous across window) ---
        let right_enum: Right = right.parse().map_err(|_| VerificationError::RightNotGranted)?;
        let onchain_continuous = history.rights.iter().any(|rg| {
            rg.key_ref == key_ref
                && rg.right == right_enum
                && rg.is_active_at(h_start)
                && rg.revoked_at_height.is_none_or(|h| h > h_end)
                && rg.expires_at_height.is_none_or(|h| h > h_end)
        });
        steps.push(StepResult { step: "on_chain_right", passed: true, detail: None });
        if onchain_continuous {
            if let Some(policy) = policy {
                policy.check(strength)?;
            }
            steps.push(StepResult { step: "policy_gate", passed: true, detail: None });
            return Ok(VerificationResult { valid: true, strength, issues: Vec::new(), steps });
        }

        // --- Step 5: Off-chain commitment path ---
        // Local helper: compute ContentId for a rights document.
        let doc_cid = |d: &RightsDocument| -> Result<ContentId, VerificationError> {
            let hash = d.compute_hash().map_err(VerificationError::DigestError)?;
            Ok(ContentId::from_bytes(hash.as_bytes()))
        };

        // Wrap in a closure so interior `return` statements exit the closure,
        // not the outer function (allowing the policy gate to run).
        let verification = (|| -> Result<VerificationResult, VerificationError> {
            match strength {
                ProofStrength::Minimal => {
                    // Any matching document in any timeline version grants the right.
                    for (seq, doc) in rights_documents {
                        let commitment = doc_cid(doc)?;
                        if history
                            .commitments
                            .iter()
                            .any(|cv| cv.sequence == *seq && cv.commitment == commitment)
                            && doc.grants_right(holder_key_ref, right)
                        {
                            return Ok(VerificationResult {
                                valid: true,
                                strength: ProofStrength::Minimal,
                                issues: Vec::new(),
                                steps: Vec::new(),
                            });
                        }
                    }
                    Err(VerificationError::RightNotGranted)
                }
                ProofStrength::AfterProof | ProofStrength::Finalized => {
                    // Find the commitment active at `h_start`.
                    let _active_at_start =
                        history.commitment_at(h_start).ok_or(VerificationError::RightNotGranted)?;

                    // Collect all commitments from the one active at `h_start` through `h_end`.
                    let start_idx = history
                        .commitments
                        .iter()
                        .rposition(|cv| cv.published_at_height <= h_start)
                        .unwrap_or(0);

                    let relevant_commitments: Vec<&CommitmentVersion> = history.commitments
                        [start_idx..]
                        .iter()
                        .take_while(|cv| cv.published_at_height <= h_end)
                        .collect();

                    if relevant_commitments.is_empty() {
                        return Err(VerificationError::RightNotGranted);
                    }

                    // Every commitment active in the window must have a matching
                    // presenter-supplied document that grants the right.
                    for &cv in &relevant_commitments {
                        let doc = doc_by_seq(rights_documents, cv.sequence)?;
                        if cv.commitment != doc_cid(doc)? {
                            return Err(VerificationError::CommitmentHashMismatch);
                        }
                        if !doc.grants_right(holder_key_ref, right) {
                            return Err(VerificationError::RightNotGranted);
                        }
                    }

                    // For Finalized: verify the previousCommitment hash chain.
                    if strength == ProofStrength::Finalized && relevant_commitments.len() > 1 {
                        for i in 1..relevant_commitments.len() {
                            let prev_doc =
                                doc_by_seq(rights_documents, relevant_commitments[i - 1].sequence)?;
                            let curr_doc =
                                doc_by_seq(rights_documents, relevant_commitments[i].sequence)?;
                            let expected_prev_cid = doc_cid(prev_doc)?;
                            let chain_ok = curr_doc
                                .previous_commitment
                                .as_ref()
                                .is_some_and(|pc| *pc == expected_prev_cid);
                            if !chain_ok {
                                return Err(VerificationError::CommitmentChainBroken);
                            }
                        }
                    }

                    Ok(VerificationResult {
                        valid: true,
                        strength,
                        issues: Vec::new(),
                        steps: Vec::new(),
                    })
                }
            }
        })()?;

        steps.push(StepResult { step: "off_chain_commitment", passed: true, detail: None });

        // --- Step 5: Policy gate ---
        if let Some(policy) = policy {
            policy.check(verification.strength)?;
        }
        steps.push(StepResult { step: "policy_gate", passed: true, detail: None });

        Ok(VerificationResult {
            valid: true,
            strength: verification.strength,
            issues: Vec::new(),
            steps,
        })
    }
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
        let mut steps: Vec<StepResult> = Vec::new();

        if self.deactivated {
            return Err(VerificationError::DidDeactivated);
        }
        steps.push(StepResult { step: "did_liveness", passed: true, detail: None });

        // Check that the key appears in verificationMethod
        let key_fragment = format!("#{holder_key_ref}");
        let key_in_doc = self.verification_method.iter().any(|vm| vm.id.ends_with(&key_fragment));
        if !key_in_doc {
            return Err(VerificationError::KeyNotFound);
        }
        steps.push(StepResult { step: "key_in_document", passed: true, detail: None });

        // Check on-chain rights via verification relationship arrays
        let in_list = |list: &[String]| list.iter().any(|id| id.ends_with(&key_fragment));

        let onchain_granted = match right {
            "update" => in_list(&self.capability_invocation),
            "delegate" => in_list(&self.capability_delegation),
            "impersonate" | "issue" => in_list(&self.assertion_method),
            _ => false,
        };
        steps.push(StepResult { step: "on_chain_right", passed: true, detail: None });

        if onchain_granted {
            return Ok(VerificationResult {
                valid: true,
                strength: ProofStrength::Finalized,
                issues: Vec::new(),
                steps,
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

        // Wrap in a closure so interior `return` statements exit the closure,
        // allowing step recording to run afterward.
        let verification = (|| -> Result<VerificationResult, VerificationError> {
            match strength {
                ProofStrength::Minimal => {
                    // Any matching document grants the right
                    for (seq, doc) in rights_documents {
                        let doc_hash =
                            doc.compute_hash().map_err(VerificationError::DigestError)?;
                        if timeline.iter().any(|(s, h)| *s == *seq && *h == doc_hash)
                            && doc.grants_right(holder_key_ref, right)
                        {
                            return Ok(VerificationResult {
                                valid: true,
                                strength: ProofStrength::Minimal,
                                issues: Vec::new(),
                                steps: Vec::new(),
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
                        let doc_hash =
                            doc.compute_hash().map_err(VerificationError::DigestError)?;
                        if doc_hash != *expected_hash {
                            return Err(VerificationError::CommitmentHashMismatch);
                        }

                        // Right must be granted in every version
                        if !doc.grants_right(holder_key_ref, right) {
                            return Err(VerificationError::RightNotGranted);
                        }

                        // Hash chain: D_i.previousCommitment must equal blake3(canonical(D_{i-1}))
                        if i > 0 {
                            let prev_doc = doc_by_seq[i - 1].expect("previous doc must exist");
                            let expected_prev =
                                prev_doc.compute_hash().map_err(VerificationError::DigestError)?;
                            let chain_ok = doc.previous_commitment.as_ref().is_some_and(|pc| {
                                *pc == crate::did::ContentId::from_bytes(expected_prev.as_bytes())
                            });
                            if !chain_ok {
                                return Err(VerificationError::CommitmentChainBroken);
                            }
                        }
                    }

                    Ok(VerificationResult {
                        valid: true,
                        strength: ProofStrength::Finalized,
                        issues: Vec::new(),
                        steps: Vec::new(),
                    })
                }
            }
        })()?;

        steps.push(StepResult { step: "off_chain_commitment", passed: true, detail: None });

        Ok(VerificationResult {
            valid: true,
            strength: verification.strength,
            issues: Vec::new(),
            steps,
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DidDocument, DidDocumentService, DidDocumentVerificationMethod};
    use crate::ed25519_blake3_signature;
    use crate::signed::{AfterEnvelope, AfterProof, Signed, SmtContent};
    use crate::smt;

    /// A test BeforeProof verifier that succeeds for a given set of anchors.
    struct TestBeforeProofVerifier {
        anchors: Vec<(u32, String)>,
    }

    impl TestBeforeProofVerifier {
        fn new(anchors: Vec<(u32, String)>) -> Self {
            Self { anchors }
        }
    }

    impl BeforeProofVerifier for TestBeforeProofVerifier {
        fn verify_before_proof(&self, block_height: u32, content_id: &str) -> bool {
            self.anchors.iter().any(|(h, c)| *h == block_height && c == content_id)
        }
    }

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
        let hash = rights_doc.compute_hash().unwrap();
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
        let hash = rights_doc.compute_hash().unwrap();
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
        let h1 = d1.compute_hash().unwrap();
        let d2 = make_rights_doc(2, Some(&h1), "impersonate");
        let h2 = d2.compute_hash().unwrap();
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
        let h1 = d1.compute_hash().unwrap();
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
        let h1 = d1.compute_hash().unwrap();
        // d2's previousCommitment points to a different hash → chain broken
        let d2 =
            make_rights_doc(2, Some("cmWRONG_CHAIN_HASH_0000000000000000000000"), "impersonate");
        let h2 = d2.compute_hash().unwrap();
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
        let h1 = d1.compute_hash().unwrap();
        let d2 = make_rights_doc(2, Some(&h1), "issue");
        let h2 = d2.compute_hash().unwrap();
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
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let result = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 200)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::AfterProof);
    }

    #[test]
    fn after_proof_fails_when_key_added_after_h_start() {
        // Key added at height 120. H_start = 100. Key not valid at H_start.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(120, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 200)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::KeyNotFound);
    }

    #[test]
    fn after_proof_fails_when_key_revoked_before_end() {
        // Key added at 10, revoked at 150. H_start = 100, end = 200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, Some(150), None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 200)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::KeyNotFound);
    }

    #[test]
    fn after_proof_fails_when_did_tombstoned_during_window() {
        // DID tombstoned at 180. H_start = 100, end = 200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let mut history = add_commitment(history_with_key(10, None, None), 1, 100);
        history = replace_commitment_hash(history, 1, cid);
        history.tombstoned_at = Some(180);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 200)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .verify()
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
        let h1 = d1.compute_hash().unwrap();
        let cid1 = ContentId::from_bytes(h1.as_bytes());
        let d2 = make_rights_doc(2, Some(&h1), "issue");
        let h2 = d2.compute_hash().unwrap();
        let cid2 = ContentId::from_bytes(h2.as_bytes());

        let history = history_with_key(10, None, None);
        let history = add_commitment(history, 1, 100);
        let history = replace_commitment_hash(history, 1, cid1);
        let history = add_commitment(history, 2, 150);
        let history = replace_commitment_hash(history, 2, cid2);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 180)
            .with_documents(&[(1, &d1), (2, &d2)])
            .require(ProofStrength::AfterProof)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    #[test]
    fn after_proof_fails_when_no_commitment_at_h_start() {
        // Commitment published at height 100, but H_start = 50.
        // No commitment active at H_start → no off-chain right.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(50, 80)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .verify()
            .unwrap_err();
        // No commitment active at H_start=50 → off-chain right not granted
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    // ===== VerifierPolicy tests =====

    #[test]
    fn policy_rejects_minimal_when_afterproof_required() {
        let policy = VerifierPolicy::b2b_invoice();
        let result = policy.check(ProofStrength::Minimal);
        assert_eq!(result, Err(VerificationError::InsufficientProofStrength));
    }

    #[test]
    fn policy_accepts_afterproof_when_afterproof_required() {
        let policy = VerifierPolicy::b2b_invoice();
        assert!(policy.check(ProofStrength::AfterProof).is_ok());
    }

    #[test]
    fn policy_accepts_finalized_when_notarization_required() {
        let policy = VerifierPolicy::notarization();
        assert!(policy.check(ProofStrength::Finalized).is_ok());
    }

    #[test]
    fn verify_right_windowed_rejects_when_below_policy() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);
        let policy = VerifierPolicy::notarization(); // requires Finalized

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 200)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .with_policy(&policy)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::InsufficientProofStrength);
    }

    #[test]
    fn verify_right_windowed_accepts_when_meets_policy() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);
        let policy = VerifierPolicy::chat(); // accepts anything

        let result = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(100, 200)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::AfterProof)
            .with_policy(&policy)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert!(result.steps.iter().any(|s| s.passed));
    }

    // ===== FinalizedProof tests =====

    /// Helper: build a `Signed<AfterEnvelope<SmtContent>>` with a dummy
    /// signature and an AfterProof at `after_block_height`.
    fn make_signed_envelope(
        after_block_height: u32, smt_root: &str,
    ) -> Signed<AfterEnvelope<SmtContent>> {
        let content = SmtContent { root: smt_root.into(), height: 10 };
        let proof = AfterProof {
            block_height: after_block_height,
            block_hash: "0x0400000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let envelope = AfterEnvelope { content, proof };
        let sig = ed25519_blake3_signature([0u8; 64]);
        Signed::new(envelope, "test-key".into(), &sig)
    }

    #[test]
    fn finalized_proof_happy_path() {
        // Setup: key added at 10, commitment at height 50 grants impersonate.
        // AfterProof at block 120 → H_start = 121 (after commitment exists).
        // BeforeProof at block 200 → H_end = 200.
        // Window [121, 200]: commitment is active throughout.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 50);
        let history = replace_commitment_hash(history, 1, cid);

        // Create Signed<AfterEnvelope<SmtContent>> with AfterProof block 120.
        // SmtContent.root can be anything — the verifier recomputes the root
        // from the inclusion proof and checks it against before_proof_content_id.
        let signed = make_signed_envelope(120, "unused-root");

        // Compute fingerprint of the signed envelope and build an SMT.
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash.clone());
        let root = trie.root().clone();
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        // H_start = 120 + 1 = 121, H_end = 200
        let before_proof_block_height = 200;
        let finalized_input = FinalizedProofInput {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_block_height,
            before_proof_content_id: root.as_str().to_string(),
        };

        let verifier = TestBeforeProofVerifier::new(alloc::vec![(200, root.as_str().to_string()),]);

        let result = history.check_right(TEST_KEY_REF, "impersonate")
            .during(0, 0) // window overridden by finalized proof
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::Finalized)
            .with_finalized_proof(finalized_input)
            .with_before_proof_verifier(&verifier)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Finalized);
        // All steps should have passed
        assert!(result.steps.iter().any(|s| s.step == "smt_leaf_hash_match" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "smt_root_match" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "before_proof_anchor" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "window_bounds" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "did_liveness" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "key_validity" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "off_chain_commitment" && s.passed));
    }

    #[test]
    fn finalized_proof_fails_when_smt_leaf_hash_mismatch() {
        // Setup: key, commitment, signed envelope.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(90, "unused-root");

        // Build SMT with a DIFFERENT leaf (not the signed envelope).
        let wrong_leaf = smt::Hash::from_digest("cmWRONG_LEAF_HASH_000000000000000000".into());
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, wrong_leaf);
        let inclusion_proof = trie.inclusion_proof(0).unwrap();
        let root = trie.root().clone();

        let finalized_input = FinalizedProofInput {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_block_height: 200,
            before_proof_content_id: root.as_str().to_string(),
        };

        let verifier = TestBeforeProofVerifier::new(alloc::vec![]);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(0, 0)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::Finalized)
            .with_finalized_proof(finalized_input)
            .with_before_proof_verifier(&verifier)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::SmtInclusionProofFailed);
    }

    #[test]
    fn finalized_proof_fails_when_smt_root_mismatch() {
        // Build a valid SMT proof but claim a wrong before_proof_content_id.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(90, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        let finalized_input = FinalizedProofInput {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_block_height: 200,
            before_proof_content_id: "cmWRONG_ROOT_0000000000000000000000000000".into(),
        };

        let verifier = TestBeforeProofVerifier::new(alloc::vec![]);

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(0, 0)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::Finalized)
            .with_finalized_proof(finalized_input)
            .with_before_proof_verifier(&verifier)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::SmtInclusionProofFailed);
    }

    #[test]
    fn finalized_proof_fails_when_before_proof_anchor_missing() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(90, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let root = trie.root().clone();
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        // The verifier has NO matching anchors.
        let verifier = TestBeforeProofVerifier::new(alloc::vec![]);

        let finalized_input = FinalizedProofInput {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_block_height: 200,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(0, 0)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::Finalized)
            .with_finalized_proof(finalized_input)
            .with_before_proof_verifier(&verifier)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::BeforeProofVerificationFailed);
    }

    #[test]
    fn finalized_proof_rejects_impossible_upper_bound() {
        // BeforeProof at height 100, AfterProof at height 200 → H_start=201, H_end=100
        // H_start > H_end → impossible window → rejected.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid = ContentId::from_bytes(h1.as_bytes());
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        // AfterProof at height 200 → H_start = 201
        let signed = make_signed_envelope(200, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let root = trie.root().clone();
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        // BeforeProof at height 100 → H_end = 100
        let verifier = TestBeforeProofVerifier::new(alloc::vec![(100, root.as_str().to_string()),]);

        let finalized_input = FinalizedProofInput {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_block_height: 100,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(0, 0)
            .with_documents(&[(1, &d1)])
            .require(ProofStrength::Finalized)
            .with_finalized_proof(finalized_input)
            .with_before_proof_verifier(&verifier)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::WindowBoundsInvalid);
    }

    #[test]
    fn finalized_proof_omitted_commitment_in_window_fails() {
        // Two commitments: D1 at height 100 grants impersonate, D2 at height 150
        // does NOT grant impersonate. Window [91, 200] covers both.
        // Even with SMT proof, the right must be present in ALL commitments.
        let d1 = make_rights_doc(1, None, "impersonate");
        let h1 = d1.compute_hash().unwrap();
        let cid1 = ContentId::from_bytes(h1.as_bytes());
        let d2 = make_rights_doc(2, Some(&h1), "issue"); // no impersonate!
        let h2 = d2.compute_hash().unwrap();
        let cid2 = ContentId::from_bytes(h2.as_bytes());

        let history = history_with_key(10, None, None);
        let history = add_commitment(history, 1, 100);
        let history = replace_commitment_hash(history, 1, cid1);
        let history = add_commitment(history, 2, 150);
        let history = replace_commitment_hash(history, 2, cid2);

        let signed = make_signed_envelope(90, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let root = trie.root().clone();
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        let verifier = TestBeforeProofVerifier::new(alloc::vec![(200, root.as_str().to_string()),]);

        let finalized_input = FinalizedProofInput {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_block_height: 200,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(TEST_KEY_REF, "impersonate")
            .during(0, 0)
            .with_documents(&[(1, &d1), (2, &d2)])
            .require(ProofStrength::Finalized)
            .with_finalized_proof(finalized_input)
            .with_before_proof_verifier(&verifier)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }
}
