//! Off-chain verifier for `did:mosaic` DID Documents.
//!
//! The verifier operates offline on a `DidDocument` produced by the indexer
//! at a specific `?versionId`. It checks on-chain rights from the document's
//! verification relationship arrays and off-chain rights from presenter-
//! supplied [`RightsDocument`]s whose hashes match the commitment timeline.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::auth::Authentication;
#[allow(unused_imports)]
use crate::did::{ContentId, KeyRef};
use crate::document::DidDocument;
use crate::history::{
    CommitmentDocumentError, DidHistory, HistoryFromDocumentError, ValidityResult,
};
use crate::operation::Right;
use crate::rights::RightsDocumentSet;
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
    /// Whether verification found no definitive failure.
    ///
    /// `true` does not mean the right held continuously across the requested
    /// window: spans without evidence are reported in [`Self::issues`].
    pub valid: bool,
    /// The proof strength that was satisfied.
    pub strength: ProofStrength,
    /// Ambiguities and warnings encountered during verification.
    ///
    /// A non-empty list can accompany `valid == true` — for example an
    /// uncovered commitment span. Callers that require continuity across the
    /// window must treat a non-empty list as insufficient.
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
    /// Full time-bounded proof — both window bounds are cryptographically
    /// anchored and the holder's SMT envelope is verified.
    ///
    /// The right is checked across `[H_start, H_end]` over the *presented*
    /// rights documents: each presented document must hash to its on-chain
    /// commitment and satisfy its [`crate::history::ChainLink`] position. A
    /// version without a presented document, or whose document does not grant
    /// the right, contributes nothing; the uncovered span is reported as a gap
    /// in [`VerificationResult::issues`] and the right result is
    /// [`ValidityResult::Ambiguous`], not a failure. A caller that requires
    /// continuous coverage across the window must require an empty `issues`
    /// list (or a `Confirmed` right result).
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
    /// A presented rights document's content ID could not be computed.
    CommitmentDocumentDigestFailed(String),
    /// A presented rights document belongs to a different DID.
    DocumentForForeignDid { document_did: String, history_did: String },
    /// The DID document's `id` is not a valid `did:mosaic` DID.
    InvalidDid(String),
    /// A commitment service `contentId` could not be parsed.
    InvalidContentId(String),
    /// A commitment service entry claims a publication height after the
    /// requested resolution height.
    CommitmentAfterHeight { sequence: u64, published_at_height: u32, at_height: u32 },
    /// A commitment service `publishedBy` fragment is not a valid key reference.
    InvalidSignerKeyRef { sequence: u64 },
    /// A commitment service `chainLink` is missing, unknown, or misplaced.
    InvalidChainLink { sequence: u64 },
    /// An on-chain commitment uses a hashing algorithm this build cannot verify.
    ///
    /// No document can match such a commitment, so the timeline is
    /// unverifiable rather than merely unproven. A supported runtime never
    /// publishes one, so this means the build is older than the chain.
    UnsupportedCommitmentAlgorithm { sequence: u64, content_id: String },
    /// The rights document does not grant the required right to this key.
    RightNotGranted,
    /// The DID document has no commitment service endpoint.
    NoCommitmentService,
    /// JSON digest computation failed.
    DigestError(String),
    /// The `previousCommitment` hash chain between consecutive rights documents is broken.
    CommitmentChainBroken,
    /// A commitment's chain position is structurally invalid: a `Linked` entry
    /// has no visible predecessor, or a `WindowStart` appears past the first
    /// visible entry.
    InvalidCommitmentChainPosition { sequence: u64 },
    /// The achieved proof strength is below the policy minimum.
    InsufficientProofStrength,
    /// SMT inclusion proof verification failed (recomputed root does not match
    /// the BeforeProof content ID, or the leaf hash does not match the
    /// signed-envelope fingerprint).
    SmtInclusionProofFailed,
    /// The SMT envelope's signature is missing, unparseable, or
    /// cryptographically invalid over the canonical envelope digest (iop-rs#2).
    EnvelopeSignatureInvalid,
    /// The SMT envelope was signed by a key other than the presenter's holder
    /// key — a replayed third-party envelope (iop-rs#2).
    EnvelopeKeyMismatch,
    /// The BeforeProof anchor could not be verified at the claimed block height.
    BeforeProofVerificationFailed,
    /// The time window is invalid: H_start >= H_end (BeforeProof block height
    /// must be strictly greater than AfterProof block height + 1).
    WindowBoundsInvalid,
}

/// Map a commitment-document rejection onto a verification error.
///
/// Each source variant keeps its own identity rather than collapsing into a
/// generic failure: a caller must be able to tell a document for the wrong DID
/// from a broken chain link from an algorithm this build predates.
fn map_commitment_document_error(err: CommitmentDocumentError) -> VerificationError {
    match err {
        CommitmentDocumentError::Digest(e) => {
            VerificationError::CommitmentDocumentDigestFailed(e.to_string())
        }
        CommitmentDocumentError::ForeignDid { document_did, history_did } => {
            VerificationError::DocumentForForeignDid {
                document_did: document_did.to_did_string(),
                history_did: history_did.to_did_string(),
            }
        }
        CommitmentDocumentError::ChainBroken { .. } => VerificationError::CommitmentChainBroken,
        CommitmentDocumentError::InvalidChainPosition { sequence } => {
            VerificationError::InvalidCommitmentChainPosition { sequence }
        }
        CommitmentDocumentError::UnsupportedAlgorithm { sequence, content_id } => {
            VerificationError::UnsupportedCommitmentAlgorithm {
                sequence,
                content_id: content_id.to_string(),
            }
        }
    }
}

/// Map a snapshot-to-history rejection onto a verification error.
///
/// The commitment service endpoint inside a DID document is untrusted input,
/// so each malformed field is reported as itself. Collapsing them into
/// [`VerificationError::KeyNotFound`] would report a missing holder key when
/// the real problem is the endpoint.
fn map_history_from_document_error(err: HistoryFromDocumentError) -> VerificationError {
    match err {
        HistoryFromDocumentError::InvalidDid(e) => VerificationError::InvalidDid(e.to_string()),
        HistoryFromDocumentError::InvalidContentId(e) => {
            VerificationError::InvalidContentId(e.to_string())
        }
        HistoryFromDocumentError::CommitmentAfterHeight {
            sequence,
            published_at_height,
            at_height,
        } => VerificationError::CommitmentAfterHeight { sequence, published_at_height, at_height },
        HistoryFromDocumentError::InvalidSignerKeyRef(sequence) => {
            VerificationError::InvalidSignerKeyRef { sequence }
        }
        HistoryFromDocumentError::InvalidChainLink(sequence) => {
            VerificationError::InvalidChainLink { sequence }
        }
    }
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

// ===== Proof validation — types guarantee chain verification happened =====

/// A validated AfterProof: the signer observed a blockhash at this height,
/// and the chain has confirmed that blockhash exists at that block.
///
/// `H_start = block_height + 1`.
///
/// The caller must validate the presenter's claim against the chain **before**
/// constructing this type and passing it to [`Documents::with_after_proof`].
/// Chain access is inherently async; this type provides compile-time proof
/// that validation was performed, so [`Documents::verify`] remains synchronous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAfterProof {
    /// Block height confirmed on chain.
    pub block_height: u32,
}

/// A validated BeforeProof: this content-ID was anchored on-chain at
/// this block height, confirmed by a chain query.
///
/// `H_end = block_height`.
///
/// The caller must validate the presenter's claim against the chain **before**
/// constructing this type and passing it to [`Documents::with_before_proof`].
/// Chain access is inherently async; this type provides compile-time proof
/// that validation was performed, so [`Documents::verify`] remains synchronous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBeforeProof {
    /// Block height confirmed on chain.
    pub block_height: u32,
}

// ===== Input types — claims from the presenter, validated before verify() =====

/// An AfterProof claim provided by the presenter.
///
/// The caller must validate this against the chain (e.g. query a full node
/// or indexer to confirm `block_hash` exists at `block_height`), then
/// construct a [`ValidatedAfterProof`] from the confirmed height.
///
/// `H_start = block_height + 1`.
#[derive(Clone, Debug)]
pub struct AfterProofInput {
    /// Block height whose hash was observed by the signer.
    pub block_height: u32,
    /// The block hash that was observed.
    pub block_hash: String,
}

/// A BeforeProof claim provided by the presenter.
///
/// The caller must validate this against the chain (e.g. query a full node
/// or indexer to confirm `content_id` was anchored at `block_height`), then
/// construct a [`ValidatedBeforeProof`] from the confirmed height.
///
/// `H_end = block_height`.
#[derive(Clone, Debug)]
pub struct BeforeProofInput {
    /// Block height at which the BeforeProof was claimed to be anchored.
    pub block_height: u32,
    /// The content ID claimed to be anchored.
    pub content_id: String,
}

/// SMT inclusion proof data for a `Finalized` verification.
///
/// The presenter provides:
/// - A `Signed<AfterEnvelope<SmtContent>>` — the signed AfterProof envelope
///   whose fingerprint is a leaf in the SMT.
/// - An [`smt::InclusionProof`] linking that envelope to the SMT root.
/// - The claimed `before_proof_content_id` — the SMT root that was anchored
///   on-chain (validated externally by [`BeforeProofValidator`]).
///
/// The verifier locally recomputes the SMT root and checks it matches
/// `before_proof_content_id`, then derives `H_start` from the AfterProof
/// inside the envelope. No chain access is needed inside [`Documents::verify`].
#[derive(Clone, Debug)]
pub struct SmtEnvelopeProof {
    /// The signed AfterEnvelope (contains the AfterProof and SMT batch root).
    pub signed_envelope: Signed<AfterEnvelope<SmtContent>>,
    /// SMT inclusion proof linking the signed envelope to the anchored root.
    pub inclusion_proof: smt::InclusionProof,
    /// The SMT root hash that was anchored on-chain (validated externally).
    pub before_proof_content_id: String,
}

impl DidHistory {
    /// Start a verification chain for `right` on `holder_key` against
    /// this DID history.
    ///
    /// This is the entry point for the type-state verification builder.
    /// Time bounds come from validated proofs; there is no explicit window:
    ///
    /// ```text
    /// // Unbounded (no proofs):
    /// history.check_right(&key, "impersonate")
    ///     .with_documents(&docs)
    ///     .verify()?;
    ///
    /// // AfterProof only (lower-bound validated against chain before verify):
    /// history.check_right(&key, "impersonate")
    ///     .with_documents(&docs)
    ///     .with_after_proof(validated_after)
    ///     .verify()?;
    ///
    /// // Finalized with SMT (both bounds validated externally):
    /// history.check_right(&key, "impersonate")
    ///     .with_documents(&docs)
    ///     .with_after_proof(validated_after)
    ///     .with_before_proof(validated_before)
    ///     .with_smt_envelope(smt_envelope_proof)
    ///     .verify()?;
    /// ```
    pub fn check_right<'a>(
        &'a self, holder_key: &'a Authentication, right: &'a str,
    ) -> Identity<'a> {
        Identity { history: self, holder_key, right }
    }
}

// ===== Type-state phase structs for the verification request builder =====

/// Phase 1: identity — the DID history, holder key reference, and right are known.
///
/// Construct via [`DidHistory::check_right`], not directly.
/// Transition to [`Documents`] via [`Identity::with_documents`].
pub struct Identity<'a> {
    // DID history (events reconstructed) for the target DID.
    history: &'a DidHistory,
    // Key identity to verify (KeyId or full PublicKey).
    holder_key: &'a Authentication,
    // The right to verify as a string (`"impersonate"`, `"issue"`, etc.).
    right: &'a str,
}

/// Phase 2: documents — rights documents are supplied, plus optional
/// validated proof attachments.
///
/// Construct via [`Identity::with_documents`], then call [`Documents::verify`]
/// (directly, for simple cases) or configure proof attachments, then call
/// [`Documents::verify`].
pub struct Documents<'a> {
    // Previous phase data.
    prev: Identity<'a>,
    // Presenter-provided rights documents, indexed by sequence.
    rights_documents: &'a RightsDocumentSet<'a>,
    // Optional validated AfterProof providing a lower time-bound.
    after_proof: Option<ValidatedAfterProof>,
    // Optional validated BeforeProof providing an upper time-bound.
    before_proof: Option<ValidatedBeforeProof>,
    // Optional "received at" height — a voluntary soft upper bound.
    received_at: Option<u32>,
    // Optional SMT inclusion proof (envelope + siblings) for Finalized.
    smt_envelope: Option<SmtEnvelopeProof>,
    // Optional verifier policy.
    policy: Option<&'a VerifierPolicy>,
}

// ---------------------------------------------------------------------------
// Phase 1: Identity
// ---------------------------------------------------------------------------
impl<'a> Identity<'a> {
    /// Supply the presenter-provided rights documents and transition to Documents.
    ///
    /// Takes a [`RightsDocumentSet`], whose construction rejects duplicate
    /// sequences — so which document is presented for a given sequence is
    /// decided by the protocol rather than by presentation order.
    pub fn with_documents(self, rights_documents: &'a RightsDocumentSet<'a>) -> Documents<'a> {
        Documents {
            prev: self,
            rights_documents,
            after_proof: None,
            before_proof: None,
            received_at: None,
            smt_envelope: None,
            policy: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Documents — collects all inputs; verify() runs synchronously
// ---------------------------------------------------------------------------
impl<'a> Documents<'a> {
    /// Attach a validated AfterProof providing a lower time-bound.
    pub fn with_after_proof(mut self, after: ValidatedAfterProof) -> Self {
        self.after_proof = Some(after);
        self
    }

    /// Attach a validated BeforeProof providing an upper time-bound.
    pub fn with_before_proof(mut self, before: ValidatedBeforeProof) -> Self {
        self.before_proof = Some(before);
        self
    }

    /// Set a "received at" height — a voluntary soft upper bound.
    /// Forces `H_end ≤ received_at`, narrowing the window.
    pub fn with_received_at(mut self, height: u32) -> Self {
        self.received_at = Some(height);
        self
    }

    /// Attach an SMT inclusion proof (signed envelope + sibling hashes)
    /// linking the AfterProof envelope to the BeforeProof-anchored root.
    pub fn with_smt_envelope(mut self, smt: SmtEnvelopeProof) -> Self {
        self.smt_envelope = Some(smt);
        self
    }

    /// Attach a verifier policy that gates the result on a minimum proof strength.
    pub fn with_policy(mut self, policy: &'a VerifierPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Execute verification using the three-outcome model.
    ///
    /// All time-bounds must already be validated against the chain by the
    /// caller (via [`ValidatedAfterProof`] and [`ValidatedBeforeProof`]).
    /// This method is purely synchronous — no network I/O.
    ///
    /// Returns `Ok(VerificationResult)` with `issues` populated from ambiguous
    /// sub-results, or `Err(VerificationError)` if any check is definitively
    /// disproven.
    pub fn verify(self) -> Result<VerificationResult, VerificationError> {
        let Documents {
            prev: Identity { history, holder_key, right },
            rights_documents,
            after_proof,
            before_proof,
            received_at,
            smt_envelope,
            policy,
        } = self;

        let mut issues: Vec<String> = Vec::new();
        let mut steps: Vec<StepResult> = Vec::new();

        // --- Derive window [h_start, h_end) ---
        let mut h_start = after_proof.as_ref().map_or(0, |ap| ap.block_height + 1);
        let mut h_end = before_proof.as_ref().map(|bp| bp.block_height);

        // If an SMT envelope proof is provided, verify the inclusion proof
        // locally and derive the AfterProof bound from the signed envelope.
        if let Some(smt) = &smt_envelope {
            // --- Envelope signature (iop-rs#2) ---
            // The envelope's AfterProof (and therefore H_start) is
            // attacker-influenced input until the signature over its canonical
            // digest is verified.
            let envelope_pk: mosaic_keyvault::multicipher::MPublicKey = smt
                .signed_envelope
                .signature
                .public_key
                .parse()
                .map_err(|_| VerificationError::EnvelopeSignatureInvalid)?;
            let envelope_sig: mosaic_keyvault::multicipher::MSignature = smt
                .signed_envelope
                .signature
                .bytes
                .parse()
                .map_err(|_| VerificationError::EnvelopeSignatureInvalid)?;
            let content_digest = json_digest::digest_data(&smt.signed_envelope.content)
                .map_err(|e| VerificationError::DigestError(e.to_string()))?;
            use mosaic_keyvault::PublicKey as _;
            if !envelope_pk.verify(content_digest.as_bytes(), &envelope_sig) {
                return Err(VerificationError::EnvelopeSignatureInvalid);
            }
            steps.push(StepResult { step: "envelope_signature", passed: true, detail: None });

            // --- Holder binding (iop-rs#2) ---
            // The envelope must be signed by the presenter's own key; a
            // validly-signed envelope from any other key is a replay, not a
            // proof about this holder.
            if envelope_pk.key_id() != holder_key.key_id() {
                return Err(VerificationError::EnvelopeKeyMismatch);
            }
            steps.push(StepResult { step: "envelope_holder_binding", passed: true, detail: None });

            let fingerprint = json_digest::digest_data(&smt.signed_envelope)
                .map_err(|e| VerificationError::DigestError(e.to_string()))?;
            if fingerprint != smt.inclusion_proof.leaf_hash.as_str() {
                return Err(VerificationError::SmtInclusionProofFailed);
            }
            steps.push(StepResult { step: "smt_leaf_hash_match", passed: true, detail: None });

            let recomputed_root = smt.inclusion_proof.compute_root();
            if recomputed_root.as_str() != smt.before_proof_content_id {
                return Err(VerificationError::SmtInclusionProofFailed);
            }
            steps.push(StepResult { step: "smt_root_match", passed: true, detail: None });

            // Extract H_start from the AfterProof inside the signed envelope.
            // This overrides any explicit with_after_proof.
            let ap_height = smt.signed_envelope.content.proof.block_height;
            h_start = ap_height + 1;
        }

        // Apply received_at soft cap.
        if let Some(rcv) = received_at {
            if let Some(ref mut end) = h_end {
                if rcv < *end {
                    *end = rcv;
                }
            } else {
                h_end = Some(rcv);
            }
        }

        // Window sanity: H_start < H_end when both are set.
        if let Some(end) = h_end
            && h_start >= end
        {
            return Err(VerificationError::WindowBoundsInvalid);
        }

        let win_detail = alloc::format!(
            "H_start={}, H_end={}",
            h_start,
            h_end.map_or("∞".to_string(), |e| e.to_string())
        );
        steps.push(StepResult { step: "window_bounds", passed: true, detail: Some(win_detail) });

        // --- Step 1: Liveness ---
        match history.check_liveness(h_start, h_end) {
            ValidityResult::Confirmed => {
                steps.push(StepResult { step: "did_liveness", passed: true, detail: None });
            }
            ValidityResult::Ambiguous { gaps } => {
                for g in &gaps {
                    issues.push(g.reason.clone());
                }
                steps.push(StepResult { step: "did_liveness", passed: true, detail: None });
            }
            ValidityResult::Absent => {
                return Err(VerificationError::DidDeactivated);
            }
        }

        // --- Step 2: Key validity ---
        let key_ref = KeyRef::new(holder_key.to_string().as_bytes().to_vec())
            .map_err(|_| VerificationError::KeyNotFound)?;
        match history.check_key_validity(&key_ref, h_start, h_end) {
            ValidityResult::Confirmed => {
                steps.push(StepResult { step: "key_validity", passed: true, detail: None });
            }
            ValidityResult::Ambiguous { gaps } => {
                for g in &gaps {
                    issues.push(g.reason.clone());
                }
                steps.push(StepResult { step: "key_validity", passed: true, detail: None });
            }
            ValidityResult::Absent => {
                return Err(VerificationError::KeyNotFound);
            }
        }

        // --- Step 3: Right (union of on-chain + off-chain + implicit) ---
        let right_enum: Right = right.parse().map_err(|_| VerificationError::RightNotGranted)?;
        match history
            .verify_right_window(&key_ref, right_enum, h_start, h_end, rights_documents)
            .map_err(map_commitment_document_error)?
        {
            ValidityResult::Confirmed => {
                steps.push(StepResult { step: "right", passed: true, detail: None });
            }
            ValidityResult::Ambiguous { gaps } => {
                for g in &gaps {
                    issues.push(g.reason.clone());
                }
                steps.push(StepResult { step: "right", passed: true, detail: None });
            }
            ValidityResult::Absent => {
                return Err(VerificationError::RightNotGranted);
            }
        }

        // --- Step 4: Proof strength classification ---
        let achieved = if smt_envelope.is_some() {
            ProofStrength::Finalized
        } else if after_proof.is_some() || before_proof.is_some() {
            ProofStrength::AfterProof
        } else {
            ProofStrength::Minimal
        };
        steps.push(StepResult {
            step: "proof_strength",
            passed: true,
            detail: Some(alloc::format!("{achieved:?}")),
        });

        // --- Policy gate ---
        if let Some(policy) = policy {
            policy.check(achieved)?;
        }
        steps.push(StepResult { step: "policy_gate", passed: true, detail: None });

        Ok(VerificationResult { valid: true, strength: achieved, issues, steps })
    }
}

impl DidDocument {
    /// Verify that `holder_key` has `right` at the document's resolution height.
    ///
    /// Builds a minimal [`DidHistory`] from this document's snapshot and
    /// delegates to the full three-outcome verifier. Because the `DidDocument`
    /// is a point-in-time snapshot without lifecycle information or validated
    /// proofs, the result is always at most [`ProofStrength::Minimal`].
    ///
    /// `rights_documents` are the presenter-supplied off-chain rights documents.
    ///
    /// # Errors
    ///
    /// This builds the history from the document snapshot, so a malformed
    /// `id`, `contentId`, `publishedBy` or publication height is reported as
    /// its own [`VerificationError`] rather than being replaced by a substitute
    /// value or collapsed into [`VerificationError::KeyNotFound`]. The snapshot
    /// is untrusted input from the commitment service endpoint.
    pub fn verify_right(
        &self, holder_key: &Authentication, right: &str, rights_documents: &RightsDocumentSet<'_>,
    ) -> Result<VerificationResult, VerificationError> {
        let at_height = self.last_modified_at_height.unwrap_or(0);
        let history = DidHistory::from_did_document_at(self, at_height)
            .map_err(map_history_from_document_error)?;

        history.check_right(holder_key, right).with_documents(rights_documents).verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{
        DID_DOCUMENT_MOSAIC_CONTEXT, DID_DOCUMENT_W3C_CONTEXT, DidDocument, DidDocumentService,
        DidDocumentVerificationMethod,
    };
    use crate::ed25519_blake3_signature;
    use crate::rights::{
        ContentHashAlgorithm, RIGHTS_DOCUMENT_V1_SCHEMA, RightsDocument, UnsafeRightsDocument,
    };
    use crate::signed::{AfterEnvelope, AfterProof, Signed, SmtContent};
    use crate::smt;

    fn make_test_document() -> DidDocument {
        let key_ref = "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";
        let did = "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";
        DidDocument {
            context: alloc::vec![
                DID_DOCUMENT_W3C_CONTEXT.into(),
                DID_DOCUMENT_MOSAIC_CONTEXT.into(),
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

    fn make_rights_doc(seq: u64, previous: Option<ContentId>, right: &str) -> RightsDocument {
        let kid: mosaic_keyvault::multicipher::MKeyId =
            "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb".parse().unwrap();
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb".into(),
            sequence: seq,
            previous_commitment: previous,
            hash_algorithm: ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![crate::rights::UnsafeRightEntry {
                key: kid.to_string(),
                rights: alloc::vec![right.into()],
            }],
        };
        raw.try_into().expect("test rights doc should be valid")
    }

    fn set_timeline(doc: &mut DidDocument, versions: &[(u64, &str)]) {
        let items: Vec<serde_json::Value> = versions
            .iter()
            .enumerate()
            .map(|(index, (seq, hash))| {
                serde_json::json!({
                    "sequence": seq,
                    "contentId": hash,
                    "publishedAtHeight": seq * 100,
                    "publishedBy": "#iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb",
                    // The helper builds complete timelines: the first entry
                    // anchors the chain, every later one links.
                    "chainLink": if index == 0 { "anchor" } else { "linked" },
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
        let result = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Minimal);
    }

    #[test]
    fn verify_right_with_key_not_in_document() {
        let doc = make_test_document();
        let err = doc.verify_right(&test_other_key(), "impersonate", &empty_docs()).unwrap_err();
        assert_eq!(err, VerificationError::KeyNotFound);
    }

    // ===== Snapshot error mapping =====
    //
    // `verify_right` builds the history from the DID document snapshot, and the
    // commitment service endpoint inside it is untrusted input. Each way the
    // snapshot can be wrong is reported as itself, so a malformed endpoint is
    // never reported as a missing holder key.

    #[test]
    fn verify_right_reports_unparseable_content_id() {
        let mut doc = make_test_document();
        set_timeline(&mut doc, &[(1, "cmNOT-A-VALID-CONTENT-ID")]);

        let err = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidContentId(_)),
            "an unparseable contentId must be reported, got {err:?}"
        );
    }

    #[test]
    fn verify_right_reports_invalid_document_did() {
        let mut doc = make_test_document();
        doc.id = "not-a-did".into();

        let err = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidDid(_)),
            "an unparseable document id must be reported, got {err:?}"
        );
    }

    #[test]
    fn verify_right_reports_snapshot_after_requested_height() {
        let mut doc = make_test_document();
        doc.created_at_height = Some(200);

        let err = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap_err();
        assert!(
            matches!(
                err,
                VerificationError::CommitmentAfterHeight {
                    published_at_height: 200,
                    at_height: 100,
                    ..
                }
            ),
            "a snapshot from after the requested height must be reported, got {err:?}"
        );
    }

    #[test]
    fn verify_right_reports_invalid_signer_key_ref() {
        let mut doc = make_test_document();
        let cid = ContentId::structured_blake3([1u8; 32]).to_string();
        set_timeline(&mut doc, &[(1, cid.as_str())]);
        doc.service[0].service_endpoint["versions"][0]["publishedBy"] =
            serde_json::json!(alloc::format!("#{}", "a".repeat(65)));

        let err = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap_err();
        assert!(
            matches!(err, VerificationError::InvalidSignerKeyRef { sequence: 1 }),
            "an oversized publishedBy must be reported, got {err:?}"
        );
    }

    #[test]
    fn verify_right_with_on_chain_impersonate() {
        let doc = make_test_document();
        let result = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn verify_right_with_deactivated_did() {
        let mut doc = make_test_document();
        doc.deactivated = true;
        doc.tombstoned_at_height = Some(50);
        let err = doc.verify_right(&test_key(), "impersonate", &empty_docs()).unwrap_err();
        assert_eq!(err, VerificationError::DidDeactivated);
    }

    #[test]
    fn verify_right_rejected_when_right_not_in_on_chain_relationships() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        // "issue" is not among the default-key implicit rights
        // (update/impersonate/delegate), so its rejection isolates the
        // on-chain-relationship check.
        let err = doc.verify_right(&test_key(), "issue", &empty_docs()).unwrap_err();
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

        let result = doc.verify_right(&test_key(), "impersonate", &docs(&[&rights_doc])).unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Minimal);
    }

    #[test]
    fn did_document_off_chain_with_commitment_document_passes() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        let rights_doc = make_rights_doc(1, None, "impersonate");
        let hash = rights_doc.compute_hash().unwrap();
        set_timeline(&mut doc, &[(1, &hash)]);

        let result = doc.verify_right(&test_key(), "impersonate", &docs(&[&rights_doc])).unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Minimal);
        // Key 'added' at height 10, commitment at 100 → gaps [0,10) and [0,100)
        assert!(result.issues.iter().any(|i| i.contains("absent [0, 10)")));
        assert!(result.issues.iter().any(|i| i.contains("absent [0, 100)")));
    }

    #[test]
    fn did_document_off_chain_wrong_right_not_granted() {
        let mut doc = make_test_document();
        doc.assertion_method.clear();
        // Grants "impersonate", queries "issue" — a right with no implicit
        // default-key grant, so rejection isolates the commitment check.
        let rights_doc = make_rights_doc(1, None, "impersonate");
        let hash = rights_doc.compute_hash().unwrap();
        set_timeline(&mut doc, &[(1, &hash)]);

        let err = doc.verify_right(&test_key(), "issue", &docs(&[&rights_doc])).unwrap_err();
        assert_eq!(err, VerificationError::RightNotGranted);
    }

    // ===== Windowed verification helpers =====

    /// A test key reference reused across windowed tests.
    const TEST_KEY_REF: &str = "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";
    /// A test DID reused across windowed tests.
    const TEST_DID_STR: &str = "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb";

    /// A lazily-parsed test authentication key.
    fn test_key() -> Authentication {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb".parse().unwrap();
        Authentication::KeyId(kid)
    }

    /// A different valid key not present in test documents.
    fn test_other_key() -> Authentication {
        use mosaic_keyvault::multicipher::MKeyId;
        let kid: MKeyId = "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse().unwrap();
        Authentication::KeyId(kid)
    }

    fn history_with_key(
        key_added_at: u32, revoked_at: Option<u32>, expires_at: Option<u32>,
    ) -> DidHistory {
        DidHistory {
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: KeyRef::new(TEST_KEY_REF.as_bytes().to_vec()).unwrap(),
                key_type: crate::operation::KeyType::Ed25519,
                controller: crate::did::Did::from_did_string(TEST_DID_STR).unwrap(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: key_added_at,
                expires_at_height: expires_at,
                revoked_at_height: revoked_at,
                nonce: 0,
            }],
            ..DidHistory::new(crate::did::Did::from_did_string(TEST_DID_STR).unwrap())
        }
    }

    /// An empty presentation.
    fn empty_docs() -> RightsDocumentSet<'static> {
        RightsDocumentSet::new(alloc::vec![]).expect("empty set is valid")
    }

    /// A presentation built from documents already in ascending sequence order.
    fn docs<'a>(docs: &[&'a RightsDocument]) -> RightsDocumentSet<'a> {
        RightsDocumentSet::new(docs.to_vec()).expect("strictly increasing sequences")
    }

    fn add_commitment(mut history: DidHistory, seq: u64, at_height: u32) -> DidHistory {
        use crate::history::ChainLink;
        let chain_link =
            if history.commitments.is_empty() { ChainLink::Anchor } else { ChainLink::Linked };
        history.commitments.push(crate::history::CommitmentVersion {
            sequence: seq,
            commitment: crate::did::ContentId::from_bytes(b"placeholder"),
            published_at_height: at_height,
            signer_key_ref: KeyRef::new(TEST_KEY_REF.as_bytes().to_vec()).unwrap(),
            chain_link,
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
        // AfterProof at block 99 → H_start = 100, received_at = 200 → H_end = 200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let after = ValidatedAfterProof { block_height: 99 };
        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(after)
            .with_received_at(200)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::AfterProof);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn after_proof_key_added_after_h_start_ambiguous() {
        // Key added at height 120. H_start = 100 (AfterProof block 99+1).
        // Window [100, 200): key absent [100, 120), valid [120, 200) → Ambiguous.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(120, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let after = ValidatedAfterProof { block_height: 99 };
        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(after)
            .with_received_at(200)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert!(result.issues.iter().any(|i| i.contains("absent [100, 120)")));
    }

    #[test]
    fn after_proof_key_revoked_mid_window_ambiguous() {
        // Key added at 10, revoked at 150. Window [100, 200): valid [100, 150), absent [150, 200).
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, Some(150), None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let after = ValidatedAfterProof { block_height: 99 };
        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(after)
            .with_received_at(200)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert!(result.issues.iter().any(|i| i.contains("absent [150, 200)")));
    }

    #[test]
    fn after_proof_did_tombstoned_during_window_error() {
        // DID tombstoned at 180. Window [100, 200). Still an error (tombstone ⇒ Absent).
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let mut history = add_commitment(history_with_key(10, None, None), 1, 100);
        history = replace_commitment_hash(history, 1, cid);
        history.tombstoned_at = Some(180);

        let after = ValidatedAfterProof { block_height: 99 };
        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(after)
            .with_received_at(200)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::DidDeactivated);
    }

    #[test]
    fn after_proof_commitment_omits_right_mid_window_ambiguous() {
        // D1 at 100 grants impersonate, D2 at 150 grants issue (no impersonate).
        // Window [100, 180): right absent [150, 180) → Ambiguous.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid1: ContentId = d1.compute_content_id().unwrap();
        let d2 = make_rights_doc(2, Some(cid1), "issue");
        let cid2: ContentId = d2.compute_content_id().unwrap();

        let history = history_with_key(10, None, None);
        let history = add_commitment(history, 1, 100);
        let history = replace_commitment_hash(history, 1, cid1);
        let history = add_commitment(history, 2, 150);
        let history = replace_commitment_hash(history, 2, cid2);

        let after = ValidatedAfterProof { block_height: 99 };
        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1, &d2]))
            .with_after_proof(after)
            .with_received_at(180)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert!(result.issues.iter().any(|i| i.contains("absent [150, 180)")));
    }

    #[test]
    fn after_proof_no_commitment_at_h_start_error() {
        // Commitment at height 100, window [50, 80). No commitment active → Absent.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let after = ValidatedAfterProof { block_height: 49 };
        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(after)
            .with_received_at(80)
            .verify()
            .unwrap_err();
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
    fn verify_right_policy_rejects_when_below_minimum() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);
        let policy = VerifierPolicy::notarization(); // requires Finalized

        // No proofs → achieved = Minimal → below Finalized minimum.
        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_policy(&policy)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::InsufficientProofStrength);
    }

    #[test]
    fn verify_right_policy_accepts_when_meets_minimum() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);
        let policy = VerifierPolicy::chat(); // accepts Minimal

        // No proofs → achieved = Minimal → meets chat minimum.
        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_policy(&policy)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Minimal);
    }

    // ===== FinalizedProof tests =====

    /// RFC 8032 §7.1 test vector 1 Ed25519 seed — the key behind
    /// [`TEST_KEY_REF`] / [`TEST_DID_STR`]. A well-known test constant, not a
    /// secret.
    const ED25519_TV1_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// Build a `Signed<AfterEnvelope<SmtContent>>` properly signed by the
    /// holder's own key (required since the iop-rs#2 fix — signature over the
    /// canonical envelope digest, holder key-id binding).
    fn make_signed_envelope(
        after_block_height: u32, smt_root: &str,
    ) -> Signed<AfterEnvelope<SmtContent>> {
        use mosaic_keyvault::PrivateKey;
        use mosaic_keyvault::ed25519::EdPrivateKey;
        use mosaic_keyvault::multicipher::MSignature;

        let content = SmtContent { root: smt_root.into(), height: 10 };
        let proof = AfterProof {
            block_height: after_block_height,
            block_hash: "0x0400000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let envelope = AfterEnvelope { content, proof };

        let sk = EdPrivateKey::from_bytes(ED25519_TV1_SK).unwrap();
        let mpk = crate::signature::public_key_from_key_type(
            crate::operation::KeyType::Ed25519,
            &sk.public_key().to_bytes(),
        )
        .unwrap();
        let digest = json_digest::digest_data(&envelope).unwrap();
        let sig = sk.sign(digest.as_bytes());
        Signed::new(envelope, alloc::format!("{mpk}"), &MSignature::Ed25519Blake3(sig))
    }

    #[test]
    fn finalized_proof_happy_path() {
        // Key at 10, commitment at 50 grants impersonate.
        // AfterProof in envelope at 120 → H_start=121, validated BeforeProof at 200 → H_end=200.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 50);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(120, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash.clone());
        let root = trie.root().clone();
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: root.as_str().to_string(),
        };

        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(ValidatedAfterProof { block_height: 120 })
            .with_before_proof(ValidatedBeforeProof { block_height: 200 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.strength, ProofStrength::Finalized);
        assert!(result.steps.iter().any(|s| s.step == "envelope_signature" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "envelope_holder_binding" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "smt_leaf_hash_match" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "smt_root_match" && s.passed));
        assert!(result.steps.iter().any(|s| s.step == "window_bounds" && s.passed));
    }

    /// iop-rs#2 pin: an all-zero (forged) envelope signature is rejected
    /// before any timeline fact is trusted.
    #[test]
    fn finalized_proof_rejects_forged_envelope_signature() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 50);
        let history = replace_commitment_hash(history, 1, cid);

        // Well-formed envelope, attacker-controlled signature material.
        let mut signed = make_signed_envelope(120, "unused-root");
        signed.signature.public_key = "pezFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z".into();
        signed.signature.bytes = alloc::format!("{}", ed25519_blake3_signature([0u8; 64]));

        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let inclusion_proof = trie.inclusion_proof(0).unwrap();
        let root = trie.root().clone();
        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(ValidatedAfterProof { block_height: 120 })
            .with_before_proof(ValidatedBeforeProof { block_height: 200 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::EnvelopeSignatureInvalid);
    }

    /// iop-rs#2 pin: a validly-signed envelope from a key other than the
    /// holder's is a replay, not a proof about this holder.
    #[test]
    fn finalized_proof_rejects_envelope_signed_by_other_key() {
        use mosaic_keyvault::PrivateKey;
        use mosaic_keyvault::ed25519::EdPrivateKey;
        use mosaic_keyvault::multicipher::MSignature;

        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 50);
        let history = replace_commitment_hash(history, 1, cid);

        // RFC 8032 §7.1 test vector 2 — a different, valid key.
        const ED25519_TV2_SK: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let bob_sk = EdPrivateKey::from_bytes(ED25519_TV2_SK).unwrap();

        let content = SmtContent { root: "unused-root".into(), height: 10 };
        let proof = AfterProof {
            block_height: 120,
            block_hash: "0x0400000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let envelope = AfterEnvelope { content, proof };
        let digest = json_digest::digest_data(&envelope).unwrap();
        let sig = bob_sk.sign(digest.as_bytes());
        let bob_mpk = crate::signature::public_key_from_key_type(
            crate::operation::KeyType::Ed25519,
            &bob_sk.public_key().to_bytes(),
        )
        .unwrap();
        let signed =
            Signed::new(envelope, alloc::format!("{bob_mpk}"), &MSignature::Ed25519Blake3(sig));

        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let inclusion_proof = trie.inclusion_proof(0).unwrap();
        let root = trie.root().clone();
        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(ValidatedAfterProof { block_height: 120 })
            .with_before_proof(ValidatedBeforeProof { block_height: 200 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::EnvelopeKeyMismatch);
    }

    #[test]
    fn finalized_proof_fails_when_smt_leaf_hash_mismatch() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(90, "unused-root");
        // SMT with wrong leaf (not the signed envelope).
        let wrong_leaf = smt::Hash::from_digest("cmWRONG_LEAF_HASH_000000000000000000".into());
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, wrong_leaf);
        let inclusion_proof = trie.inclusion_proof(0).unwrap();
        let root = trie.root().clone();

        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(ValidatedAfterProof { block_height: 90 })
            .with_before_proof(ValidatedBeforeProof { block_height: 200 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::SmtInclusionProofFailed);
    }

    #[test]
    fn finalized_proof_fails_when_smt_root_mismatch() {
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(90, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let inclusion_proof = trie.inclusion_proof(0).unwrap();
        // Valid SMT proof, but claim wrong before_proof_content_id → root mismatch.

        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: "cmWRONG_ROOT_0000000000000000000000000000".into(),
        };

        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(ValidatedAfterProof { block_height: 90 })
            .with_before_proof(ValidatedBeforeProof { block_height: 200 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::SmtInclusionProofFailed);
    }

    #[test]
    fn finalized_proof_rejects_impossible_upper_bound() {
        // AfterProof at 200 → H_start=201, validated BeforeProof at 100 → H_end=100.
        // H_start > H_end → rejected.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid: ContentId = d1.compute_content_id().unwrap();
        let history = add_commitment(history_with_key(10, None, None), 1, 100);
        let history = replace_commitment_hash(history, 1, cid);

        let signed = make_signed_envelope(200, "unused-root");
        let fingerprint = json_digest::digest_data(&signed).unwrap();
        let leaf_hash = smt::Hash::from_digest(fingerprint);
        let mut trie = smt::SparseMerkleTrie::new();
        trie.insert(0, leaf_hash);
        let root = trie.root().clone();
        let inclusion_proof = trie.inclusion_proof(0).unwrap();

        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: root.as_str().to_string(),
        };

        let err = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1]))
            .with_after_proof(ValidatedAfterProof { block_height: 200 })
            .with_before_proof(ValidatedBeforeProof { block_height: 100 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap_err();
        assert_eq!(err, VerificationError::WindowBoundsInvalid);
    }

    #[test]
    fn finalized_proof_commitment_omission_mid_window_ambiguous() {
        // D1 at 100 grants impersonate, D2 at 150 grants issue (no impersonate).
        // Window [91, 200): absent [150, 200) → Ambiguous.
        let d1 = make_rights_doc(1, None, "impersonate");
        let cid1: ContentId = d1.compute_content_id().unwrap();
        let d2 = make_rights_doc(2, Some(cid1), "issue");
        let cid2: ContentId = d2.compute_content_id().unwrap();

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

        let smt = SmtEnvelopeProof {
            signed_envelope: signed,
            inclusion_proof,
            before_proof_content_id: root.as_str().to_string(),
        };

        let result = history
            .check_right(&test_key(), "impersonate")
            .with_documents(&docs(&[&d1, &d2]))
            .with_after_proof(ValidatedAfterProof { block_height: 90 })
            .with_before_proof(ValidatedBeforeProof { block_height: 200 })
            .with_smt_envelope(smt)
            .verify()
            .unwrap();
        assert!(result.valid);
        assert!(result.issues.iter().any(|i| i.contains("absent [150, 200)")));
        assert_eq!(result.strength, ProofStrength::Finalized);
    }
}
