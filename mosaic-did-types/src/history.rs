//! DID history reconstruction from the event stream.
//!
//! `DidHistory` is the authoritative data structure for reconstructing DID
//! state from the event stream. It lives in `mosaic-did-types` — all fields
//! use concrete types from that crate, so it compiles under `no_std` with
//! no pallet dependency.
//!
//! The indexer consumes SCALE-encoded chain events and delegates to `DidHistory`.
//! This module itself is a pure data type — it has no knowledge of SCALE encoding,
//! Substrate RPCs, or block subscriptions.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::did::{ContentId, Did, KeyRef};
use crate::document::{
    DID_DOCUMENT_MOSAIC_CONTEXT, DID_DOCUMENT_W3C_CONTEXT, w3c_type_to_key_type,
};
use crate::operation::{KeyType, Right};
use crate::rights::{RightsDocumentSet, UnsafeRightsDocument};

/// Schema URI for V1 DID history wire format.
pub const DID_HISTORY_V1_SCHEMA: &str = "https://mosaic-trust.net/ns/did-history/v1";

/// Validates the `$schema` field during deserialization.
///
/// Serialization always writes [`DID_HISTORY_V1_SCHEMA`], so only this value
/// (and only this value) is accepted on deserialization. Empty or unrecognised
/// schema URIs are rejected with a deserialization error.
fn validate_schema<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    use alloc::string::String;
    use serde::{Deserialize, de::Error};
    let s = String::deserialize(d)?;
    if s == DID_HISTORY_V1_SCHEMA {
        Ok(s)
    } else if s.is_empty() {
        Err(D::Error::custom("empty $schema, expected DID history v1"))
    } else {
        Err(D::Error::custom(alloc::format!("unsupported $schema version: {s}")))
    }
}

/// A commitment version in the DID history, reconstructed from events.
///
/// Serialized camelCase to match the commitment service inside a DID document,
/// which spells the same concepts `contentId` / `publishedAtHeight` /
/// `publishedBy`. The service is hand-built from these values, so the two
/// representations must not drift.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitmentVersion {
    /// Monotonic sequence number (gapless, starting at 1).
    pub sequence: u64,
    /// The commitment hash (blake3 of the canonicalized rights document).
    pub commitment: ContentId,
    /// Block height at which this commitment was published on-chain.
    pub published_at_height: u32,
    /// Key reference of the signer who published this commitment.
    pub signer_key_ref: KeyRef,
    /// Whether this commitment starts a fresh document chain.
    ///
    /// `true` for the first commitment and for every commitment published via
    /// `CommitmentReset`, which restarts the chain while the sequence counter
    /// keeps running (resets are gapless too). The document at a chain start
    /// must carry **no** `previous_commitment`; every other document must carry
    /// its predecessor's content ID exactly.
    ///
    /// Defaults to `false` when absent from a serialized history. A reset
    /// buried in a history without this field is then reported as
    /// [`CommitmentDocumentError::ChainBroken`], so a chain link is never left
    /// unchecked.
    ///
    /// The one exception is the first *visible* entry of a truncated snapshot
    /// (a `from_height` window that dropped its predecessors). It is flagged
    /// `false` because it genuinely is not a chain start, yet its predecessor
    /// is outside the window: its linkage is unknown, and verification skips
    /// only that one link rather than rejecting the timeline.
    #[serde(default)]
    pub chain_start: bool,
}

/// On-chain right grant with full lifecycle information.
///
/// Similar to `RightGrant` in `document.rs`, but used in the indexer context
/// where the full lifecycle (including revoked entries) is preserved for
/// historical reconstruction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RightLifecycle {
    /// The key this right is granted to.
    pub key_ref: KeyRef,
    /// The right granted.
    pub right: Right,
    /// Block height at which the right was granted.
    pub granted_at_height: u32,
    /// Optional block height at which the right grant expires.
    pub expires_at_height: Option<u32>,
    /// Block height at which this right was revoked (None if still active).
    pub revoked_at_height: Option<u32>,
    /// Block height at which this right becomes exercisable.
    /// None means immediate maturity (used for implicit initial key rights).
    pub matures_at_height: Option<u32>,
}

impl RightLifecycle {
    /// Returns whether this right grant is active and matured at the given height.
    #[inline]
    pub fn is_active_at(&self, height: u32) -> bool {
        height >= self.granted_at_height
            && self.revoked_at_height.is_none_or(|h| height < h)
            && self.expires_at_height.is_none_or(|h| height < h)
            && self.matures_at_height.is_none_or(|m| height >= m)
    }
}

/// The complete commitment timeline for one DID, reconstructed from events.
///
/// This type is direction-agnostic: the same type and its query methods
/// (`commitment_at`, `valid_keys_at`, `has_right_at`) work identically
/// regardless of how events were collected:
/// - **Forward (indexer):** consume the full event stream chronologically.
/// - **Backward (light client):** start from a proven `DidState`, walk backwards
///   through `previous_version_id` pointers, collect events in reverse, call
///   `.reverse()`, then apply in forward order.
///
/// Both paths produce equivalent results for the same `[H_start, H_end]` range.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DidHistory {
    /// Schema identifier for versioning. Serialized as `"$schema"`.
    #[serde(rename = "$schema", deserialize_with = "validate_schema")]
    pub schema: String,
    /// The DID this history describes.
    pub did: Did,
    /// Ordered commitment versions (oldest first).
    pub commitments: Vec<CommitmentVersion>,
    /// All keys ever added to this DID, with their lifecycle events.
    /// Uses `crate::state::VerificationMethod` which already carries
    /// the full key lifecycle (added_at_height, revoked_at_height, expires_at_height).
    pub keys: Vec<crate::state::VerificationMethod>,
    /// On-chain right grants with lifecycle.
    pub rights: Vec<RightLifecycle>,
    /// The tombstone block, if any.
    pub tombstoned_at: Option<u32>,
}

/// A DID-history event — the `no_std` equivalent of the pallet's SCALE events.
///
/// Each variant carries the block height at which it occurred (`at_height`).
/// Events are collected into `Vec<DidHistoryEvent>` (forward from an indexer or
/// reverse-walked then `.reverse()`d from the pointer chain) and applied via
/// `DidHistory::apply()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidHistoryEvent {
    /// A key was added to the DID document.
    KeyAdded {
        key_ref: KeyRef,
        key_type: KeyType,
        controller: Did,
        public_key: Vec<u8>,
        at_height: u32,
        expires_at_height: Option<u32>,
    },
    /// A key was revoked.
    KeyRevoked { key_ref: KeyRef, at_height: u32 },
    /// An on-chain right was granted.
    RightAdded {
        key_ref: KeyRef,
        right: Right,
        at_height: u32,
        matures_at_height: Option<u32>,
        expires_at_height: Option<u32>,
    },
    /// An on-chain right was revoked.
    RightRevoked { key_ref: KeyRef, right: Right, at_height: u32 },
    /// A rights-document commitment was published on-chain.
    CommitmentUpdated {
        sequence: u64,
        commitment: ContentId,
        signer_key_ref: KeyRef,
        at_height: u32,
    },
    /// A governed `CommitmentReset` took effect, restarting the document chain.
    ///
    /// The pallet emits its own `CommitmentReset` event for this — not
    /// `CommitmentUpdated` — because reset sequences stay gapless and only the
    /// event kind identifies the restart. An indexer maps that event to this
    /// variant, so the post-reset commitment is visible in the timeline and the
    /// document published at it is expected to carry no predecessor.
    CommitmentReset { sequence: u64, commitment: ContentId, signer_key_ref: KeyRef, at_height: u32 },
    /// The DID was permanently deactivated.
    DidTombstoned { at_height: u32 },
}

/// Resolves a `ContentId` to the full off-chain rights document.
///
/// In practice, the presenter provides the document (or Merkle-proof
/// subset) in the Verifiable Presentation. The verifier checks the
/// hash/Merkle proof against the on-chain commitment root. The trait
/// exists for testing and for the rare case where a DID controller
/// intentionally publishes the rights document publicly.
pub trait CommitmentResolver {
    /// Resolve a content ID to the full rights document.
    fn resolve(&self, content_id: &ContentId) -> Option<UnsafeRightsDocument>;
}

/// Why a DID document snapshot could not be turned into a history.
///
/// A snapshot arrives from the commitment service endpoint, which is untrusted
/// input, so every field it supplies is validated rather than substituted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HistoryFromDocumentError {
    /// The document ID is not a valid DID.
    #[error("DID document id is not a valid DID: {0}")]
    InvalidDid(#[source] crate::did::DidParseError),
    /// A `contentId` in the commitment service is not a valid content ID.
    #[error("commitment service returned an invalid contentId: {0}")]
    InvalidContentId(#[source] crate::did::ContentIdParseError),
    /// A commitment claims a publication height beyond the requested height.
    #[error(
        "commitment {sequence} claims publication at height {published_at_height}, \
         beyond the requested height {at_height}"
    )]
    CommitmentAfterHeight { sequence: u64, published_at_height: u32, at_height: u32 },
    /// A commitment names a `publishedBy` fragment that is not a valid key ref.
    #[error("commitment {0} names an invalid publisher key ref")]
    InvalidSignerKeyRef(u64),
}

/// A presenter-supplied rights document failed validation.
///
/// These are **not** "the right was not granted". Every variant describes a
/// document the presenter actually submitted and got wrong, so each is
/// reported rather than skipped: a malformed document, a document for the
/// wrong DID, and a broken chain link stay distinguishable from a document
/// that simply did not grant the right.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommitmentDocumentError {
    /// The document's content ID could not be computed.
    #[error("rights document digest failed: {0}")]
    Digest(#[source] crate::rights::ContentIdError),
    /// The document belongs to a different DID than the history being verified.
    #[error("rights document is for {document_did} but was presented against {history_did}")]
    ForeignDid { document_did: Did, history_did: Did },
    /// The document's `previous_commitment` does not link to the timeline.
    ///
    /// At a chain start the document must carry no `previous_commitment`;
    /// anywhere else it must carry the immediately preceding commitment.
    #[error("rights document at sequence {sequence} does not link to the preceding commitment")]
    ChainBroken { sequence: u64 },
    /// The on-chain commitment uses a hashing algorithm this build cannot verify.
    ///
    /// Distinct from a hash mismatch: no document can ever match this
    /// commitment, so the timeline is unverifiable rather than merely
    /// unproven. Reported when an old build reads a commitment published under
    /// a newer runtime's algorithm.
    #[error(
        "commitment at sequence {sequence} uses hashing algorithm not supported by this build: \
         {content_id}"
    )]
    UnsupportedAlgorithm { sequence: u64, content_id: ContentId },
}

impl DidHistory {
    /// Create an empty history for the given DID.
    pub fn new(did: Did) -> Self {
        Self {
            schema: DID_HISTORY_V1_SCHEMA.into(),
            did,
            commitments: Vec::new(),
            keys: Vec::new(),
            rights: Vec::new(),
            tombstoned_at: None,
        }
    }

    /// Apply a single history event to this DID's timeline.
    ///
    /// Events are applied in chronological order (oldest first). Both the
    /// forward (indexer) and backward (light-client) paths produce events in
    /// this order before calling `apply`.
    pub fn apply(&mut self, event: DidHistoryEvent) {
        match event {
            DidHistoryEvent::KeyAdded {
                key_ref,
                key_type,
                controller,
                public_key,
                at_height,
                expires_at_height,
            } => {
                let vm = crate::state::VerificationMethod {
                    key_ref,
                    key_type,
                    controller,
                    public_key: public_key.try_into().expect("public key fits in bounded vec"),
                    added_at_height: at_height,
                    expires_at_height,
                    revoked_at_height: None,
                };
                self.keys.push(vm);
            }
            DidHistoryEvent::KeyRevoked { key_ref, at_height } => {
                if let Some(key) = self
                    .keys
                    .iter_mut()
                    .find(|k| k.key_ref == key_ref && k.revoked_at_height.is_none())
                {
                    key.revoked_at_height = Some(at_height);
                }
            }
            DidHistoryEvent::RightAdded {
                key_ref,
                right,
                at_height,
                matures_at_height,
                expires_at_height,
            } => {
                let rl = RightLifecycle {
                    key_ref,
                    right,
                    granted_at_height: at_height,
                    expires_at_height,
                    revoked_at_height: None,
                    matures_at_height,
                };
                self.rights.push(rl);
            }
            DidHistoryEvent::RightRevoked { key_ref, right, at_height } => {
                if let Some(rl) = self.rights.iter_mut().find(|r| {
                    r.key_ref == key_ref && r.right == right && r.revoked_at_height.is_none()
                }) {
                    rl.revoked_at_height = Some(at_height);
                }
            }
            DidHistoryEvent::CommitmentUpdated {
                sequence,
                commitment,
                signer_key_ref,
                at_height,
            } => {
                // A plain update starts a chain only when it is the first
                // commitment ever seen; later ones link to their predecessor.
                let chain_start = self.commitments.is_empty();
                let cv = CommitmentVersion {
                    sequence,
                    commitment,
                    published_at_height: at_height,
                    signer_key_ref,
                    chain_start,
                };
                self.commitments.push(cv);
            }
            DidHistoryEvent::CommitmentReset {
                sequence,
                commitment,
                signer_key_ref,
                at_height,
            } => {
                let cv = CommitmentVersion {
                    sequence,
                    commitment,
                    published_at_height: at_height,
                    signer_key_ref,
                    chain_start: true,
                };
                self.commitments.push(cv);
            }
            DidHistoryEvent::DidTombstoned { at_height } => {
                self.tombstoned_at = Some(at_height);
            }
        }
    }
    /// Find the commitment active at a given block height.
    ///
    /// Returns the most recent commitment whose `published_at_height <= height`,
    /// or `None` if no commitment was published before or at that height.
    pub fn commitment_at(&self, height: u32) -> Option<&CommitmentVersion> {
        self.commitments.iter().rev().find(|cv| cv.published_at_height <= height)
    }

    /// Return all keys valid at a given height.
    ///
    /// A key is valid if it was added at or before `height` and has not been
    /// revoked or expired by that height.
    pub fn valid_keys_at(&self, height: u32) -> Vec<&crate::state::VerificationMethod> {
        self.keys.iter().filter(|k| k.is_valid_at(height)).collect()
    }

    /// Check whether a key held a specific right at `height`.
    ///
    /// Union semantics (§3.7): checks on-chain `RightLifecycle` entries first,
    /// then falls through to the commitment document via the `CommitmentResolver`.
    pub fn has_right_at(
        &self, key_ref: &KeyRef, right: Right, height: u32,
        commitment_resolver: &dyn CommitmentResolver,
    ) -> bool {
        // Check 1: on-chain RightLifecycle (any right type)
        if self
            .rights
            .iter()
            .any(|rg| rg.key_ref == *key_ref && rg.right == right && rg.is_active_at(height))
        {
            return true;
        }

        // Check 2: commitment document (off-chain path). `grants_right`
        // parses both sides into `Authentication`, so it matches a
        // full-public-key entry against the bare key id exactly like the
        // validated path (`grants_right_by_key_ref`) does.
        if let Some(cv) = self.commitment_at(height)
            && let Some(doc) = commitment_resolver.resolve(&cv.commitment)
            && doc.grants_right(key_ref.as_str().unwrap_or(""), &right.to_string())
        {
            return true;
        }

        false
    }

    /// Check whether the DID was alive (not tombstoned) throughout the entire
    /// `[start, end]` range (both inclusive).
    ///
    /// Returns `false` if `start > end` or if the DID was tombstoned at a
    /// height ≤ `end`.
    pub fn is_alive_across(&self, start: u32, end: u32) -> bool {
        if start > end {
            return false;
        }
        // If tombstoned, the tombstone height must be strictly after `end`.
        self.tombstoned_at.is_none_or(|h| h > end)
    }

    /// Check whether `key_ref` was valid throughout the entire `[start, end]`
    /// range (both inclusive).
    ///
    /// A key is valid across the window if it was added at or before `start`
    /// and not revoked or expired before or at `end`.
    pub fn is_key_valid_across(&self, key_ref: &KeyRef, start: u32, end: u32) -> bool {
        if start > end {
            return false;
        }
        self.keys.iter().any(|k| {
            k.key_ref == *key_ref
                && k.added_at_height <= start
                && k.revoked_at_height.is_none_or(|h| h > end)
                && k.expires_at_height.is_none_or(|h| h > end)
        })
    }

    /// Check key validity across `[h_start, h_end)` producing a three-outcome
    /// [`ValidityResult`].
    ///
    /// - `h_start` is inclusive; `h_end` is exclusive (`None` = unbounded).
    /// - For zero-transaction DIDs, the default key (whose `key_ref` matches
    ///   `self.did.default_key_id`) is valid from height 0.
    /// - Once the DID is registered, lifecycle events in `self.keys` (add,
    ///   revoke, expire) govern the default key's validity like any other key.
    pub fn check_key_validity(
        &self, key_ref: &KeyRef, h_start: u32, h_end: Option<u32>,
    ) -> ValidityResult {
        // Default-key fast path only for zero-transaction DIDs (no key events).
        // Once the key appears in the event stream, lifecycle events (revocation,
        // expiry) take precedence.
        if self.keys.iter().any(|k| k.key_ref == *key_ref) {
            // Key has lifecycle events — fall through to normal interval logic.
        } else if self.is_default_key(key_ref) {
            return ValidityResult::Confirmed;
        }

        // Check regular keys from the event stream.
        if let Some(end) = h_end
            && h_start >= end
        {
            return ValidityResult::Absent;
        }

        let candidates: Vec<_> = self.keys.iter().filter(|k| k.key_ref == *key_ref).collect();

        if candidates.is_empty() {
            return ValidityResult::Absent;
        }

        // Collect all intervals where the key is valid, then compare against
        // [h_start, h_end) to produce Confirmed / Ambiguous / Absent.
        let mut valid_intervals = self.key_validity_intervals(key_ref);
        valid_intervals.normalize();

        // Constrain to the verification window.
        let constrained = valid_intervals.clamp(h_start, h_end);

        build_validity_result(&constrained, h_start, h_end)
    }

    /// Build a list of `[added, min(revoked, expired))` intervals for `key_ref`.
    ///
    /// Each key entry produces one interval. Call [`Intervals::normalize`] before
    /// querying if multiple sources are combined.
    fn key_validity_intervals(&self, key_ref: &KeyRef) -> Intervals {
        Intervals(
            self.keys
                .iter()
                .filter(|k| k.key_ref == *key_ref)
                .map(|k| {
                    let rev = k.revoked_at_height;
                    let exp = k.expires_at_height;
                    let end = match (rev, exp) {
                        (Some(r), Some(e)) => Some(r.min(e)),
                        (Some(r), None) => Some(r),
                        (None, Some(e)) => Some(e),
                        (None, None) => None,
                    };
                    (k.added_at_height, end)
                })
                .collect(),
        )
    }

    /// Returns `true` if `key_ref` is the default key of this DID
    /// (matches `self.did.default_key_id`).
    pub fn is_default_key(&self, key_ref: &KeyRef) -> bool {
        let kid_str = self.did.default_key_id.to_string();
        key_ref.as_str().is_some_and(|s| s == kid_str)
    }

    /// Check DID liveness across `[h_start, h_end)` producing a three-outcome
    /// [`ValidityResult`].
    ///
    /// Since tombstoning is permanent, the only possible outcomes are:
    /// - `Confirmed` — DID was alive throughout the entire window.
    /// - `Absent` — DID was dead at `h_start` or died during the window.
    pub fn check_liveness(&self, h_start: u32, h_end: Option<u32>) -> ValidityResult {
        let tomb = self.tombstoned_at;

        // Not tombstoned → alive forever.
        let Some(tomb_height) = tomb else {
            return ValidityResult::Confirmed;
        };

        let end = h_end.unwrap_or(u32::MAX);

        // Tombstoned before or at H_start → dead the whole window.
        if tomb_height <= h_start {
            return ValidityResult::Absent;
        }

        // Tombstoned during the window → alive [h_start, tomb_height), dead [tomb_height, ...).
        // Since tombstoning is permanent, this is Absent — the DID was not alive throughout.
        // We don't need Ambiguous because the DID being dead at any point in the window
        // means the claim is definitively invalid (you can't sign for a dead DID).
        if tomb_height < end {
            return ValidityResult::Absent;
        }

        // tomb_height >= end: DID alive throughout [h_start, h_end).
        ValidityResult::Confirmed
    }

    /// Check whether `key_ref` held `right` across `[h_start, h_end)`.
    ///
    /// Union semantics (§3.7): on-chain right grants, commitment documents, and
    /// implicit default-key rights are all checked. The right is held if ANY
    /// source grants it in a given sub-interval.
    ///
    /// Returns `Confirmed` if continuous, `Ambiguous` with gaps, or `Absent`.
    pub fn verify_right_window(
        &self, key_ref: &KeyRef, right: Right, h_start: u32, h_end: Option<u32>,
        documents: &RightsDocumentSet<'_>,
    ) -> Result<ValidityResult, CommitmentDocumentError> {
        let mut intervals = Intervals::new();

        // --- Check 1: on-chain RightLifecycle ---
        intervals.extend(self.right_validity_intervals(key_ref, right));

        // --- Check 2: commitment documents ---
        intervals.extend(self.commitment_right_intervals(key_ref, right, documents)?);

        // --- Check 3: implicit default-key rights ---
        if intervals.is_empty()
            && self.is_default_key(key_ref)
            && matches!(right, Right::Update | Right::Impersonate | Right::Delegate)
        {
            return Ok(ValidityResult::Confirmed);
        }

        // --- Normalize, clamp, compare ---
        intervals.normalize();
        let constrained = intervals.clamp(h_start, h_end);
        Ok(build_validity_result(&constrained, h_start, h_end))
    }

    /// Collect intervals where `key_ref` held `right` from on-chain grants.
    fn right_validity_intervals(&self, key_ref: &KeyRef, right: Right) -> Intervals {
        Intervals(
            self.rights
                .iter()
                .filter(|rl| rl.key_ref == *key_ref && rl.right == right)
                .map(|rl| {
                    let end = match (rl.revoked_at_height, rl.expires_at_height) {
                        (Some(r), Some(e)) => Some(r.min(e)),
                        (Some(r), None) => Some(r),
                        (None, Some(e)) => Some(e),
                        (None, None) => None,
                    };
                    (rl.granted_at_height, end)
                })
                .collect(),
        )
    }

    /// Collect intervals from commitment documents where `key_ref` held `right`.
    ///
    /// Each on-chain commitment is validated in four steps, and each has a
    /// distinct failure mode:
    ///
    /// 1. **Algorithm support.** A commitment whose algorithm this build cannot
    ///    verify is reported as [`CommitmentDocumentError::UnsupportedAlgorithm`].
    ///    It must not be treated as an ordinary mismatch, because no document
    ///    can ever match it and the timeline is therefore unverifiable.
    /// 2. **DID binding.** The document's own `did` must equal the history's.
    ///    The digest already implies this, so the check is redundant by
    ///    construction — it is made explicit because a claim about a DID is a
    ///    security statement, and deriving it from a hash alone means a future
    ///    narrowing of the preimage would remove the binding with no other
    ///    signal. See the `preimage_covers_*` tests in `rights.rs`.
    /// 3. **Hash binding.** The document's content ID must equal the on-chain
    ///    commitment. This is the core of the check: both sides of the
    ///    comparison are attacker-influenced, so a sequence number alone would
    ///    let a presenter graft arbitrary rights onto someone else's timeline.
    /// 4. **Chain linkage.** `previous_commitment` must name the immediately
    ///    preceding commitment, or be absent at a chain start. Without this,
    ///    each document is bound only to itself and supersession is unproven.
    ///
    /// A *missing* document is not an error: at `Minimal` strength a presenter
    /// legitimately sends only the versions they need.
    fn commitment_right_intervals(
        &self, key_ref: &KeyRef, right: Right, documents: &RightsDocumentSet<'_>,
    ) -> Result<Intervals, CommitmentDocumentError> {
        let right_str = right.to_string();
        let key_str = key_ref.as_str().unwrap_or("");
        let mut intervals = Intervals::new();

        for (index, cv) in self.commitments.iter().enumerate() {
            if !cv.commitment.is_supported_commitment_algorithm() {
                return Err(CommitmentDocumentError::UnsupportedAlgorithm {
                    sequence: cv.sequence,
                    content_id: cv.commitment,
                });
            }

            let Some(doc) = documents.get(cv.sequence) else {
                continue;
            };

            if doc.did() != &self.did {
                return Err(CommitmentDocumentError::ForeignDid {
                    document_did: doc.did().clone(),
                    history_did: self.did.clone(),
                });
            }

            let presented_cid =
                doc.compute_content_id().map_err(CommitmentDocumentError::Digest)?;
            if presented_cid != cv.commitment {
                continue;
            }

            // The flag is authoritative: a chain starts at the genuine first
            // commitment (marked in `apply`) or at a governed reset. Note the
            // condition reads *this* entry's flag, not the previous entry's:
            // after a reset at index N, index N+1 must link back to the reset
            // document.
            //
            // An unflagged first entry means the timeline is truncated before
            // the visible window (`to_did_document_at(_, Some(from_height))`):
            // its true predecessor is outside the snapshot, so the link cannot
            // be checked and is not required. Every later entry must link
            // exactly to its visible predecessor.
            let linked = if cv.chain_start {
                doc.previous_commitment().is_none()
            } else if index == 0 {
                true
            } else {
                doc.previous_commitment() == Some(&self.commitments[index - 1].commitment)
            };
            if !linked {
                return Err(CommitmentDocumentError::ChainBroken { sequence: cv.sequence });
            }

            if doc.grants_right_by_key_ref(key_str, &right_str) {
                let next = self
                    .commitments
                    .iter()
                    .find(|nc| nc.published_at_height > cv.published_at_height);
                let end = next.map(|nc| Some(nc.published_at_height)).unwrap_or_default();
                intervals.extend([(cv.published_at_height, end)]);
            }
        }

        Ok(intervals)
    }

    /// Produce a W3C-compliant DID Document at the given block height.
    ///
    /// All valid keys appear in `verificationMethod`. W3C verification
    /// relationships (`authentication`, `assertionMethod`, etc.) are derived
    /// from **on-chain rights only**. Off-chain rights (from the commitment
    /// document) must be checked separately by the verifier using the
    /// presenter-supplied rights document and the commitment service endpoint.
    ///
    /// If `from_height` is provided, the document is filtered to the window
    /// `[from_height, height]`:
    /// - Keys added after `from_height` or revoked/expired before it are excluded.
    /// - The commitment service carries the full timeline from the commit active
    ///   at `from_height` through the one at `height`.
    /// - `mosaic:lastModifiedAtHeight` is capped to the window.
    ///
    /// Keys with neither on-chain nor commitment rights are excluded entirely.
    pub fn to_did_document_at(
        &self, height: u32, from_height: Option<u32>,
    ) -> crate::document::DidDocument {
        use crate::document::{
            DidDocument, DidDocumentService, DidDocumentVerificationMethod, key_type_to_w3c_string,
            multibase_encode_key,
        };

        // Collect on-chain rights per key
        fn key_rights(key_ref: &KeyRef, rights: &[RightLifecycle], height: u32) -> Vec<Right> {
            rights
                .iter()
                .filter(|rl| rl.key_ref == *key_ref && rl.is_active_at(height))
                .map(|rl| rl.right)
                .collect()
        }

        // Determine the window.
        let window_start = from_height.unwrap_or(0);

        // Exclude keys with no on-chain rights.
        let valid_keys = self.valid_keys_at(height);

        // Filter keys: must be valid at `height`, and if `from_height` is given,
        // must have been added at or before `from_height` and not revoked/expired
        // before `from_height` (i.e. valid throughout the window).
        let righted_keys: Vec<_> = valid_keys
            .into_iter()
            .filter(|k| {
                if window_start > 0 {
                    k.added_at_height <= window_start
                        && k.revoked_at_height.is_none_or(|h| h > window_start)
                        && k.expires_at_height.is_none_or(|h| h > window_start)
                } else {
                    true
                }
            })
            .filter_map(|k| {
                let onchain = key_rights(&k.key_ref, &self.rights, height);
                if onchain.is_empty() { None } else { Some((k, onchain)) }
            })
            .collect();

        let did_string = self.did.to_did_string();

        let verification_methods: Vec<DidDocumentVerificationMethod> = righted_keys
            .iter()
            .map(|(k, _)| DidDocumentVerificationMethod {
                id: alloc::format!("{}#{}", did_string, k.key_ref),
                type_: key_type_to_w3c_string(k.key_type),
                controller: did_string.clone(),
                public_key_multibase: multibase_encode_key(&k.public_key),
            })
            .collect();

        // W3C relationships derived from on-chain rights
        let authentication: Vec<alloc::string::String> = righted_keys
            .iter()
            .filter(|(_, rs)| !rs.is_empty())
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();

        let assertion_method: Vec<alloc::string::String> = righted_keys
            .iter()
            .filter(|(_, rs)| rs.contains(&Right::Issue) || rs.contains(&Right::Impersonate))
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();

        let capability_invocation: Vec<alloc::string::String> = righted_keys
            .iter()
            .filter(|(_, rs)| rs.contains(&Right::Update))
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();

        let capability_delegation: Vec<alloc::string::String> = righted_keys
            .iter()
            .filter(|(_, rs)| rs.contains(&Right::Delegate))
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();

        // Commitment timeline: from the one active at window_start through height.
        let commitment_service = {
            let start_idx = self
                .commitments
                .iter()
                .rposition(|cv| cv.published_at_height <= window_start)
                .unwrap_or(0);

            let versions: Vec<_> = self.commitments[start_idx..]
                .iter()
                .take_while(|cv| cv.published_at_height <= height)
                .map(|cv| {
                    serde_json::json!({
                        "sequence": cv.sequence,
                        "contentId": cv.commitment.to_string(),
                        "publishedAtHeight": cv.published_at_height,
                        "publishedBy": alloc::format!("#{}", cv.signer_key_ref),
                        "chainStart": cv.chain_start,
                    })
                })
                .collect();

            if versions.is_empty() {
                None
            } else {
                Some(DidDocumentService {
                    id: alloc::format!("{}#rights-commitment", did_string),
                    type_: "MosaicCommitmentTimeline2026".into(),
                    service_endpoint: serde_json::json!({ "versions": versions }),
                })
            }
        };

        let created_at_height = self.keys.iter().map(|k| k.added_at_height).min();
        let last_modified_at_height = {
            let candidates: [Option<u32>; 6] = [
                self.keys.iter().map(|k| k.added_at_height).max(),
                self.keys.iter().filter_map(|k| k.revoked_at_height).max(),
                self.rights.iter().map(|r| r.granted_at_height).max(),
                self.rights.iter().filter_map(|r| r.revoked_at_height).max(),
                self.commitments.iter().map(|c| c.published_at_height).max(),
                self.tombstoned_at,
            ];
            candidates.into_iter().flatten().max().map(|h| u32::min(h, height))
        };

        DidDocument {
            context: alloc::vec![
                DID_DOCUMENT_W3C_CONTEXT.into(),
                DID_DOCUMENT_MOSAIC_CONTEXT.into(),
            ],
            id: did_string,
            controller: None, // DID is self-controlled
            also_known_as: None,
            verification_method: verification_methods,
            authentication,
            assertion_method,
            key_agreement: Vec::new(),
            capability_invocation,
            capability_delegation,
            service: commitment_service.into_iter().collect(),
            deactivated: self.tombstoned_at.is_some_and(|h| height >= h),
            created_at_height,
            last_modified_at_height,
            tombstoned_at_height: self.tombstoned_at,
        }
    }

    /// Build a minimal [`DidHistory`] from a resolved [`DidDocument`] at a
    /// specific block height.
    ///
    /// The `DidDocument` is a point-in-time snapshot — it lacks lifecycle
    /// information for keys and rights (no `added_at`, `revoked_at`, or
    /// `expires_at`). This constructor approximates:
    ///
    /// - Keys are assumed valid since `doc.created_at_height` (or height 0).
    /// - Rights are assumed granted since `doc.created_at_height` (or height 0).
    ///   `assertionMethod` yields `Impersonate` **only** — the W3C relationship
    ///   is the union of `Issue` and `Impersonate`, so inferring `Issue` would
    ///   over-grant; there is no marker in the snapshot that carries it.
    /// - Commitment versions have real `publishedAtHeight` from the service endpoint.
    ///
    /// The resulting `DidHistory` is suitable for `Minimal`-strength
    /// verification — "the right existed at some point" — but cannot
    /// produce `AfterProof` or `Finalized` because no validated proof
    /// tokens are attached.
    pub(crate) fn from_did_document_at(
        doc: &crate::document::DidDocument, at_height: u32,
    ) -> Result<Self, HistoryFromDocumentError> {
        let did = crate::did::Did::from_did_string(&doc.id)
            .map_err(HistoryFromDocumentError::InvalidDid)?;
        let created = doc.created_at_height.unwrap_or(0);

        // --- Keys (verification methods → VerificationMethod) ---
        //
        // A W3C snapshot is a single point in time and carries no per-key
        // height, so there is nothing to filter per key — the whole snapshot is
        // admitted or rejected together, via the `created > at_height` check
        // below.
        let keys: Vec<_> = doc
            .verification_method
            .iter()
            .filter_map(|vm| {
                // Extract key_ref from fragment: "did:mosaic:ioz...#iozABC" → "iozABC"
                let key_ref_str = vm.id.rsplit('#').next()?;
                let key_ref = KeyRef::new(key_ref_str.as_bytes().to_vec()).ok()?;
                let key_type = w3c_type_to_key_type(&vm.type_)?;
                let public_key = decode_multibase_key(&vm.public_key_multibase)?;
                Some(crate::state::VerificationMethod {
                    key_ref,
                    key_type,
                    controller: did.clone(),
                    public_key: public_key.try_into().ok()?,
                    added_at_height: created,
                    expires_at_height: None,
                    revoked_at_height: None,
                })
            })
            .collect();

        if created > at_height {
            return Err(HistoryFromDocumentError::CommitmentAfterHeight {
                sequence: 0,
                published_at_height: created,
                at_height,
            });
        }

        // --- Rights (W3C relationship arrays → RightLifecycle) ---
        fn key_ids_in(list: &[String]) -> Vec<&str> {
            list.iter().filter_map(|id| id.rsplit('#').next()).collect()
        }

        let mut rights = Vec::new();

        let update_keys = key_ids_in(&doc.capability_invocation);
        let delegate_keys = key_ids_in(&doc.capability_delegation);
        // `assertionMethod` is the union of `Issue` and `Impersonate` (see
        // `to_did_document_at`), so membership alone cannot distinguish them.
        // Only `Impersonate` is inferred: minting `Issue` here would upgrade an
        // impersonation-only snapshot into an issuer-authorized history at
        // Minimal strength. `Issue` needs an explicit marker the snapshot does
        // not carry.
        let assertion_keys = key_ids_in(&doc.assertion_method);

        // A key may appear in multiple lists → one right per appearance.
        for kr in &update_keys {
            let key_ref = KeyRef::new(kr.as_bytes().to_vec()).ok();
            if let Some(kr) = key_ref {
                rights.push(RightLifecycle {
                    key_ref: kr,
                    right: Right::Update,
                    granted_at_height: created,
                    expires_at_height: None,
                    revoked_at_height: None,
                    matures_at_height: None,
                });
            }
        }
        for kr in &delegate_keys {
            let key_ref = KeyRef::new(kr.as_bytes().to_vec()).ok();
            if let Some(kr) = key_ref {
                rights.push(RightLifecycle {
                    key_ref: kr,
                    right: Right::Delegate,
                    granted_at_height: created,
                    expires_at_height: None,
                    revoked_at_height: None,
                    matures_at_height: None,
                });
            }
        }
        for kr in &assertion_keys {
            let key_ref = KeyRef::new(kr.as_bytes().to_vec()).ok();
            if let Some(kr) = key_ref {
                rights.push(RightLifecycle {
                    key_ref: kr,
                    right: Right::Impersonate,
                    granted_at_height: created,
                    expires_at_height: None,
                    revoked_at_height: None,
                    matures_at_height: None,
                });
            }
        }

        // --- Commitments (MosaicCommitmentTimeline2026 service) ---
        let mut commitments = Vec::new();
        if let Some(svc) = doc.service.iter().find(|s| s.type_ == "MosaicCommitmentTimeline2026")
            && let Some(versions) = svc.service_endpoint.get("versions").and_then(|v| v.as_array())
        {
            for v in versions {
                let seq = v.get("sequence").and_then(|s| s.as_u64());
                let cid_str = v.get("contentId").and_then(|c| c.as_str());
                let pub_at = v.get("publishedAtHeight").and_then(|h| h.as_u64());
                let signer =
                    v.get("publishedBy").and_then(|s| s.as_str()).and_then(|s| s.strip_prefix('#'));

                if let (Some(seq), Some(cid_str), Some(pub_at), Some(signer)) =
                    (seq, cid_str, pub_at, signer)
                {
                    // Strict parse. A `contentId` this build cannot read is
                    // reported, not replaced: a substitute value would be
                    // indistinguishable from a publisher-supplied hash and
                    // could never match a document.
                    let commitment = cid_str
                        .parse::<ContentId>()
                        .map_err(HistoryFromDocumentError::InvalidContentId)?;

                    // Height filtering. The endpoint is untrusted, so a version
                    // claiming a future publication height must be rejected:
                    // the height bounds the window a commitment-derived right
                    // is asserted over.
                    if pub_at as u32 > at_height {
                        return Err(HistoryFromDocumentError::CommitmentAfterHeight {
                            sequence: seq,
                            published_at_height: pub_at as u32,
                            at_height,
                        });
                    }

                    let key_ref = KeyRef::new(signer.as_bytes().to_vec())
                        .map_err(|_| HistoryFromDocumentError::InvalidSignerKeyRef(seq))?;
                    commitments.push(CommitmentVersion {
                        sequence: seq,
                        commitment,
                        published_at_height: pub_at as u32,
                        signer_key_ref: key_ref,
                        // Absent means "not a chain start" (see the field's
                        // documentation). When it lands on the first visible
                        // entry, verification reads the timeline as truncated
                        // before the window and skips that one link, so an
                        // older snapshot still loads.
                        chain_start: v.get("chainStart").and_then(|c| c.as_bool()).unwrap_or(false),
                    });
                }
            }
        }

        Ok(DidHistory {
            commitments,
            keys,
            rights,
            tombstoned_at: if doc.deactivated { doc.tombstoned_at_height } else { None },
            ..DidHistory::new(did)
        })
    }
}

/// Decode a `publicKeyMultibase` string (`z<base58btc>`) into raw bytes.
fn decode_multibase_key(encoded: &str) -> Option<Vec<u8>> {
    let b58 = encoded.strip_prefix('z')?;
    bs58::decode(b58).into_vec().ok()
}

// ===== Intervals generic domain type =====

/// A collection of half-open time intervals `[start, end)`,
/// where `end = None` means unbounded.
///
/// Used internally to track when a key or right is valid. Supports
/// union-building via [`Extend`], [`Intervals::normalize`] (sort + merge
/// overlapping), and [`Intervals::clamp`] (constrain to a window).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Intervals(Vec<(u32, Option<u32>)>);

impl Intervals {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Sort by start and merge overlapping intervals into a canonical form.
    fn normalize(&mut self) {
        if self.0.is_empty() {
            return;
        }
        self.0.sort_by_key(|(s, _)| *s);

        let mut merged = Vec::new();
        let mut cur = self.0[0];
        for &(s, e) in &self.0[1..] {
            let cur_end = cur.1.unwrap_or(u32::MAX);
            if s <= cur_end {
                // Overlapping: extend current.
                let new_end = match (cur.1, e) {
                    (None, _) | (_, None) => None,
                    (Some(c), Some(o)) => Some(c.max(o)),
                };
                cur = (cur.0, new_end);
            } else {
                merged.push(cur);
                cur = (s, e);
            }
        }
        merged.push(cur);
        self.0 = merged;
    }

    /// Constrain all intervals to `[lower, upper)`, returning concrete
    /// `(start, end)` pairs suitable for gap analysis.
    ///
    /// `upper = None` means no upper bound (the original unbounded ends
    /// are preserved).
    fn clamp(&self, lower: u32, upper: Option<u32>) -> Vec<(u32, u32)> {
        let end = upper.unwrap_or(u32::MAX);
        self.0
            .iter()
            .filter_map(|&(istart, iend)| {
                let s = istart.max(lower);
                let e = iend.unwrap_or(u32::MAX).min(end);
                if s < e { Some((s, e)) } else { None }
            })
            .collect()
    }
}

impl Extend<(u32, Option<u32>)> for Intervals {
    fn extend<T: IntoIterator<Item = (u32, Option<u32>)>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

impl IntoIterator for Intervals {
    type Item = (u32, Option<u32>);
    type IntoIter = alloc::vec::IntoIter<(u32, Option<u32>)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// ===== Three-outcome validity helpers =====

/// Build a `ValidityResult` from clamped intervals against `[h_start, h_end)`.
fn build_validity_result(
    clamped: &[(u32, u32)], h_start: u32, h_end: Option<u32>,
) -> ValidityResult {
    if clamped.is_empty() {
        return ValidityResult::Absent;
    }

    let end = h_end.unwrap_or(u32::MAX);

    // Single interval covering the full window?
    if clamped.len() == 1 && clamped[0].0 <= h_start && clamped[0].1 >= end {
        return ValidityResult::Confirmed;
    }

    // Multiple intervals → find the gaps.
    let gaps = collect_gaps(clamped, h_start, end, h_end.is_none());
    ValidityResult::Ambiguous { gaps }
}

/// Find gaps between clamped intervals within `[h_start, end)`.
fn collect_gaps(
    clamped: &[(u32, u32)], h_start: u32, end: u32, unbounded_end: bool,
) -> Vec<ValidityGap> {
    let mut gaps = Vec::new();
    let mut cursor = h_start;

    for &(s, e) in clamped {
        if cursor < s {
            gaps.push(ValidityGap {
                start: cursor,
                end: Some(s),
                reason: alloc::format!("key absent [{cursor}, {s})"),
            });
        }
        cursor = cursor.max(e);
    }

    let final_end = if unbounded_end { None } else { Some(end) };
    if cursor < end {
        gaps.push(ValidityGap {
            start: cursor,
            end: final_end,
            reason: if unbounded_end {
                alloc::format!("key absent [{cursor}, ∞)")
            } else {
                alloc::format!("key absent [{cursor}, {end})")
            },
        });
    }

    gaps
}

// ===== Three-outcome validity types =====

/// Result of checking a condition (key validity, liveness, right) across
/// a time window `[h_start, h_end)`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidityResult {
    /// Condition holds definitively throughout the entire `[h_start, h_end)` window.
    Confirmed,
    /// Condition holds in some sub-intervals but not others — the signature
    /// timing is ambiguous. Each gap describes a sub-interval `[start, end)`
    /// where the condition was absent.
    Ambiguous { gaps: Vec<ValidityGap> },
    /// Condition is definitively absent throughout the entire window.
    Absent,
}

/// A sub-interval `[start, end)` where a condition was absent.
///
/// `end` is exclusive and `None` means unbounded (end of time).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidityGap {
    /// Inclusive start height.
    pub start: u32,
    /// Exclusive end height (`None` = unbounded).
    pub end: Option<u32>,
    /// Human-readable reason for the gap.
    pub reason: alloc::string::String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rights::RIGHTS_DOCUMENT_V1_SCHEMA;

    /// A test resolver that holds a map of ContentId -> UnsafeRightsDocument.
    struct TestResolver {
        documents: Vec<(ContentId, UnsafeRightsDocument)>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self { documents: Vec::new() }
        }

        fn insert(&mut self, content_id: ContentId, doc: UnsafeRightsDocument) {
            self.documents.push((content_id, doc));
        }
    }

    impl CommitmentResolver for TestResolver {
        fn resolve(&self, content_id: &ContentId) -> Option<UnsafeRightsDocument> {
            self.documents.iter().find(|(cid, _)| cid == content_id).map(|(_, doc)| doc.clone())
        }
    }

    fn test_did() -> crate::did::Did {
        crate::did::Did::alice()
    }

    fn test_key_ref(n: u8) -> KeyRef {
        use mosaic_keyvault::PrivateKey;
        use mosaic_keyvault::PublicKey;
        use mosaic_keyvault::ed25519::EdPrivateKey;

        // Deterministic seed from n
        let mut seed = [0u8; 32];
        seed[0] = n;
        seed[31] = 1;

        let sk = EdPrivateKey::from_bytes(seed).unwrap();
        let pk = sk.public_key();
        let mpk =
            crate::signature::public_key_from_key_type(KeyType::Ed25519, &pk.to_bytes()).unwrap();
        let key_id = alloc::format!("{}", mpk.key_id());
        KeyRef::new(key_id.into_bytes()).unwrap()
    }

    fn test_commitment(n: u8) -> ContentId {
        ContentId::from_bytes(&[n; 32])
    }

    #[test]
    fn commitment_at_returns_most_recent_before_height() {
        let did = test_did();
        let kr = test_key_ref(1);

        let history = DidHistory {
            commitments: alloc::vec![
                CommitmentVersion {
                    sequence: 1,
                    commitment: test_commitment(1),
                    published_at_height: 100,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
                CommitmentVersion {
                    sequence: 2,
                    commitment: test_commitment(2),
                    published_at_height: 200,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
            ],
            ..DidHistory::new(did)
        };

        assert_eq!(history.commitment_at(50), None);
        assert_eq!(history.commitment_at(100).unwrap().commitment, test_commitment(1));
        assert_eq!(history.commitment_at(150).unwrap().commitment, test_commitment(1));
        assert_eq!(history.commitment_at(200).unwrap().commitment, test_commitment(2));
        assert_eq!(history.commitment_at(300).unwrap().commitment, test_commitment(2));
    }

    #[test]
    fn valid_keys_at_filters_by_height() {
        let did = test_did();
        let kr1 = test_key_ref(1);
        let kr2 = test_key_ref(2);

        let history = DidHistory {
            keys: alloc::vec![
                crate::state::VerificationMethod {
                    key_ref: kr1.clone(),
                    key_type: KeyType::Ed25519,
                    controller: test_did(),
                    public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                    added_at_height: 10,
                    expires_at_height: Some(100),
                    revoked_at_height: None,
                },
                crate::state::VerificationMethod {
                    key_ref: kr2.clone(),
                    key_type: KeyType::Ed25519,
                    controller: test_did(),
                    public_key: alloc::vec![2u8; 32].try_into().unwrap(),
                    added_at_height: 50,
                    expires_at_height: None,
                    revoked_at_height: Some(80),
                },
            ],
            ..DidHistory::new(did)
        };

        // At height 5: no valid keys
        assert!(history.valid_keys_at(5).is_empty());

        // At height 15: only key1
        let valid = history.valid_keys_at(15);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].key_ref, kr1);

        // At height 55: both keys
        let valid = history.valid_keys_at(55);
        assert_eq!(valid.len(), 2);

        // At height 85: only key1 (key2 revoked at 80)
        let valid = history.valid_keys_at(85);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].key_ref, kr1);

        // At height 105: no valid keys (key1 expired at 100, key2 revoked at 80)
        assert!(history.valid_keys_at(105).is_empty());
    }

    #[test]
    fn has_right_at_checks_on_chain_rights() {
        let did = test_did();
        let kr = test_key_ref(1);

        let history = DidHistory {
            rights: alloc::vec![RightLifecycle {
                key_ref: kr.clone(),
                right: Right::Impersonate,
                granted_at_height: 10,
                expires_at_height: None,
                revoked_at_height: Some(50),
                matures_at_height: None,
            }],
            ..DidHistory::new(did)
        };

        let resolver = TestResolver::new();

        assert!(!history.has_right_at(&kr, Right::Impersonate, 5, &resolver));
        assert!(history.has_right_at(&kr, Right::Impersonate, 10, &resolver));
        assert!(history.has_right_at(&kr, Right::Impersonate, 49, &resolver));
        assert!(!history.has_right_at(&kr, Right::Impersonate, 50, &resolver));
    }

    #[test]
    fn has_right_at_falls_through_to_commitment() {
        let did = test_did();
        let kr = test_key_ref(1);
        let commitment = test_commitment(1);

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            ..DidHistory::new(did)
        };

        let mut resolver = TestResolver::new();
        resolver.insert(
            commitment,
            UnsafeRightsDocument {
                schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
                did: "did:mosaic:iozABC".into(),
                sequence: 1,
                previous_commitment: None,
                hash_algorithm: crate::rights::ContentHashAlgorithm::Blake3CanonicalJson,
                rights: alloc::vec![crate::rights::UnsafeRightEntry {
                    key: kr.to_string(),
                    rights: alloc::vec!["impersonate".into()],
                }],
            },
        );

        // No commitment before height 100
        assert!(!history.has_right_at(&kr, Right::Impersonate, 50, &resolver));

        // Commitment active at height 100+
        assert!(history.has_right_at(&kr, Right::Impersonate, 100, &resolver));
    }

    /// The resolver path must use the same cross-variant key matching as the
    /// validated path: an entry revealing the **full public key** must match
    /// the bare key id the chain stores.
    #[test]
    fn has_right_at_matches_a_full_public_key_entry() {
        use mosaic_keyvault::PrivateKey as _;
        use mosaic_keyvault::PublicKey as _;
        use mosaic_keyvault::ed25519::EdPrivateKey;
        use mosaic_keyvault::multicipher::MPublicKey;

        let mut seed = [0u8; 32];
        seed[0] = 9;
        let pk = MPublicKey::Ed25519(EdPrivateKey::from_bytes(seed).unwrap().public_key());
        // On-chain key refs are the derived key id (`ioz...`), never the
        // public key (`poz...`).
        let kr = KeyRef::new(pk.key_id().to_string().into_bytes()).unwrap();

        let commitment = test_commitment(2);
        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: true,
            }],
            ..DidHistory::new(test_did())
        };

        let mut resolver = TestResolver::new();
        resolver.insert(
            commitment,
            UnsafeRightsDocument {
                schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
                did: test_did().to_did_string(),
                sequence: 1,
                previous_commitment: None,
                hash_algorithm: crate::rights::ContentHashAlgorithm::Blake3CanonicalJson,
                rights: alloc::vec![crate::rights::UnsafeRightEntry {
                    // The revealing form: a full public key, not a key id.
                    key: pk.to_string(),
                    rights: alloc::vec!["impersonate".into()],
                }],
            },
        );

        assert!(
            history.has_right_at(&kr, Right::Impersonate, 100, &resolver),
            "a public-key entry must match the key ref derived from that same key"
        );
        assert!(
            !history.has_right_at(&kr, Right::Issue, 100, &resolver),
            "the right name must still be honoured"
        );
    }

    #[test]
    fn right_lifecycle_is_active_at() {
        let rl = RightLifecycle {
            key_ref: test_key_ref(1),
            right: Right::Issue,
            granted_at_height: 10,
            expires_at_height: Some(100),
            revoked_at_height: Some(50),
            matures_at_height: None,
        };

        assert!(!rl.is_active_at(9));
        assert!(rl.is_active_at(10));
        assert!(rl.is_active_at(49));
        assert!(!rl.is_active_at(50)); // revoked
        assert!(!rl.is_active_at(100));
    }

    #[test]
    fn right_lifecycle_maturity_delays_activity() {
        let rl = RightLifecycle {
            key_ref: test_key_ref(1),
            right: Right::Update,
            granted_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
            matures_at_height: Some(50),
        };

        // Not yet mature — not active
        assert!(!rl.is_active_at(10));
        assert!(!rl.is_active_at(49));

        // Mature — now active
        assert!(rl.is_active_at(50));
        assert!(rl.is_active_at(100));

        // None means immediate maturity — active as soon as granted
        let immediate = RightLifecycle { matures_at_height: None, ..rl };
        assert!(immediate.is_active_at(10));
    }

    // ===== DidHistoryEvent apply tests =====

    #[test]
    fn apply_key_added_adds_key_to_history() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        let pk: alloc::vec::Vec<u8> = alloc::vec![1u8; 32];

        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: pk.clone(),
            at_height: 10,
            expires_at_height: None,
        });

        assert_eq!(history.keys.len(), 1);
        let key = &history.keys[0];
        assert_eq!(key.key_ref, kr);
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert_eq!(key.added_at_height, 10);
        assert_eq!(&key.public_key[..], pk.as_slice());
    }

    #[test]
    fn apply_key_revoked_sets_revoked_at_height() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);

        // Add a key first at height 10
        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });

        // Revoke at height 50
        history.apply(DidHistoryEvent::KeyRevoked { key_ref: kr.clone(), at_height: 50 });

        let key = &history.keys[0];
        assert_eq!(key.revoked_at_height, Some(50));
    }

    #[test]
    fn apply_right_added_pushes_right_lifecycle() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);

        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr.clone(),
            right: Right::Impersonate,
            at_height: 20,
            matures_at_height: Some(50),
            expires_at_height: Some(100),
        });

        assert_eq!(history.rights.len(), 1);
        let rl = &history.rights[0];
        assert_eq!(rl.key_ref, kr);
        assert_eq!(rl.right, Right::Impersonate);
        assert_eq!(rl.granted_at_height, 20);
        assert_eq!(rl.matures_at_height, Some(50));
        assert_eq!(rl.expires_at_height, Some(100));
        assert_eq!(rl.revoked_at_height, None);
    }

    #[test]
    fn apply_right_revoked_sets_revoked_at_height() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);

        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr.clone(),
            right: Right::Issue,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightRevoked {
            key_ref: kr.clone(),
            right: Right::Issue,
            at_height: 60,
        });

        let rl = &history.rights[0];
        assert_eq!(rl.revoked_at_height, Some(60));
    }

    #[test]
    fn apply_commitment_updated_pushes_commitment_version() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        let cid = test_commitment(1);

        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: cid,
            signer_key_ref: kr.clone(),
            at_height: 100,
        });
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 2,
            commitment: test_commitment(2),
            signer_key_ref: kr.clone(),
            at_height: 200,
        });

        assert_eq!(history.commitments.len(), 2);
        let cv = &history.commitments[0];
        assert_eq!(cv.sequence, 1);
        assert_eq!(cv.commitment, cid);
        assert_eq!(cv.published_at_height, 100);
        assert_eq!(cv.signer_key_ref, kr);
        assert!(cv.chain_start, "the first commitment starts the chain");
        assert!(
            !history.commitments[1].chain_start,
            "a later plain update links to its predecessor instead of restarting the chain"
        );
    }

    /// A reset event marks its commitment as a chain start, even though the
    /// sequence counter keeps running. The document published at it must carry
    /// no predecessor, so the verifier expects a fresh chain from here.
    #[test]
    fn apply_commitment_reset_marks_chain_start() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);

        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: test_commitment(1),
            signer_key_ref: kr.clone(),
            at_height: 100,
        });
        history.apply(DidHistoryEvent::CommitmentReset {
            sequence: 2,
            commitment: test_commitment(2),
            signer_key_ref: kr.clone(),
            at_height: 150,
        });

        assert_eq!(history.commitments.len(), 2);
        assert!(
            history.commitments[0].chain_start,
            "the first commitment starts the initial chain"
        );
        assert!(
            history.commitments[1].chain_start,
            "a reset starts a new document chain at a continuing sequence"
        );
        assert_eq!(history.commitments[1].sequence, 2);
    }

    #[test]
    fn apply_did_tombstoned_sets_tombstoned_at() {
        let mut history = DidHistory::new(test_did());

        history.apply(DidHistoryEvent::DidTombstoned { at_height: 500 });

        assert_eq!(history.tombstoned_at, Some(500));
    }

    #[test]
    fn apply_event_stream_builds_complete_history() {
        let mut history = DidHistory::new(test_did());
        let kr1 = test_key_ref(1);
        let kr2 = test_key_ref(2);
        let cid1 = test_commitment(1);

        // Simulate a full event stream
        let events = alloc::vec![
            DidHistoryEvent::KeyAdded {
                key_ref: kr1.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![1u8; 32],
                at_height: 10,
                expires_at_height: None,
            },
            DidHistoryEvent::RightAdded {
                key_ref: kr1.clone(),
                right: Right::Update,
                at_height: 10,
                matures_at_height: None,
                expires_at_height: None,
            },
            DidHistoryEvent::KeyAdded {
                key_ref: kr2.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![2u8; 32],
                at_height: 50,
                expires_at_height: Some(200),
            },
            DidHistoryEvent::CommitmentUpdated {
                sequence: 1,
                commitment: cid1,
                signer_key_ref: kr1.clone(),
                at_height: 100,
            },
            DidHistoryEvent::RightRevoked {
                key_ref: kr1.clone(),
                right: Right::Update,
                at_height: 150,
            },
            DidHistoryEvent::KeyRevoked { key_ref: kr2.clone(), at_height: 180 },
            DidHistoryEvent::DidTombstoned { at_height: 500 },
        ];

        for event in events {
            history.apply(event);
        }

        assert_eq!(history.keys.len(), 2);
        assert_eq!(history.rights.len(), 1);
        assert_eq!(history.commitments.len(), 1);
        assert_eq!(history.tombstoned_at, Some(500));

        // Key 1 added at 10, never revoked
        assert!(history.valid_keys_at(15).iter().any(|k| k.key_ref == kr1));
        // Key 2 revoked at 180, not valid after
        assert!(history.valid_keys_at(55).iter().any(|k| k.key_ref == kr2));
        assert!(!history.valid_keys_at(181).iter().any(|k| k.key_ref == kr2));

        // Right revoked at 150
        let resolver = TestResolver::new();
        assert!(history.has_right_at(&kr1, Right::Update, 50, &resolver));
        assert!(!history.has_right_at(&kr1, Right::Update, 151, &resolver));
    }

    #[test]
    fn to_did_document_at_produces_w3c_document() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        let cid = test_commitment(1);

        // Add key + on-chain rights + commitment
        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr.clone(),
            right: Right::Update,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr.clone(),
            right: Right::Impersonate,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: cid,
            signer_key_ref: kr.clone(),
            at_height: 100,
        });

        let doc = history.to_did_document_at(150, None);

        assert!(doc.id.starts_with("did:mosaic:ioz"));
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1); // Impersonate → assertionMethod
        assert_eq!(doc.capability_invocation.len(), 1); // Update → capabilityInvocation
        assert_eq!(doc.capability_delegation.len(), 0); // No Delegate right
        assert!(!doc.deactivated);

        // Mosaic extensions
        assert_eq!(doc.created_at_height, Some(10));
        assert!(doc.last_modified_at_height.is_some());
        assert_eq!(doc.tombstoned_at_height, None); // not tombstoned

        // Commitment service
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].type_, "MosaicCommitmentTimeline2026");
        // Versions array in the endpoint
        let versions = doc.service[0].service_endpoint.get("versions").unwrap().as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["sequence"], serde_json::json!(1));

        // Regression: pin the JSON format
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains(r#""@context""#));
        assert!(json.contains(r#""did:mosaic:ioz"#));
        assert!(json.contains(r#""verificationMethod""#));
        assert!(json.contains(r#""MosaicCommitmentTimeline2026""#));
        assert!(json.contains(r#""mosaic:createdAtHeight": 10"#));
        assert!(!json.contains("tombstonedAtHeight")); // omitted when None
        // Service endpoint is a structured object
        assert!(json.contains(r#""serviceEndpoint": {"#));
        // Round-trip: parse the JSON back
        let parsed: crate::document::DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.verification_method.len(), 1);
        assert_eq!(parsed.authentication.len(), 1);
        assert_eq!(parsed.service.len(), 1);
        assert_eq!(parsed.created_at_height, Some(10));
    }

    #[test]
    fn from_did_document_at_roundtrips_commitment_content_ids() {
        // Build a DidHistory with a commitment whose ContentId has a concrete value.
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        let original_cid = test_commitment(1); // Blake3Flat([1u8; 32])

        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr.clone(),
            right: Right::Update,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: original_cid,
            signer_key_ref: kr,
            at_height: 100,
        });

        // Serialize to a JSON DidDocument, then reconstruct via from_did_document_at.
        let doc = history.to_did_document_at(150, None);
        let reconstructed =
            DidHistory::from_did_document_at(&doc, 150).expect("reconstruction must succeed");

        assert_eq!(reconstructed.commitments.len(), 1);
        let roundtripped_cid = reconstructed.commitments[0].commitment;
        assert_eq!(
            original_cid, roundtripped_cid,
            "ContentId must round-trip through DidDocument; from_did_document_at must parse the ContentId string, not BLAKE3-hash it"
        );
    }

    /// A snapshot cannot distinguish `Issue` from `Impersonate`: both map to
    /// `assertionMethod`. Reconstruction must not upgrade an impersonation-only
    /// key into an issuer-authorized history. `Issue` requires an explicit
    /// marker the snapshot does not carry, so it stays absent.
    #[test]
    fn from_did_document_at_does_not_mint_issue_from_assertion_method() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);

        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr.clone(),
            right: Right::Impersonate,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });

        let doc = history.to_did_document_at(150, None);
        assert_eq!(doc.assertion_method.len(), 1, "impersonate maps to assertionMethod");

        let reconstructed =
            DidHistory::from_did_document_at(&doc, 150).expect("reconstruction must succeed");

        assert!(
            reconstructed
                .rights
                .iter()
                .any(|rl| rl.key_ref == kr && rl.right == Right::Impersonate),
            "Impersonate must be derived from assertionMethod membership"
        );
        assert!(
            !reconstructed.rights.iter().any(|rl| rl.key_ref == kr && rl.right == Right::Issue),
            "assertionMethod membership alone must not mint Issue"
        );
    }

    /// An unparseable `contentId` is reported, not replaced. A substitute
    /// value could never match a document and would be indistinguishable from
    /// a genuine publisher-supplied hash.
    #[test]
    fn from_did_document_at_rejects_unparseable_content_id() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: test_commitment(1),
            signer_key_ref: kr,
            at_height: 100,
        });
        let doc = history.to_did_document_at(150, None);

        // Corrupt the contentId in the service endpoint.
        let mut doc = doc;
        for svc in &mut doc.service {
            if svc.type_ == "MosaicCommitmentTimeline2026" {
                svc.service_endpoint = serde_json::json!({
                    "versions": [{
                        "sequence": 1,
                        "contentId": "cmNOT-A-VALID-CONTENT-ID",
                        "publishedAtHeight": 100,
                        "publishedBy": "#ioztest",
                    }]
                });
            }
        }

        let err = DidHistory::from_did_document_at(&doc, 150)
            .expect_err("an unparseable contentId must be reported");
        assert!(
            matches!(err, HistoryFromDocumentError::InvalidContentId(_)),
            "expected InvalidContentId, got {err:?}"
        );
    }

    /// A commitment claiming a future publication height must be rejected, not
    /// admitted — the endpoint is untrusted and this height bounds the window
    /// the resulting right is asserted over.
    #[test]
    fn from_did_document_at_rejects_commitment_published_after_requested_height() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: test_commitment(1),
            signer_key_ref: kr,
            at_height: 100,
        });
        let doc = history.to_did_document_at(150, None);

        // Ask for a height before the commitment was published.
        let err = DidHistory::from_did_document_at(&doc, 50)
            .expect_err("a commitment published after the requested height must be rejected");
        assert_eq!(
            err,
            HistoryFromDocumentError::CommitmentAfterHeight {
                sequence: 1,
                published_at_height: 100,
                at_height: 50
            }
        );
    }

    /// A snapshot whose creation height is beyond the requested height is
    /// rejected: the caller asked about a point in time before the DID existed.
    #[test]
    fn from_did_document_at_rejects_snapshot_created_after_requested_height() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr,
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: test_key_ref(1),
            right: Right::Update,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });
        let doc = history.to_did_document_at(200, None);

        let err = DidHistory::from_did_document_at(&doc, 5)
            .expect_err("a snapshot from after the requested height must be rejected");
        assert!(
            matches!(err, HistoryFromDocumentError::CommitmentAfterHeight { at_height: 5, .. }),
            "expected CommitmentAfterHeight, got {err:?}"
        );
    }

    #[test]
    fn to_did_document_at_with_from_height_filters_window() {
        let mut history = DidHistory::new(test_did());
        let kr1 = test_key_ref(1);
        let kr2 = test_key_ref(2);

        // Key at height 10
        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr1.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr1.clone(),
            right: Right::Update,
            at_height: 10,
            matures_at_height: None,
            expires_at_height: None,
        });

        // Key at height 50 — added after the window start
        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr2.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![2u8; 32],
            at_height: 50,
            expires_at_height: None,
        });
        history.apply(DidHistoryEvent::RightAdded {
            key_ref: kr2.clone(),
            right: Right::Impersonate,
            at_height: 50,
            matures_at_height: None,
            expires_at_height: None,
        });

        // Commitments at 100 and 200
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: test_commitment(1),
            signer_key_ref: kr1.clone(),
            at_height: 100,
        });
        history.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 2,
            commitment: test_commitment(2),
            signer_key_ref: kr1.clone(),
            at_height: 200,
        });

        // Full document at height 250 — both keys, both commitments
        let full = history.to_did_document_at(250, None);
        assert_eq!(full.verification_method.len(), 2);

        // Filtered: from_height=150 → both keys (added before 150, not revoked/expired).
        // Timeline starts at commit active at 150 (commit1 @ 100) + commit2 @ 200.
        let filtered = history.to_did_document_at(250, Some(150));
        assert_eq!(filtered.verification_method.len(), 2);

        // Timeline: from_height=150 → active at 150 is commit1 (100) + commit2 (200)
        let timeline =
            filtered.service[0].service_endpoint.get("versions").unwrap().as_array().unwrap();
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0]["sequence"], serde_json::json!(1));
        assert_eq!(timeline[1]["sequence"], serde_json::json!(2));
    }

    // ===== Three-outcome tests =====

    /// Return a `KeyRef` that matches `test_did()`'s default key.
    fn test_default_key_ref() -> KeyRef {
        let did = test_did();
        let kid_str = did.default_key_id.to_string();
        KeyRef::new(kid_str.into_bytes()).unwrap()
    }

    #[test]
    fn check_key_validity_default_key_unbounded_confirmed() {
        // Zero-transaction DID: no events, empty keys/rights/commitments.
        let history = DidHistory::new(test_did());
        let key_ref = test_default_key_ref();

        // Unbounded window [0, ∞)
        let result = history.check_key_validity(&key_ref, 0, None);
        assert_eq!(result, ValidityResult::Confirmed);
    }

    #[test]
    fn check_key_validity_default_key_revoked_absent() {
        // Default key registered on-chain, then revoked at height 50.
        // Window [100, 200): the default key is absent.
        // BUG: the current fast-path ignores revocation.
        let key_ref = test_default_key_ref();
        let history = DidHistory {
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: key_ref.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: 0,
                expires_at_height: None,
                revoked_at_height: Some(50),
            }],
            ..DidHistory::new(test_did())
        };

        let result = history.check_key_validity(&key_ref, 100, Some(200));
        assert_eq!(result, ValidityResult::Absent);
    }

    #[test]
    fn check_key_validity_revoked_mid_window_ambiguous() {
        // Key added at 10, revoked at 50. AfterProof only: H_start=100, H_end=None.
        // Key was valid [100, unbounded) at H_start=100 – no, wait.
        // The key is valid [10, 50) and absent [50, unbounded).
        // Window [100, ∞): key was already revoked at 100 → Absent.
        //
        // Let's use a better scenario: key added at 10, revoked at 150.
        // Window [100, 200): valid [100, 150), absent [150, 200) → Ambiguous.
        let did = test_did();
        let kr = test_key_ref(1);
        let history = DidHistory {
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: kr.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: 10,
                expires_at_height: None,
                revoked_at_height: Some(150),
            }],
            ..DidHistory::new(did)
        };

        let result = history.check_key_validity(&kr, 100, Some(200));
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(gaps.len(), 1);
                assert_eq!(gaps[0].start, 150);
                assert_eq!(gaps[0].end, Some(200));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn check_key_validity_added_mid_window_ambiguous() {
        // Key added at 150. BeforeProof only: H_start=0, H_end=200.
        // Valid [150, 200), absent [0, 150) → Ambiguous.
        let did = test_did();
        let kr = test_key_ref(1);
        let history = DidHistory {
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: kr.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: 150,
                expires_at_height: None,
                revoked_at_height: None,
            }],
            ..DidHistory::new(did)
        };

        let result = history.check_key_validity(&kr, 0, Some(200));
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(gaps.len(), 1);
                assert_eq!(gaps[0].start, 0);
                assert_eq!(gaps[0].end, Some(150));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn check_key_validity_revoked_before_h_start_absent() {
        // Key added at 10, revoked at 50. Window [100, 200): absent.
        let did = test_did();
        let kr = test_key_ref(1);
        let history = DidHistory {
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: kr.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: 10,
                expires_at_height: None,
                revoked_at_height: Some(50),
            }],
            ..DidHistory::new(did)
        };

        let result = history.check_key_validity(&kr, 100, Some(200));
        assert_eq!(result, ValidityResult::Absent);
    }

    #[test]
    fn check_key_validity_added_after_h_end_absent() {
        // Key added at 300. Window [100, 200): absent.
        let did = test_did();
        let kr = test_key_ref(1);
        let history = DidHistory {
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: kr.clone(),
                key_type: KeyType::Ed25519,
                controller: test_did(),
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: 300,
                expires_at_height: None,
                revoked_at_height: None,
            }],
            ..DidHistory::new(did)
        };

        let result = history.check_key_validity(&kr, 100, Some(200));
        assert_eq!(result, ValidityResult::Absent);
    }

    #[test]
    fn check_key_validity_multiple_gaps_ambiguous() {
        // Key added at 100, revoked at 200, re-added at 300.
        // Window [50, 400): absent [50,100), valid [100,200), absent [200,300), valid [300,400).
        // → Ambiguous with 2 gaps.
        let did = test_did();
        let kr = test_key_ref(1);
        let history = DidHistory {
            keys: alloc::vec![
                crate::state::VerificationMethod {
                    key_ref: kr.clone(),
                    key_type: KeyType::Ed25519,
                    controller: test_did(),
                    public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                    added_at_height: 100,
                    expires_at_height: None,
                    revoked_at_height: Some(200),
                },
                crate::state::VerificationMethod {
                    key_ref: kr.clone(),
                    key_type: KeyType::Ed25519,
                    controller: test_did(),
                    public_key: alloc::vec![2u8; 32].try_into().unwrap(),
                    added_at_height: 300,
                    expires_at_height: None,
                    revoked_at_height: None,
                },
            ],
            ..DidHistory::new(did)
        };

        let result = history.check_key_validity(&kr, 50, Some(400));
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(gaps.len(), 2, "expected 2 gaps, got {gaps:?}");
                // Gap 1: absent [50, 100) — key not yet added
                assert_eq!(gaps[0].start, 50);
                assert_eq!(gaps[0].end, Some(100));
                // Gap 2: absent [200, 300) — key revoked
                assert_eq!(gaps[1].start, 200);
                assert_eq!(gaps[1].end, Some(300));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    // ===== Liveness tests =====

    #[test]
    fn check_liveness_not_tombstoned_confirmed() {
        let history = DidHistory::new(test_did());
        assert_eq!(history.check_liveness(0, None), ValidityResult::Confirmed);
        assert_eq!(history.check_liveness(100, Some(200)), ValidityResult::Confirmed);
    }

    #[test]
    fn check_liveness_tombstoned_before_h_start_absent() {
        let mut history = DidHistory::new(test_did());
        history.tombstoned_at = Some(50);
        // Window [100, 200): DID was dead before window started.
        assert_eq!(history.check_liveness(100, Some(200)), ValidityResult::Absent);
    }

    #[test]
    fn check_liveness_tombstoned_during_window_absent() {
        let mut history = DidHistory::new(test_did());
        history.tombstoned_at = Some(150);
        // Window [100, 200): DID died at 150, not alive throughout.
        assert_eq!(history.check_liveness(100, Some(200)), ValidityResult::Absent);
    }

    #[test]
    fn check_liveness_tombstoned_after_h_end_confirmed() {
        let mut history = DidHistory::new(test_did());
        history.tombstoned_at = Some(300);
        // Window [100, 200): DID alive throughout (tombstone at 300 not yet hit).
        assert_eq!(history.check_liveness(100, Some(200)), ValidityResult::Confirmed);
    }

    #[test]
    fn check_liveness_tombstoned_exactly_at_h_start_absent() {
        let mut history = DidHistory::new(test_did());
        history.tombstoned_at = Some(100);
        // tomb_height = h_start → DID was dead at window start.
        assert_eq!(history.check_liveness(100, Some(200)), ValidityResult::Absent);
    }

    // ===== check_right tests =====

    /// Make a rights document granting `right` to `key_str`.
    ///
    /// `previous` must be the predecessor's real content ID — a document that
    /// omits it where the timeline expects a predecessor is rejected as
    /// [`CommitmentDocumentError::ChainBroken`].
    fn make_rights_doc(
        seq: u64, previous: Option<ContentId>, key_str: &str, right: &str,
    ) -> crate::rights::RightsDocument {
        use crate::rights::{RIGHTS_DOCUMENT_V1_SCHEMA, UnsafeRightEntry, UnsafeRightsDocument};
        let did_str = test_did().to_did_string();
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: did_str,
            sequence: seq,
            previous_commitment: previous,
            hash_algorithm: crate::rights::ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: key_str.into(),
                rights: alloc::vec![right.into()],
            }],
        };
        raw.try_into().expect("test rights doc should be valid")
    }

    /// A rights document belonging to an arbitrary DID.
    fn make_rights_doc_for_did(
        seq: u64, previous: Option<ContentId>, did: &crate::did::Did, key_str: &str, right: &str,
    ) -> crate::rights::RightsDocument {
        use crate::rights::{RIGHTS_DOCUMENT_V1_SCHEMA, UnsafeRightEntry, UnsafeRightsDocument};
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: did.to_did_string(),
            sequence: seq,
            previous_commitment: previous,
            hash_algorithm: crate::rights::ContentHashAlgorithm::Blake3CanonicalJson,
            rights: alloc::vec![UnsafeRightEntry {
                key: key_str.into(),
                rights: alloc::vec![right.into()],
            }],
        };
        raw.try_into().expect("test rights doc should be valid")
    }

    /// A three-document presentation.
    fn set3<'a>(
        a: &'a crate::rights::RightsDocument, b: &'a crate::rights::RightsDocument,
        c: &'a crate::rights::RightsDocument,
    ) -> RightsDocumentSet<'a> {
        RightsDocumentSet::new(alloc::vec![a, b, c]).expect("strictly increasing is valid")
    }

    /// Build a document and return it with its content ID.
    fn make_rights_doc_cid(
        seq: u64, previous: Option<ContentId>, key_str: &str, right: &str,
    ) -> (crate::rights::RightsDocument, ContentId) {
        let doc = make_rights_doc(seq, previous, key_str, right);
        let cid = doc.compute_content_id().expect("digest must compute");
        (doc, cid)
    }

    /// An empty presentation.
    fn empty_set() -> RightsDocumentSet<'static> {
        RightsDocumentSet::new(alloc::vec![]).expect("empty set is valid")
    }

    /// A one-document presentation.
    fn set1<'a>(docs: &[&'a crate::rights::RightsDocument]) -> RightsDocumentSet<'a> {
        RightsDocumentSet::new(docs.to_vec()).expect("single document is valid")
    }

    /// A two-document presentation.
    fn set2<'a>(
        a: &'a crate::rights::RightsDocument, b: &'a crate::rights::RightsDocument,
    ) -> RightsDocumentSet<'a> {
        RightsDocumentSet::new(alloc::vec![a, b]).expect("strictly increasing is valid")
    }

    #[test]
    fn verify_right_window_on_chain_full_window_confirmed() {
        // On-chain right grant from height 10, never revoked, window [10, 100).
        let kr = test_key_ref(1);
        let history = DidHistory {
            rights: alloc::vec![RightLifecycle {
                key_ref: kr.clone(),
                right: Right::Impersonate,
                granted_at_height: 10,
                expires_at_height: None,
                revoked_at_height: None,
                matures_at_height: None,
            }],
            ..DidHistory::new(test_did())
        };

        assert_eq!(
            history
                .verify_right_window(&kr, Right::Impersonate, 10, Some(100), &empty_set())
                .unwrap(),
            ValidityResult::Confirmed
        );
    }

    #[test]
    fn verify_right_window_on_chain_revoked_mid_window_ambiguous() {
        // On-chain right granted at 10, revoked at 50. Window [0, 100).
        let kr = test_key_ref(1);
        let history = DidHistory {
            rights: alloc::vec![RightLifecycle {
                key_ref: kr.clone(),
                right: Right::Impersonate,
                granted_at_height: 10,
                expires_at_height: None,
                revoked_at_height: Some(50),
                matures_at_height: None,
            }],
            ..DidHistory::new(test_did())
        };

        let result = history
            .verify_right_window(&kr, Right::Impersonate, 0, Some(100), &empty_set())
            .unwrap();
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(gaps.len(), 2);
                // Gap 1: absent [0, 10) — not yet granted
                assert_eq!(gaps[0].start, 0);
                assert_eq!(gaps[0].end, Some(10));
                // Gap 2: absent [50, 100) — revoked
                assert_eq!(gaps[1].start, 50);
                assert_eq!(gaps[1].end, Some(100));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn verify_right_window_no_rights_absent() {
        // No on-chain rights, no commitments, not default key → Absent.
        let kr = test_key_ref(1);
        let history = DidHistory::new(test_did());
        assert_eq!(
            history.verify_right_window(&kr, Right::Issue, 0, Some(100), &empty_set()).unwrap(),
            ValidityResult::Absent
        );
    }

    #[test]
    fn verify_right_window_implicit_default_right_confirmed() {
        // Zero-transaction DID, default key, Impersonate right.
        let history = DidHistory::new(test_did());
        let key_ref = test_default_key_ref();

        // Implicit Impersonate right for default key.
        assert_eq!(
            history
                .verify_right_window(&key_ref, Right::Impersonate, 0, None, &empty_set())
                .unwrap(),
            ValidityResult::Confirmed
        );
        assert_eq!(
            history.verify_right_window(&key_ref, Right::Update, 0, None, &empty_set()).unwrap(),
            ValidityResult::Confirmed
        );
        assert_eq!(
            history.verify_right_window(&key_ref, Right::Delegate, 0, None, &empty_set()).unwrap(),
            ValidityResult::Confirmed
        );

        // Issue is NOT implicit.
        assert_eq!(
            history.verify_right_window(&key_ref, Right::Issue, 0, None, &empty_set()).unwrap(),
            ValidityResult::Absent
        );
    }

    /// A presentation for a DID that is not the one being verified is a
    /// security claim about a different subject, so it is rejected outright
    /// rather than contributing nothing.
    #[test]
    fn verify_right_window_rejects_document_for_foreign_did() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();

        // A document that is internally valid but belongs to another DID.
        let foreign =
            make_rights_doc_for_did(1, None, &crate::did::Did::bob(), key_str, "impersonate");
        let foreign_cid = foreign.compute_content_id().unwrap();

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: foreign_cid,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            ..DidHistory::new(test_did())
        };

        let err = history
            .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&foreign]))
            .expect_err("a document for another DID must be rejected");
        assert_eq!(
            err,
            CommitmentDocumentError::ForeignDid {
                document_did: crate::did::Did::bob(),
                history_did: test_did(),
            }
        );
    }

    /// A commitment published under an algorithm this build cannot verify makes
    /// the timeline unverifiable — no document can ever match it — so it is
    /// reported rather than read as "right not granted".
    #[test]
    fn verify_right_window_rejects_commitment_with_unsupported_algorithm() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let doc = make_rights_doc(1, None, key_str, "impersonate");

        // A `cb` (BLAKE3 flat) commitment: representable, but not a commitment
        // algorithm — a flat hash has no canonical-JSON preimage a document
        // could reproduce.
        let flat = ContentId::from_bytes(b"not a rights document");
        assert!(!flat.is_supported_commitment_algorithm());

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: flat,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            ..DidHistory::new(test_did())
        };

        let err = history
            .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&doc]))
            .expect_err("an unverifiable commitment must be reported, not skipped");
        assert_eq!(
            err,
            CommitmentDocumentError::UnsupportedAlgorithm { sequence: 1, content_id: flat }
        );
    }

    /// A `cj` (structured SHA3) commitment is permitted: the document declares
    /// its algorithm, the verifier dispatches on the declaration, and the
    /// content IDs compare as typed values.
    #[test]
    fn verify_right_window_accepts_commitment_with_sha3_algorithm() {
        use json_digest::JsonDigest;
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();

        // The document declares SHA3, so its content ID is the `cj` value the
        // commitment must carry.
        let raw = UnsafeRightsDocument {
            schema: RIGHTS_DOCUMENT_V1_SCHEMA.into(),
            did: test_did().to_did_string(),
            sequence: 1,
            previous_commitment: None,
            hash_algorithm: crate::rights::ContentHashAlgorithm::Sha3CanonicalJson,
            rights: alloc::vec![crate::rights::UnsafeRightEntry {
                key: key_str.into(),
                rights: alloc::vec!["impersonate".into()],
            }],
        };
        let sha3 = raw.compute_content_id().unwrap();
        assert!(matches!(sha3, ContentId::Structured(JsonDigest::Sha3(_))));
        assert!(sha3.is_supported_commitment_algorithm());
        let doc: crate::rights::RightsDocument =
            raw.try_into().expect("the declaration is well formed");

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: sha3,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            ..DidHistory::new(test_did())
        };

        assert_eq!(
            history
                .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&doc]))
                .unwrap(),
            ValidityResult::Confirmed,
            "a SHA3 commitment must verify against a document that declares SHA3"
        );
    }

    /// A chain-start document legitimately carries no predecessor.
    #[test]
    fn verify_right_window_accepts_chain_start_without_previous_commitment() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let (doc, cid) = make_rights_doc_cid(1, None, key_str, "impersonate");

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: cid,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: true,
            }],
            ..DidHistory::new(test_did())
        };

        assert_eq!(
            history
                .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&doc]))
                .unwrap(),
            ValidityResult::Confirmed
        );
    }

    /// A chain-start document that nevertheless claims a predecessor is
    /// inconsistent: it says "I supersede X" while sitting at the start of a
    /// chain that has no X.
    #[test]
    fn verify_right_window_rejects_chain_start_that_claims_a_predecessor() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let bogus_predecessor = ContentId::from_bytes(b"not a real predecessor");
        let (doc, cid) = make_rights_doc_cid(1, Some(bogus_predecessor), key_str, "impersonate");

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: cid,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: true,
            }],
            ..DidHistory::new(test_did())
        };

        let err = history
            .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&doc]))
            .expect_err("a chain start must not claim a predecessor");
        assert_eq!(err, CommitmentDocumentError::ChainBroken { sequence: 1 });
    }

    /// A `from_height` snapshot drops the commitments before the window, so
    /// its first visible entry is mid-chain and its real document legitimately
    /// carries a `previousCommitment` that is simply outside the snapshot.
    /// Demanding `None` there would break every genuinely truncated timeline.
    #[test]
    fn verify_right_window_accepts_a_truncated_snapshot_window() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();

        // Three commitments, each linking to the previous one.
        let (_d1, cid1) = make_rights_doc_cid(1, None, key_str, "impersonate");
        let (d2, cid2) = make_rights_doc_cid(2, Some(cid1), key_str, "impersonate");
        let (_d3, cid3) = make_rights_doc_cid(3, Some(cid2), key_str, "impersonate");

        let mut full = DidHistory::new(test_did());
        for (seq, cid, at) in [(1u64, cid1, 100u32), (2, cid2, 200), (3, cid3, 300)] {
            full.apply(DidHistoryEvent::CommitmentUpdated {
                sequence: seq,
                commitment: cid,
                signer_key_ref: kr.clone(),
                at_height: at,
            });
        }

        // Window from 250 drops sequence 1; sequence 2 becomes the visible
        // start while its true predecessor is out of scope.
        let snapshot = full.to_did_document_at(350, Some(250));
        let reconstructed = DidHistory::from_did_document_at(&snapshot, 350)
            .expect("a truncated snapshot must reconstruct");

        assert_eq!(reconstructed.commitments.len(), 2);
        assert_eq!(reconstructed.commitments[0].sequence, 2);
        assert!(
            !reconstructed.commitments[0].chain_start,
            "a mid-chain window start is not a chain start"
        );

        assert_eq!(
            reconstructed
                .verify_right_window(&kr, Right::Impersonate, 200, Some(300), &set1(&[&d2]))
                .unwrap(),
            ValidityResult::Confirmed,
            "the real document at the visible start must verify despite its \
             predecessor being outside the window"
        );
    }

    /// After a governed reset the chain restarts, and the *next* document must
    /// link back to the reset document. This is the case that reads the current
    /// entry's `chain_start` rather than the previous entry's.
    #[test]
    fn verify_right_window_after_reset_relinks_to_the_reset_document() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();

        // Pre-reset document, then a reset at sequence 2, then sequence 3.
        let (d1, cid1) = make_rights_doc_cid(1, None, key_str, "impersonate");
        let (d2, cid2) = make_rights_doc_cid(2, None, key_str, "issue"); // chain start
        let (d3, cid3) = make_rights_doc_cid(3, Some(cid2), key_str, "impersonate");

        let history = DidHistory {
            commitments: alloc::vec![
                CommitmentVersion {
                    sequence: 1,
                    commitment: cid1,
                    published_at_height: 100,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
                CommitmentVersion {
                    sequence: 2,
                    commitment: cid2,
                    published_at_height: 150,
                    signer_key_ref: kr.clone(),
                    chain_start: true,
                },
                CommitmentVersion {
                    sequence: 3,
                    commitment: cid3,
                    published_at_height: 200,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
            ],
            ..DidHistory::new(test_did())
        };

        assert_eq!(
            history
                .verify_right_window(&kr, Right::Impersonate, 200, Some(300), &set3(&d1, &d2, &d3))
                .unwrap(),
            ValidityResult::Confirmed,
            "the document after a reset must link to the reset document"
        );
    }

    /// A document that hashes correctly but names the wrong predecessor is
    /// rejected: it was genuinely committed, yet its supersession claim is
    /// unproven.
    #[test]
    fn verify_right_window_rejects_document_naming_the_wrong_predecessor() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();

        let (d1, cid1) = make_rights_doc_cid(1, None, key_str, "impersonate");
        let (d2, _cid2) = make_rights_doc_cid(2, Some(cid1), key_str, "issue");
        // A third document, correct sequence, but pointing at the wrong parent.
        let (d3, _cid3) = make_rights_doc_cid(
            3,
            Some(ContentId::from_bytes(b"wrong parent")),
            key_str,
            "impersonate",
        );
        let history = DidHistory {
            commitments: alloc::vec![
                CommitmentVersion {
                    sequence: 1,
                    commitment: cid1,
                    published_at_height: 100,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
                CommitmentVersion {
                    sequence: 2,
                    commitment: make_rights_doc(2, Some(cid1), key_str, "issue")
                        .compute_content_id()
                        .unwrap(),
                    published_at_height: 150,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
                CommitmentVersion {
                    sequence: 3,
                    commitment: d3.compute_content_id().unwrap(),
                    published_at_height: 200,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
            ],
            ..DidHistory::new(test_did())
        };

        let err = history
            .verify_right_window(&kr, Right::Impersonate, 200, Some(300), &set3(&d1, &d2, &d3))
            .expect_err("a wrong predecessor must be rejected");
        assert_eq!(err, CommitmentDocumentError::ChainBroken { sequence: 3 });
    }

    /// iop-rs#1 pin: a presenter-supplied document that grants the right but
    /// does not hash to the on-chain commitment contributes nothing, even when
    /// its sequence matches.
    #[test]
    fn verify_right_window_commitment_hash_mismatch_grants_nothing() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let doc = make_rights_doc(1, None, key_str, "impersonate");

        // Commitment is the hash of DIFFERENT content, sequence matches.
        let wrong_cid = make_rights_doc(1, None, key_str, "issue").compute_content_id().unwrap();

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: wrong_cid,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            ..DidHistory::new(test_did())
        };

        assert_eq!(
            history
                .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&doc]))
                .unwrap(),
            ValidityResult::Absent
        );
    }

    #[test]
    fn verify_right_window_commitment_full_window_confirmed() {
        // Commitment published at 100 grants Impersonate. Window [100, 200).
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let doc = make_rights_doc(1, None, key_str, "impersonate");
        let cid: ContentId = doc.compute_content_id().unwrap();

        let history = DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: cid,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            ..DidHistory::new(test_did())
        };

        assert_eq!(
            history
                .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&doc]))
                .unwrap(),
            ValidityResult::Confirmed
        );
    }

    #[test]
    fn verify_right_window_commitment_omits_mid_window_ambiguous() {
        // Two commitments: C1 at 100 grants Impersonate, C2 at 150 omits it.
        // Window [100, 200) → Ambiguous with gap [150, 200).
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let (d1, cid1) = make_rights_doc_cid(1, None, key_str, "impersonate");
        // grants issue, NOT impersonate; chains back to cid1
        let (d2, cid2) = make_rights_doc_cid(2, Some(cid1), key_str, "issue");

        let history = DidHistory {
            commitments: alloc::vec![
                CommitmentVersion {
                    sequence: 1,
                    commitment: cid1,
                    published_at_height: 100,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
                CommitmentVersion {
                    sequence: 2,
                    commitment: cid2,
                    published_at_height: 150,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
            ],
            ..DidHistory::new(test_did())
        };

        let result = history
            .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set2(&d1, &d2))
            .unwrap();
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(gaps.len(), 1);
                assert_eq!(gaps[0].start, 150);
                assert_eq!(gaps[0].end, Some(200));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// Evidence can start after the window does. When the window's lower bound
    /// precedes the first commitment, the leading stretch has no off-chain
    /// rights proof and must be reported as a gap — never silently folded into
    /// a `Confirmed` verdict.
    #[test]
    fn verify_right_window_reports_a_gap_before_the_first_commitment() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();
        let (d1, cid1) = make_rights_doc_cid(1, None, key_str, "impersonate");
        let (_d2, cid2) = make_rights_doc_cid(2, Some(cid1), key_str, "impersonate");

        let history = DidHistory {
            commitments: alloc::vec![
                CommitmentVersion {
                    sequence: 1,
                    commitment: cid1,
                    published_at_height: 150,
                    signer_key_ref: kr.clone(),
                    chain_start: true,
                },
                CommitmentVersion {
                    sequence: 2,
                    commitment: cid2,
                    published_at_height: 250,
                    signer_key_ref: kr.clone(),
                    chain_start: false,
                },
            ],
            ..DidHistory::new(test_did())
        };

        // The first (and only presented) document was committed at 150, but
        // the window starts at 100: [100, 150) has no evidence.
        let result = history
            .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&d1]))
            .unwrap();
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(gaps.len(), 1, "expected exactly the leading gap: {gaps:?}");
                assert_eq!(gaps[0].start, 100);
                assert_eq!(gaps[0].end, Some(150));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// The same gap through the real snapshot path, with the presenter omitting
    /// the document that was active at the window start. Dropping the earliest
    /// document must not turn the unevidenced leading stretch into a silent
    /// grant.
    #[test]
    fn verify_right_window_snapshot_with_unevidenced_window_start_reports_a_gap() {
        let kr = test_key_ref(1);
        let key_str = kr.as_str().unwrap();

        // Commitment 1 is active at the window start (100); commitment 2 is
        // published later.
        let (_d1, cid1) = make_rights_doc_cid(1, None, key_str, "impersonate");
        let (d2, cid2) = make_rights_doc_cid(2, Some(cid1), key_str, "impersonate");

        let mut full = DidHistory::new(test_did());
        full.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 1,
            commitment: cid1,
            signer_key_ref: kr.clone(),
            at_height: 80,
        });
        full.apply(DidHistoryEvent::CommitmentUpdated {
            sequence: 2,
            commitment: cid2,
            signer_key_ref: kr.clone(),
            at_height: 150,
        });

        let snapshot = full.to_did_document_at(200, Some(100));
        let reconstructed =
            DidHistory::from_did_document_at(&snapshot, 200).expect("a snapshot must reconstruct");
        assert_eq!(reconstructed.commitments.len(), 2);

        // Only the 150 document is presented; the 80 one is withheld.
        let result = reconstructed
            .verify_right_window(&kr, Right::Impersonate, 100, Some(200), &set1(&[&d2]))
            .unwrap();
        match result {
            ValidityResult::Ambiguous { gaps } => {
                assert_eq!(
                    gaps.len(),
                    1,
                    "the unevidenced [100, 150) stretch must be a gap: {gaps:?}"
                );
                assert_eq!(gaps[0].start, 100);
                assert_eq!(gaps[0].end, Some(150));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    // ===== Serde round‑trip tests =====

    #[test]
    fn did_history_serde_roundtrip_includes_schema() {
        let did = test_did();
        let kr = test_key_ref(1);

        let history = build_test_history(did.clone(), kr);

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&history).expect("serialization must succeed");
        assert!(json.contains(r#""$schema""#), "wire format must include $schema field");
        assert!(
            json.contains(crate::history::DID_HISTORY_V1_SCHEMA),
            "$schema must be the V1 URI: {json}"
        );

        // Deserialize back
        let deserialized: DidHistory =
            serde_json::from_str(&json).expect("deserialization must succeed");

        // Round-trip equality
        assert_eq!(history.did, deserialized.did);
        assert_eq!(history.commitments.len(), deserialized.commitments.len());
        assert_eq!(history.keys.len(), deserialized.keys.len());
        assert_eq!(history.rights.len(), deserialized.rights.len());
        assert_eq!(history.tombstoned_at, deserialized.tombstoned_at);
    }

    #[test]
    fn did_history_schema_is_present_in_wire_format() {
        let mut history = DidHistory::new(test_did());
        let kr = test_key_ref(1);
        history.apply(DidHistoryEvent::KeyAdded {
            key_ref: kr.clone(),
            key_type: KeyType::Ed25519,
            controller: test_did(),
            public_key: alloc::vec![1u8; 32],
            at_height: 10,
            expires_at_height: None,
        });

        let json = serde_json::to_string(&history).expect("serialization must succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(
            parsed["$schema"].as_str(),
            Some(crate::history::DID_HISTORY_V1_SCHEMA),
            "$schema field must contain the V1 URI"
        );
    }

    #[test]
    fn did_history_serde_rejects_empty_schema() {
        let json = r#"{
            "$schema": "",
            "did": "did:mosaic:iozABC",
            "commitments": [],
            "keys": [],
            "rights": [],
            "tombstoned_at": null
        }"#;

        let result: Result<DidHistory, _> = serde_json::from_str(json);
        assert!(result.is_err(), "empty $schema must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("$schema"), "error should mention schema: {err}");
    }

    #[test]
    fn did_history_serde_rejects_unknown_schema() {
        let json = r#"{
            "$schema": "https://unknown-schema/v42",
            "did": "did:mosaic:iozABC",
            "commitments": [],
            "keys": [],
            "rights": [],
            "tombstoned_at": null
        }"#;

        let result: Result<DidHistory, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown $schema must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("v42"), "error should mention the version: {err}");
    }

    #[test]
    fn did_history_serde_rejects_missing_schema() {
        let json = r#"{
            "did": "did:mosaic:iozABC",
            "commitments": [],
            "keys": [],
            "rights": [],
            "tombstoned_at": null
        }"#;

        let result: Result<DidHistory, _> = serde_json::from_str(json);
        assert!(result.is_err(), "missing $schema must be rejected");
    }

    #[test]
    fn did_history_serde_roundtrip_commitment_version() {
        let cv = CommitmentVersion {
            sequence: 42,
            commitment: test_commitment(1),
            published_at_height: 100,
            signer_key_ref: test_key_ref(1),
            chain_start: false,
        };

        let json = serde_json::to_string(&cv).expect("serialization must succeed");
        let deserialized: CommitmentVersion =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(cv.sequence, deserialized.sequence);
        assert_eq!(cv.commitment, deserialized.commitment);
        assert_eq!(cv.published_at_height, deserialized.published_at_height);
        assert_eq!(cv.signer_key_ref, deserialized.signer_key_ref);
    }

    #[test]
    fn did_history_serde_roundtrip_right_lifecycle() {
        let rl = RightLifecycle {
            key_ref: test_key_ref(1),
            right: Right::Impersonate,
            granted_at_height: 10,
            expires_at_height: Some(100),
            revoked_at_height: None,
            matures_at_height: Some(50),
        };

        let json = serde_json::to_string(&rl).expect("serialization must succeed");
        let deserialized: RightLifecycle =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(rl.key_ref, deserialized.key_ref);
        assert_eq!(rl.right, deserialized.right);
        assert_eq!(rl.granted_at_height, deserialized.granted_at_height);
        assert_eq!(rl.expires_at_height, deserialized.expires_at_height);
        assert_eq!(rl.revoked_at_height, deserialized.revoked_at_height);
        assert_eq!(rl.matures_at_height, deserialized.matures_at_height);
    }

    #[test]
    fn did_history_serde_roundtrip_validity_result() {
        let confirmed = ValidityResult::Confirmed;
        let json = serde_json::to_string(&confirmed).expect("serialization must succeed");
        let back: ValidityResult =
            serde_json::from_str(&json).expect("deserialization must succeed");
        assert_eq!(confirmed, back);

        let absent = ValidityResult::Absent;
        let json = serde_json::to_string(&absent).expect("serialization must succeed");
        let back: ValidityResult =
            serde_json::from_str(&json).expect("deserialization must succeed");
        assert_eq!(absent, back);

        let ambiguous = ValidityResult::Ambiguous { gaps: alloc::vec![] };
        let json = serde_json::to_string(&ambiguous).expect("serialization must succeed");
        let back: ValidityResult =
            serde_json::from_str(&json).expect("deserialization must succeed");
        assert_eq!(ambiguous, back);
    }

    /// Build a non-trivial DidHistory for serde tests.
    fn build_test_history(did: crate::did::Did, kr: KeyRef) -> DidHistory {
        let controller = did.clone();
        DidHistory {
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment: test_commitment(1),
                published_at_height: 100,
                signer_key_ref: kr.clone(),
                chain_start: false,
            }],
            keys: alloc::vec![crate::state::VerificationMethod {
                key_ref: kr.clone(),
                key_type: KeyType::Ed25519,
                controller,
                public_key: alloc::vec![1u8; 32].try_into().unwrap(),
                added_at_height: 10,
                expires_at_height: None,
                revoked_at_height: None,
            }],
            rights: alloc::vec![RightLifecycle {
                key_ref: kr.clone(),
                right: Right::Impersonate,
                granted_at_height: 10,
                expires_at_height: None,
                revoked_at_height: None,
                matures_at_height: None,
            }],
            ..DidHistory::new(did)
        }
    }
}
