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

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::did::{ContentId, Did, KeyRef};
use crate::operation::{KeyType, Right};
use crate::rights::RightsDocument;

/// A commitment version in the DID history, reconstructed from events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentVersion {
    /// Monotonic sequence number (gapless, starting at 1).
    pub sequence: u64,
    /// The commitment hash (blake3 of the canonicalized rights document).
    pub commitment: ContentId,
    /// Block height at which this commitment was published on-chain.
    pub published_at_height: u32,
    /// Key reference of the signer who published this commitment.
    pub signer_key_ref: KeyRef,
}

/// On-chain right grant with full lifecycle information.
///
/// Similar to `RightGrant` in `document.rs`, but used in the indexer context
/// where the full lifecycle (including revoked entries) is preserved for
/// historical reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug)]
pub struct DidHistory {
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
    fn resolve(&self, content_id: &ContentId) -> Option<RightsDocument>;
}

impl DidHistory {
    /// Create an empty history for the given DID.
    pub fn new(did: Did) -> Self {
        Self {
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
                let cv = CommitmentVersion {
                    sequence,
                    commitment,
                    published_at_height: at_height,
                    signer_key_ref,
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

        // Check 2: commitment document (off-chain path)
        if let Some(cv) = self.commitment_at(height)
            && let Some(doc) = commitment_resolver.resolve(&cv.commitment)
            && doc.rights.iter().any(|entry| {
                entry.key_ref == key_ref.to_string() && entry.rights.contains(&right.to_string())
            })
        {
            return true;
        }

        false
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
    #[cfg(feature = "serde")]
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
                "https://www.w3.org/ns/did/v1".into(),
                "https://mosaic-trust.net/ns/did/v1".into(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test resolver that holds a map of ContentId -> RightsDocument.
    struct TestResolver {
        documents: Vec<(ContentId, RightsDocument)>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self { documents: Vec::new() }
        }

        fn insert(&mut self, content_id: ContentId, doc: RightsDocument) {
            self.documents.push((content_id, doc));
        }
    }

    impl CommitmentResolver for TestResolver {
        fn resolve(&self, content_id: &ContentId) -> Option<RightsDocument> {
            self.documents.iter().find(|(cid, _)| cid == content_id).map(|(_, doc)| doc.clone())
        }
    }

    fn test_did() -> crate::did::Did {
        crate::did::Did::alice()
    }

    fn test_key_ref(n: u8) -> KeyRef {
        use iop_keyvault::PrivateKey;
        use iop_keyvault::PublicKey;
        use iop_keyvault::ed25519::EdPrivateKey;

        // Deterministic seed from n
        let mut seed = [0u8; 32];
        seed[0] = n;
        seed[31] = 1;

        let sk = EdPrivateKey::from_bytes(&seed).unwrap();
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
            did,
            commitments: alloc::vec![
                CommitmentVersion {
                    sequence: 1,
                    commitment: test_commitment(1),
                    published_at_height: 100,
                    signer_key_ref: kr.clone(),
                },
                CommitmentVersion {
                    sequence: 2,
                    commitment: test_commitment(2),
                    published_at_height: 200,
                    signer_key_ref: kr.clone(),
                },
            ],
            keys: alloc::vec![],
            rights: alloc::vec![],
            tombstoned_at: None,
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
            did,
            commitments: alloc::vec![],
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
            rights: alloc::vec![],
            tombstoned_at: None,
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
            did,
            commitments: alloc::vec![],
            keys: alloc::vec![],
            rights: alloc::vec![RightLifecycle {
                key_ref: kr.clone(),
                right: Right::Impersonate,
                granted_at_height: 10,
                expires_at_height: None,
                revoked_at_height: Some(50),
                matures_at_height: None,
            }],
            tombstoned_at: None,
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
            did,
            commitments: alloc::vec![CommitmentVersion {
                sequence: 1,
                commitment,
                published_at_height: 100,
                signer_key_ref: kr.clone(),
            }],
            keys: alloc::vec![],
            rights: alloc::vec![],
            tombstoned_at: None,
        };

        let mut resolver = TestResolver::new();
        resolver.insert(
            commitment,
            RightsDocument {
                schema: "https://mosaic-trust.net/ns/did-rights/v1".into(),
                did: "did:mosaic:iozABC".into(),
                sequence: 1,
                previous_commitment: None,
                rights: alloc::vec![crate::rights::RightEntry {
                    key_ref: kr.to_string(),
                    rights: alloc::vec!["impersonate".into()],
                }],
            },
        );

        // No commitment before height 100
        assert!(!history.has_right_at(&kr, Right::Impersonate, 50, &resolver));

        // Commitment active at height 100+
        assert!(history.has_right_at(&kr, Right::Impersonate, 100, &resolver));
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

        assert_eq!(history.commitments.len(), 1);
        let cv = &history.commitments[0];
        assert_eq!(cv.sequence, 1);
        assert_eq!(cv.commitment, cid);
        assert_eq!(cv.published_at_height, 100);
        assert_eq!(cv.signer_key_ref, kr);
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

    #[cfg(feature = "serde")]
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

    #[cfg(feature = "serde")]
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
}
