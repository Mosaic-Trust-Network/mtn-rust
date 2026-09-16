//! DID state types for the `did:mosaic` pallet.
//!
//! Consensus-critical types stored on-chain in `StorageMap<Did, DidState>`.
//! These types are bounded for deterministic `MaxEncodedLen` and safe on-chain
//! storage. W3C DID Document rendering is an indexer/SDK concern and lives in
//! `document.rs`.

use alloc::vec::Vec;

use bounded_collections::{BoundedBTreeMap, BoundedVec, ConstU32};

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

use crate::did::{ContentId, Did, KeyRef};
use crate::operation::{KeyType, MAX_PUBLIC_KEY_LEN, Right};
use crate::validity::is_height_valid;

// ========== PROTOCOL CONSTANTS ==========

/// Maximum number of keys per DID document.
pub const MAX_KEYS_PER_DID: u32 = 32;
/// Maximum number of right grants per DID document.
pub const MAX_RIGHTS_PER_DID: u32 = 64;
/// Maximum number of nonce entries per DID document.
pub const MAX_NONCES_PER_DID: u32 = 32;

// The nonce-eviction fallback in `update_nonce` relies on every live
// signer always fitting into the nonce map.
const _: () = assert!(MAX_KEYS_PER_DID <= MAX_NONCES_PER_DID);

// ========== CORE STATE TYPES ==========

/// A verification method (key) stored in `DidState`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[derive(Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Key reference (document fragment), e.g. "ioz9vVgY...".
    pub key_ref: KeyRef,
    /// Algorithm type.
    pub key_type: KeyType,
    /// Controller DID (usually the DID itself).
    pub controller: Did,
    /// Raw public key bytes.
    pub public_key: BoundedVec<u8, ConstU32<MAX_PUBLIC_KEY_LEN>>,
    /// Block height at which this key was added.
    pub added_at_height: u32,
    /// Optional block height at which this key expires.
    pub expires_at_height: Option<u32>,
    /// Block height at which this key was revoked (None if still active).
    pub revoked_at_height: Option<u32>,
}

impl VerificationMethod {
    /// Returns whether this key is valid (not expired, not revoked) at the given height.
    #[inline]
    pub fn is_valid_at(&self, height: u32) -> bool {
        is_height_valid(
            height,
            self.added_at_height,
            self.expires_at_height,
            self.revoked_at_height,
        )
    }

    /// Compute the block height at which this key becomes fully activated.
    ///
    /// Returns `added_at_height` unless the key has Update/Delegate rights
    /// with a maturity delay, in which case it returns the maximum of
    /// `added_at_height` and those maturity heights. Pass the full rights
    /// vector from the containing `DidState` or `DidHistory`.
    pub fn activated_at_height(&self, rights: &[RightGrant]) -> u32 {
        let max_maturity = rights
            .iter()
            .filter(|rg| {
                rg.key_ref == self.key_ref
                    && matches!(rg.right, Right::Update | Right::Delegate)
                    && rg.matures_at_height.is_some()
            })
            .filter_map(|rg| rg.matures_at_height)
            .max();
        max_maturity.unwrap_or(self.added_at_height)
    }
}

/// A right grant record stored in `DidState`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[derive(Serialize, Deserialize)]
pub struct RightGrant {
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
    /// For Update and Delegate rights, the key cannot exercise them until
    /// this height. None means immediate (implicit initial key rights).
    pub matures_at_height: Option<u32>,
}

impl RightGrant {
    /// Returns whether this right grant is active and matured at the given height.
    ///
    /// A right is active only if it has been granted, has not been revoked or
    /// expired, and (for Update/Delegate rights) the maturity delay has elapsed.
    /// `matures_at_height: None` means immediate maturity (implicit initial key rights).
    #[inline]
    pub fn is_active_at(&self, height: u32) -> bool {
        is_height_valid(
            height,
            self.granted_at_height,
            self.expires_at_height,
            self.revoked_at_height,
        ) && self.matures_at_height.is_none_or(|m| height >= m)
    }
}

/// DID document state with bounded collections.
///
/// Stored directly in pallet storage (`StorageMap<Did, DidState>`) and also
/// usable off-chain. All collections are bounded for deterministic
/// `MaxEncodedLen` and safe on-chain storage.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[derive(Serialize, Deserialize)]
pub struct DidState {
    /// The DID this document describes.
    pub did: Did,
    /// All verification methods (keys), including revoked/expired ones for history.
    pub keys: BoundedVec<VerificationMethod, ConstU32<MAX_KEYS_PER_DID>>,
    /// All right grants, including revoked ones for history.
    pub rights: BoundedVec<RightGrant, ConstU32<MAX_RIGHTS_PER_DID>>,
    /// Block height at which this DID was tombstoned, if ever.
    pub tombstoned_at_height: Option<u32>,
    /// Per-key nonce for replay protection.
    pub nonces: BoundedBTreeMap<KeyRef, u64, ConstU32<MAX_NONCES_PER_DID>>,
    /// Latest rights-document commitment published by the DID controller.
    /// `(sequence, commitment_hash)`. `None` means no commitment has ever been published.
    pub commitment: Option<(u64, ContentId)>,
    /// Block height and extrinsic index of the most recent state change.
    /// Used by the rewind algorithm to check whether the current state
    /// covers a given target height.
    pub last_modified_at: (u32, u32),
}

impl DidState {
    /// Create a new empty DID state.
    pub fn new(did: Did) -> Self {
        Self {
            did,
            keys: BoundedVec::default(),
            rights: BoundedVec::default(),
            tombstoned_at_height: None,
            nonces: BoundedBTreeMap::default(),
            commitment: None,
            last_modified_at: (0, 0),
        }
    }

    /// Returns whether this DID exists (has at least one key).
    pub fn exists(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Returns whether this DID is tombstoned at the given height.
    pub fn is_tombstoned_at(&self, height: u32) -> bool {
        self.tombstoned_at_height.map(|h| height >= h).unwrap_or(false)
    }

    /// Find a key by its KeyRef.
    pub fn find_key(&self, key_ref: &KeyRef) -> Option<&VerificationMethod> {
        self.keys.iter().find(|k| k.key_ref == *key_ref)
    }

    /// Find a key by its KeyRef (mutable).
    pub fn find_key_mut(&mut self, key_ref: &KeyRef) -> Option<&mut VerificationMethod> {
        self.keys.iter_mut().find(|k| k.key_ref == *key_ref)
    }

    /// Returns all currently valid keys at the given height.
    pub fn valid_keys_at(&self, height: u32) -> Vec<&VerificationMethod> {
        self.keys.iter().filter(|k| k.is_valid_at(height)).collect()
    }

    /// Check if a key has a specific right at the given height.
    ///
    /// Both the key itself and the right grant must be valid at the given height.
    /// A revoked or expired key has no rights, even if the grant is still active.
    pub fn has_right_at(&self, key_ref: &KeyRef, right: Right, height: u32) -> bool {
        let key_valid = self.keys.iter().any(|k| k.key_ref == *key_ref && k.is_valid_at(height));

        key_valid
            && self
                .rights
                .iter()
                .any(|rg| rg.key_ref == *key_ref && rg.right == right && rg.is_active_at(height))
    }

    /// Get the current nonce for a key.
    pub fn nonce_for_key(&self, key_ref: &KeyRef) -> u64 {
        self.nonces.get(key_ref).copied().unwrap_or(0)
    }

    /// Update the nonce for a key, inserting if not present.
    ///
    /// Nonce entries of removed or invalidated keys persist so that
    /// re-registering the same `key_ref` cannot reset the replay window.
    /// That history is bounded by `MAX_NONCES_PER_DID`; when the map is
    /// full, an entry whose key can no longer sign (absent, revoked, or
    /// expired) is evicted instead of failing every future operation.
    /// Only a map whose entries all belong to currently valid keys
    /// returns `Err` — while `MAX_KEYS_PER_DID <= MAX_NONCES_PER_DID`
    /// (enforced below) every live signer always fits, so the map is
    /// never full of valid signers when a new one inserts.
    pub fn update_nonce(
        &mut self, key_ref: &KeyRef, nonce: u64, now: u32,
    ) -> Result<(), &'static str> {
        if let Some(existing) = self.nonces.get_mut(key_ref) {
            *existing = nonce;
            return Ok(());
        }
        if self.nonces.try_insert(key_ref.clone(), nonce).is_ok() {
            return Ok(());
        }
        let victim = self
            .nonces
            .keys()
            .find(|r| match self.find_key(r) {
                None => true,
                Some(k) => !k.is_valid_at(now),
            })
            .cloned();
        match victim {
            Some(v) => {
                self.nonces.remove(&v);
                self.nonces
                    .try_insert(key_ref.clone(), nonce)
                    .map(|_| ())
                    .map_err(|_| "nonce storage bounds exceeded")
            }
            None => Err("nonce storage bounds exceeded"),
        }
    }

    /// Render this state as a W3C DID Document evaluated at `height`.
    ///
    /// Mirrors `DidHistory::to_did_document_at` (history.rs) but operates
    /// directly on the materialized `DidState` — keys + rights — matching the
    /// TypeScript port `buildDidDocument` in authority-poc
    /// (services/blockchain-provider). W3C verification relationships are
    /// DERIVED from on-chain rights; keys without active rights are excluded:
    ///   authentication        ← any active right
    ///   assertionMethod       ← Right::Issue | Right::Impersonate
    ///   capabilityInvocation  ← Right::Update
    ///   capabilityDelegation  ← Right::Delegate
    pub fn to_did_document_at(&self, height: u32) -> crate::document::DidDocument {
        use crate::document::{
            DID_DOCUMENT_MOSAIC_CONTEXT, DID_DOCUMENT_W3C_CONTEXT, DidDocument,
            DidDocumentVerificationMethod, key_type_to_w3c_string, multibase_encode_key,
        };

        // Active on-chain rights per key at `height`.
        let rights_of = |key_ref: &KeyRef| -> Vec<Right> {
            self.rights
                .iter()
                .filter(|rg| rg.key_ref == *key_ref && rg.is_active_at(height))
                .map(|rg| rg.right)
                .collect()
        };

        // Valid keys that also hold active rights (righted_keys).
        let righted: Vec<(&VerificationMethod, Vec<Right>)> = self
            .keys
            .iter()
            .filter(|k| k.is_valid_at(height))
            .filter_map(|k| {
                let rs = rights_of(&k.key_ref);
                if rs.is_empty() { None } else { Some((k, rs)) }
            })
            .collect();

        let did_string = self.did.to_did_string();
        let verification_method: Vec<DidDocumentVerificationMethod> = righted
            .iter()
            .map(|(k, _)| DidDocumentVerificationMethod {
                id: alloc::format!("{}#{}", did_string, k.key_ref),
                type_: key_type_to_w3c_string(k.key_type),
                controller: did_string.clone(),
                public_key_multibase: multibase_encode_key(&k.public_key),
            })
            .collect();

        let authentication: Vec<alloc::string::String> =
            righted.iter().map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref)).collect();
        let assertion_method: Vec<alloc::string::String> = righted
            .iter()
            .filter(|(_, rs)| rs.iter().any(|r| matches!(r, Right::Issue | Right::Impersonate)))
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();
        let capability_invocation: Vec<alloc::string::String> = righted
            .iter()
            .filter(|(_, rs)| rs.iter().any(|r| matches!(r, Right::Update)))
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();
        let capability_delegation: Vec<alloc::string::String> = righted
            .iter()
            .filter(|(_, rs)| rs.iter().any(|r| matches!(r, Right::Delegate)))
            .map(|(k, _)| alloc::format!("{}#{}", did_string, k.key_ref))
            .collect();

        let created_at_height = self.keys.iter().map(|k| k.added_at_height).min();
        let last_modified_at_height = {
            let candidates: [Option<u32>; 4] = [
                self.keys.iter().map(|k| k.added_at_height).max(),
                self.keys.iter().filter_map(|k| k.revoked_at_height).max(),
                self.rights.iter().map(|r| r.granted_at_height).max(),
                self.rights.iter().filter_map(|r| r.revoked_at_height).max(),
            ];
            let from_candidates = candidates.into_iter().flatten().max();
            // `last_modified_at` is the authoritative last-mutation height —
            // revoked keys/rights are physically removed from the state, so
            // candidate heights alone would understate it (e.g. after
            // RevokeKey/RevokeRight). Fall back to candidates only when it is
            // unset (freshly-constructed states).
            match self.last_modified_at {
                (h, _) if h > 0 => Some(u32::min(h, height)),
                _ => from_candidates.map(|h| u32::min(h, height)),
            }
        };

        DidDocument {
            context: alloc::vec![
                DID_DOCUMENT_W3C_CONTEXT.into(),
                DID_DOCUMENT_MOSAIC_CONTEXT.into(),
            ],
            id: did_string,
            controller: None,
            also_known_as: None,
            verification_method,
            authentication,
            assertion_method,
            key_agreement: Vec::new(),
            capability_invocation,
            capability_delegation,
            service: Vec::new(),
            deactivated: self.tombstoned_at_height.is_some_and(|h| height >= h),
            created_at_height,
            last_modified_at_height,
            tombstoned_at_height: self.tombstoned_at_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bounded_collections::BoundedVec;

    fn test_pk_bytes() -> [u8; 32] {
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn test_key_ref() -> KeyRef {
        let auth = crate::auth::Authentication::from_key_type_and_bytes(
            KeyType::Ed25519,
            &test_pk_bytes(),
        )
        .unwrap();
        KeyRef::new(format!("{}", auth.key_id()).into_bytes()).unwrap()
    }

    fn test_key_ref_2() -> KeyRef {
        let pk: [u8; 32] =
            hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .unwrap()
                .try_into()
                .unwrap();
        let auth =
            crate::auth::Authentication::from_key_type_and_bytes(KeyType::Ed25519, &pk).unwrap();
        KeyRef::new(format!("{}", auth.key_id()).into_bytes()).unwrap()
    }

    fn make_test_state() -> DidState {
        let did = Did::alice();
        let mut state = DidState::new(did.clone());
        let pk: BoundedVec<u8, ConstU32<MAX_PUBLIC_KEY_LEN>> =
            test_pk_bytes().to_vec().try_into().unwrap();

        state
            .keys
            .try_push(VerificationMethod {
                key_ref: test_key_ref(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: pk,
                added_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
            })
            .unwrap();

        state
    }

    #[test]
    fn new_state_is_empty() {
        let state = DidState::new(Did::alice());
        assert!(!state.exists());
        assert!(!state.is_tombstoned_at(0));
        assert!(!state.is_tombstoned_at(1000));
    }

    #[test]
    fn new_state_has_default_commitment_fields() {
        let state = DidState::new(Did::alice());
        assert_eq!(state.commitment, None);
        assert_eq!(state.last_modified_at, (0, 0));
    }

    #[test]
    fn state_with_key_exists() {
        let state = make_test_state();
        assert!(state.exists());
    }

    #[test]
    fn key_validity_at_height() {
        let vm = VerificationMethod {
            key_ref: test_key_ref(),
            key_type: KeyType::Ed25519,
            controller: Did::bob(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            added_at_height: 10,
            expires_at_height: Some(100),
            revoked_at_height: None,
        };

        assert!(!vm.is_valid_at(9));
        assert!(vm.is_valid_at(10));
        assert!(vm.is_valid_at(50));
        assert!(vm.is_valid_at(99));
        assert!(!vm.is_valid_at(100));
    }

    #[test]
    fn key_revoked_at_height() {
        let vm = VerificationMethod {
            key_ref: test_key_ref(),
            key_type: KeyType::Ed25519,
            controller: Did::bob(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            added_at_height: 10,
            expires_at_height: None,
            revoked_at_height: Some(50),
        };

        assert!(vm.is_valid_at(10));
        assert!(vm.is_valid_at(49));
        assert!(!vm.is_valid_at(50));
        assert!(!vm.is_valid_at(100));
    }

    #[test]
    fn tombstoned_did() {
        let mut state = make_test_state();
        state.tombstoned_at_height = Some(50);

        assert!(!state.is_tombstoned_at(49));
        assert!(state.is_tombstoned_at(50));
        assert!(state.is_tombstoned_at(100));
    }

    #[test]
    fn bootstrap_rights_granted_implicitly() {
        let mut state = make_test_state();
        let key_ref: KeyRef = test_key_ref();

        // Simulates what the pallet does on DID creation: push bootstrapping rights.
        for right in [Right::Update, Right::Impersonate, Right::Delegate] {
            state
                .rights
                .try_push(RightGrant {
                    key_ref: key_ref.clone(),
                    right,
                    granted_at_height: 1,
                    expires_at_height: None,
                    revoked_at_height: None,
                    matures_at_height: None,
                })
                .unwrap();
        }

        assert!(state.has_right_at(&key_ref, Right::Update, 1));
        assert!(state.has_right_at(&key_ref, Right::Impersonate, 1));
        assert!(state.has_right_at(&key_ref, Right::Delegate, 1));
        assert!(!state.has_right_at(&key_ref, Right::Issue, 1));
    }

    #[test]
    fn explicit_right_grant() {
        let mut state = make_test_state();
        let key_ref = test_key_ref();

        state
            .rights
            .try_push(RightGrant {
                key_ref: key_ref.clone(),
                right: Right::Issue,
                granted_at_height: 10,
                expires_at_height: Some(100),
                revoked_at_height: None,
                matures_at_height: None,
            })
            .unwrap();

        assert!(!state.has_right_at(&key_ref, Right::Issue, 9));
        assert!(state.has_right_at(&key_ref, Right::Issue, 10));
        assert!(state.has_right_at(&key_ref, Right::Issue, 99));
        assert!(!state.has_right_at(&key_ref, Right::Issue, 100));
    }

    #[test]
    fn right_grant_maturity_delay() {
        let grant = RightGrant {
            key_ref: test_key_ref(),
            right: Right::Update,
            granted_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
            matures_at_height: Some(50),
        };

        // Not yet mature — not active even though grant started
        assert!(!grant.is_active_at(10));
        assert!(!grant.is_active_at(49));

        // Mature at height 50 — now active
        assert!(grant.is_active_at(50));
        assert!(grant.is_active_at(100));

        // None means immediate maturity — active as soon as granted
        let immediate = RightGrant { matures_at_height: None, ..grant.clone() };
        assert!(immediate.is_active_at(10));
    }

    #[test]
    fn activated_at_height_from_added_at() {
        let vm = VerificationMethod {
            key_ref: test_key_ref(),
            key_type: KeyType::Ed25519,
            controller: Did::alice(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            added_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
        };
        // No rights → activated_at = added_at
        assert_eq!(vm.activated_at_height(&[]), 10);
    }

    #[test]
    fn activated_at_height_from_maturity() {
        let vm = VerificationMethod {
            key_ref: test_key_ref(),
            key_type: KeyType::Ed25519,
            controller: Did::alice(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            added_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
        };
        let rights = alloc::vec![RightGrant {
            key_ref: test_key_ref(),
            right: Right::Update,
            granted_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
            matures_at_height: Some(50),
        }];
        // Maturity at 50 > added_at 10 → activated_at = 50
        assert_eq!(vm.activated_at_height(&rights), 50);
    }

    #[test]
    fn activated_at_height_ignores_other_keys() {
        let vm = VerificationMethod {
            key_ref: test_key_ref(),
            key_type: KeyType::Ed25519,
            controller: Did::alice(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            added_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
        };
        let rights = alloc::vec![RightGrant {
            key_ref: test_key_ref_2(),
            right: Right::Update,
            granted_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
            matures_at_height: Some(100),
        }];
        // key-2 maturity does not affect key-1
        assert_eq!(vm.activated_at_height(&rights), 10);
    }

    #[test]
    fn nonce_defaults_to_zero() {
        let state = make_test_state();
        let key_ref = test_key_ref();
        assert_eq!(state.nonce_for_key(&key_ref), 0);

        let unknown = "key-nonexistent".parse().unwrap();
        assert_eq!(state.nonce_for_key(&unknown), 0);
    }

    #[test]
    fn to_did_document_at_prefers_last_modified_at_over_candidates() {
        let mut state = make_test_state();
        // Revoked keys/rights are physically removed, so candidate heights
        // understate the last mutation — `last_modified_at` is authoritative.
        state.last_modified_at = (40, 1);
        let doc = state.to_did_document_at(100);
        assert_eq!(doc.last_modified_at_height, Some(40));
    }

    #[test]
    fn to_did_document_at_falls_back_to_candidates_when_unset() {
        let mut state = make_test_state();
        state.last_modified_at = (0, 0);
        let doc = state.to_did_document_at(100);
        // make_test_state adds its key at height 1 → candidate max is 1.
        assert_eq!(doc.last_modified_at_height, Some(1));
    }
}
