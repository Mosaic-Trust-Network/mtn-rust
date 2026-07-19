//! DID Document types for `did:mosaic`.
//!
//! Contains the canonical state types used both on-chain (pallet storage)
//! and off-chain (API/SDK). A single set of types using bounded collections
//! eliminates the prior two-tree duplication and all conversion overhead.

use alloc::vec::Vec;

use bounded_collections::{BoundedBTreeMap, BoundedVec, ConstU32};

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::did::{ContentId, Did, KeyRef};
use crate::operation::{GovernedOperation, KeyPurpose, KeyType, MAX_PUBLIC_KEY_LEN, MAX_PURPOSES_PER_KEY, Right};
use crate::validity::is_height_valid;

// ========== PROTOCOL CONSTANTS ==========

/// Maximum number of keys per DID document.
pub const MAX_KEYS_PER_DID: u32 = 32;
/// Maximum number of right grants per DID document.
pub const MAX_RIGHTS_PER_DID: u32 = 64;
/// Maximum number of nonce entries per DID document.
pub const MAX_NONCES_PER_DID: u32 = 32;

// ========== CORE STATE TYPES ==========

/// A verification method in the DID Document.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerificationMethod {
    /// Key reference (document fragment), e.g. "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".
    pub key_ref: KeyRef,
    /// Algorithm type.
    pub key_type: KeyType,
    /// Controller DID (usually the DID itself).
    pub controller: Did,
    /// Raw public key bytes.
    pub public_key: BoundedVec<u8, ConstU32<MAX_PUBLIC_KEY_LEN>>,
    /// W3C verification relationships this key participates in.
    pub purposes: BoundedVec<KeyPurpose, ConstU32<MAX_PURPOSES_PER_KEY>>,
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

/// A right grant record.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

/// A pending governed operation awaiting its delay window.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PendingGovernedOp {
    /// The governed operation to execute.
    pub operation: GovernedOperation,
    /// Block height at which the operation was announced.
    pub announced_at_height: u32,
    /// Account that deposited the announcement bond.
    pub deposit_account: [u8; 32],
    /// Deposit amount locked for the governed operation.
    pub deposit_amount: u128,
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    /// Pending governed operation, if one has been announced.
    pub pending_operation: Option<PendingGovernedOp>,
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
            pending_operation: None,
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
        // The initial key (first key added) implicitly has Update, Impersonate, and
        // Delegate rights. Delegate is required to bootstrap the rights system (grant
        // rights to other keys). Without it, AddRight/RevokeRight are unreachable.
        if let Some(first_key) = self.keys.first()
            && first_key.key_ref == *key_ref
            && first_key.is_valid_at(height)
            && matches!(right, Right::Update | Right::Impersonate | Right::Delegate)
        {
            return true;
        }

        // For explicit rights: the key must be valid AND the grant must be active.
        // A revoked/expired key is cryptographically dead -- no rights survive revocation.
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
    /// Returns `Err` if the nonce map is full and the key is new.
    pub fn update_nonce(&mut self, key_ref: &KeyRef, nonce: u64) -> Result<(), &'static str> {
        if let Some(existing) = self.nonces.get_mut(key_ref) {
            *existing = nonce;
        } else {
            self.nonces
                .try_insert(key_ref.clone(), nonce)
                .map_err(|_| "nonce storage bounds exceeded")?;
        }
        Ok(())
    }
}

// ========== W3C DID DOCUMENT RENDERING ==========

#[cfg(feature = "serde")]
use alloc::string::String;

#[cfg(feature = "serde")]
impl DidState {
    /// Produce a W3C-compliant DID Document JSON structure at the given height.
    pub fn to_did_document_at(&self, height: u32) -> DidDocument {
        let deactivated = self.is_tombstoned_at(height);
        let valid_keys = self.valid_keys_at(height);

        let verification_methods: Vec<DidDocumentVerificationMethod> = valid_keys
            .iter()
            .map(|k| DidDocumentVerificationMethod {
                id: alloc::format!("{}#{}", self.did.to_did_string(), k.key_ref),
                type_: key_type_to_w3c_string(k.key_type),
                controller: self.did.to_did_string(),
                public_key_multibase: multibase_encode_key(&k.public_key),
            })
            .collect();

        let authentication: Vec<String> = valid_keys
            .iter()
            .filter(|k| k.purposes.contains(&KeyPurpose::Authentication))
            .map(|k| alloc::format!("{}#{}", self.did.to_did_string(), k.key_ref))
            .collect();

        let assertion_method: Vec<String> = valid_keys
            .iter()
            .filter(|k| k.purposes.contains(&KeyPurpose::AssertionMethod))
            .map(|k| alloc::format!("{}#{}", self.did.to_did_string(), k.key_ref))
            .collect();

        let key_agreement: Vec<String> = valid_keys
            .iter()
            .filter(|k| k.purposes.contains(&KeyPurpose::KeyAgreement))
            .map(|k| alloc::format!("{}#{}", self.did.to_did_string(), k.key_ref))
            .collect();

        let capability_invocation: Vec<String> = valid_keys
            .iter()
            .filter(|k| k.purposes.contains(&KeyPurpose::CapabilityInvocation))
            .map(|k| alloc::format!("{}#{}", self.did.to_did_string(), k.key_ref))
            .collect();

        let capability_delegation: Vec<String> = valid_keys
            .iter()
            .filter(|k| k.purposes.contains(&KeyPurpose::CapabilityDelegation))
            .map(|k| alloc::format!("{}#{}", self.did.to_did_string(), k.key_ref))
            .collect();

        DidDocument {
            context: alloc::vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://mosaic-trust.net/ns/did/v1".into(),
            ],
            id: self.did.to_did_string(),
            controller: Some(self.did.to_did_string()),
            verification_method: verification_methods,
            authentication,
            assertion_method,
            key_agreement,
            capability_invocation,
            capability_delegation,
            service: Vec::new(),
            deactivated,
        }
    }
}

/// W3C DID Core 1.0 compliant DID Document for external consumption.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<DidDocumentVerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "keyAgreement", skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,
    #[serde(rename = "capabilityInvocation", skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<String>,
    #[serde(rename = "capabilityDelegation", skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidDocumentService>,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub deactivated: bool,
}

/// A verification method entry in the W3C DID Document.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DidDocumentVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// A service endpoint in the W3C DID Document.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DidDocumentService {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Convert a KeyType to its W3C verification method type string.
#[cfg(feature = "serde")]
fn key_type_to_w3c_string(key_type: KeyType) -> String {
    match key_type {
        KeyType::Ed25519 => "Ed25519VerificationKey2020".into(),
        KeyType::Secp256k1 => "EcdsaSecp256k1VerificationKey2019".into(),
        KeyType::Secp256r1 => "EcdsaSecp256r1VerificationKey2019".into(),
        KeyType::X25519 => "X25519KeyAgreementKey2020".into(),
    }
}

/// Encode a public key as multibase base58btc.
#[cfg(feature = "serde")]
fn multibase_encode_key(key_bytes: &[u8]) -> String {
    let encoded = bs58::encode(key_bytes).into_string();
    alloc::format!("z{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bounded_collections::BoundedVec;

    fn make_test_state() -> DidState {
        let did = Did::alice();
        let mut state = DidState::new(did.clone());

        state
            .keys
            .try_push(VerificationMethod {
                key_ref: "key-1".parse().unwrap(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: hex::decode(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                purposes: alloc::vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                    .try_into()
                    .unwrap(),
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
        assert_eq!(state.pending_operation, None);
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
            key_ref: "key-1".parse().unwrap(),
            key_type: KeyType::Ed25519,
            controller: Did::bob(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            purposes: BoundedVec::default(),
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
            key_ref: "key-1".parse().unwrap(),
            key_type: KeyType::Ed25519,
            controller: Did::bob(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            purposes: BoundedVec::default(),
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
    fn initial_key_has_implicit_rights() {
        let state = make_test_state();
        let key_ref = "key-1".parse().unwrap();

        assert!(state.has_right_at(&key_ref, Right::Update, 1));
        assert!(state.has_right_at(&key_ref, Right::Impersonate, 1));
        assert!(state.has_right_at(&key_ref, Right::Delegate, 1));
        assert!(!state.has_right_at(&key_ref, Right::Issue, 1));
    }

    #[test]
    fn explicit_right_grant() {
        let mut state = make_test_state();
        let key_ref: KeyRef = "key-1".parse().unwrap();

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
            key_ref: "key-1".parse().unwrap(),
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
        let immediate = RightGrant {
            matures_at_height: None,
            ..grant.clone()
        };
        assert!(immediate.is_active_at(10));
    }

    #[test]
    fn activated_at_height_from_added_at() {
        let vm = VerificationMethod {
            key_ref: "key-1".parse().unwrap(),
            key_type: KeyType::Ed25519,
            controller: Did::alice(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            purposes: BoundedVec::default(),
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
            key_ref: "key-1".parse().unwrap(),
            key_type: KeyType::Ed25519,
            controller: Did::alice(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            purposes: BoundedVec::default(),
            added_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
        };
        let rights = alloc::vec![RightGrant {
            key_ref: "key-1".parse().unwrap(),
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
            key_ref: "key-1".parse().unwrap(),
            key_type: KeyType::Ed25519,
            controller: Did::alice(),
            public_key: alloc::vec![0u8; 32].try_into().unwrap(),
            purposes: BoundedVec::default(),
            added_at_height: 10,
            expires_at_height: None,
            revoked_at_height: None,
        };
        let rights = alloc::vec![RightGrant {
            key_ref: "key-2".parse().unwrap(),
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
        let key_ref = "key-1".parse().unwrap();
        assert_eq!(state.nonce_for_key(&key_ref), 0);

        let unknown = "key-nonexistent".parse().unwrap();
        assert_eq!(state.nonce_for_key(&unknown), 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn w3c_did_document_structure() {
        let pk_hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let did = Did::from_public_key(&pk_bytes).unwrap();

        let mut state = DidState::new(did.clone());
        state
            .keys
            .try_push(VerificationMethod {
                key_ref: "key-1".parse().unwrap(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: pk_bytes.try_into().unwrap(),
                purposes: alloc::vec![
                    KeyPurpose::Authentication,
                    KeyPurpose::AssertionMethod,
                    KeyPurpose::CapabilityDelegation,
                ]
                .try_into()
                .unwrap(),
                added_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
            })
            .unwrap();

        let doc = state.to_did_document_at(1);

        assert_eq!(doc.context[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(doc.context[1], "https://mosaic-trust.net/ns/did/v1");
        assert!(doc.id.starts_with("did:mosaic:ioz"));
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].type_, "Ed25519VerificationKey2020");
        assert!(doc.verification_method[0].public_key_multibase.starts_with('z'));
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.capability_delegation.len(), 1);
        assert!(doc.capability_invocation.is_empty());
        assert!(!doc.deactivated);

        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("\"@context\""));
        assert!(json.contains("\"verificationMethod\""));
        assert!(json.contains("\"Ed25519VerificationKey2020\""));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn tombstoned_did_document() {
        let mut state = make_test_state();
        state.tombstoned_at_height = Some(50);

        let doc = state.to_did_document_at(100);
        assert!(doc.deactivated);
    }
}
