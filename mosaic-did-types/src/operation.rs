//! DID operations for the `did:mosaic` method.
//!
//! All SSI state changes flow through signed operations submitted in atomic batches.
//! Phase 1 (MVP) implements the 5 core DID operations + BeforeProof.

#[cfg(feature = "substrate")]
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
#[cfg(feature = "substrate")]
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::auth::Authentication;
use crate::did::{ContentId, Did, KeyRef};
use iop_keyvault::multicipher::MSignature;

/// Maximum public key size in bytes.
pub const MAX_PUBLIC_KEY_LEN: u32 = 64;

/// Rights that can be assigned to keys in a DID Document.
///
/// The rights model extends IOP Morpheus (Update, Impersonate) with
/// additional capabilities for enterprise and compliance use cases.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Right {
    /// Can modify the DID Document (add/revoke keys, rights).
    Update,
    /// Can act on behalf of the DID (sign as the DID).
    Impersonate,
    /// Can grant rights to other keys.
    Delegate,
    /// Can issue Verifiable Credentials from this DID.
    Issue,
    /// Can revoke Verifiable Credentials from this DID.
    Revoke,
    /// Can perform RecoverDid operation (Phase 2).
    Recovery,
}

impl Right {
    /// Returns all Phase 1 (MVP) rights.
    pub fn phase1_variants() -> &'static [Right] {
        &[
            Right::Update,
            Right::Impersonate,
            Right::Delegate,
            Right::Issue,
            Right::Revoke,
            Right::Recovery,
        ]
    }

    /// Stable lower-case wire name for client bindings.
    pub fn as_str(&self) -> &'static str {
        match self {
            Right::Update => "update",
            Right::Impersonate => "impersonate",
            Right::Delegate => "delegate",
            Right::Issue => "issue",
            Right::Revoke => "revoke",
            Right::Recovery => "recovery",
        }
    }
}

impl core::fmt::Display for Right {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl core::str::FromStr for Right {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "update" | "Update" => Ok(Right::Update),
            "impersonate" | "Impersonate" => Ok(Right::Impersonate),
            "delegate" | "Delegate" => Ok(Right::Delegate),
            "issue" | "Issue" => Ok(Right::Issue),
            "revoke" | "Revoke" => Ok(Right::Revoke),
            "recovery" | "Recovery" => Ok(Right::Recovery),
            _ => Err("invalid Mosaic DID right"),
        }
    }
}

/// Supported key types for verification methods.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyType {
    /// Ed25519 -- default, required.
    Ed25519,
    /// secp256k1 -- Ethereum compatibility.
    Secp256k1,
    /// secp256r1 (P-256) -- HSM compatibility (Phase 2).
    Secp256r1,
    /// X25519 -- key agreement only (Phase 2).
    X25519,
}

impl KeyType {
    /// Stable lower-case wire name for client bindings.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Secp256k1 => "secp256k1",
            KeyType::Secp256r1 => "secp256r1",
            KeyType::X25519 => "x25519",
        }
    }
}

impl core::fmt::Display for KeyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl core::str::FromStr for KeyType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" | "Ed25519" => Ok(KeyType::Ed25519),
            "secp256k1" | "Secp256k1" => Ok(KeyType::Secp256k1),
            "secp256r1" | "Secp256r1" => Ok(KeyType::Secp256r1),
            "x25519" | "X25519" => Ok(KeyType::X25519),
            _ => Err("invalid Mosaic DID key type"),
        }
    }
}

/// Key purposes per W3C DID Core verification relationships.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyPurpose {
    /// Prove control of DID (login, challenge-response).
    Authentication,
    /// Sign Verifiable Credentials.
    AssertionMethod,
    /// Establish encrypted communication channel.
    KeyAgreement,
    /// Invoke capabilities.
    CapabilityInvocation,
    /// Delegate capabilities.
    CapabilityDelegation,
}

impl KeyPurpose {
    /// Stable lower-camel-case wire name for client bindings.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyPurpose::Authentication => "authentication",
            KeyPurpose::AssertionMethod => "assertionMethod",
            KeyPurpose::KeyAgreement => "keyAgreement",
            KeyPurpose::CapabilityInvocation => "capabilityInvocation",
            KeyPurpose::CapabilityDelegation => "capabilityDelegation",
        }
    }
}

impl core::fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl core::str::FromStr for KeyPurpose {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authentication" | "Authentication" => Ok(KeyPurpose::Authentication),
            "assertionMethod" | "AssertionMethod" => Ok(KeyPurpose::AssertionMethod),
            "keyAgreement" | "KeyAgreement" => Ok(KeyPurpose::KeyAgreement),
            "capabilityInvocation" | "CapabilityInvocation" => Ok(KeyPurpose::CapabilityInvocation),
            "capabilityDelegation" | "CapabilityDelegation" => Ok(KeyPurpose::CapabilityDelegation),
            _ => Err("invalid Mosaic DID key purpose"),
        }
    }
}

/// Phase 1 (MVP) DID operations.
///
/// All operations are submitted inside `SignedOperation` bundles within an
/// atomic `submit_did_operations` batch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DidOperation {
    /// Add a new key to the DID document.
    ///
    /// Implicit creation: the first `AddKey` for a DID creates that DID.
    /// The DID identifier MUST equal `BLAKE3-256(public_key)` for the initial key.
    ///
    /// The `auth` field must be the `PublicKey` variant – the chain needs the actual
    /// key bytes for signature verification. The key's document ID (`KeyRef`) and
    /// `KeyType` are derived from the [`Authentication`] value.
    AddKey {
        did: Did,
        auth: Authentication,
        /// Optional block height at which this key expires.
        expires_at_height: Option<u32>,
    },

    /// Revoke an existing key from the DID document.
    RevokeKey { did: Did, key_ref: KeyRef },

    /// Grant a right to a key.
    AddRight {
        did: Did,
        key_ref: KeyRef,
        right: Right,
        /// Optional block height at which this right grant expires.
        expires_at_height: Option<u32>,
    },

    /// Revoke a right from a key.
    RevokeRight { did: Did, key_ref: KeyRef, right: Right },

    /// Permanently deactivate the DID. Irreversible.
    ///
    /// After tombstoning:
    /// - Resolution returns `deactivated: true`
    /// - No further operations are accepted
    /// - Historical state remains queryable
    TombstoneDid { did: Did },

    /// Publish a new rights-document commitment.
    ///
    /// Requires `Right::Update`. The `sequence` MUST equal `stored_sequence + 1`
    /// — no gaps. Every sequence number must be anchored on-chain for the
    /// verifier to have a provable timestamp for that version.
    UpdateCommitment { did: Did, commitment: ContentId, sequence: u64 },

    /// Announce a governed operation (commitment reset or tombstone).
    ///
    /// Locks a deposit and starts a delay window. Only one governed operation
    /// can be pending per DID at a time.
    AnnounceGoverned { did: Did, operation: GovernedOperation },

    /// Cancel a pending governed operation.
    ///
    /// Releases the deposit to the gas wallet that submitted the cancel.
    CancelGoverned { did: Did },

    /// Execute a previously announced governed operation.
    ///
    /// Only valid after the delay window has elapsed and before expiry.
    ExecuteGoverned { did: Did },
}

impl DidOperation {
    /// Returns the DID this operation targets.
    pub fn did(&self) -> &Did {
        match self {
            DidOperation::AddKey { did, .. } => did,
            DidOperation::RevokeKey { did, .. } => did,
            DidOperation::AddRight { did, .. } => did,
            DidOperation::RevokeRight { did, .. } => did,
            DidOperation::TombstoneDid { did } => did,
            DidOperation::UpdateCommitment { did, .. } => did,
            DidOperation::AnnounceGoverned { did, .. } => did,
            DidOperation::CancelGoverned { did } => did,
            DidOperation::ExecuteGoverned { did } => did,
        }
    }

    /// Returns the required Right to perform this operation.
    pub fn required_right(&self) -> Right {
        match self {
            DidOperation::AddKey { .. } => Right::Update,
            DidOperation::RevokeKey { .. } => Right::Update,
            DidOperation::AddRight { .. } => Right::Delegate,
            DidOperation::RevokeRight { .. } => Right::Delegate,
            DidOperation::TombstoneDid { .. } => Right::Update,
            DidOperation::UpdateCommitment { .. } => Right::Update,
            DidOperation::AnnounceGoverned { .. } => Right::Update,
            DidOperation::CancelGoverned { .. } => Right::Update,
            DidOperation::ExecuteGoverned { .. } => Right::Update,
        }
    }
}

/// A governed operation that requires a delay window before execution.
///
/// Destructive state changes (commitment resets, tombstones) follow a shared
/// Announce → Delay → Execute lifecycle backed by an economic deposit.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GovernedOperation {
    /// Reset the commitment hash chain to a new starting point.
    CommitmentReset {
        /// Content ID of a document explaining the reason for the reset.
        reason: ContentId,
        /// The new commitment hash.
        commitment: ContentId,
        /// The new sequence number (must equal stored_sequence + 1).
        sequence: u64,
    },
    /// Permanently deactivate the DID.
    Tombstone,
}

/// A top-level SSI operation: either a DID operation or a BeforeProof timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo, DecodeWithMemTracking))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::large_enum_variant)] // Not worth Box-ing it in WASM
pub enum SsiOperation {
    /// A signed DID document operation.
    Did(SignedDidOperation),
    /// A BeforeProof timestamp registration (permissionless).
    BeforeProof(ContentId),
}

/// A signed DID operation bundle with proof of authorization.
///
/// The signature proves the signer has authority over the operation.
/// The nonce provides replay protection.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "substrate", derive(Encode, Decode, TypeInfo, DecodeWithMemTracking))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignedDidOperation {
    /// The DID operation to execute.
    pub operation: DidOperation,
    /// The key reference of the signer within the target DID document.
    pub signer_key_ref: KeyRef,
    /// Cryptographic signature over the operation.
    pub signature: MSignature,
    /// Monotonic nonce for replay protection (per-DID, per-key).
    pub nonce: u64,
}

/// Type of DID operation (for events, without carrying full data).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "substrate",
    derive(Encode, Decode, MaxEncodedLen, TypeInfo, DecodeWithMemTracking)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DidOperationType {
    AddKey,
    RevokeKey,
    AddRight,
    RevokeRight,
    TombstoneDid,
    UpdateCommitment,
    AnnounceGoverned,
    CancelGoverned,
    ExecuteGoverned,
}

impl From<&DidOperation> for DidOperationType {
    fn from(op: &DidOperation) -> Self {
        match op {
            DidOperation::AddKey { .. } => DidOperationType::AddKey,
            DidOperation::RevokeKey { .. } => DidOperationType::RevokeKey,
            DidOperation::AddRight { .. } => DidOperationType::AddRight,
            DidOperation::RevokeRight { .. } => DidOperationType::RevokeRight,
            DidOperation::TombstoneDid { .. } => DidOperationType::TombstoneDid,
            DidOperation::UpdateCommitment { .. } => DidOperationType::UpdateCommitment,
            DidOperation::AnnounceGoverned { .. } => DidOperationType::AnnounceGoverned,
            DidOperation::CancelGoverned { .. } => DidOperationType::CancelGoverned,
            DidOperation::ExecuteGoverned { .. } => DidOperationType::ExecuteGoverned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 test vector 1 public key
    const TEST_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn test_auth() -> Authentication {
        Authentication::from_key_type_and_bytes(KeyType::Ed25519, &TEST_PK).unwrap()
    }

    #[test]
    fn operation_did_accessor() {
        let did = Did::alice();

        let op =
            DidOperation::AddKey { did: did.clone(), auth: test_auth(), expires_at_height: None };

        assert_eq!(op.did(), &did);
        assert_eq!(op.required_right(), Right::Update);
    }

    #[test]
    fn operation_type_conversion() {
        let did = Did::alice();
        let auth = test_auth();
        let key_ref = KeyRef::new(format!("{}", auth.key_id()).into_bytes()).unwrap();

        let ops = alloc::vec![
            DidOperation::AddKey { did: did.clone(), auth: test_auth(), expires_at_height: None },
            DidOperation::RevokeKey { did: did.clone(), key_ref: key_ref.clone() },
            DidOperation::AddRight {
                did: did.clone(),
                key_ref: key_ref.clone(),
                right: Right::Update,
                expires_at_height: None,
            },
            DidOperation::RevokeRight {
                did: did.clone(),
                key_ref: key_ref.clone(),
                right: Right::Update
            },
            DidOperation::TombstoneDid { did },
        ];

        let types: Vec<DidOperationType> = ops.iter().map(DidOperationType::from).collect();
        assert_eq!(
            types,
            alloc::vec![
                DidOperationType::AddKey,
                DidOperationType::RevokeKey,
                DidOperationType::AddRight,
                DidOperationType::RevokeRight,
                DidOperationType::TombstoneDid,
            ]
        );
    }

    #[test]
    fn right_display() {
        assert_eq!(Right::Update.to_string(), "update");
        assert_eq!(Right::Impersonate.to_string(), "impersonate");
        assert_eq!(Right::Delegate.to_string(), "delegate");
        assert_eq!(Right::Issue.to_string(), "issue");
        assert_eq!(Right::Revoke.to_string(), "revoke");
        assert_eq!(Right::Recovery.to_string(), "recovery");
    }

    #[test]
    fn client_wire_names_parse_and_display() {
        assert_eq!("update".parse::<Right>().unwrap(), Right::Update);
        assert_eq!("Issue".parse::<Right>().unwrap(), Right::Issue);
        assert_eq!(Right::Recovery.to_string(), "recovery");

        assert_eq!("ed25519".parse::<KeyType>().unwrap(), KeyType::Ed25519);
        assert_eq!("Secp256k1".parse::<KeyType>().unwrap(), KeyType::Secp256k1);
        assert_eq!(KeyType::X25519.to_string(), "x25519");

        assert_eq!("assertionMethod".parse::<KeyPurpose>().unwrap(), KeyPurpose::AssertionMethod);
        assert_eq!(
            "CapabilityDelegation".parse::<KeyPurpose>().unwrap(),
            KeyPurpose::CapabilityDelegation
        );
        assert_eq!(KeyPurpose::KeyAgreement.to_string(), "keyAgreement");
    }

    #[test]
    fn client_wire_names_reject_unknown_values() {
        assert!("admin".parse::<Right>().is_err());
        assert!("rsa".parse::<KeyType>().is_err());
        assert!("signing".parse::<KeyPurpose>().is_err());
    }

    #[test]
    fn update_commitment_operation() {
        let did = Did::alice();
        let commitment = ContentId::from_bytes(b"test commitment");
        let op = DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence: 1 };
        assert_eq!(op.did(), &did);
        assert_eq!(op.required_right(), Right::Update);
    }

    #[test]
    fn governed_operation_variants() {
        let did = Did::alice();
        let commitment = ContentId::from_bytes(b"new commitment");
        let reason = ContentId::from_bytes(b"reason doc");

        let announce = DidOperation::AnnounceGoverned {
            did: did.clone(),
            operation: GovernedOperation::CommitmentReset { reason, commitment, sequence: 1 },
        };
        assert_eq!(announce.did(), &did);
        assert_eq!(announce.required_right(), Right::Update);

        let cancel = DidOperation::CancelGoverned { did: did.clone() };
        assert_eq!(cancel.did(), &did);
        assert_eq!(cancel.required_right(), Right::Update);

        let execute = DidOperation::ExecuteGoverned { did: did.clone() };
        assert_eq!(execute.did(), &did);
        assert_eq!(execute.required_right(), Right::Update);
    }

    #[test]
    fn governed_operation_type_conversion() {
        let did = Did::alice();
        let ops = alloc::vec![
            DidOperation::UpdateCommitment {
                did: did.clone(),
                commitment: ContentId::from_bytes(b"c1"),
                sequence: 1,
            },
            DidOperation::AnnounceGoverned {
                did: did.clone(),
                operation: GovernedOperation::Tombstone,
            },
            DidOperation::CancelGoverned { did: did.clone() },
            DidOperation::ExecuteGoverned { did },
        ];

        let types: Vec<DidOperationType> = ops.iter().map(DidOperationType::from).collect();
        assert_eq!(
            types,
            alloc::vec![
                DidOperationType::UpdateCommitment,
                DidOperationType::AnnounceGoverned,
                DidOperationType::CancelGoverned,
                DidOperationType::ExecuteGoverned,
            ]
        );
    }
}
