//! W3C DID Document rendering types for `did:mosaic`.
//!
//! These types are used by the indexer/SDK to produce W3C-compliant DID
//! documents from the reconstructed `DidHistory` event stream. They are
//! purely a rendering concern — the pallet's consensus state lives in
//! `state.rs`.

use alloc::string::String;
use alloc::vec::Vec;
use serde_json;

use crate::operation::KeyType;

// ========== DID Document context URIs ==========

/// W3C DID Core 1.0 JSON-LD context URI.
pub const DID_DOCUMENT_W3C_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// Mosaic DID extension JSON-LD context URI for mosaic-prefixed properties.
pub const DID_DOCUMENT_MOSAIC_CONTEXT: &str = "https://mosaic-trust.net/ns/did/v1";

// ========== W3C DID DOCUMENT TYPES ==========

/// W3C DID Core 1.0 compliant DID Document for external consumption.
///
/// Mosaic extensions (prefixed `mosaic:`) are added as top-level properties.
/// Unknown consumers safely ignore them per W3C DID Core §4.1.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    /// Optional reference to the full rights document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<String>,
    #[serde(rename = "verificationMethod")]
    #[serde(default)]
    pub verification_method: Vec<DidDocumentVerificationMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod", default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "keyAgreement", default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,
    #[serde(rename = "capabilityInvocation", default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<String>,
    #[serde(rename = "capabilityDelegation", default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidDocumentService>,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub deactivated: bool,

    // --- Mosaic extensions ---
    /// Block height at which the DID was created (first `KeyAdded`).
    #[serde(rename = "mosaic:createdAtHeight", skip_serializing_if = "Option::is_none")]
    pub created_at_height: Option<u32>,
    /// Block height at which the most recent state change occurred.
    #[serde(rename = "mosaic:lastModifiedAtHeight", skip_serializing_if = "Option::is_none")]
    pub last_modified_at_height: Option<u32>,
    /// Block height at which the DID was deactivated, if tombstoned.
    #[serde(rename = "mosaic:tombstonedAtHeight", skip_serializing_if = "Option::is_none")]
    pub tombstoned_at_height: Option<u32>,
}

/// A verification method entry in the W3C DID Document.
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
///
/// `service_endpoint` uses `serde_json::Value` to accommodate both
/// plain strings (standard services) and structured objects (mosaic extension
/// services like `MosaicRightsCommitment2026`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DidDocumentService {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,
}

// ========== RENDERING HELPERS ==========

/// Convert a [`KeyType`] to its W3C `verificationMethod` type string.
///
/// This `match` is exhaustive — adding a new `KeyType` variant will cause
/// a compile error here, reminding you to also update the reverse mapping
/// in [`w3c_type_to_key_type`].
pub fn key_type_to_w3c_string(key_type: KeyType) -> String {
    match key_type {
        KeyType::Ed25519 => "Ed25519VerificationKey2020".into(),
        KeyType::Secp256k1 => "EcdsaSecp256k1VerificationKey2019".into(),
        KeyType::Secp256r1 => "EcdsaSecp256r1VerificationKey2019".into(),
        KeyType::X25519 => "X25519KeyAgreementKey2020".into(),
    }
}

/// Reverse of [`key_type_to_w3c_string`]: parse a W3C verification method
/// type string back to a [`KeyType`].
///
/// Uses [`strum::IntoEnumIterator`] so all variants are automatically
/// covered. Adding a new variant to [`KeyType`] only requires updating the
/// exhaustive `match` in [`key_type_to_w3c_string`].
pub fn w3c_type_to_key_type(s: &str) -> Option<KeyType> {
    use strum::IntoEnumIterator;
    KeyType::iter().find(|&kt| key_type_to_w3c_string(kt) == s)
}

/// Encode a public key as multibase base58btc.
pub fn multibase_encode_key(key_bytes: &[u8]) -> String {
    let encoded = bs58::encode(key_bytes).into_string();
    alloc::format!("z{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "serde")]
    use crate::did::{Did, KeyRef};
    #[cfg(feature = "serde")]
    use crate::operation::Right;
    #[cfg(feature = "serde")]
    use crate::state::{DidState, RightGrant, VerificationMethod};

    #[test]
    fn w3c_key_type_roundtrip_all_variants() {
        use strum::IntoEnumIterator;
        for kt in KeyType::iter() {
            let s = key_type_to_w3c_string(kt);
            assert_eq!(w3c_type_to_key_type(&s), Some(kt));
        }
    }

    /// Golden DID document vector for the TypeScript port in authority-poc
    /// (`services/blockchain-provider`, did-operations.test.ts pins this exact
    /// output as a conformance test). Regenerate with:
    ///
    /// ```sh
    /// cargo test -p mosaic-did-types --features serde conformance_document_vector -- --nocapture
    /// ```
    ///
    /// When the expected JSON changes, update the pinned vector on the TS
    /// side in the same change.
    #[cfg(feature = "serde")]
    #[test]
    fn conformance_document_vector() {
        // RFC 8032 test vector 1 public key.
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let did = Did::from_public_key(&pk_bytes).unwrap();

        let mut state = DidState::new(did.clone());
        let key_ref: KeyRef = "key-1".parse().unwrap();
        state
            .keys
            .try_push(VerificationMethod {
                key_ref: key_ref.clone(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: pk_bytes.try_into().unwrap(),
                added_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
            })
            .unwrap();
        // Rights produce the W3C relationships in to_did_document_at:
        // Impersonate -> authentication + assertionMethod, Delegate -> capabilityDelegation.
        state
            .rights
            .try_push(RightGrant {
                key_ref: key_ref.clone(),
                right: Right::Impersonate,
                granted_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
                matures_at_height: None,
            })
            .unwrap();
        state
            .rights
            .try_push(RightGrant {
                key_ref,
                right: Right::Delegate,
                granted_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
                matures_at_height: None,
            })
            .unwrap();

        let doc = state.to_did_document_at(10);
        println!("CONFORMANCE_DOCUMENT_JSON={}", serde_json::to_string(&doc).unwrap());
    }
}
