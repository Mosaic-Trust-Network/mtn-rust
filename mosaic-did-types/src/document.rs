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

/// Convert a KeyType to its W3C verification method type string.
/// Map a `KeyType` to its W3C `verificationMethod` type string.
pub fn key_type_to_w3c_string(key_type: KeyType) -> String {
    match key_type {
        KeyType::Ed25519 => "Ed25519VerificationKey2020".into(),
        KeyType::Secp256k1 => "EcdsaSecp256k1VerificationKey2019".into(),
        KeyType::Secp256r1 => "EcdsaSecp256r1VerificationKey2019".into(),
        KeyType::X25519 => "X25519KeyAgreementKey2020".into(),
    }
}

/// Encode a public key as multibase base58btc.
pub fn multibase_encode_key(key_bytes: &[u8]) -> String {
    let encoded = bs58::encode(key_bytes).into_string();
    alloc::format!("z{encoded}")
}
