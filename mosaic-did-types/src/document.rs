//! W3C DID Document rendering types for `did:mosaic`.
//!
//! These types are used by the indexer/SDK to produce W3C-compliant DID
//! documents from the reconstructed `DidHistory` event stream. They are
//! purely a rendering concern — the pallet's consensus state lives in
//! `state.rs`.

#[cfg(feature = "serde")]
use crate::operation::KeyType;
#[cfg(feature = "serde")]
use alloc::string::String;
#[cfg(feature = "serde")]
use alloc::vec::Vec;

// ========== W3C DID DOCUMENT TYPES ==========

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

// ========== RENDERING HELPERS ==========

/// Convert a KeyType to its W3C verification method type string.
#[cfg(feature = "serde")]
pub fn key_type_to_w3c_string(key_type: KeyType) -> String {
    match key_type {
        KeyType::Ed25519 => "Ed25519VerificationKey2020".into(),
        KeyType::Secp256k1 => "EcdsaSecp256k1VerificationKey2019".into(),
        KeyType::Secp256r1 => "EcdsaSecp256r1VerificationKey2019".into(),
        KeyType::X25519 => "X25519KeyAgreementKey2020".into(),
    }
}

/// Encode a public key as multibase base58btc.
#[cfg(feature = "serde")]
pub fn multibase_encode_key(key_bytes: &[u8]) -> String {
    let encoded = bs58::encode(key_bytes).into_string();
    alloc::format!("z{encoded}")
}
