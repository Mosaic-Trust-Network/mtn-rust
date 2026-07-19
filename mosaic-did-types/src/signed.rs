//! Generic signed envelope for off-chain payloads.
//!
//! `Signed<T>` wraps any serializable content with a cryptographic signature,
//! providing a standard envelope format for Verifiable Presentations,
//! AfterProofs, and other signed documents.

use alloc::vec::Vec;

use crate::did::ContentId;
use crate::signature::MultiSignature;

/// A generic signed envelope: content + cryptographic proof.
///
/// The signature covers the canonical JSON serialization of the `content` field.
/// The envelope format matches the legacy morpheus-proto `Signed<T>` wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signed<T> {
    /// The signed content.
    pub content: T,
    /// Cryptographic signature over the content.
    pub signature: SignedEnvelope,
    /// Optional nonce for replay protection.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nonce: Option<u64>,
}

/// Signature material within a `Signed<T>` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedEnvelope {
    /// The public key as a multicipher string (e.g. "pezFVen3X...").
    pub public_key: Vec<u8>,
    /// The raw signature bytes.
    pub bytes: Vec<u8>,
}

impl<T> Signed<T> {
    /// Create a new signed envelope.
    pub fn new(content: T, public_key_bytes: Vec<u8>, signature: MultiSignature) -> Self {
        Self {
            content,
            signature: SignedEnvelope {
                public_key: public_key_bytes,
                bytes: signature.0.to_bytes(),
            },
            nonce: None,
        }
    }

    /// Create a new signed envelope with a nonce.
    pub fn new_with_nonce(
        content: T, public_key_bytes: Vec<u8>, signature: MultiSignature, nonce: u64,
    ) -> Self {
        Self {
            content,
            signature: SignedEnvelope {
                public_key: public_key_bytes,
                bytes: signature.0.to_bytes(),
            },
            nonce: Some(nonce),
        }
    }
}

/// Trait for types that can be hashed to produce a content ID.
///
/// Provides consistent "what bytes get signed" semantics across all types.
pub trait Content: Clone {
    /// Compute the BLAKE3-256 flat-hash content ID from this value's serialization.
    fn content_id(&self) -> ContentId;
}

/// Trait for types that can be signed.
///
/// Extends `Content` with signing-specific serialization.
pub trait Signable: Content {
    /// The canonical bytes that are signed.
    ///
    /// By default, this is the content ID bytes. Override for custom signing payloads.
    fn content_to_sign(&self) -> Vec<u8> {
        self.content_id().as_bytes().to_vec()
    }

    /// Compute the fingerprint (SMT leaf hash) of the signed envelope.
    ///
    /// This is `blake3(canonical_json(self))` — used as the leaf hash in
    /// Sparse Merkle Tree batching (§6.4).
    fn fingerprint(&self) -> ContentId {
        self.content_id()
    }
}

/// A proof that a signature was created after a specific block height.
///
/// The signer observes a recent blockhash and embeds it in an `AfterEnvelope`.
/// Since the signer could not have known the blockhash before that block was
/// produced, `H_start = block_height + 1` is a cryptographic lower bound on
/// when the signature was created (§6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AfterProof {
    /// The block height whose hash is referenced.
    pub block_height: u32,
    /// The hash of the block at `block_height`.
    pub block_hash: Vec<u8>,
}

/// An envelope wrapping arbitrary content with an `AfterProof`.
///
/// When signed, this creates a `Signed<AfterEnvelope<T>>` — a lower-bound
/// time-bounded signature. The proof proves the signature was created after
/// `block_height` (§6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AfterEnvelope<T> {
    /// The signed content (e.g. an SMT batch root or a document digest).
    pub content: T,
    /// The lower-bound time proof.
    pub proof: AfterProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_envelope_construction() {
        let pk_bytes = b"test-public-key-bytes".to_vec();
        let sig = MultiSignature::ed25519([0u8; 64]);

        let signed = Signed::new("hello", pk_bytes.clone(), sig);
        assert_eq!(signed.nonce, None);
        assert_eq!(signed.signature.public_key, pk_bytes);
    }

    #[test]
    fn signed_envelope_with_nonce() {
        let pk_bytes = b"test-public-key".to_vec();
        let sig = MultiSignature::ed25519([0u8; 64]);

        let signed = Signed::new_with_nonce("hello", pk_bytes, sig, 42);
        assert_eq!(signed.nonce, Some(42));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn signed_json_roundtrip() {
        let pk_bytes = b"test-public-key".to_vec();
        let sig = MultiSignature::ed25519([0u8; 64]);

        let signed = Signed::new("hello", pk_bytes, sig);
        let json = serde_json::to_string(&signed).unwrap();
        assert!(json.contains("\"content\""));
        assert!(json.contains("\"signature\""));

        let parsed: Signed<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.content, "hello");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn signed_json_omits_none_nonce() {
        let pk_bytes = b"key".to_vec();
        let sig = MultiSignature::ed25519([0u8; 64]);

        let signed = Signed::new("x", pk_bytes, sig);
        let json = serde_json::to_string(&signed).unwrap();
        assert!(!json.contains("nonce"));
    }

    #[test]
    fn after_proof_construction() {
        let proof = AfterProof { block_height: 42, block_hash: b"0x0400abcdef".to_vec() };
        assert_eq!(proof.block_height, 42);
        assert_eq!(proof.block_hash, b"0x0400abcdef");
    }

    #[test]
    fn after_envelope_construction() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct SmtContent {
            root: alloc::string::String,
            height: u32,
        }

        let content = SmtContent { root: "cjuXXXX".into(), height: 10 };
        let proof = AfterProof { block_height: 42, block_hash: b"0x0400".to_vec() };
        let envelope = AfterEnvelope { content: content.clone(), proof: proof.clone() };
        assert_eq!(envelope.content, content);
        assert_eq!(envelope.proof, proof);
    }

    #[test]
    fn after_envelope_h_start_calculation() {
        let proof = AfterProof { block_height: 42, block_hash: b"hash".to_vec() };
        // H_start = block_height + 1 per §6.2
        let h_start = proof.block_height + 1;
        assert_eq!(h_start, 43);
    }
}
