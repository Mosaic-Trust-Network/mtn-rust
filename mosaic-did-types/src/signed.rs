//! Generic signed envelope for off-chain payloads.
//!
//! `Signed<T>` wraps any serializable content with a cryptographic signature,
//! providing a standard envelope format for Verifiable Presentations,
//! AfterProofs, and other signed documents.

use iop_keyvault::multicipher::MSignature;

use crate::did::ContentId;

/// A generic signed envelope: content + cryptographic proof.
///
/// The signature covers the canonical JSON serialization of the `content` field.
/// The envelope format matches the legacy morpheus-proto `Signed<T>` wire format.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Signed<T> {
    /// The signed content.
    pub content: T,
    /// Cryptographic signature over the content.
    pub signature: SignedEnvelope,
    /// Optional nonce for replay protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
}

/// Signature material within a `Signed<T>` envelope.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedEnvelope {
    /// The public key as a multicipher string (e.g. "pezFVen3X...").
    #[serde(rename = "publicKey")]
    pub public_key: alloc::string::String,
    /// The multicipher signature string (e.g. "sez8TKYaZiP...").
    pub bytes: alloc::string::String,
}

impl<T> Signed<T> {
    /// Create a new signed envelope.
    pub fn new(content: T, public_key: alloc::string::String, signature: &MSignature) -> Self {
        Self {
            content,
            signature: SignedEnvelope { public_key, bytes: alloc::format!("{signature}") },
            nonce: None,
        }
    }

    /// Create a new signed envelope with a nonce.
    pub fn new_with_nonce(
        content: T, public_key: alloc::string::String, signature: &MSignature, nonce: u64,
    ) -> Self {
        Self {
            content,
            signature: SignedEnvelope { public_key, bytes: alloc::format!("{signature}") },
            nonce: Some(nonce),
        }
    }
}

/// Trait for types that can be hashed to produce a content ID.
pub trait Content: Clone {
    /// Compute the BLAKE3-256 flat-hash content ID from this value's serialization.
    fn content_id(&self) -> ContentId;
}

/// Trait for types that can be signed.
pub trait Signable: Content {
    /// The canonical bytes that are signed.
    fn content_to_sign(&self) -> alloc::vec::Vec<u8> {
        self.content_id().as_bytes().to_vec()
    }

    /// Compute the fingerprint (SMT leaf hash) of the signed envelope.
    fn fingerprint(&self) -> ContentId {
        self.content_id()
    }
}

/// A proof that a signature was created after a specific block height.
///
/// Since the signer could not have known the blockhash before that block was
/// produced, `H_start = block_height + 1` is a cryptographic lower bound.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AfterProof {
    #[serde(rename = "blockHeight")]
    pub block_height: u32,
    #[serde(rename = "blockHash")]
    pub block_hash: alloc::string::String,
}

/// An envelope wrapping arbitrary content with an `AfterProof`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AfterEnvelope<T> {
    pub content: T,
    pub proof: AfterProof,
}

/// SMT batch content for `AfterEnvelope<SmtContent>`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SmtContent {
    pub root: alloc::string::String,
    pub height: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::ed25519_blake3_signature;

    #[test]
    fn signed_envelope_construction() {
        let sig = ed25519_blake3_signature([0u8; 64]);
        let signed = Signed::new("hello", "test-key".into(), &sig);
        assert_eq!(signed.nonce, None);
        assert_eq!(signed.signature.public_key, "test-key");
    }

    #[test]
    fn signed_envelope_with_nonce() {
        let sig = ed25519_blake3_signature([0u8; 64]);
        let signed = Signed::new_with_nonce("hello", "test-key".into(), &sig, 42);
        assert_eq!(signed.nonce, Some(42));
    }

    #[test]
    fn signed_json_roundtrip() {
        let sig = ed25519_blake3_signature([0u8; 64]);
        let signed = Signed::new("hello", "test-key".into(), &sig);
        let json = serde_json::to_string(&signed).unwrap();
        assert!(json.contains("\"content\""));
        assert!(json.contains("\"signature\""));
        let parsed: Signed<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.content, "hello");
    }

    #[test]
    fn signed_json_omits_none_nonce() {
        let sig = ed25519_blake3_signature([0u8; 64]);
        let signed = Signed::new("x", "key".into(), &sig);
        let json = serde_json::to_string(&signed).unwrap();
        assert!(!json.contains("nonce"));
    }

    #[test]
    fn after_proof_construction() {
        let proof = AfterProof { block_height: 42, block_hash: "0x0400abcdef".into() };
        assert_eq!(proof.block_height, 42);
        assert_eq!(proof.block_hash, "0x0400abcdef");
    }

    #[test]
    fn after_envelope_construction() {
        let content = SmtContent { root: "cjuXXXX".into(), height: 10 };
        let proof = AfterProof { block_height: 42, block_hash: "0x0400".into() };
        let envelope = AfterEnvelope { content: content.clone(), proof: proof.clone() };
        assert_eq!(envelope.content, content);
        assert_eq!(envelope.proof, proof);
    }

    #[test]
    fn after_envelope_h_start_calculation() {
        let proof = AfterProof { block_height: 42, block_hash: "0xhash".into() };
        assert_eq!(proof.block_height + 1, 43);
    }

    // ===== Golden vectors (from morpheus-proto) =====

    #[test]
    fn after_envelope_golden_vector_single_document() {
        let sk_bytes: &[u8; 32] =
            b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60";
        let pk_string = "pezFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z";

        let content = SmtContent {
            root: "cjuF2OXGNIY3Zl5mFXZ9rq1s6dwq_QXtrPtqUjxrtga2jw".into(),
            height: 10,
        };
        let proof = AfterProof {
            block_height: 42,
            block_hash: "0x0400000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let block_height = proof.block_height;
        let envelope = AfterEnvelope { content, proof };

        // afterEnvelopeDigest
        let digest = json_digest::digest_data(&envelope).expect("digest_data should succeed");
        assert_eq!(digest, "cjuwowG6jmmPTiRFoayB76MQkytv1aFtDkRIO2q6eBirNs", "afterEnvelopeDigest");

        // Sign and verify
        use iop_keyvault::ed25519::EdPrivateKey;
        use iop_keyvault::{PrivateKey, PublicKey};
        let sk = EdPrivateKey::from_bytes(sk_bytes).expect("valid rfc8032 key");
        let pk = sk.public_key();
        let sig = sk.sign(digest.as_bytes());
        assert!(pk.verify(digest.as_bytes(), &sig), "signature must be valid");

        // Build Signed<AfterEnvelope> and compute fingerprint
        let signed = Signed::new(envelope.clone(), pk_string.into(), &MSignature::Ed25519(sig));
        let fingerprint =
            json_digest::digest_data(&signed).expect("fingerprint digest should succeed");
        assert_eq!(fingerprint, "cjua2swGJzAEP4vNAiVbD6lvLvwPDQkm9jnNZt4CDYfuZY", "fingerprint");

        assert_eq!(block_height + 1, 43);
    }
}
