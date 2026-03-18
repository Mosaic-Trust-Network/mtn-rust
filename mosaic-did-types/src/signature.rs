//! Multi-algorithm signature and public key types for `did:mosaic`.
//!
//! Thin wrappers around keyvault's [`MSignature`] and [`MPublicKey`] multicipher types.
//! `MultiSignature` provides SCALE codec compatibility for Substrate extrinsics.
//! `MultiPublicKey` provides signature verification with [`KeyType`] mapping.
//!
//! ## Cipher Suite
//!
//! `did:mosaic` uses the Ed25519Blake3 cipher suite: Ed25519 cryptography with
//! BLAKE3-256 key ID derivation. The `ed25519()` constructor produces Ed25519Blake3
//! signatures, and `from_key_type_and_bytes(Ed25519, ..)` produces Ed25519Blake3 keys.

use iop_keyvault::ed25519::{EdPublicKey, EdSignature};
use iop_keyvault::multicipher::{MKeyId, MPublicKey, MSignature};
use iop_keyvault::PublicKey;

use crate::operation::KeyType;

// ========== MultiSignature ==========

/// Multi-algorithm cryptographic signature wrapping keyvault's [`MSignature`].
///
/// Uses Ed25519Blake3 cipher suite for Ed25519 signatures (matching the
/// `did:mosaic` key derivation scheme) and Secp256k1 for Ethereum compat.
///
/// SCALE encoding uses keyvault's UTF-8 string-based byte representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiSignature(pub MSignature);

impl MultiSignature {
    /// Create an Ed25519Blake3 signature from raw 64 Ed25519 signature bytes.
    ///
    /// Always succeeds – `ed25519_dalek` accepts any 64-byte array as a
    /// `Signature` (mathematical validity is only checked during `verify()`).
    pub fn ed25519(sig: [u8; 64]) -> Self {
        let mut versioned = [0u8; 65];
        versioned[0] = 0x01; // Ed25519 SIGNATURE_VERSION1
        versioned[1..].copy_from_slice(&sig);
        let ed_sig = EdSignature::from_bytes(&versioned[..])
            .expect("64 bytes + version byte is always accepted by EdSignature");
        MultiSignature(MSignature::Ed25519Blake3(ed_sig))
    }

    /// Create a secp256k1 signature from raw 64 signature bytes (r ‖ s).
    ///
    /// Panics if `r` or `s` are zero or ≥ the secp256k1 curve order.
    pub fn secp256k1(sig: [u8; 64]) -> Self {
        use iop_keyvault::secp256k1::SecpSignature;
        let mut versioned = [0u8; 65];
        versioned[0] = 0x01; // Secp256k1 SIGNATURE_VERSION1
        versioned[1..].copy_from_slice(&sig);
        let secp_sig = SecpSignature::from_bytes(&versioned[..])
            .expect("valid secp256k1 r‖s bytes with version prefix");
        MultiSignature(MSignature::Secp256k1(secp_sig))
    }

    /// Returns the cipher suite algorithm name.
    pub fn algorithm(&self) -> &'static str {
        match &self.0 {
            MSignature::Ed25519(_) => "Ed25519",
            MSignature::Secp256k1(_) => "secp256k1",
            MSignature::Ed25519Blake3(_) => "Ed25519Blake3",
        }
    }

    /// Access the inner keyvault [`MSignature`].
    pub fn inner(&self) -> &MSignature {
        &self.0
    }
}

impl From<MSignature> for MultiSignature {
    fn from(sig: MSignature) -> Self {
        MultiSignature(sig)
    }
}

// ========== SCALE codec (Substrate) ==========

#[cfg(feature = "substrate")]
mod sig_scale_impls {
    use super::*;
    use parity_scale_codec::{Decode, Encode, EncodeLike};
    use scale_info::TypeInfo;

    impl EncodeLike for MultiSignature {}

    impl Encode for MultiSignature {
        fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
            let bytes = self.0.to_bytes();
            Encode::encode_to(&bytes, dest);
        }
    }

    impl Decode for MultiSignature {
        fn decode<I: parity_scale_codec::Input>(
            input: &mut I,
        ) -> Result<Self, parity_scale_codec::Error> {
            let bytes = Vec::<u8>::decode(input)?;
            let sig = MSignature::from_bytes(bytes)
                .map_err(|_| parity_scale_codec::Error::from("invalid MSignature encoding"))?;
            Ok(MultiSignature(sig))
        }
    }

    impl TypeInfo for MultiSignature {
        type Identity = Self;
        fn type_info() -> scale_info::Type {
            scale_info::Type::builder()
                .path(scale_info::Path::new(
                    "MultiSignature",
                    "mosaic_did_types::signature",
                ))
                .composite(
                    scale_info::build::Fields::unnamed()
                        .field(|f| f.ty::<Vec<u8>>().type_name("MSignature")),
                )
        }
    }
}

// ========== Serde ==========

#[cfg(feature = "serde")]
mod sig_serde_impls {
    use super::*;

    impl serde::Serialize for MultiSignature {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for MultiSignature {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            MSignature::deserialize(deserializer).map(MultiSignature)
        }
    }
}

// ========== MultiPublicKey ==========

/// Multi-algorithm public key wrapping keyvault's [`MPublicKey`].
///
/// Maps the pallet's [`KeyType`] enum to the correct keyvault cipher suite.
/// Provides signature verification and key ID derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiPublicKey(pub MPublicKey);

/// Maximum SCALE-encoded length of a MultiPublicKey.
///
/// MPublicKey strings are at most ~56 UTF-8 bytes (secp256k1 compressed).
/// SCALE encodes as a length-prefixed `Vec<u8>`: compact(len) + bytes.
const MAX_PK_ENCODED_LEN: usize = 66;

impl MultiPublicKey {
    /// Construct from a [`KeyType`] and raw public key bytes.
    ///
    /// Maps `KeyType::Ed25519` → `MPublicKey::Ed25519Blake3` (the `did:mosaic`
    /// cipher suite) and `KeyType::Secp256k1` → `MPublicKey::Secp256k1`.
    /// Returns `None` for key types that don't support signature verification
    /// (e.g. X25519 key agreement, Secp256r1 not yet implemented).
    pub fn from_key_type_and_bytes(key_type: KeyType, bytes: &[u8]) -> Option<Self> {
        match key_type {
            KeyType::Ed25519 => {
                let pk = EdPublicKey::from_bytes(bytes).ok()?;
                Some(MultiPublicKey(MPublicKey::Ed25519Blake3(pk)))
            }
            KeyType::Secp256k1 => {
                use iop_keyvault::secp256k1::SecpPublicKey;
                let pk = SecpPublicKey::from_bytes(bytes).ok()?;
                Some(MultiPublicKey(MPublicKey::Secp256k1(pk)))
            }
            _ => None,
        }
    }

    /// Derive the multicipher key ID from this public key.
    pub fn key_id(&self) -> MKeyId {
        self.0.key_id()
    }

    /// Verify a signature against this public key and message.
    ///
    /// Delegates to keyvault's [`PublicKey::verify()`] which handles cipher suite
    /// matching internally (rejects cross-suite signature/key pairs).
    pub fn verify(&self, message: &[u8], signature: &MultiSignature) -> bool {
        self.0.verify(message, &signature.0)
    }

    /// Access the inner keyvault [`MPublicKey`].
    pub fn inner(&self) -> &MPublicKey {
        &self.0
    }
}

impl From<MPublicKey> for MultiPublicKey {
    fn from(pk: MPublicKey) -> Self {
        MultiPublicKey(pk)
    }
}

// ========== MultiPublicKey SCALE codec ==========

#[cfg(feature = "substrate")]
mod pk_scale_impls {
    use super::*;
    use parity_scale_codec::{Decode, Encode, EncodeLike, MaxEncodedLen};
    use scale_info::TypeInfo;

    impl EncodeLike for MultiPublicKey {}

    impl Encode for MultiPublicKey {
        fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
            let bytes = self.0.to_bytes();
            Encode::encode_to(&bytes, dest);
        }
    }

    impl Decode for MultiPublicKey {
        fn decode<I: parity_scale_codec::Input>(
            input: &mut I,
        ) -> Result<Self, parity_scale_codec::Error> {
            let bytes = Vec::<u8>::decode(input)?;
            let pk = MPublicKey::from_bytes(bytes)
                .map_err(|_| parity_scale_codec::Error::from("invalid MPublicKey encoding"))?;
            Ok(MultiPublicKey(pk))
        }
    }

    impl MaxEncodedLen for MultiPublicKey {
        fn max_encoded_len() -> usize {
            MAX_PK_ENCODED_LEN
        }
    }

    impl TypeInfo for MultiPublicKey {
        type Identity = Self;
        fn type_info() -> scale_info::Type {
            scale_info::Type::builder()
                .path(scale_info::Path::new(
                    "MultiPublicKey",
                    "mosaic_did_types::signature",
                ))
                .composite(
                    scale_info::build::Fields::unnamed()
                        .field(|f| f.ty::<Vec<u8>>().type_name("MPublicKey")),
                )
        }
    }
}

// ========== MultiPublicKey Serde ==========

#[cfg(feature = "serde")]
mod pk_serde_impls {
    use super::*;

    impl serde::Serialize for MultiPublicKey {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for MultiPublicKey {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            MPublicKey::deserialize(deserializer).map(MultiPublicKey)
        }
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_signature_construction() {
        let sig = MultiSignature::ed25519([42u8; 64]);
        assert_eq!(sig.algorithm(), "Ed25519Blake3");
    }

    #[test]
    fn secp256k1_signature_construction() {
        // r=1, s=1 are valid non-zero secp256k1 scalars
        let mut sig_bytes = [0u8; 64];
        sig_bytes[31] = 1;
        sig_bytes[63] = 1;
        let sig = MultiSignature::secp256k1(sig_bytes);
        assert_eq!(sig.algorithm(), "secp256k1");
    }

    #[test]
    fn from_msignature_conversion() {
        let sig = MultiSignature::ed25519([0u8; 64]);
        let inner = sig.inner().clone();
        let converted = MultiSignature::from(inner);
        assert_eq!(sig, converted);
    }

    #[test]
    fn ed25519_public_key_from_valid_bytes() {
        // RFC 8032 test vector 1 public key
        let pk_bytes = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let pk = MultiPublicKey::from_key_type_and_bytes(KeyType::Ed25519, &pk_bytes);
        assert!(pk.is_some());
    }

    #[test]
    fn unsupported_key_type_returns_none() {
        let pk = MultiPublicKey::from_key_type_and_bytes(KeyType::X25519, &[0u8; 32]);
        assert!(pk.is_none());

        let pk = MultiPublicKey::from_key_type_and_bytes(KeyType::Secp256r1, &[0u8; 33]);
        assert!(pk.is_none());
    }

    #[test]
    fn cross_suite_verify_returns_false() {
        // Ed25519Blake3 key cannot verify a secp256k1 signature
        let pk_bytes = hex::decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let pk = MultiPublicKey::from_key_type_and_bytes(KeyType::Ed25519, &pk_bytes).unwrap();

        let mut sig_bytes = [0u8; 64];
        sig_bytes[31] = 1;
        sig_bytes[63] = 1;
        let sig = MultiSignature::secp256k1(sig_bytes);
        assert!(!pk.verify(b"test", &sig));
    }
}
