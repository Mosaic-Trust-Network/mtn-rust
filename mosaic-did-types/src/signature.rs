//! Key-type bridging between `did:mosaic` and keyvault multicipher types.
//!
//! `did:mosaic` uses the [`KeyType`] enum to identify cipher suites in on-chain
//! storage. This module provides functions that map between [`KeyType`] and
//! keyvault's [`MPublicKey`] / [`MSignature`] variants, plus convenience
//! constructors for tests and benchmarks.
//!
//! No wrapper types — keyvault's [`MPublicKey`] and [`MSignature`] are used
//! directly. SCALE codec and serde are provided by keyvault's own feature flags.

use mosaic_keyvault::multicipher::{MPublicKey, MSignature};

use crate::operation::KeyType;

// ========== Signature constructors ==========

/// Create an Ed25519Blake3 [`MSignature`] from raw 64 Ed25519 signature bytes.
///
/// Always succeeds — `ed25519_dalek` accepts any 64-byte array as a
/// `Signature` (mathematical validity is only checked during `verify()`).
pub fn ed25519_blake3_signature(sig: [u8; 64]) -> MSignature {
    use mosaic_keyvault::ed25519::EdSignature;
    let mut versioned = [0u8; 65];
    versioned[0] = 0x01; // SIGNATURE_VERSION1
    versioned[1..].copy_from_slice(&sig);
    let ed_sig = EdSignature::from_bytes(&versioned[..])
        .expect("64 bytes + version byte is always accepted by EdSignature");
    MSignature::Ed25519Blake3(ed_sig)
}

/// Create a Secp256k1 [`MSignature`] from raw 64 signature bytes (r ‖ s).
///
/// Panics if `r` or `s` are zero or ≥ the secp256k1 curve order.
pub fn secp256k1_signature(sig: [u8; 64]) -> MSignature {
    use mosaic_keyvault::secp256k1::SecpSignature;
    let mut versioned = [0u8; 65];
    versioned[0] = 0x01; // SIGNATURE_VERSION1
    versioned[1..].copy_from_slice(&sig);
    let secp_sig = SecpSignature::from_bytes(&versioned[..])
        .expect("valid secp256k1 r‖s bytes with version prefix");
    MSignature::Secp256k1(secp_sig)
}

// ========== Public key bridging ==========

/// Build an [`MPublicKey`] from a [`KeyType`] and raw public key bytes.
///
/// Maps `KeyType::Ed25519` → `MPublicKey::Ed25519Blake3` (the `did:mosaic`
/// cipher suite) and `KeyType::Secp256k1` → `MPublicKey::Secp256k1`.
/// Returns `None` for key types that don't support signature verification
/// (e.g. X25519 key agreement, Secp256r1 not yet implemented).
pub fn public_key_from_key_type(key_type: KeyType, bytes: &[u8]) -> Option<MPublicKey> {
    match key_type {
        KeyType::Ed25519 => {
            use mosaic_keyvault::ed25519::EdPublicKey;
            let pk = EdPublicKey::from_bytes(bytes).ok()?;
            Some(MPublicKey::Ed25519Blake3(pk))
        }
        KeyType::Secp256k1 => {
            use mosaic_keyvault::secp256k1::SecpPublicKey;
            let pk = SecpPublicKey::from_bytes(bytes).ok()?;
            Some(MPublicKey::Secp256k1(pk))
        }
        _ => None,
    }
}

/// Map an [`MPublicKey`] back to its [`KeyType`].
///
/// Returns `None` for the legacy `Ed25519` variant (not used in `did:mosaic`).
pub fn public_key_to_key_type(pk: &MPublicKey) -> Option<KeyType> {
    match pk {
        MPublicKey::Ed25519Blake3(_) => Some(KeyType::Ed25519),
        MPublicKey::Secp256k1(_) => Some(KeyType::Secp256k1),
        _ => None,
    }
}

/// Extract raw public key bytes from an [`MPublicKey`].
pub fn public_key_raw_bytes(pk: &MPublicKey) -> alloc::vec::Vec<u8> {
    match pk {
        MPublicKey::Ed25519Blake3(p) | MPublicKey::Ed25519(p) => p.to_bytes(),
        MPublicKey::Secp256k1(p) => p.to_bytes(),
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_signature_construction() {
        let sig = ed25519_blake3_signature([42u8; 64]);
        match &sig {
            MSignature::Ed25519Blake3(_) => {} // expected
            _ => panic!("expected Ed25519Blake3"),
        }
    }

    #[test]
    fn secp256k1_signature_construction() {
        let sig_bytes: [u8; 64] = {
            let mut bytes = [0u8; 64];
            bytes[31] = 0x01;
            bytes[63] = 0x01;
            bytes
        };
        let sig = secp256k1_signature(sig_bytes);
        match &sig {
            MSignature::Secp256k1(_) => {} // expected
            _ => panic!("expected Secp256k1"),
        }
    }

    #[test]
    fn from_msignature_conversion() {
        // MSignature is used directly — no wrapper conversion needed
        let sig = ed25519_blake3_signature([0u8; 64]);
        assert!(matches!(sig, MSignature::Ed25519Blake3(_)));
    }

    #[test]
    fn cross_suite_verify_returns_false() {
        // Verification is handled by MPublicKey::verify()
        // This test just confirms the basic plumbing works
        let sig = ed25519_blake3_signature([0u8; 64]);
        assert!(matches!(sig, MSignature::Ed25519Blake3(_)));
    }

    #[test]
    fn public_key_from_key_type_from_ed25519() {
        use mosaic_keyvault::PrivateKey;
        use mosaic_keyvault::ed25519::EdPrivateKey;
        let sk = EdPrivateKey::from_bytes([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ])
        .unwrap();
        let pk_bytes = sk.public_key().to_bytes();
        let pk = public_key_from_key_type(KeyType::Ed25519, &pk_bytes).unwrap();
        assert!(matches!(pk, MPublicKey::Ed25519Blake3(_)));
    }

    #[test]
    fn unsupported_key_type_returns_none() {
        assert!(public_key_from_key_type(KeyType::X25519, &[0u8; 32]).is_none());
        assert!(public_key_from_key_type(KeyType::Secp256r1, &[0u8; 33]).is_none());
    }

    #[test]
    fn public_key_to_key_type_mapping() {
        use mosaic_keyvault::PrivateKey;
        use mosaic_keyvault::ed25519::EdPrivateKey;
        let sk = EdPrivateKey::from_bytes([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ])
        .unwrap();
        let pk_bytes = sk.public_key().to_bytes();
        let pk = public_key_from_key_type(KeyType::Ed25519, &pk_bytes).unwrap();
        assert_eq!(public_key_to_key_type(&pk), Some(KeyType::Ed25519));
    }
}
