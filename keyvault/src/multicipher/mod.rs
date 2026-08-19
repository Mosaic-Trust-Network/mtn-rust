//! A type-erased version of [`AsymmetricCrypto`] and [`KeyDerivationCrypto`]. Serialized versions
//! of crypto concepts, like [`KeyId`], [`PublicKey`], [`PrivateKey`], [`Signature`],
//! [`ExtendedPrivateKey`] and [`ExtendedPublicKey`] can be all deserialized into
//! their [`MultiCipher`] versions.
//! This allows multiple cryptographic algorithms to co-exist in a software, which is needed
//! during migration of a single software to a new cryptography, or which is the status quo in
//! larger software ecosystems.
//!
//! [`MultiCipher`] can be thought of a variant of multiple incompatible cipher suits, which are
//! strongly typed, but are chosen at run-time.
//!
//! [`MultiCipher`]: struct.MultiCipher.html
//! [`AsymmetricCrypto`]: ../trait.AsymmetricCrypto.html
//! [`KeyDerivationCrypto`]: ../trait.KeyDerivationCrypto.html
//! [`KeyId`]: ../trait.AsymmetricCrypto.html#associatedtype.KeyId
//! [`PublicKey`]: ../trait.PublicKey.html
//! [`PrivateKey`]: ../trait.PrivateKey.html
//! [`Signature`]: ../trait.AsymmetricCrypto.html#associatedtype.Signature
//! [`ExtendedPrivateKey`]: ../trait.ExtendedPrivateKey.html
//! [`ExtendedPublicKey`]: ../trait.ExtendedPublicKey.html

mod id;
mod pk;
mod sig;
mod sk;

use super::*;

use core::hash::Hash;

use crate::ed25519::{EdKeyId, EdPrivateKey, EdPublicKey, EdSignature};
use crate::error::KeyvaultError;
use crate::secp256k1::{SecpKeyId, SecpPrivateKey, SecpPublicKey, SecpSignature};
use crate::{AsymmetricCrypto, PrivateKey, PublicKey};

pub use id::MKeyId;
pub use pk::MPublicKey;
pub use sig::MSignature;
pub use sk::MPrivateKey;

/// A suite type that is used to keep the type-safety of the erased types in [`multicipher`]
///
/// [`multicipher`]: index.html
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum CipherSuite {
    /// The object tagged with this variant belongs to the [`ed25519`] module
    /// using the legacy Blake2b-MAC key ID derivation.
    ///
    /// [`ed25519`]: ../ed25519/index.html
    Ed25519,
    /// The object tagged with this variant belongs to the [`secp256k1`] module
    ///
    /// [`secp256k1`]: ../secp256k1/index.html
    Secp256k1,
    /// Ed25519 cryptography with Blake3 key ID derivation.
    /// Same signing/verification as [`Ed25519`], but key IDs use BLAKE3-256
    /// instead of the legacy salted Blake2b-MAC. Produces `ioz…` / `poz…` / `soz…` strings.
    Ed25519Blake3,
}

impl CipherSuite {
    fn as_byte(&self) -> u8 {
        match self {
            Self::Ed25519 => b'e',
            Self::Secp256k1 => b's',
            Self::Ed25519Blake3 => b'o',
        }
    }

    fn as_char(&self) -> char {
        self.as_byte() as char
    }

    fn from_char(c: char) -> Result<Self> {
        match c {
            'e' => Ok(Self::Ed25519),
            's' => Ok(Self::Secp256k1),
            'o' => Ok(Self::Ed25519Blake3),
            _ => Err(KeyvaultError::UnknownCryptoSuite { suite: c }),
        }
    }
}

#[derive(Clone, Debug)]
/// See the [module-level description](index.html).
pub struct MultiCipher;

impl AsymmetricCrypto for MultiCipher {
    type KeyId = MKeyId;
    type PublicKey = MPublicKey;
    type PrivateKey = MPrivateKey;
    type Signature = MSignature;
}

#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
/// Cipher-prefixed serialization of cryptographic entities
pub struct ErasedBytes {
    #[serde(rename = "s")]
    /// The cipher-suite prefix
    pub suite: u8,
    #[serde(rename = "v", with = "serde_bytes")]
    /// The suite-dependent serialization of the entity
    pub value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create() {
        let _cipher = MultiCipher {};
    }
}

#[cfg(all(test, feature = "substrate"))]
mod freeze_tests {
    //! SPEC-012 Frozen Wire-Format Registry regression pins.
    //!
    //! The crate is renamed to mosaic-keyvault, but these scale_info paths are
    //! embedded in live chain metadata. If one of these tests fails, someone
    //! changed a frozen path — that forks the type registry of every deployed
    //! chain. Do not update the expected strings; revert the change instead.

    use super::{MKeyId, MPublicKey, MSignature};
    use scale_info::TypeInfo as _;

    #[test]
    fn m_key_id_metadata_path_is_frozen() {
        let ty = MKeyId::type_info();
        let rendered = format!("{ty:?}");
        assert!(
            rendered.contains("iop_keyvault") && rendered.contains("multicipher"),
            "MKeyId scale_info path drifted from the frozen literal: {rendered}"
        );
    }

    #[test]
    fn m_public_key_metadata_path_is_frozen() {
        let ty = MPublicKey::type_info();
        let rendered = format!("{ty:?}");
        assert!(
            rendered.contains("iop_keyvault") && rendered.contains("multicipher"),
            "MPublicKey scale_info path drifted from the frozen literal: {rendered}"
        );
    }

    #[test]
    fn m_signature_metadata_path_is_frozen() {
        let ty = MSignature::type_info();
        let rendered = format!("{ty:?}");
        assert!(
            rendered.contains("iop_keyvault") && rendered.contains("multicipher"),
            "MSignature scale_info path drifted from the frozen literal: {rendered}"
        );
    }
}
