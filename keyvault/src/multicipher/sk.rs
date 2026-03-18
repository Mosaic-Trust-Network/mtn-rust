use super::*;

/// Multicipher [`PrivateKey`]
///
/// [`PrivateKey`]: ../trait.AsymmetricCrypto.html#associatedtype.PrivateKey
#[derive(Clone)]
pub enum MPrivateKey {
    /// The private key tagged with this variant belongs to the [`ed25519`] module
    /// using the legacy Blake2b-MAC key ID derivation.
    ///
    /// [`ed25519`]: ../ed25519/index.html
    Ed25519(EdPrivateKey),
    /// The private key tagged with this variant belongs to the [`secp256k1`] module
    ///
    /// [`secp256k1`]: ../secp256k1/index.html
    Secp256k1(SecpPrivateKey),
    /// Ed25519 private key under the Blake3 cipher suite.
    Ed25519Blake3(EdPrivateKey),
}

impl PrivateKey<MultiCipher> for MPrivateKey {
    fn public_key(&self) -> MPublicKey {
        match self {
            Self::Ed25519(edsk) => MPublicKey::from(edsk.public_key()),
            Self::Secp256k1(secpsk) => MPublicKey::from(secpsk.public_key()),
            Self::Ed25519Blake3(edsk) => MPublicKey::Ed25519Blake3(edsk.public_key()),
        }
    }
    fn sign<D: AsRef<[u8]>>(&self, data: D) -> MSignature {
        match self {
            Self::Ed25519(edsk) => MSignature::from(edsk.sign(data)),
            Self::Secp256k1(secpsk) => MSignature::from(secpsk.sign(data)),
            Self::Ed25519Blake3(edsk) => MSignature::Ed25519Blake3(edsk.sign(data)),
        }
    }
}

impl From<EdPrivateKey> for MPrivateKey {
    fn from(src: EdPrivateKey) -> Self {
        Self::Ed25519(src)
    }
}

impl From<SecpPrivateKey> for MPrivateKey {
    fn from(src: SecpPrivateKey) -> Self {
        Self::Secp256k1(src)
    }
}
