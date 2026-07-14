use core::fmt;
use core::ops::Add;
use core::str::FromStr;

use super::*;
use crate::PublicKey;
use crate::error::KeyvaultError;

/// The size of the public key in the compressed format used by [`to_bytes`]
///
/// [`to_bytes`]: #method.to_bytes
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The size of the public key in the uncompressed format used by [`uncompressed`]
///
/// [`uncompressed`]: #method.uncompressed
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;

/// Implementation of Secp256k1::PublicKey
#[derive(Clone, Eq, PartialEq)]
pub struct SecpPublicKey(pub(super) KPublicKey);

impl SecpPublicKey {
    /// The public key serialized in a format that can be fed to [`from_bytes`]
    ///
    /// [`from_bytes`]: #method.from_bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Creates a public key from a byte slice possibly returned by the [`to_bytes`] method.
    ///
    /// # Error
    /// If `bytes` is rejected by `k256::PublicKey::from_sec1_bytes`
    ///
    /// [`to_bytes`]: #method.to_bytes
    pub fn from_bytes<D: AsRef<[u8]>>(bytes: D) -> Result<Self> {
        if bytes.as_ref().len() != PUBLIC_KEY_SIZE {
            return Err(KeyvaultError::PublicKeyLength { expected: PUBLIC_KEY_SIZE });
        }
        let pk = KPublicKey::from_sec1_bytes(bytes.as_ref()).map_err(display_err)?;
        Ok(Self(pk))
    }

    /// The public key serialized in the uncompressed format used in some places in the bitcoin
    /// ecosystem (like address hashing in [`SecpKeyId::bitcoin_address`])
    ///
    /// [`SecpKeyId::bitcoin_address`]: ../struct.SecpKeyId.html#method.bitcoin_address
    pub fn uncompressed(&self) -> [u8; PUBLIC_KEY_UNCOMPRESSED_SIZE] {
        let encoded = self.0.to_encoded_point(false);
        let mut bytes = [0u8; PUBLIC_KEY_UNCOMPRESSED_SIZE];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    /// ARK uses a non-standards hashing of the compressed public key.
    pub fn ark_key_id(&self) -> SecpKeyId {
        SecpKeyId::from_ark_pk(self)
    }

    /// ARK uses a non-standards hashing of the compressed public key.
    pub fn validate_ark_id(&self, key_id: &SecpKeyId) -> bool {
        &self.ark_key_id() == key_id
    }
}

impl Add<&[u8]> for &SecpPublicKey {
    type Output = Result<SecpPublicKey>;

    fn add(self, rhs: &[u8]) -> Self::Output {
        let tweak = scalar_from_bytes(rhs)?;
        let sum = self.0.to_projective() + ProjectivePoint::GENERATOR * tweak;
        Ok(SecpPublicKey(KPublicKey::from_affine(sum.to_affine()).map_err(display_err)?))
    }
}

impl PublicKey<Secp256k1> for SecpPublicKey {
    fn key_id(&self) -> SecpKeyId {
        SecpKeyId::from(self)
    }

    fn validate_id(&self, key_id: &SecpKeyId) -> bool {
        &self.key_id() == key_id
    }

    fn verify<D: AsRef<[u8]>>(&self, data: D, sig: &SecpSignature) -> bool {
        let msg = Secp256k1::hash_message(data);
        VerifyingKey::from(self.0).verify_prehash(&msg, &sig.0).is_ok()
    }
}

impl Hash for SecpPublicKey {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.to_bytes().hash(hasher);
    }
}

impl PartialOrd<Self> for SecpPublicKey {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Ord for SecpPublicKey {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.to_bytes().cmp(&rhs.to_bytes())
    }
}

impl FromStr for SecpPublicKey {
    type Err = KeyvaultError;
    fn from_str(src: &str) -> Result<Self> {
        Self::from_bytes(crate::hex_decode(src)?)
    }
}

impl fmt::Display for SecpPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for SecpPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> core::fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn string_roundtrip() -> Result<()> {
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk: SecpPublicKey = key.parse()?;
        assert_eq!(pk.to_string(), key);
        Ok(())
    }
}
