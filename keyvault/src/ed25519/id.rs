use blake2::{
    Blake2bMac,
    digest::{consts::U16, typenum::Unsigned},
};

use super::*;
use crate::multicipher::MKeyId;

type HashSize = U16;

/// This constant is used for keyed hashing of public keys. This does not improve the security
/// of the hash algorithm, but allows for domain separation if some use-case requires a different
/// hash of the public key with the same algorithm.
pub const KEY_ID_SALT: &[u8; 17] = b"open social graph";

/// The size of the legacy key identifier in bytes (version byte + 128-bit Blake2b MAC).
pub const KEY_ID_SIZE: usize = <HashSize as Unsigned>::USIZE + VERSION_SIZE;

/// The serialized byte representation for the legacy morpheus non-multihash algorithm
/// applied on the public key to obtain the key identifier
pub const KEY_ID_VERSION1: u8 = b'\x01';

/// Version byte for Blake3-derived key identifiers (multihash prefix for blake3).
pub const KEY_ID_VERSION_BLAKE3: u8 = b'\x1e';

/// The size of a Blake3 key identifier in bytes (version byte + 256-bit Blake3 hash).
pub const BLAKE3_KEY_ID_SIZE: usize = 32 + VERSION_SIZE;

/// A trait that makes it possible to use different hashing strategies for calculating key ids from public keys
pub trait IdHasher {
    /// A single-byte version prefix that will be prepended to the hash to discriminate it from other strategies
    const VERSION_BYTE: u8;

    /// The actual algorithm that hashes the public key bytes
    fn hash(pk: &EdPublicKey) -> Vec<u8>;
}

type Blake2bMacVar = Blake2bMac<HashSize>;

/// A hashing strategy used by legacy Morpheus, which is a salted Blake2b MAC using a non-standard version byte prefix
pub struct LegacyV1;

impl IdHasher for LegacyV1 {
    // 128-bit Blake2bMac with a salt would still use 0xb210 in multihash, but our legacy code just used
    // 0x01 as a version number
    const VERSION_BYTE: u8 = KEY_ID_VERSION1;

    fn hash(pk: &EdPublicKey) -> Vec<u8> {
        let mut hasher = <Blake2bMacVar as KeyInit>::new_from_slice(KEY_ID_SALT)
            .expect("KEY_ID_SALT is shorter than 512 bits for Blake2b512; qed");
        hasher.update(&pk.to_bytes());
        hasher.finalize().into_bytes().to_vec()
        // let mut hash = [0u8; KEY_ID_SIZE];
        // hash[0] = KEY_ID_VERSION1;
        // hash[VERSION_SIZE..].clone_from_slice(&hasher.finalize().into_bytes());
        // hash.into()
    }
}

/// A hashing strategy using plain Blake3 and the standard multihash prefix
pub struct Blake3;

impl IdHasher for Blake3 {
    const VERSION_BYTE: u8 = KEY_ID_VERSION_BLAKE3;

    fn hash(pk: &EdPublicKey) -> Vec<u8> {
        let hash = blake3::hash(&pk.to_bytes());
        hash.as_slice().to_vec()
    }
}

/// Implementation of Ed25519::KeyId
#[derive(Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct EdKeyId(Vec<u8>);

impl EdKeyId {
    /// The key id serialized in a format that can be fed to [`from_bytes`]
    ///
    /// [`from_bytes`]: #method.from_bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Creates a key id from a byte slice possibly returned by the [`to_bytes`] method.
    ///
    /// Accepts both legacy V1 key IDs (17 bytes, version `0x01`) and
    /// Blake3 key IDs (33 bytes, version `0x1e`).
    ///
    /// # Error
    /// If `bytes` has an unrecognised version byte or wrong length for its version.
    pub fn from_bytes<D: AsRef<[u8]>>(bytes: D) -> Result<Self> {
        let bytes = bytes.as_ref();
        match bytes.first() {
            Some(&KEY_ID_VERSION1) => {
                ensure!(bytes.len() == KEY_ID_SIZE, "Legacy key id must be {KEY_ID_SIZE} bytes");
                Ok(Self(bytes.to_owned()))
            }
            Some(&KEY_ID_VERSION_BLAKE3) => {
                ensure!(bytes.len() == BLAKE3_KEY_ID_SIZE, "Blake3 key id must be {BLAKE3_KEY_ID_SIZE} bytes");
                Ok(Self(bytes.to_owned()))
            }
            Some(v) => bail!("Unknown key id version byte 0x{v:02x}"),
            None => bail!("Empty key id bytes"),
        }
    }

    /// Creates a key id from a public key using a hashing strategy.
    ///
    /// Usage: `EdKeyId::from_pk::<Blake3>(pk)`
    pub fn from_pk<H: IdHasher>(pk: &EdPublicKey) -> Self {
        let mut hash = H::hash(pk);
        hash.insert(0, H::VERSION_BYTE);
        EdKeyId(hash)
    }
}

impl From<&EdPublicKey> for EdKeyId {
    fn from(pk: &EdPublicKey) -> Self {
        let mut hasher = <Blake2bMacVar as KeyInit>::new_from_slice(KEY_ID_SALT)
            .expect("KEY_ID_SALT is shorter than 512 bits for Blake2b512; qed");
        hasher.update(&pk.to_bytes());
        let mut hash = [0u8; KEY_ID_SIZE];
        hash[0] = KEY_ID_VERSION1;
        hash[VERSION_SIZE..].clone_from_slice(&hasher.finalize().into_bytes());
        EdKeyId(hash.into())
    }
}

impl fmt::Debug for EdKeyId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let id = MKeyId::from(self.clone());
        id.fmt(formatter)
    }
}
