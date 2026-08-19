use super::*;
use crate::error::KeyvaultError;

/// Multicipher [`KeyId`]
///
/// [`KeyId`]: ../trait.AsymmetricCrypto.html#associatedtype.KeyId
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MKeyId {
    /// The key id tagged with this variant belongs to the [`ed25519`] module
    /// using the legacy Blake2b-MAC key ID derivation.
    ///
    /// [`ed25519`]: ../ed25519/index.html
    Ed25519(EdKeyId),
    /// The key id tagged with this variant belongs to the [`secp256k1`] module
    ///
    /// [`secp256k1`]: ../secp256k1/index.html
    Secp256k1(SecpKeyId),
    /// Ed25519 key id derived via Blake3 hashing. Same inner type, different derivation.
    Ed25519Blake3(EdKeyId),
}

impl MKeyId {
    /// All multicipher key ids start with this prefix
    pub const PREFIX: char = 'i';

    /// The ciphersuite that this key id belongs to
    pub fn suite(&self) -> CipherSuite {
        match self {
            Self::Ed25519(_) => CipherSuite::Ed25519,
            Self::Secp256k1(_) => CipherSuite::Secp256k1,
            Self::Ed25519Blake3(_) => CipherSuite::Ed25519Blake3,
        }
    }

    /// Even the binary representation of a multicipher keyid is readable with this.
    // TODO Should we really keep it like this?
    pub fn to_bytes(&self) -> Vec<u8> {
        String::from(self).as_bytes().to_vec()
    }

    /// Even the binary representation of a multicipher keyid is readable with this.
    // TODO Should we really keep it like this?
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self> {
        let string = String::from_utf8(bytes.as_ref().to_owned())?;
        string.parse()
    }

    fn to_inner_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(edid) => edid.to_bytes(),
            Self::Secp256k1(secpid) => secpid.to_bytes(),
            Self::Ed25519Blake3(edid) => edid.to_bytes(),
        }
    }

    fn from_inner_bytes<B: AsRef<[u8]>>(suite: char, inner_bytes: B) -> Result<Self> {
        match CipherSuite::from_char(suite)? {
            CipherSuite::Ed25519 => Ok(Self::Ed25519(EdKeyId::from_bytes(inner_bytes)?)),
            CipherSuite::Secp256k1 => Ok(Self::Secp256k1(SecpKeyId::from_bytes(inner_bytes)?)),
            CipherSuite::Ed25519Blake3 => {
                Ok(Self::Ed25519Blake3(EdKeyId::from_bytes(inner_bytes)?))
            }
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for MKeyId {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes_out = self.to_inner_bytes();
        bytes_out.insert(0, self.suite().as_byte());
        serde_bytes::serialize(bytes_out.as_slice(), serializer)
    }
}

#[cfg(feature = "serde")]
fn deser(bytes: Vec<u8>) -> Result<MKeyId> {
    if bytes.is_empty() {
        return Err(KeyvaultError::NoCryptoSuite);
    }
    let suite = bytes[0] as char;
    let data = &bytes[1..];
    MKeyId::from_inner_bytes(suite, data)
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MKeyId {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use alloc::string::ToString;
        serde_bytes::deserialize(deserializer)
            .and_then(|b| deser(b).map_err(|e| serde::de::Error::custom(e.to_string())))
    }
}

impl From<&MKeyId> for alloc::string::String {
    fn from(src: &MKeyId) -> Self {
        let mut output = multibase::encode(multibase::Base::Base58Btc, src.to_inner_bytes());
        output.insert(0, src.suite().as_char());
        output.insert(0, MKeyId::PREFIX);
        output
    }
}

impl From<MKeyId> for alloc::string::String {
    fn from(src: MKeyId) -> Self {
        (&src).into()
    }
}

impl fmt::Display for MKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", alloc::string::String::from(self))
    }
}

impl fmt::Debug for MKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &dyn fmt::Display).fmt(f)
    }
}

impl core::str::FromStr for MKeyId {
    type Err = KeyvaultError;
    fn from_str(src: &str) -> Result<Self> {
        let mut chars = src.chars();
        if chars.next() != Some(Self::PREFIX) {
            return Err(KeyvaultError::InvalidIdentifierPrefix);
        }
        if let Some(suite) = chars.next() {
            let (_base, binary) = multibase::decode(chars.as_str()).map_err(map_multibase_err)?;
            Self::from_inner_bytes(suite, &binary)
        } else {
            Err(KeyvaultError::NoCryptoSuite)
        }
    }
}

impl From<EdKeyId> for MKeyId {
    fn from(src: EdKeyId) -> Self {
        Self::Ed25519(src)
    }
}

impl From<SecpKeyId> for MKeyId {
    fn from(src: SecpKeyId) -> Self {
        Self::Secp256k1(src)
    }
}

// ========== SCALE codec (Substrate) ==========

#[cfg(feature = "substrate")]
mod scale_impls {
    use super::*;
    use alloc::vec::Vec;
    use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, EncodeLike};
    use scale_info::TypeInfo;

    impl EncodeLike for MKeyId {}

    impl Encode for MKeyId {
        fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
            let bytes = self.to_bytes();
            Encode::encode_to(&bytes, dest);
        }
    }

    impl Decode for MKeyId {
        fn decode<I: parity_scale_codec::Input>(
            input: &mut I,
        ) -> core::result::Result<Self, parity_scale_codec::Error> {
            let bytes = Vec::<u8>::decode(input)
                .map_err(|_| parity_scale_codec::Error::from("failed to decode MKeyId bytes"))?;
            MKeyId::from_bytes(bytes)
                .map_err(|_| parity_scale_codec::Error::from("invalid multicipher key id"))
        }
    }

    impl DecodeWithMemTracking for MKeyId {}

    impl TypeInfo for MKeyId {
        type Identity = Self;
        fn type_info() -> scale_info::Type {
            scale_info::Type::builder()
// WIRE-FORMAT FREEZE: this path string is embedded in live chain metadata
                // (scale type registry). The crate was renamed to mosaic-keyvault, but this
                // literal must stay "iop_keyvault::multicipher" — changing it forks the type
                // registry of every deployed chain. See SPEC-012 Frozen Wire-Format Registry.
                .path(scale_info::Path::new("MKeyId", "iop_keyvault::multicipher"))
                .composite(
                    scale_info::build::Fields::unnamed()
                        .field(|f| f.ty::<Vec<u8>>().type_name("MKeyId")),
                )
        }
    }
}

#[cfg(test)]
mod test {
    mod parse_key_id {
        use crate::ed25519::EdKeyId;
        use crate::multicipher::{CipherSuite, MKeyId};

        #[allow(dead_code)]
        fn case(input: &str, key_id_hex: &str) {
            let key_id_bytes = hex::decode(key_id_hex).unwrap();
            let id1 = EdKeyId::from_bytes(&key_id_bytes).unwrap();
            let erased_id1 = MKeyId::from(id1);
            assert_eq!(erased_id1.to_string(), input);

            let erased_id2 = input.parse::<MKeyId>().unwrap();
            assert_eq!(erased_id2, erased_id1);
        }

        #[test]
        fn test_1() {
            case("iez21JXEtMzXjbCK6BAYFU9ewX", "01d8245272e2317ef53b26407e925edf7e");
        }

        #[test]
        fn test_2() {
            case("iezpmXKKc2QRZpXbzGV62MgKe", "0182d4ecfc12c5ad8efa5ef494f47e5285");
        }

        #[test]
        fn ed_suite() {
            let id = "iez21JXEtMzXjbCK6BAYFU9ewX".parse::<MKeyId>().unwrap();
            assert_eq!(id.suite(), CipherSuite::Ed25519);
            assert!(matches!(&id, MKeyId::Ed25519(_)));
            assert!(!matches!(&id, MKeyId::Secp256k1(_)));
        }

        #[test]
        fn secp_suite() {
            let id = "isz7un9h2Ddua9rfHefJMKiPLxSy2pX".parse::<MKeyId>().unwrap();
            assert_eq!(id.suite(), CipherSuite::Secp256k1);
            assert!(!matches!(&id, MKeyId::Ed25519(_)));
            assert!(matches!(&id, MKeyId::Secp256k1(_)));
        }

        #[test]
        #[should_panic(expected = "UnknownCryptoSuite { suite: 'g' }")]
        fn invalid_suite() {
            let _id = "igz21JXEtMzXjbCK6BAYFU9ewX".parse::<MKeyId>().unwrap();
        }

        #[test]
        #[should_panic(expected = "NoCryptoSuite")]
        fn missing_suite() {
            let _id = "i".parse::<MKeyId>().unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidIdentifierPrefix")]
        fn invalid_type() {
            let _id = "fez21JXEtMzXjbCK6BAYFU9ewX".parse::<MKeyId>().unwrap();
        }

        #[test]
        #[should_panic(expected = "InvalidIdentifierPrefix")]
        fn empty() {
            let _id = "".parse::<MKeyId>().unwrap();
        }
    }

    /// Pinned test vectors for Blake3-derived key IDs.
    /// If Blake3 output changes, these tests break immediately.
    mod blake3_key_id {
        use crate::PublicKey;
        use crate::ed25519::{Blake3, EdKeyId, EdPublicKey};
        use crate::multicipher::{CipherSuite, MKeyId};

        /// Pinned: pk 8fe969... → Blake3 key id
        #[test]
        fn case_1() {
            let pk_bytes =
                hex::decode("8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a")
                    .unwrap();
            let pk = EdPublicKey::from_bytes(&pk_bytes).unwrap();
            let blake3_id = EdKeyId::from_pk::<Blake3>(&pk);
            let m_id = MKeyId::Ed25519Blake3(blake3_id.clone());

            // Pinned string representation
            assert_eq!(m_id.to_string(), "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH");

            // Pinned inner bytes (version 0x1e + 32-byte Blake3 hash)
            assert_eq!(
                hex::encode(blake3_id.to_bytes()),
                "1e09031c1f8bf271dad54c2e1ebad9c9b4cc6f729ed5aea61e73c2c185a3067394",
            );

            // String roundtrip
            let parsed =
                "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH".parse::<MKeyId>().unwrap();
            assert_eq!(parsed, m_id);
            assert_eq!(parsed.suite(), CipherSuite::Ed25519Blake3);

            // Must differ from legacy Blake2b key id for the same public key
            let legacy_id = MKeyId::from(pk.key_id());
            assert_eq!(legacy_id.to_string(), "iezpmXKKc2QRZpXbzGV62MgKe");
            assert_ne!(legacy_id, m_id);
        }

        /// Pinned: pk d75a98... → Blake3 key id
        #[test]
        fn case_2() {
            let pk_bytes =
                hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                    .unwrap();
            let pk = EdPublicKey::from_bytes(&pk_bytes).unwrap();
            let blake3_id = EdKeyId::from_pk::<Blake3>(&pk);
            let m_id = MKeyId::Ed25519Blake3(blake3_id.clone());

            assert_eq!(m_id.to_string(), "iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb");
            assert_eq!(
                hex::encode(blake3_id.to_bytes()),
                "1e6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062",
            );

            // Bytes roundtrip: 33 bytes = version(1) + blake3(32)
            let id_bytes = blake3_id.to_bytes();
            assert_eq!(id_bytes.len(), 33);
            assert_eq!(id_bytes[0], 0x1e);
            let roundtripped = EdKeyId::from_bytes(&id_bytes).unwrap();
            assert_eq!(roundtripped, blake3_id);

            // Legacy comparison
            let legacy_id = MKeyId::from(pk.key_id());
            assert_eq!(legacy_id.to_string(), "iezZH3E9fRxfv1a1iPiK6gXxu");
            assert_ne!(legacy_id, m_id);
        }

        #[cfg(feature = "serde")]
        #[test]
        fn blake3_serde_roundtrip() {
            let pk_bytes =
                hex::decode("8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a")
                    .unwrap();
            let pk = EdPublicKey::from_bytes(&pk_bytes).unwrap();
            let m_id = MKeyId::Ed25519Blake3(EdKeyId::from_pk::<Blake3>(&pk));

            let bin = rmp_serde::to_vec(&m_id).unwrap();
            let deser: MKeyId = rmp_serde::from_slice(&bin).unwrap();
            assert_eq!(deser, m_id);
            assert_eq!(deser.to_string(), m_id.to_string());
        }
    }

    #[cfg(feature = "serde")]
    mod serde_key_id {
        use crate::multicipher::MKeyId;

        #[test]
        fn messagepack_serialization() {
            let id_str = "iez21JXEtMzXjbCK6BAYFU9ewX";
            let id = id_str.parse::<MKeyId>().unwrap();
            let id_bin = rmp_serde::to_vec(&id).unwrap();

            assert_eq!(
                id_bin,
                vec![
                    196, 18, 101, 1, 216, 36, 82, 114, 226, 49, 126, 245, 59, 38, 64, 126, 146, 94,
                    223, 126
                ]
            );

            let id_deser: MKeyId = rmp_serde::from_slice(&id_bin).unwrap();
            let id_tostr = id_deser.to_string();
            assert_eq!(id, id_deser);
            assert_eq!(id_str, id_tostr);
        }
    }

    #[cfg(feature = "substrate")]
    mod scale_roundtrip {
        use crate::multicipher::MKeyId;
        use parity_scale_codec::{Decode, Encode};

        #[test]
        fn ed25519_key_id_scale_roundtrip() {
            let id_str = "iez21JXEtMzXjbCK6BAYFU9ewX";
            let id = id_str.parse::<MKeyId>().unwrap();
            let encoded = id.encode();
            let decoded = MKeyId::decode(&mut &encoded[..]).unwrap();
            assert_eq!(id, decoded);
            assert_eq!(decoded.to_string(), id_str);
        }

        #[test]
        fn secp256k1_key_id_scale_roundtrip() {
            let id_str = "isz7un9h2Ddua9rfHefJMKiPLxSy2pX";
            let id = id_str.parse::<MKeyId>().unwrap();
            let encoded = id.encode();
            let decoded = MKeyId::decode(&mut &encoded[..]).unwrap();
            assert_eq!(id, decoded);
            assert_eq!(decoded.to_string(), id_str);
        }
    }
}
