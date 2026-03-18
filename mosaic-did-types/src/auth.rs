//! Authentication types for `did:mosaic`.
//!
//! Ported from the Morpheus SSI protocol's `Authentication` type. Identifies a key
//! either by its multicipher key ID (compact reference) or by the full multicipher
//! public key (self-contained, verifiable).
//!
//! Cross-comparison works: `KeyId(kid) == PublicKey(pk)` iff `pk.validate_id(&kid)`.
//!
//! ## On-chain Usage
//!
//! - `AddKey` requires the `PublicKey` variant (chain needs actual key bytes).
//! - `RevokeKey`, `AddRight`, `RevokeRight` accept either variant.
//! - SCALE-encoded as: `variant_byte + length_prefixed_string_bytes`.

use core::fmt;

use iop_keyvault::PublicKey;
use iop_keyvault::multicipher::{MKeyId, MPublicKey};

/// Identifies a key for authentication – either by key ID or full public key.
///
/// The custom [`PartialEq`] handles cross-variant comparison: a `KeyId` and a
/// `PublicKey` are equal when `pk.validate_id(&kid)` returns `true`.
#[derive(Clone, Debug)]
pub enum Authentication {
    /// Reference a key by its multicipher key ID (compact, hash-derived).
    KeyId(MKeyId),
    /// Provide the full multicipher public key (self-contained, verifiable).
    PublicKey(MPublicKey),
}

impl Authentication {
    /// Construct a `PublicKey` variant from a [`KeyType`] and raw public key bytes.
    ///
    /// Maps `KeyType` to the correct keyvault cipher suite via [`MultiPublicKey`].
    /// Returns `None` for unsupported key types or invalid bytes.
    ///
    /// [`MultiPublicKey`]: crate::signature::MultiPublicKey
    pub fn from_key_type_and_bytes(
        key_type: crate::operation::KeyType, bytes: &[u8],
    ) -> Option<Self> {
        let pk = crate::signature::MultiPublicKey::from_key_type_and_bytes(key_type, bytes)?;
        Some(Authentication::PublicKey(pk.0))
    }

    /// Resolve the key ID, deriving it from the public key if necessary.
    pub fn key_id(&self) -> MKeyId {
        match self {
            Authentication::KeyId(kid) => kid.clone(),
            Authentication::PublicKey(pk) => pk.key_id(),
        }
    }

    /// Returns `true` if this is the `PublicKey` variant.
    pub fn has_public_key(&self) -> bool {
        matches!(self, Authentication::PublicKey(_))
    }

    /// Extract the public key, if available.
    pub fn public_key(&self) -> Option<&MPublicKey> {
        match self {
            Authentication::PublicKey(pk) => Some(pk),
            Authentication::KeyId(_) => None,
        }
    }

    /// Wrap the public key as a [`MultiPublicKey`] for verification.
    ///
    /// Returns `None` if this is the `KeyId` variant.
    ///
    /// [`MultiPublicKey`]: crate::signature::MultiPublicKey
    pub fn to_multi_public_key(&self) -> Option<crate::signature::MultiPublicKey> {
        self.public_key().map(|pk| crate::signature::MultiPublicKey(pk.clone()))
    }
}

// Cross-variant PartialEq: KeyId and PublicKey are equal if the key ID matches.
impl PartialEq for Authentication {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Authentication::KeyId(a), Authentication::KeyId(b)) => a == b,
            (Authentication::PublicKey(a), Authentication::PublicKey(b)) => a == b,
            (Authentication::KeyId(kid), Authentication::PublicKey(pk))
            | (Authentication::PublicKey(pk), Authentication::KeyId(kid)) => pk.validate_id(kid),
        }
    }
}

impl Eq for Authentication {}

impl fmt::Display for Authentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Authentication::KeyId(kid) => kid.fmt(f),
            Authentication::PublicKey(pk) => pk.fmt(f),
        }
    }
}

impl From<MKeyId> for Authentication {
    fn from(kid: MKeyId) -> Self {
        Authentication::KeyId(kid)
    }
}

impl From<MPublicKey> for Authentication {
    fn from(pk: MPublicKey) -> Self {
        Authentication::PublicKey(pk)
    }
}

// ========== SCALE codec (Substrate) ==========

#[cfg(feature = "substrate")]
mod scale_impls {
    use super::*;
    use alloc::vec::Vec;
    use parity_scale_codec::{Decode, Encode, EncodeLike, MaxEncodedLen};
    use scale_info::TypeInfo;

    /// Maximum SCALE-encoded length of an Authentication value.
    ///
    /// 1 byte variant + compact length prefix (2 bytes) +
    /// max string bytes (~56 for secp256k1 public key string form).
    const MAX_AUTH_ENCODED_LEN: usize = 68;

    impl EncodeLike for Authentication {}

    impl Encode for Authentication {
        fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
            match self {
                Authentication::KeyId(kid) => {
                    0u8.encode_to(dest);
                    let bytes = kid.to_bytes();
                    Encode::encode_to(&bytes, dest);
                }
                Authentication::PublicKey(pk) => {
                    1u8.encode_to(dest);
                    let bytes = pk.to_bytes();
                    Encode::encode_to(&bytes, dest);
                }
            }
        }
    }

    impl Decode for Authentication {
        fn decode<I: parity_scale_codec::Input>(
            input: &mut I,
        ) -> Result<Self, parity_scale_codec::Error> {
            let variant = u8::decode(input)?;
            let bytes = Vec::<u8>::decode(input)?;
            match variant {
                0 => {
                    let kid = MKeyId::from_bytes(bytes)
                        .map_err(|_| parity_scale_codec::Error::from("invalid MKeyId encoding"))?;
                    Ok(Authentication::KeyId(kid))
                }
                1 => {
                    let pk = MPublicKey::from_bytes(bytes).map_err(|_| {
                        parity_scale_codec::Error::from("invalid MPublicKey encoding")
                    })?;
                    Ok(Authentication::PublicKey(pk))
                }
                _ => Err(parity_scale_codec::Error::from("invalid Authentication variant")),
            }
        }
    }

    impl MaxEncodedLen for Authentication {
        fn max_encoded_len() -> usize {
            MAX_AUTH_ENCODED_LEN
        }
    }

    impl TypeInfo for Authentication {
        type Identity = Self;
        fn type_info() -> scale_info::Type {
            scale_info::Type::builder()
                .path(scale_info::Path::new("Authentication", "mosaic_did_types::auth"))
                .variant(
                    scale_info::build::Variants::new()
                        .variant("KeyId", |v| {
                            v.index(0).fields(
                                scale_info::build::Fields::unnamed()
                                    .field(|f| f.ty::<Vec<u8>>().type_name("MKeyId")),
                            )
                        })
                        .variant("PublicKey", |v| {
                            v.index(1).fields(
                                scale_info::build::Fields::unnamed()
                                    .field(|f| f.ty::<Vec<u8>>().type_name("MPublicKey")),
                            )
                        }),
                )
        }
    }
}

// ========== Serde ==========

#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use alloc::string::String;

    // Serialize as a simple string (matching Morpheus `serde_str` pattern).
    // KeyId produces "ioz..." / "iez...", PublicKey produces "poz..." / "pez...".
    impl serde::Serialize for Authentication {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> serde::Deserialize<'de> for Authentication {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            // PublicKey strings start with 'p', KeyId strings start with 'i'
            if s.starts_with(MPublicKey::PREFIX) {
                let pk: MPublicKey = s.parse().map_err(serde::de::Error::custom)?;
                Ok(Authentication::PublicKey(pk))
            } else if s.starts_with(MKeyId::PREFIX) {
                let kid: MKeyId = s.parse().map_err(serde::de::Error::custom)?;
                Ok(Authentication::KeyId(kid))
            } else {
                Err(serde::de::Error::custom(
                    "Authentication string must start with 'p' (PublicKey) or 'i' (KeyId)",
                ))
            }
        }
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;
    use iop_keyvault::ed25519::{Blake3, EdKeyId, EdPublicKey};

    fn alice_pk() -> MPublicKey {
        let pk_bytes =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let ed_pk = EdPublicKey::from_bytes(&pk_bytes).unwrap();
        MPublicKey::Ed25519Blake3(ed_pk)
    }

    fn alice_kid() -> MKeyId {
        let pk_bytes =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let ed_pk = EdPublicKey::from_bytes(&pk_bytes).unwrap();
        MKeyId::Ed25519Blake3(EdKeyId::from_pk::<Blake3>(&ed_pk))
    }

    #[test]
    fn key_id_from_public_key() {
        let auth = Authentication::PublicKey(alice_pk());
        let kid = auth.key_id();
        assert!(kid.to_string().starts_with("ioz"));
    }

    #[test]
    fn cross_variant_equality() {
        let auth_pk = Authentication::PublicKey(alice_pk());
        let auth_kid = Authentication::KeyId(alice_kid());

        // KeyId(kid) == PublicKey(pk) when pk.validate_id(&kid)
        assert_eq!(auth_pk, auth_kid);
        assert_eq!(auth_kid, auth_pk);
    }

    #[test]
    fn same_variant_equality() {
        assert_eq!(Authentication::KeyId(alice_kid()), Authentication::KeyId(alice_kid()),);
        assert_eq!(Authentication::PublicKey(alice_pk()), Authentication::PublicKey(alice_pk()),);
    }

    #[test]
    fn different_keys_not_equal() {
        let bob_bytes =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap();
        let bob_pk = EdPublicKey::from_bytes(&bob_bytes).unwrap();
        let bob = Authentication::PublicKey(MPublicKey::Ed25519Blake3(bob_pk));
        let alice = Authentication::KeyId(alice_kid());
        assert_ne!(alice, bob);
    }

    #[test]
    fn display_formats() {
        let pk_auth = Authentication::PublicKey(alice_pk());
        assert!(pk_auth.to_string().starts_with("poz"));

        let kid_auth = Authentication::KeyId(alice_kid());
        assert!(kid_auth.to_string().starts_with("ioz"));
    }

    #[test]
    fn has_public_key_accessor() {
        let pk_auth = Authentication::PublicKey(alice_pk());
        assert!(pk_auth.has_public_key());
        assert!(pk_auth.public_key().is_some());

        let kid_auth = Authentication::KeyId(alice_kid());
        assert!(!kid_auth.has_public_key());
        assert!(kid_auth.public_key().is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_public_key() {
        let auth = Authentication::PublicKey(alice_pk());
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("poz"));
        let parsed: Authentication = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, parsed);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_key_id() {
        let auth = Authentication::KeyId(alice_kid());
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("ioz"));
        let parsed: Authentication = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, parsed);
    }
}
