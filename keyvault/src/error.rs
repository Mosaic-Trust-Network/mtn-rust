//! Error types for the iop-keyvault crate.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

/// Errors that can occur during keyvault operations.
#[derive(Error, Debug)]
pub enum KeyvaultError {
    /// Invalid hex string.
    #[error("invalid hex")]
    InvalidHex,

    /// Multibase encoding/decoding error.
    #[error("Multibase error: {0}")]
    Multibase(String),

    /// UTF-8 conversion error.
    #[error(transparent)]
    Utf8(#[from] core::str::Utf8Error),

    /// A general display error (wraps any Display type).
    #[error("{0}")]
    Display(String),

    /// Network not found.
    #[error("Could not find network with name {name}.")]
    NetworkNotFound {
        /// The network name that was looked up.
        name: String,
    },

    /// Invalid BIP39 language code.
    #[error("Invalid BIP39 language code")]
    InvalidBip39Language,

    /// Invalid BIP39 mnemonic phrase (bip39 crate error).
    #[cfg(feature = "std")]
    #[error("{0}")]
    Bip39(#[from] ::bip39::ErrorKind),

    /// A `FromUtf8Error` from converting bytes to a UTF-8 string.
    #[error(transparent)]
    FromUtf8(#[from] alloc::string::FromUtf8Error),

    /// Invalid BIP39 mnemonic phrase (general validation).
    #[cfg(feature = "std")]
    #[error("{0}")]
    Bip39Msg(String),

    /// Invalid signature format.
    #[error("invalid signature format")]
    InvalidSignatureFormat,

    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Signature length mismatch.
    #[error("Signature length is not {expected}")]
    SignatureLength {
        /// Expected length.
        expected: usize,
    },

    /// Unsupported signature version.
    #[error("Only identifier version {version:x} is supported")]
    UnsupportedSignatureVersion {
        /// The supported version byte.
        version: u8,
    },

    /// Public key length mismatch.
    #[error("Public key length is not {expected}")]
    PublicKeyLength {
        /// Expected length.
        expected: usize,
    },

    /// Ed25519 normal derivation is invalid per SLIP-0010.
    #[error("Normal derivation of Ed25519 is invalid based on SLIP-0010.")]
    Ed25519NormalDerivationInvalid,

    /// Unknown DID kind.
    #[error("Unknown DID kind {kind}")]
    UnknownDidKind {
        /// The unrecognized kind string.
        kind: String,
    },

    /// BIP32 derivation path error.
    #[error("BIP32 derivation path needs to start with 'm'")]
    Bip32PathNotStartingWithM,

    /// BIP32 derivation path is empty.
    #[error("BIP32 derivation path cannot be empty")]
    Bip32PathEmpty,

    /// BIP32 derivation index cannot be negative.
    #[error("BIP32 derivation index cannot be negative")]
    NegativeBip32Index,

    /// BIP32 derivation path contains invalid child indices.
    #[error("BIP32 derivation path contains invalid child indices: {details:?}")]
    InvalidChildIndices {
        /// Details about invalid indices.
        details: Vec<(String, core::result::Result<(), KeyvaultError>)>,
    },

    /// Integer parse error.
    #[error(transparent)]
    ParseInt(#[from] core::num::ParseIntError),

    /// Scalar length is wrong.
    #[error("Scalar length is not {expected}")]
    ScalarLength {
        /// Expected length.
        expected: usize,
    },

    /// Invalid secp256k1 scalar.
    #[error("Invalid secp256k1 scalar")]
    InvalidScalar,

    /// Base58 check decoding failed.
    #[error("Incorrect checksum")]
    IncorrectChecksum,

    /// Unknown WIF suffix.
    #[error("Unknown wif suffix {suffix}")]
    UnknownWifSuffix {
        /// The hex-encoded suffix bytes.
        suffix: String,
    },

    /// WIF data is too short.
    #[error("WIF data is too short")]
    WifTooShort,

    /// Invalid network prefix in WIF.
    #[error("Invalid network prefix found: {prefix}")]
    InvalidWifNetworkPrefix {
        /// The hex-encoded prefix that was found.
        prefix: String,
    },

    /// Unknown crypto suite.
    #[error("Unknown crypto suite '{suite}'")]
    UnknownCryptoSuite {
        /// The unrecognized suite character.
        suite: char,
    },

    /// No crypto suite found.
    #[error("No crypto suite found")]
    NoCryptoSuite,

    /// Public keys must start with 'p'.
    #[error("Public keys must start with 'p'")]
    InvalidPublicKeyPrefix,

    /// Signatures must start with 's'.
    #[error("Signatures must start with 's'")]
    InvalidSignaturePrefix,

    /// Identifiers must start with 'i'.
    #[error("Identifiers must start with 'i'")]
    InvalidIdentifierPrefix,

    /// Password is too short.
    #[error("Password is too short")]
    PasswordTooShort,

    /// Salt is too short.
    #[error("Salt is too short")]
    SaltTooShort,

    /// Could not derive key from password.
    #[error("Could not derive key from password")]
    KeyDerivationFailed,

    /// Could not convert key.
    #[error("Could not convert key")]
    KeyConversionFailed,

    /// Key is invalid.
    #[error("Key is invalid")]
    InvalidKey,

    /// Nonce is too short.
    #[error("Nonce is too short")]
    NonceTooShort,

    /// Plaintext is too long.
    #[error("Plaintext is too long")]
    PlaintextTooLong,

    /// Ciphertext is too short.
    #[error("Ciphertext is too short")]
    CiphertextTooShort,

    /// Ciphertext was tampered with.
    #[error("Ciphertext was tampered with")]
    CiphertextTampered,

    /// Only N-word mnemonics are supported.
    #[error("Only {word_count}-word mnemonics are supported")]
    MnemonicWordCount {
        /// The expected word count.
        word_count: usize,
    },

    /// Only N-bit entropy is supported.
    #[error("Only {bit_count}-bit entropy is supported")]
    InvalidEntropyBitCount {
        /// The expected bit count.
        bit_count: usize,
    },

    /// Key ID length mismatch.
    #[error("Identifier length is not {expected}")]
    IdLength {
        /// Expected length.
        expected: usize,
    },

    /// Key ID version byte is not recognized.
    #[error("Unknown key id version byte 0x{version:02x}")]
    UnknownKeyIdVersion {
        /// The unrecognized version byte.
        version: u8,
    },

    /// Empty key ID bytes.
    #[error("Empty key id bytes")]
    EmptyKeyIdBytes,

    /// Legacy key ID must have a certain size.
    #[error("Legacy key id must be {expected} bytes")]
    LegacyKeyIdSize {
        /// Expected byte count.
        expected: usize,
    },

    /// Derivation index cannot be negative.
    #[error("Derivation index cannot be negative")]
    NegativeDerivationIndex,

    /// A derivation index was expected but not present in the BIP32 path segment.
    #[error("BIP32 derivation index missing in segment: {segment}")]
    MissingDerivationIndex {
        /// The problematic path segment.
        segment: String,
    },

    /// Invalid seed size (only 256-bit seeds are supported).
    #[error("Only {bit_count}-bit seeds are supported")]
    InvalidSeedBits {
        /// Expected bit count.
        bit_count: usize,
    },

    /// Chain code has wrong length.
    #[error("Chain code length is not {expected}")]
    ChainCodeLength {
        /// Expected length.
        expected: usize,
    },

    /// Cannot use negative account index.
    #[error("Cannot use negative account index")]
    NegativeAccountIndex,

    /// The extended key length is wrong.
    #[error("Length of data must be {expected}")]
    ExtKeyLength {
        /// Expected length.
        expected: usize,
    },

    /// The extended key version does not match.
    #[error("Version mismatch: expected {expected_ver}, found {found_ver}")]
    ExtKeyVersion {
        /// Expected version hex.
        expected_ver: String,
        /// Found version hex.
        found_ver: String,
    },

    /// xprv prefix is wrong.
    #[error("xprv must have a private key prefixed with {expected}")]
    XprvPrefix {
        /// Expected prefix byte.
        expected: u8,
    },

    /// Unexpected data length.
    #[error("Unexpected data length, expected {expected} but got {actual}")]
    DataLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Errors from the `getrandom` crate.
    #[cfg(feature = "std")]
    #[error(transparent)]
    GetRandom(#[from] getrandom::Error),
}

/// Convenience alias for `Result<T, KeyvaultError>`.
pub type Result<T> = core::result::Result<T, KeyvaultError>;

/// Helper to convert a `multibase::Error` into a `KeyvaultError`.
#[inline]
pub fn multibase_err(e: multibase::Error) -> KeyvaultError {
    KeyvaultError::Multibase(format!("{e}"))
}

/// Helper to convert a `Display`-implementing error into a `KeyvaultError`.
#[inline]
pub fn display_err<E: core::fmt::Display>(e: E) -> KeyvaultError {
    KeyvaultError::Display(format!("{e}"))
}

impl From<hex::FromHexError> for KeyvaultError {
    fn from(e: hex::FromHexError) -> Self {
        KeyvaultError::Display(format!("invalid hex: {e}"))
    }
}
