//! Error types for the json-digest crate.

use alloc::string::String;
use thiserror::Error;

/// Errors that can occur during JSON digest operations.
#[derive(Error, Debug)]
pub enum JsonDigestError {
    /// A JSON path did not start with `.`.
    #[error("Path must start with '.' but it's: {path}")]
    InvalidPathStart {
        /// The offending path
        path: String,
    },

    /// An unclosed bracket was found in a path.
    #[error("Unclosed bracket in path: {path}")]
    UnclosedBracket {
        /// The offending path
        path: String,
    },

    /// A non-composite type was passed to a digest function that requires objects or arrays.
    #[error("Json digest is currently implemented only for composite types")]
    NonCompositeType,

    /// An internal inconsistency in the digest implementation.
    #[error("{0}")]
    Internal(String),

    /// The input JSON string was not NFKD-normalized.
    #[error("Json string to be digested must be normalized with Unicode NFKD")]
    NonNormalizedInput,

    /// JSON serialization/deserialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Convenience alias for `Result<T, JsonDigestError>`.
pub type Result<T> = core::result::Result<T, JsonDigestError>;
