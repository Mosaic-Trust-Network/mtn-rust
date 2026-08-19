//! # Mosaic SDK
//!
//! Unified entry point for the Mosaic Trust Network crates. Each sub-module re-exports
//! one workspace crate so downstream code only needs a single dependency.
//!
//! ```no_run
//! use mosaic_sdk::vault::Vault;
//! use mosaic_sdk::did::Did;
//! ```

/// Cryptographic primitives: keys, signatures, hierarchical derivation, BIP-39/44.
pub use mosaic_keyvault as keyvault;

/// Hierarchical deterministic vault with pluggable extensions.
pub use mosaic_vault as vault;

/// Core `did:mosaic` type definitions (DID, authentication, operations, documents).
pub use mosaic_did_types as did;

/// Privacy-preserving JSON document digests.
pub use json_digest;
