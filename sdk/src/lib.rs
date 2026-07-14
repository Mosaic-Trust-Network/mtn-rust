//! # IOP SDK
//!
//! Unified entry point for the IOP Stack crates. Each sub-module re-exports
//! one workspace crate so downstream code only needs a single dependency.
//!
//! ```ignore
//! use iop_sdk::vault::Vault;
//! use iop_sdk::did::Did;
//! ```

/// Cryptographic primitives: keys, signatures, hierarchical derivation, BIP-39/44.
pub use iop_keyvault as keyvault;

/// Hierarchical deterministic vault with pluggable extensions.
pub use iop_vault as vault;

/// Core `did:mosaic` type definitions (DID, authentication, operations, documents).
pub use mosaic_did_types as did;

/// Substrate pallet implementing the `did:mosaic` DID registry on-chain.
pub use pallet_mosaic_did as pallet;

/// Privacy-preserving JSON document digests.
pub use json_digest;
