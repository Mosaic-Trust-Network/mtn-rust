//! Core type definitions for the `did:mosaic` DID method.
//!
//! This crate defines the data types used by the Mosaic Trust Network DID system,
//! which is derived from the IOP Morpheus SSI Stack and adapted for the
//! Substrate/Polkadot ecosystem.
//!
//! # Architecture
//!
//! The `did:mosaic` method preserves the battle-tested semantics of IOP Morpheus
//! while introducing:
//! - BLAKE3-256 for DID identifier derivation (faster, modern)
//! - SCALE codec encoding for Substrate compatibility
//! - Expanded operations set (Phase 1: 5 core + BeforeProof)
//! - Expanded rights model (6 rights vs original 2)
//!
//! # Anti-Censorship Design
//!
//! Any account can submit operations for any DID. Authorization is verified via
//! cryptographic signatures inside operations, not transaction origin. This prevents
//! node censorship of specific DIDs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod auth;
pub mod did;
pub mod document;
pub mod history;
pub mod operation;
pub mod rights;
pub mod signature;
pub mod signed;
pub mod smt;
pub mod state;
pub mod validity;
pub mod verifier;

pub use auth::*;
pub use did::*;
pub use document::*;
pub use operation::*;
pub use signature::{
    ed25519_blake3_signature, public_key_from_key_type, public_key_raw_bytes,
    public_key_to_key_type, secp256k1_signature,
};
pub use state::*;
pub use validity::is_height_valid;

#[cfg(all(test, feature = "substrate"))]
mod freeze_tests {
    //! SPEC-012 Frozen Wire-Format Registry regression pins for the
    //! hand-written scale_info paths. If one of these tests fails, a frozen
    //! metadata path drifted — revert the change, do not update the strings.

    use crate::auth::Authentication;
    use crate::did::Did;
    use scale_info::TypeInfo as _;

    #[test]
    fn did_metadata_path_is_frozen() {
        let rendered = format!("{:?}", Did::type_info());
        assert!(
            rendered.contains("mosaic_did_types") && rendered.contains("did"),
            "Did scale_info path drifted: {rendered}"
        );
    }

    #[test]
    fn authentication_metadata_path_is_frozen() {
        let rendered = format!("{:?}", Authentication::type_info());
        assert!(
            rendered.contains("mosaic_did_types") && rendered.contains("auth"),
            "Authentication scale_info path drifted: {rendered}"
        );
    }
}
