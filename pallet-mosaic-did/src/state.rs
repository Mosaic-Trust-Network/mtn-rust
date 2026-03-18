//! On-chain DID state types and re-exports.
//!
//! Re-exports the canonical types from `mosaic-did-types`.
//! `BeforeProofRecord` is defined locally as it's pallet-specific.

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub use mosaic_did_types::document::*;

/// Record stored on-chain for a registered BeforeProof.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct BeforeProofRecord {
    /// Block height at which the proof was registered.
    pub block_height: u32,
    /// Index of the extrinsic within the block.
    pub extrinsic_index: u32,
}
