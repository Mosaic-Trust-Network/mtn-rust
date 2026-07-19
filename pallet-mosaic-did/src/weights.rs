use polkadot_sdk::frame_support::weights::{Weight, constants::RocksDbWeight};

/// Weight information trait for the pallet's extrinsics.
///
/// Each DID operation type has its own weight function to allow
/// precise weight calculation for heterogeneous batches.
pub trait WeightInfo {
    fn add_key() -> Weight;
    fn revoke_key() -> Weight;
    fn add_right() -> Weight;
    fn revoke_right() -> Weight;
    fn tombstone_did() -> Weight;
    fn update_commitment() -> Weight;
    fn register_before_proof() -> Weight;
}

/// Weights for `pallet_mosaic_did` using the recommended hardware.
impl WeightInfo for () {
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(14717), added: 17192, mode: `MaxEncodedLen`)
    fn add_key() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `6`
        //  Estimated: `18182`
        // Minimum execution time: 193_937_000 picoseconds.
        Weight::from_parts(196_517_000, 18182)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(14717), added: 17192, mode: `MaxEncodedLen`)
    fn revoke_key() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3325`
        //  Estimated: `18182`
        // Minimum execution time: 354_262_000 picoseconds.
        Weight::from_parts(363_553_000, 18182)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(14717), added: 17192, mode: `MaxEncodedLen`)
    fn add_right() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3325`
        //  Estimated: `18182`
        // Minimum execution time: 364_582_000 picoseconds.
        Weight::from_parts(373_374_000, 18182)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(14717), added: 17192, mode: `MaxEncodedLen`)
    fn revoke_right() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3381`
        //  Estimated: `18182`
        // Minimum execution time: 362_103_000 picoseconds.
        Weight::from_parts(371_903_000, 18182)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(14717), added: 17192, mode: `MaxEncodedLen`)
    fn tombstone_did() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3325`
        //  Estimated: `18182`
        // Minimum execution time: 358_223_000 picoseconds.
        Weight::from_parts(368_094_000, 18182)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(14717), added: 17192, mode: `MaxEncodedLen`)
    fn update_commitment() -> Weight {
        // Same pattern as tombstone_did: one read + one write on DidStates.
        Weight::from_parts(368_094_000, 18182)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::BeforeProofs` (r:1 w:1)
    /// Proof: `Did::BeforeProofs` (`max_values`: None, `max_size`: Some(57), added: 2532, mode: `MaxEncodedLen`)
    fn register_before_proof() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `6`
        //  Estimated: `3522`
        // Minimum execution time: 13_731_000 picoseconds.
        Weight::from_parts(14_530_000, 3522)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
}
