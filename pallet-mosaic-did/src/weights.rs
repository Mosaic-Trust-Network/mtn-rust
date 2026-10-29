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
    fn update_commitment() -> Weight;
    fn announce_governed_op() -> Weight;
    fn cancel_governed_op() -> Weight;
    fn execute_governed_op() -> Weight;
    fn register_before_proof() -> Weight;
}

/// Weights for `pallet_mosaic_did` using the recommended hardware.
impl WeightInfo for () {
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    fn add_key() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `175`
        //  Estimated: `16279`
        // Minimum execution time: 188_464_000 picoseconds.
        Weight::from_parts(198_533_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    fn revoke_key() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3785`
        //  Estimated: `16279`
        // Minimum execution time: 462_621_000 picoseconds.
        Weight::from_parts(486_445_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    fn add_right() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3785`
        //  Estimated: `16279`
        // Minimum execution time: 460_656_000 picoseconds.
        Weight::from_parts(484_993_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    fn revoke_right() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3842`
        //  Estimated: `16279`
        // Minimum execution time: 461_719_000 picoseconds.
        Weight::from_parts(485_343_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    fn update_commitment() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3785`
        //  Estimated: `16279`
        // Minimum execution time: 464_173_000 picoseconds.
        Weight::from_parts(491_635_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    /// Storage: `Did::PendingGovernedOps` (r:1 w:1)
    /// Proof: `Did::PendingGovernedOps` (`max_values`: None, `max_size`: Some(273), added: 2748, mode: `MaxEncodedLen`)
    /// Storage: `Parameters::Parameters` (r:1 w:0)
    /// Proof: `Parameters::Parameters` (`max_values`: None, `max_size`: Some(37), added: 2512, mode: `MaxEncodedLen`)
    /// Storage: `Balances::Holds` (r:1 w:1)
    /// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(805), added: 3280, mode: `MaxEncodedLen`)
    fn announce_governed_op() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `3789`
        //  Estimated: `16279`
        // Minimum execution time: 514_328_000 picoseconds.
        Weight::from_parts(544_544_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    /// Storage: `Did::PendingGovernedOps` (r:1 w:1)
    /// Proof: `Did::PendingGovernedOps` (`max_values`: None, `max_size`: Some(273), added: 2748, mode: `MaxEncodedLen`)
    /// Storage: `Balances::Holds` (r:1 w:1)
    /// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(805), added: 3280, mode: `MaxEncodedLen`)
    fn cancel_governed_op() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `4059`
        //  Estimated: `16279`
        // Minimum execution time: 506_793_000 picoseconds.
        Weight::from_parts(535_518_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    /// Storage: `Did::DidStates` (r:1 w:1)
    /// Proof: `Did::DidStates` (`max_values`: None, `max_size`: Some(12814), added: 15289, mode: `MaxEncodedLen`)
    /// Storage: `Did::PendingGovernedOps` (r:1 w:1)
    /// Proof: `Did::PendingGovernedOps` (`max_values`: None, `max_size`: Some(273), added: 2748, mode: `MaxEncodedLen`)
    /// Storage: `Balances::Holds` (r:1 w:1)
    /// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(805), added: 3280, mode: `MaxEncodedLen`)
    fn execute_governed_op() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `4059`
        //  Estimated: `16279`
        // Minimum execution time: 511_102_000 picoseconds.
        Weight::from_parts(539_414_000, 16279)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
    /// Storage: `Did::BeforeProofs` (r:1 w:1)
    /// Proof: `Did::BeforeProofs` (`max_values`: None, `max_size`: Some(89), added: 2564, mode: `MaxEncodedLen`)
    fn register_before_proof() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `175`
        //  Estimated: `3554`
        // Minimum execution time: 17_083_000 picoseconds.
        Weight::from_parts(18_675_000, 3554)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(1_u64))
    }
}
