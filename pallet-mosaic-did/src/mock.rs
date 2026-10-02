//! Mock runtime for testing and benchmarking.
//!
//! Provides a minimal test environment with frame-system, pallet-balances,
//! and pallet-mosaic-did.

use frame_support::{derive_impl, parameter_types};
use polkadot_sdk::*;
use sp_runtime::{BuildStorage, traits::IdentityLookup};

pub use crate as pallet_mosaic_did;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        Balances: pallet_balances,
        MosaicDid: pallet_mosaic_did,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountData = pallet_balances::AccountData<<Self as pallet_balances::Config>::Balance>;
    type Lookup = IdentityLookup<u64>;
    type AccountId = u64;
    // Real DB weights, so batch actual-weight accounting is observable in
    // tests (the test default is zero).
    type DbWeight = frame_support::weights::constants::RocksDbWeight;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

parameter_types! {
    pub const GovernedOpDeposit: u64 = 1_000_000_000_000;
}

impl pallet_mosaic_did::Config for Test {
    type MaxOperationsPerTx = frame_support::traits::ConstU32<100>;
    type WeightInfo = ();
    type RuntimeHoldReason = RuntimeHoldReason;
    type Currency = Balances;
    type GovernedOpDeposit = GovernedOpDeposit;
}

/// Build test externalities with endowed accounts for governed operation deposits.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (1, 1_000_000_000_000_000u64), // ALICE (submitter in tests)
            (2, 1_000_000_000_000_000u64), // BOB
        ],
        dev_accounts: None,
    }
    .assimilate_storage(&mut ext)
    .unwrap();
    ext.into()
}
