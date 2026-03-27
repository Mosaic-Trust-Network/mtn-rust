//! Mock runtime for testing and benchmarking.
//!
//! Provides a minimal test environment with frame-system and pallet-mosaic-did.

use frame_support::{
    construct_runtime,
    traits::{ConstU16, ConstU32, ConstU64},
};
use polkadot_sdk::*;
use sp_runtime::{
    BuildStorage,
    traits::{BlakeTwo256, IdentityLookup},
};

pub use crate as pallet_mosaic_did;

construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        MosaicDid: pallet_mosaic_did,
    }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = polkadot_sdk::sp_core::H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = frame_system::mocking::MockBlock<Test>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type RuntimeTask = RuntimeTask;
    type ExtensionsWeightInfo = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

impl pallet_mosaic_did::Config for Test {
    type MaxOperationsPerTx = ConstU32<100>;
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default().build_storage().unwrap().into()
}
