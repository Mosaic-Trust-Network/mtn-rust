// sub-modules

pub mod error;
mod state;
mod vault;

// exports

pub use error::*;
pub use state::*;
pub use vault::*;

// imports from standard library

use std::any::Any;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

// imports from 3rd party crates

use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
#[cfg(not(target_arch = "wasm32"))]
use serde::Deserialize;
use serde::Serialize;

// imports from own crates

use mosaic_keyvault::{Bip39, Seed, encrypt::*};
