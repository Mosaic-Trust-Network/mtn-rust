//! Error types for the mosaic-vault crate.

use thiserror::Error;

/// Errors that can occur during vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    /// Failed to acquire a read lock on the vault.
    #[error("Read lock on Vault failed")]
    ReadLockFailed,

    /// Failed to acquire a write lock on the vault.
    #[error("Write lock on Vault failed")]
    WriteLockFailed,

    /// Failed to acquire a read lock on vault state.
    #[error("Read lock on Vault state failed")]
    StateReadLockFailed,

    /// Failed to acquire a write lock on vault state.
    #[error("Write lock on Vault state failed")]
    StateWriteLockFailed,

    /// A plugin with the same identity was already added.
    #[error("Same plugin was already added to vault")]
    DuplicatePlugin,

    /// Errors from the keyvault crate.
    #[error(transparent)]
    Keyvault(#[from] mosaic_keyvault::KeyvaultError),

    /// Multibase encoding/decoding errors.
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
}

/// Convenience alias for `Result<T, VaultError>`.
pub type Result<T> = core::result::Result<T, VaultError>;
