//! # Mosaic DID Registry Pallet
//!
//! Substrate pallet implementing the `did:mosaic` DID method for the
//! Mosaic Trust Network. Derived from the IOP Morpheus SSI Stack.
//!
//! ## Architecture (v2 — Materialized State)
//!
//! DID document state is stored directly on-chain using `DidState`.
//! No event-log replay is needed for validation — the pallet reads and
//! mutates state in-place. Events carry full operation payloads for
//! off-chain indexers to reconstruct history.
//!
//! ## Anti-Censorship Design
//!
//! Any account can submit operations for any DID. Authorization is verified
//! via cryptographic signatures inside operations, not transaction origin.

#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::wildcard_imports)]
use polkadot_sdk::*;

use scale_info::prelude::format;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;

#[cfg(test)]
pub mod mock;
pub mod state;
mod validation;

pub use pallet::*;
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;

    use mosaic_did_types::{
        ContentId, Did, DidOperation, DidState, GovernedOperation, KeyPurpose, KeyRef, KeyType,
        Right, RightGrant, SignedDidOperation, SsiOperation, VerificationMethod,
    };

    use crate::state::BeforeProofRecord;
    use crate::validation;

    /// Number of blocks before a newly granted Update/Delegate right becomes
    /// exercisable. Gives the controller time to detect and revoke rights
    /// added by a compromised key.
    pub const RIGHT_MATURITY_BLOCKS: u32 = 100;

    /// Number of blocks that must elapse between announcing a governed
    /// operation and when it can be executed.
    pub const GOVERNED_OP_DELAY_BLOCKS: u32 = 200;

    /// Number of blocks after which an unexecuted governed operation expires.
    pub const GOVERNED_OP_EXPIRY_BLOCKS: u32 = 400;

    #[pallet::config]
    pub trait Config: polkadot_sdk::frame_system::Config {
        /// Maximum operations per transaction.
        #[pallet::constant]
        type MaxOperationsPerTx: Get<u32>;

        /// Weight information for extrinsics.
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ========== STORAGE ==========

    /// Materialized DID document state, keyed by DID.
    /// This is the single source of truth — read and mutated in place.
    #[pallet::storage]
    #[pallet::getter(fn did_state)]
    pub type DidStates<T: Config> = StorageMap<_, Blake2_128Concat, Did, DidState, OptionQuery>;

    /// BeforeProof timestamps.
    #[pallet::storage]
    #[pallet::getter(fn before_proofs)]
    pub type BeforeProofs<T: Config> =
        StorageMap<_, Blake2_128Concat, ContentId, BeforeProofRecord, OptionQuery>;

    // ========== EVENTS ==========

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Atomic SSI batch successfully applied.
        SsiBatchApplied {
            submitter: T::AccountId,
            operation_count: u32,
            block_height: BlockNumberFor<T>,
        },

        /// A key was added to a DID document.
        KeyAdded {
            did: Did,
            key_ref: Vec<u8>,
            key_type: KeyType,
            public_key: Vec<u8>,
            purposes: Vec<KeyPurpose>,
            expires_at_height: Option<u32>,
            block_height: BlockNumberFor<T>,
        },

        /// A key was revoked from a DID document.
        KeyRevoked { did: Did, key_ref: Vec<u8>, block_height: BlockNumberFor<T> },

        /// A right was granted to a key.
        RightAdded {
            did: Did,
            key_ref: Vec<u8>,
            right: Right,
            expires_at_height: Option<u32>,
            /// Block height at which this right becomes exercisable (Update/Delegate only).
            matures_at_height: Option<u32>,
            block_height: BlockNumberFor<T>,
        },

        /// A right was revoked from a key.
        RightRevoked { did: Did, key_ref: Vec<u8>, right: Right, block_height: BlockNumberFor<T> },

        /// DID permanently deactivated.
        DidTombstoned { did: Did, block_height: BlockNumberFor<T> },

        /// BeforeProof timestamp registered.
        BeforeProofRegistered { content_id: ContentId, block_height: BlockNumberFor<T> },

        /// A rights-document commitment was published on-chain.
        CommitmentUpdated {
            did: Did,
            commitment: ContentId,
            sequence: u64,
            signer_key_ref: Vec<u8>,
            block_height: BlockNumberFor<T>,
            /// Previous state before this update: `Some((sequence, commitment))` or `None`.
            previous_version_id: Option<(u64, ContentId)>,
        },

        /// A governed operation was announced (commitment reset or tombstone).
        GovernedOpAnnounced {
            did: Did,
            /// The operation being announced.
            operation: GovernedOperation,
            /// Block height at which the operation was announced.
            announced_at_height: BlockNumberFor<T>,
            /// Account that deposited the announcement bond.
            deposit_account: T::AccountId,
            /// Deposit amount locked for the governed operation.
            deposit: u128,
            /// Previous state before this update: `Some((sequence, commitment))` or `None`.
            previous_version_id: Option<(u64, ContentId)>,
        },

        /// A governed operation was cancelled before execution.
        GovernedOpCancelled {
            did: Did,
            /// Previous state before this update: `Some((sequence, commitment))` or `None`.
            previous_version_id: Option<(u64, ContentId)>,
        },

        /// A governed operation was executed after its delay window.
        GovernedOpExecuted {
            did: Did,
            /// The operation that was executed.
            operation: GovernedOperation,
            /// Key reference of the signer who executed the operation.
            signer_key_ref: Vec<u8>,
            /// Block height at which execution occurred.
            block_height: BlockNumberFor<T>,
            /// Previous state before this update: `Some((sequence, commitment))` or `None`.
            previous_version_id: Option<(u64, ContentId)>,
        },
    }

    // ========== ERRORS ==========

    #[pallet::error]
    pub enum Error<T> {
        /// The DID has been tombstoned and cannot be modified.
        DidTombstoned,
        /// The signer does not have the required right for this operation.
        InsufficientRight,
        /// The signature verification failed.
        InvalidSignature,
        /// The nonce is invalid (replay protection).
        InvalidNonce,
        /// The key being revoked does not exist.
        KeyNotFound,
        /// The signer's key has been revoked or has expired.
        SignerKeyInvalid,
        /// The key already exists.
        KeyAlreadyExists,
        /// The right is already granted.
        RightAlreadyGranted,
        /// The right does not exist.
        RightNotFound,
        /// BeforeProof content already exists.
        BeforeProofAlreadyExists,
        /// The DID does not exist (no keys registered).
        DidNotFound,
        /// Operation references a DID that doesn't match the derived identifier.
        DidMismatch,
        /// The public key is invalid or unsupported.
        InvalidPublicKey,
        /// Storage bounds exceeded (too many keys, rights, or nonces).
        StorageBoundsExceeded,
        /// Commitment sequence does not equal stored_sequence + 1 (gap or duplicate).
        InvalidCommitmentSequence,
        /// A governed operation is already pending for this DID.
        PendingGovernedOpExists,
        /// No governed operation is pending for this DID to cancel or execute.
        NoPendingGovernedOp,
        /// The governed operation's delay window has not yet elapsed.
        GovernedOpNotYetExecutable,
        /// The governed operation's execution window has expired.
        GovernedOpExpired,
        /// A newly granted Update or Delegate right has not yet matured.
        RightNotYetMatured,
    }

    // ========== EXTRINSICS ==========

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a batch of SSI operations atomically.
        ///
        /// **Anti-Censorship:** Any account can submit for any DID.
        #[pallet::call_index(0)]
        #[pallet::weight({
            operations.iter().fold(Weight::zero(), |acc, op| {
                let w = match op {
                    SsiOperation::Did(signed) => match &signed.operation {
                        DidOperation::AddKey { .. } => T::WeightInfo::add_key(),
                        DidOperation::RevokeKey { .. } => T::WeightInfo::revoke_key(),
                        DidOperation::AddRight { .. } => T::WeightInfo::add_right(),
                        DidOperation::RevokeRight { .. } => T::WeightInfo::revoke_right(),
                        DidOperation::TombstoneDid { .. } => T::WeightInfo::tombstone_did(),
                        DidOperation::UpdateCommitment { .. } => T::WeightInfo::update_commitment(),
                        DidOperation::AnnounceGoverned { .. } => T::WeightInfo::announce_governed_op(),
                        DidOperation::CancelGoverned { .. } => T::WeightInfo::cancel_governed_op(),
                        DidOperation::ExecuteGoverned { .. } => T::WeightInfo::execute_governed_op(),
                    },
                    SsiOperation::BeforeProof(_) => T::WeightInfo::register_before_proof(),
                };
                acc.saturating_add(w)
            })
        })]
        pub fn submit_did_operations(
            origin: OriginFor<T>, operations: BoundedVec<SsiOperation, T::MaxOperationsPerTx>,
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;
            let block_height = <frame_system::Pallet<T>>::block_number();
            let height_u32: u32 = Self::block_number_to_u32(block_height);

            // Validate-then-apply each operation sequentially so that later
            // operations in the same batch see state mutations from earlier ones
            // (e.g. AddKey creates a DID, then AddRight on the same DID).
            // Substrate extrinsics are transactional — if any op fails, all
            // storage mutations in this call are rolled back.
            for op in &operations {
                match op {
                    SsiOperation::Did(signed_op) => {
                        Self::sweep_expired(&signed_op.operation.did().clone(), height_u32)?;
                        validation::validate_did_operation::<T>(signed_op, height_u32)?;
                        Self::apply_did_operation(signed_op, height_u32, block_height, &submitter)?;
                    }
                    SsiOperation::BeforeProof(content_id) => {
                        ensure!(
                            !BeforeProofs::<T>::contains_key(content_id),
                            Error::<T>::BeforeProofAlreadyExists
                        );
                        Self::apply_before_proof(*content_id, height_u32, block_height)?;
                    }
                }
            }

            Self::deposit_event(Event::SsiBatchApplied {
                submitter,
                operation_count: operations.len() as u32,
                block_height,
            });

            Ok(())
        }

        /// Register a content hash for proof-of-existence (convenience wrapper).
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::register_before_proof())]
        pub fn register_before_proof(
            origin: OriginFor<T>, content_id: ContentId,
        ) -> DispatchResult {
            let mut ops = BoundedVec::new();
            ops.try_push(SsiOperation::BeforeProof(content_id)).expect("1 op fits");
            Self::submit_did_operations(origin, ops)
        }
    }

    // ========== INTERNAL METHODS ==========

    impl<T: Config> Pallet<T> {
        /// Create a `DidState` pre-populated with a bootstrapping key and the
        /// three implicit rights (Update, Impersonate, Delegate). Used by
        /// `AddKey` for DID creation; reusable by future registration paths
        /// (e.g. `AddKey` with `KeyId` variant per `keyvault-plan.md`).
        fn bootstrap_did_state(
            did: &Did, vm: VerificationMethod, height_u32: u32,
        ) -> Result<DidState, DispatchError> {
            let key_ref = vm.key_ref.clone();
            let mut state = DidState::new(did.clone());
            state.keys.try_push(vm).map_err(|_| Error::<T>::StorageBoundsExceeded)?;

            for right in [Right::Update, Right::Impersonate, Right::Delegate] {
                state
                    .rights
                    .try_push(RightGrant {
                        key_ref: key_ref.clone(),
                        right,
                        granted_at_height: height_u32,
                        expires_at_height: None,
                        revoked_at_height: None,
                        matures_at_height: None,
                    })
                    .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
            }
            Ok(state)
        }

        /// Apply a single signed DID operation by mutating `DidState` in place.
        ///
        /// Types are already bounded — no conversion needed at the pallet boundary.
        fn apply_did_operation(
            signed_op: &SignedDidOperation, height_u32: u32, block_height: BlockNumberFor<T>,
            submitter: &T::AccountId,
        ) -> DispatchResult {
            let did = signed_op.operation.did().clone();

            match &signed_op.operation {
                DidOperation::AddKey { did: _, auth, purposes, expires_at_height } => {
                    // Extract key material from Authentication (validated as PublicKey variant
                    // by validation::validate_did_operation before we reach here).
                    let mpk = auth.to_multi_public_key().ok_or(Error::<T>::InvalidPublicKey)?;
                    let key_type = mpk.key_type().ok_or(Error::<T>::InvalidPublicKey)?;
                    let raw_bytes: Vec<u8> = mpk.raw_bytes();
                    let key_ref = KeyRef::new(format!("{}", auth.key_id()).into_bytes())
                        .map_err(|_| Error::<T>::InvalidPublicKey)?;

                    let vm = VerificationMethod {
                        key_ref: key_ref.clone(),
                        key_type,
                        controller: did.clone(),
                        public_key: raw_bytes
                            .try_into()
                            .map_err(|_| Error::<T>::InvalidPublicKey)?,
                        purposes: purposes.clone(),
                        added_at_height: height_u32,
                        expires_at_height: *expires_at_height,
                        revoked_at_height: None,
                    };

                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        match maybe_state {
                            None => {
                                *maybe_state =
                                    Some(Self::bootstrap_did_state(&did, vm, height_u32)?);
                            }
                            Some(state) => {
                                ensure!(
                                    state.find_key(&key_ref).is_none(),
                                    Error::<T>::KeyAlreadyExists
                                );
                                state
                                    .keys
                                    .try_push(vm)
                                    .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            }
                        }
                        // Update nonce in the state (works for both creation and existing).
                        let state = maybe_state.as_mut().unwrap();
                        state
                            .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                            .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                        Ok(())
                    })?;

                    Self::deposit_event(Event::KeyAdded {
                        did,
                        key_ref: key_ref.as_bytes().to_vec(),
                        key_type,
                        public_key: mpk.raw_bytes(),
                        purposes: purposes.to_vec(),
                        expires_at_height: *expires_at_height,
                        block_height,
                    });
                }

                DidOperation::RevokeKey { did: _, key_ref } => {
                    let removed_key = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<VerificationMethod, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let pos = state
                                .keys
                                .iter()
                                .position(|k| k.key_ref == *key_ref)
                                .ok_or(Error::<T>::KeyNotFound)?;
                            let removed = state.keys.remove(pos);
                            state
                                .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                                .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            Ok(removed)
                        },
                    )?;

                    Self::deposit_event(Event::KeyRevoked {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        block_height,
                    });
                }

                DidOperation::AddRight { did: _, key_ref, right, expires_at_height } => {
                    let matures_at_height = if matches!(right, Right::Update | Right::Delegate) {
                        Some(height_u32 + RIGHT_MATURITY_BLOCKS)
                    } else {
                        None
                    };
                    let grant = RightGrant {
                        key_ref: key_ref.clone(),
                        right: *right,
                        granted_at_height: height_u32,
                        expires_at_height: *expires_at_height,
                        revoked_at_height: None,
                        matures_at_height,
                    };

                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        state
                            .rights
                            .try_push(grant)
                            .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                        state
                            .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                            .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                        Ok(())
                    })?;

                    Self::deposit_event(Event::RightAdded {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        right: *right,
                        expires_at_height: *expires_at_height,
                        matures_at_height,
                        block_height,
                    });
                }

                DidOperation::RevokeRight { did: _, key_ref, right } => {
                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        let pos = state
                            .rights
                            .iter()
                            .rposition(|rg| rg.key_ref == *key_ref && rg.right == *right)
                            .ok_or(Error::<T>::RightNotFound)?;
                        state.rights.remove(pos);
                        state
                            .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                            .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                        Ok(())
                    })?;

                    Self::deposit_event(Event::RightRevoked {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        right: *right,
                        block_height,
                    });
                }

                DidOperation::TombstoneDid { did: _ } => {
                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        state.tombstoned_at_height = Some(height_u32);
                        state
                            .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                            .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                        Ok(())
                    })?;

                    Self::deposit_event(Event::DidTombstoned { did, block_height });
                }

                DidOperation::UpdateCommitment { did: _, commitment, sequence } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<_, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;

                            let prev = state.commitment;

                            state.commitment = Some((*sequence, *commitment));
                            state.last_modified_at = (height_u32, 0); // TODO: extrinsic index
                            state
                                .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                                .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            Ok(prev)
                        },
                    )?;

                    Self::deposit_event(Event::CommitmentUpdated {
                        did,
                        commitment: *commitment,
                        sequence: *sequence,
                        signer_key_ref: signed_op.signer_key_ref.as_bytes().to_vec(),
                        block_height,
                        previous_version_id,
                    });
                }

                DidOperation::AnnounceGoverned { did: _, operation } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<_, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;

                            let prev = state.commitment;

                            // Build the pending governed operation record.
                            // deposit_account stores who funded the announcement.
                            // deposit_amount is currently 0; a future Currency integration
                            // will lock the actual deposit from the caller's balance.
                            let pending = mosaic_did_types::PendingGovernedOp {
                                operation: operation.clone(),
                                announced_at_height: height_u32,
                                deposit_account: Self::encode_account(submitter),
                                deposit_amount: 0u128,
                            };
                            state.pending_operation = Some(pending);
                            state.last_modified_at = (height_u32, 0);
                            state
                                .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                                .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            Ok(prev)
                        },
                    )?;

                    Self::deposit_event(Event::GovernedOpAnnounced {
                        did,
                        operation: operation.clone(),
                        announced_at_height: block_height,
                        deposit_account: submitter.clone(),
                        deposit: 0u128,
                        previous_version_id,
                    });
                }

                DidOperation::CancelGoverned { did: _ } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<_, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;

                            let prev = state.commitment;
                            state.pending_operation = None;
                            state.last_modified_at = (height_u32, 0);
                            state
                                .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                                .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            Ok(prev)
                        },
                    )?;

                    Self::deposit_event(Event::GovernedOpCancelled { did, previous_version_id });
                }

                DidOperation::ExecuteGoverned { did: _ } => {
                    // Extract the pending operation before clearing it.
                    // (validation.rs already confirmed the pending op exists.)
                    let state = DidStates::<T>::get(&did).ok_or(Error::<T>::DidNotFound)?;
                    let pending_op =
                        state.pending_operation.as_ref().ok_or(Error::<T>::NoPendingGovernedOp)?;
                    let op = pending_op.operation.clone();

                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<_, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;

                            let prev = state.commitment;

                            // Apply the variant-specific state change.
                            match &op {
                                GovernedOperation::CommitmentReset {
                                    reason: _,
                                    commitment,
                                    sequence,
                                } => {
                                    state.commitment = Some((*sequence, *commitment));
                                }
                                GovernedOperation::Tombstone => {
                                    state.tombstoned_at_height = Some(height_u32);
                                }
                            }

                            state.pending_operation = None;
                            state.last_modified_at = (height_u32, 0);
                            state
                                .update_nonce(&signed_op.signer_key_ref, signed_op.nonce)
                                .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            Ok(prev)
                        },
                    )?;

                    Self::deposit_event(Event::GovernedOpExecuted {
                        did,
                        operation: op,
                        signer_key_ref: signed_op.signer_key_ref.as_bytes().to_vec(),
                        block_height,
                        previous_version_id,
                    });
                }
            }

            Ok(())
        }

        /// Apply a BeforeProof timestamp registration.
        /// Caller must verify that the content_id does not already exist.
        fn apply_before_proof(
            content_id: ContentId, height_u32: u32, block_height: BlockNumberFor<T>,
        ) -> DispatchResult {
            BeforeProofs::<T>::insert(
                content_id,
                BeforeProofRecord {
                    block_height: height_u32,
                    extrinsic_index: 0, // TODO: get actual extrinsic index
                },
            );

            Self::deposit_event(Event::BeforeProofRegistered { content_id, block_height });

            Ok(())
        }

        /// Helper to convert BlockNumber to u32.
        pub(crate) fn block_number_to_u32(block_number: BlockNumberFor<T>) -> u32 {
            use sp_runtime::traits::SaturatedConversion;
            block_number.saturated_into()
        }

        /// Encode an account ID into a fixed 32-byte array for storage in
        /// `PendingGovernedOp`. Pads with zeros if the account ID is shorter.
        fn encode_account(account: &T::AccountId) -> [u8; 32] {
            let encoded = account.encode();
            let mut buf = [0u8; 32];
            let len = encoded.len().min(32);
            buf[..len].copy_from_slice(&encoded[..len]);
            buf
        }

        /// Sweep expired keys and right grants from a DID's state.
        ///
        /// Called before every state-changing operation (§4.2). Removes entries
        /// where `expires_at_height ≤ current_height` and emits synthetic
        /// `KeyRevoked`/`RightRevoked` events so indexers record the expiration.
        /// Returns silently if the DID does not exist (no-op).
        fn sweep_expired(did: &Did, current_height: u32) -> Result<(), sp_runtime::DispatchError> {
            DidStates::<T>::try_mutate(did, |maybe_state| -> DispatchResult {
                let state = match maybe_state.as_mut() {
                    Some(s) => s,
                    None => return Ok(()), // DID not registered yet — nothing to sweep
                };

                // Sweep expired keys.
                let mut i = 0;
                while i < state.keys.len() {
                    if state.keys[i].expires_at_height.is_some_and(|h| current_height >= h) {
                        let removed = state.keys.swap_remove(i);
                        Self::deposit_event(Event::KeyRevoked {
                            did: did.clone(),
                            key_ref: removed.key_ref.as_bytes().to_vec(),
                            block_height: BlockNumberFor::<T>::from(current_height),
                        });
                    } else {
                        i += 1;
                    }
                }

                // Sweep expired right grants.
                let mut i = 0;
                while i < state.rights.len() {
                    if state.rights[i].expires_at_height.is_some_and(|h| current_height >= h) {
                        let removed = state.rights.swap_remove(i);
                        Self::deposit_event(Event::RightRevoked {
                            did: did.clone(),
                            key_ref: removed.key_ref.as_bytes().to_vec(),
                            right: removed.right,
                            block_height: BlockNumberFor::<T>::from(current_height),
                        });
                    } else {
                        i += 1;
                    }
                }

                Ok(())
            })
        }
    }
}
