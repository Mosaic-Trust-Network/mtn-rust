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
        ContentId, Did, DidOperation, DidState, GovernedOperation, KeyRef, KeyType, Right,
        RightGrant, SignedDidOperation, SsiOperation, VerificationMethod,
    };

    use crate::state::BeforeProofRecord;
    use crate::validation;

    /// A pending governed operation awaiting its delay window.
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
    pub struct PendingGovernedOp<AccountId> {
        pub operation: GovernedOperation,
        pub announced_at_height: u32,
        pub deposit_account: AccountId,
        pub deposit_amount: u128,
    }

    /// Number of blocks before a newly granted Update/Delegate right becomes
    /// exercisable. Gives the controller time to detect and revoke rights
    /// added by a compromised key.
    pub const RIGHT_MATURITY_BLOCKS: u32 = 100;

    /// Number of blocks that must elapse before a governed operation can be
    /// executed. Combined with GOVERNED_OP_EXPIRY_BLOCKS, this creates a
    /// window during which a compromised Update key cannot destroy the DID
    /// without the controller having time to cancel.
    pub const GOVERNED_OP_DELAY_BLOCKS: u32 = 200;

    pub const GOVERNED_OP_EXPIRY_BLOCKS: u32 = 400;

    #[pallet::config]
    pub trait Config: polkadot_sdk::frame_system::Config {
        #[pallet::constant]
        type MaxOperationsPerTx: Get<u32>;

        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ========== STORAGE ==========

    /// Materialized DID document state, keyed by DID.
    #[pallet::storage]
    pub type DidStates<T: Config> = StorageMap<_, Blake2_128Concat, Did, DidState, OptionQuery>;

    /// BeforeProof timestamps.
    #[pallet::storage]
    pub type BeforeProofs<T: Config> =
        StorageMap<_, Blake2_128Concat, ContentId, BeforeProofRecord, OptionQuery>;

    /// Pending governed operations, keyed by DID.
    #[pallet::storage]
    pub type PendingGovernedOps<T: Config> =
        StorageMap<_, Blake2_128Concat, Did, PendingGovernedOp<T::AccountId>, OptionQuery>;

    // ========== EVENTS ==========

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Atomic SSI batch successfully applied.
        SsiBatchApplied { submitter: T::AccountId, operation_count: u32 },

        /// A key was added to a DID document.
        KeyAdded {
            did: Did,
            key_ref: Vec<u8>,
            key_type: KeyType,
            public_key: Vec<u8>,
            expires_at_height: Option<u32>,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A key was revoked from a DID document.
        KeyRevoked { did: Did, key_ref: Vec<u8>, previous_version_id: Option<(u32, u32)> },

        /// A right was granted to a key.
        RightAdded {
            did: Did,
            key_ref: Vec<u8>,
            right: Right,
            expires_at_height: Option<u32>,
            matures_at_height: Option<u32>,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A right was revoked from a key.
        RightRevoked {
            did: Did,
            key_ref: Vec<u8>,
            right: Right,
            previous_version_id: Option<(u32, u32)>,
        },

        /// DID permanently deactivated.
        DidTombstoned { did: Did, previous_version_id: Option<(u32, u32)> },

        /// BeforeProof timestamp registered.
        BeforeProofRegistered { content_id: ContentId },

        /// A rights-document commitment was published on-chain.
        CommitmentUpdated {
            did: Did,
            commitment: ContentId,
            sequence: u64,
            signer_key_ref: Vec<u8>,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A governed operation was announced.
        GovernedOpAnnounced {
            did: Did,
            operation: GovernedOperation,
            deposit_account: T::AccountId,
            deposit: u128,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A governed operation was cancelled before execution.
        GovernedOpCancelled { did: Did, previous_version_id: Option<(u32, u32)> },

        /// A governed operation was executed after its delay window.
        GovernedOpExecuted {
            did: Did,
            operation: GovernedOperation,
            signer_key_ref: Vec<u8>,
            previous_version_id: Option<(u32, u32)>,
        },
    }

    // ========== ERRORS ==========

    #[pallet::error]
    pub enum Error<T> {
        DidTombstoned,
        InsufficientRight,
        InvalidSignature,
        InvalidNonce,
        KeyNotFound,
        SignerKeyInvalid,
        KeyAlreadyExists,
        RightAlreadyGranted,
        RightNotFound,
        BeforeProofAlreadyExists,
        DidNotFound,
        DidMismatch,
        InvalidPublicKey,
        StorageBoundsExceeded,
        InvalidCommitmentSequence,
        PendingGovernedOpExists,
        NoPendingGovernedOp,
        GovernedOpNotYetExecutable,
        GovernedOpExpired,
        RightNotYetMatured,
        CannotModifyOwnKey,
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
            let height_u32: u32 =
                Self::block_number_to_u32(<frame_system::Pallet<T>>::block_number());

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
                        Self::apply_did_operation(signed_op, height_u32, &submitter)?;
                    }
                    SsiOperation::BeforeProof(content_id) => {
                        ensure!(
                            !BeforeProofs::<T>::contains_key(content_id),
                            Error::<T>::BeforeProofAlreadyExists
                        );
                        Self::apply_before_proof(*content_id, height_u32)?;
                    }
                }
            }

            Self::deposit_event(Event::SsiBatchApplied {
                submitter,
                operation_count: operations.len() as u32,
            });

            Ok(())
        }

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
        /// three implicit rights (Update, Impersonate, Delegate).
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

        fn record_mutation(
            state: &mut DidState, key_ref: &KeyRef, nonce: u64,
        ) -> Result<(), sp_runtime::DispatchError> {
            let height: u32 = Self::block_number_to_u32(<frame_system::Pallet<T>>::block_number());
            let idx: u32 = frame_system::Pallet::<T>::extrinsic_index().unwrap_or(0);
            state.last_modified_at = (height, idx);
            state.update_nonce(key_ref, nonce).map_err(|_| Error::<T>::StorageBoundsExceeded.into())
        }

        fn apply_did_operation(
            signed_op: &SignedDidOperation, height_u32: u32, submitter: &T::AccountId,
        ) -> DispatchResult {
            let did = signed_op.operation.did().clone();

            match &signed_op.operation {
                DidOperation::AddKey { did: _, auth, expires_at_height } => {
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
                        added_at_height: height_u32,
                        expires_at_height: *expires_at_height,
                        revoked_at_height: None,
                    };

                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let prev = maybe_state.as_ref().map_or((0, 0), |s| s.last_modified_at);
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
                            let state = maybe_state.as_mut().unwrap();
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::KeyAdded {
                        did,
                        key_ref: key_ref.as_bytes().to_vec(),
                        key_type,
                        public_key: mpk.raw_bytes(),
                        expires_at_height: *expires_at_height,
                        previous_version_id,
                    });
                }

                DidOperation::RevokeKey { did: _, key_ref } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
                            let pos = state
                                .keys
                                .iter()
                                .position(|k| k.key_ref == *key_ref)
                                .ok_or(Error::<T>::KeyNotFound)?;
                            let removed = state.keys.remove(pos);
                            state.nonces.remove(&removed.key_ref);
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::KeyRevoked {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        previous_version_id,
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

                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
                            state
                                .rights
                                .try_push(grant)
                                .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::RightAdded {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        right: *right,
                        expires_at_height: *expires_at_height,
                        matures_at_height,
                        previous_version_id,
                    });
                }

                DidOperation::RevokeRight { did: _, key_ref, right } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
                            let pos = state
                                .rights
                                .iter()
                                .rposition(|rg| rg.key_ref == *key_ref && rg.right == *right)
                                .ok_or(Error::<T>::RightNotFound)?;
                            state.rights.remove(pos);
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::RightRevoked {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        right: *right,
                        previous_version_id,
                    });
                }

                DidOperation::TombstoneDid { did: _ } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
                            state.tombstoned_at_height = Some(height_u32);
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::DidTombstoned { did, previous_version_id });
                }

                DidOperation::UpdateCommitment { did: _, commitment, sequence } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
                            state.commitment = Some((*sequence, *commitment));
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::CommitmentUpdated {
                        did,
                        commitment: *commitment,
                        sequence: *sequence,
                        signer_key_ref: signed_op.signer_key_ref.as_bytes().to_vec(),
                        previous_version_id,
                    });
                }

                DidOperation::AnnounceGoverned { did: _, operation } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;

                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    // Build the pending governed operation record.
                    // deposit_account stores who funded the announcement.
                    // deposit_amount is currently 0; a future Fungible integration
                    // will lock the actual deposit from the caller's balance
                    let pending = PendingGovernedOp {
                        operation: operation.clone(),
                        announced_at_height: height_u32,
                        deposit_account: submitter.clone(),
                        deposit_amount: 0u128,
                    };
                    PendingGovernedOps::<T>::insert(&did, pending);

                    Self::deposit_event(Event::GovernedOpAnnounced {
                        did,
                        operation: operation.clone(),
                        deposit_account: submitter.clone(),
                        deposit: 0u128,
                        previous_version_id,
                    });
                }

                DidOperation::CancelGoverned { did: _ } => {
                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;
                    PendingGovernedOps::<T>::remove(&did);

                    Self::deposit_event(Event::GovernedOpCancelled { did, previous_version_id });
                }

                DidOperation::ExecuteGoverned { did: _ } => {
                    let pending_op = PendingGovernedOps::<T>::get(&did)
                        .ok_or(Error::<T>::NoPendingGovernedOp)?;
                    let op = pending_op.operation.clone();
                    PendingGovernedOps::<T>::remove(&did);

                    let previous_version_id = DidStates::<T>::try_mutate(
                        &did,
                        |maybe_state| -> Result<Option<(u32, u32)>, DispatchError> {
                            let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                            let prev = state.last_modified_at;
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
                            Self::record_mutation(
                                state,
                                &signed_op.signer_key_ref,
                                signed_op.nonce,
                            )?;
                            Ok(Some(prev))
                        },
                    )?;

                    Self::deposit_event(Event::GovernedOpExecuted {
                        did,
                        operation: op,
                        signer_key_ref: signed_op.signer_key_ref.as_bytes().to_vec(),
                        previous_version_id,
                    });
                }
            }

            Ok(())
        }

        fn apply_before_proof(content_id: ContentId, height_u32: u32) -> DispatchResult {
            BeforeProofs::<T>::insert(
                content_id,
                BeforeProofRecord { block_height: height_u32, extrinsic_index: 0 },
            );

            Self::deposit_event(Event::BeforeProofRegistered { content_id });

            Ok(())
        }

        pub(crate) fn block_number_to_u32(block_number: BlockNumberFor<T>) -> u32 {
            use sp_runtime::traits::SaturatedConversion;
            block_number.saturated_into()
        }

        fn sweep_expired(did: &Did, current_height: u32) -> Result<(), sp_runtime::DispatchError> {
            DidStates::<T>::try_mutate(did, |maybe_state| -> DispatchResult {
                let state = match maybe_state.as_mut() {
                    Some(s) => s,
                    None => return Ok(()),
                };

                // Sweep expired keys.
                let mut i = 0;
                while i < state.keys.len() {
                    if state.keys[i].expires_at_height.is_some_and(|h| current_height >= h) {
                        let removed = state.keys.swap_remove(i);
                        state.nonces.remove(&removed.key_ref);
                        Self::deposit_event(Event::KeyRevoked {
                            did: did.clone(),
                            key_ref: removed.key_ref.as_bytes().to_vec(),
                            previous_version_id: Some(state.last_modified_at),
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
                            previous_version_id: Some(state.last_modified_at),
                        });
                    } else {
                        i += 1;
                    }
                }

                state.last_modified_at =
                    (current_height, frame_system::Pallet::<T>::extrinsic_index().unwrap_or(0));

                Ok(())
            })
        }
    }
}
