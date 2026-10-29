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
    use frame_support::dispatch::PostDispatchInfo;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::tokens::{
        Fortitude, Precision, Restriction, fungible::Inspect as FungibleInspect,
        fungible::hold::Mutate as HoldMutate,
    };
    use frame_system::pallet_prelude::*;
    use sp_std::collections::btree_map::BTreeMap;
    use sp_std::vec::Vec;

    use mosaic_did_types::{
        ContentId, Did, DidOperation, DidState, GovernedOperation, KeyRef, KeyType, Right,
        RightGrant, SignedDidOperation, SsiOperation, VerificationMethod, public_key_raw_bytes,
        public_key_to_key_type,
    };

    use crate::state::BeforeProofRecord;
    use crate::validation;

    /// A pending governed operation awaiting its delay window.
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
    pub struct PendingGovernedOp<AccountId, Balance> {
        pub operation: GovernedOperation,
        pub announced_at_height: u32,
        pub deposit_account: AccountId,
        pub deposit_amount: Balance,
    }

    /// Convenience alias for the Balance type used by this pallet's Currency.
    #[allow(type_alias_bounds)]
    pub type BalanceOf<T: Config> = <<T as Config>::Currency as FungibleInspect<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

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

    /// Reasons for holding (locking) funds in this pallet.
    #[pallet::composite_enum]
    pub enum HoldReason {
        /// Deposit held while a governed operation awaits its delay window.
        GovernedOpDeposit,
    }

    #[pallet::config]
    pub trait Config: polkadot_sdk::frame_system::Config {
        #[pallet::constant]
        type MaxOperationsPerTx: Get<u32>;

        type WeightInfo: WeightInfo;

        /// Aggregated `HoldReason` from the runtime's `construct_runtime!`.
        type RuntimeHoldReason: From<HoldReason>;

        /// Currency type supporting holds for governed-operation deposits.
        type Currency: HoldMutate<Self::AccountId, Reason = Self::RuntimeHoldReason>;

        /// Amount of the native currency locked as a deposit when announcing a
        /// governed operation. On successful execution the deposit is released back
        /// to the announcer. On cancellation the deposit is transferred to the
        /// canceler as an anti-griefing bounty.
        #[pallet::constant]
        type GovernedOpDeposit: Get<<Self::Currency as FungibleInspect<Self::AccountId>>::Balance>;
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
    pub type PendingGovernedOps<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Did,
        PendingGovernedOp<T::AccountId, BalanceOf<T>>,
        OptionQuery,
    >;

    // ========== EVENTS ==========

    /// The signed operation that caused an event.
    ///
    /// Bundling the signer with the nonce makes it impossible for an event to
    /// expose a nonce without naming whose counter it advances, or vice versa.
    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
    pub struct OperationSigner {
        /// Key reference of the signer whose counter this operation consumed.
        pub key_ref: Vec<u8>,
        /// The operation's nonce.
        pub nonce: u64,
    }

    /// # Variant order
    ///
    /// SCALE encodes enum variants by declaration order, so every variant index
    /// is part of the wire format. Append new variants at the end; never insert
    /// one between existing variants.
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
            /// Replay-protection floor the added key starts from.
            initial_nonce: u64,
            /// The signed `AddKey` operation. For the self-signed creation of
            /// the DID, `signer.key_ref == key_ref`.
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A key was revoked by a signed `RevokeKey` operation.
        KeyRevoked {
            did: Did,
            key_ref: Vec<u8>,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A right was granted to a key.
        RightAdded {
            did: Did,
            key_ref: Vec<u8>,
            right: Right,
            expires_at_height: Option<u32>,
            matures_at_height: Option<u32>,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A right was revoked by a signed `RevokeRight` operation.
        RightRevoked {
            did: Did,
            key_ref: Vec<u8>,
            right: Right,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// BeforeProof timestamp registered.
        BeforeProofRegistered { content_id: ContentId },

        /// A rights-document commitment was published on-chain.
        CommitmentUpdated {
            did: Did,
            commitment: ContentId,
            sequence: u64,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A governed operation was announced.
        GovernedOpAnnounced {
            did: Did,
            operation: GovernedOperation,
            deposit_account: T::AccountId,
            deposit: BalanceOf<T>,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A governed operation was cancelled before execution.
        GovernedOpCancelled {
            did: Did,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A governed operation was executed after its delay window.
        GovernedOpExecuted {
            did: Did,
            operation: GovernedOperation,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A governed commitment reset was executed, restarting the document
        /// chain at this commitment.
        ///
        /// Emitted instead of [`Event::CommitmentUpdated`], not in addition to
        /// it: reset sequences stay gapless, so only the event kind tells an
        /// indexer that the post-reset document must carry no
        /// `previousCommitment`.
        CommitmentReset {
            did: Did,
            commitment: ContentId,
            sequence: u64,
            signer: OperationSigner,
            previous_version_id: Option<(u32, u32)>,
        },

        /// A key expired and was removed by the permissionless expiry sweep.
        ///
        /// Distinct from [`Event::KeyRevoked`]: no signed operation caused
        /// this removal, so there is no signer and no operation nonce.
        KeyExpired { did: Did, key_ref: Vec<u8>, previous_version_id: Option<(u32, u32)> },

        /// A right expired and was removed by the permissionless expiry sweep.
        RightExpired {
            did: Did,
            key_ref: Vec<u8>,
            right: Right,
            previous_version_id: Option<(u32, u32)>,
        },
    }

    // ========== ERRORS ==========

    /// # Variant order
    ///
    /// SCALE encodes enum variants by declaration order, so every error index
    /// is part of the dispatch-error wire format. Append new variants at the
    /// end; never insert one between existing variants.
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
        /// The deposit for a governed operation could not be reserved or transferred.
        DepositLockFailed,
        /// A rights-document commitment uses a hashing algorithm this runtime
        /// does not support.
        ///
        /// Structured BLAKE3 (`cm`) and structured SHA3 (`cj`) are supported;
        /// flat hashes (`cb`, `cB`) are not commitment algorithms. The set is
        /// closed: see `ContentId::is_supported_commitment_algorithm`.
        /// Widening it requires a runtime upgrade, so a chain never
        /// accumulates a commitment that the verifier cannot check. Applies
        /// only to commitments — a BeforeProof anchors arbitrary content and
        /// may use any representable algorithm.
        UnsupportedCommitmentAlgorithm,
    }

    // ========== WEIGHT HELPERS ==========

    /// Weight of a single SSI operation.
    ///
    /// Shared by the pre-dispatch batch estimate and the post-dispatch actual
    /// weight so the operation-to-weight mapping lives in exactly one place.
    pub fn ssi_operation_weight<T: Config>(op: &SsiOperation) -> Weight {
        match op {
            SsiOperation::Did(signed) => match &signed.operation {
                DidOperation::AddKey { .. } => T::WeightInfo::add_key(),
                DidOperation::RevokeKey { .. } => T::WeightInfo::revoke_key(),
                DidOperation::AddRight { .. } => T::WeightInfo::add_right(),
                DidOperation::RevokeRight { .. } => T::WeightInfo::revoke_right(),
                DidOperation::UpdateCommitment { .. } => T::WeightInfo::update_commitment(),
                DidOperation::AnnounceGoverned { .. } => T::WeightInfo::announce_governed_op(),
                DidOperation::CancelGoverned { .. } => T::WeightInfo::cancel_governed_op(),
                DidOperation::ExecuteGoverned { .. } => T::WeightInfo::execute_governed_op(),
            },
            SsiOperation::BeforeProof(_) => T::WeightInfo::register_before_proof(),
        }
    }

    /// Weight of a batch: every operation plus one `DidStates` read per
    /// distinct DID.
    ///
    /// `distinct_dids` is the upper bound (one per DID-carrying operation) for
    /// the pre-dispatch charge, and the actually touched count for the
    /// post-dispatch refund. The explicit read covers the lazy per-DID capture
    /// until the per-operation weights are regenerated from the current
    /// benchmark suite; drop it together with the weights update.
    pub fn batch_weight<T: Config>(operations: &[SsiOperation], distinct_dids: u64) -> Weight {
        operations
            .iter()
            .fold(Weight::zero(), |acc, op| acc.saturating_add(ssi_operation_weight::<T>(op)))
            .saturating_add(T::DbWeight::get().reads(distinct_dids))
    }

    // ========== EXTRINSICS ==========

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a batch of SSI operations atomically.
        ///
        /// **Anti-Censorship:** Any account can submit for any DID.
        #[pallet::call_index(0)]
        #[pallet::weight({
            // Worst case: every DID-carrying operation touches a different DID.
            let distinct_dids = operations
                .iter()
                .filter(|op| matches!(op, SsiOperation::Did(_)))
                .count() as u64;
            batch_weight::<T>(operations, distinct_dids)
        })]
        pub fn submit_did_operations(
            origin: OriginFor<T>, operations: BoundedVec<SsiOperation, T::MaxOperationsPerTx>,
        ) -> DispatchResultWithPostInfo {
            let submitter = ensure_signed(origin)?;
            let height_u32: u32 =
                Self::block_number_to_u32(<frame_system::Pallet<T>>::block_number());

            // Validate-then-apply each operation sequentially so that later
            // operations in the same batch see state mutations from earlier ones
            // (e.g. AddKey creates a DID, then AddRight on the same DID).
            // Substrate extrinsics are transactional — if any op fails, all
            // storage mutations in this call are rolled back.
            //
            // Plan §3.2: every event for a DID in this call carries the state
            // version from *before the call* as its `previous_version_id`, not
            // the previous operation's version. A backward walker reads all
            // events at this `(height, extrinsic)` location together and
            // follows that one pointer, so a per-operation capture would make
            // the second event point at the batch itself and strand the walker.
            // Captured lazily per DID: applying an operation mutates
            // `last_modified_at` in place, so later operations on the same DID
            // must reuse the first capture.
            let mut batch_previous: BTreeMap<Did, Option<(u32, u32)>> = BTreeMap::new();
            for op in &operations {
                match op {
                    SsiOperation::Did(signed_op) => {
                        let did = signed_op.operation.did();
                        let previous_version_id =
                            *batch_previous.entry(did.clone()).or_insert_with(|| {
                                DidStates::<T>::get(did).map(|s| s.last_modified_at)
                            });
                        Self::sweep_expired(did, height_u32, previous_version_id)?;
                        validation::validate_did_operation::<T>(signed_op, height_u32)?;
                        Self::apply_did_operation(
                            signed_op,
                            height_u32,
                            &submitter,
                            previous_version_id,
                        )?;
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

            // The capture ran once per DID actually touched, so refund the
            // worst-case distinct-DID reads charged up front.
            let actual_weight = batch_weight::<T>(&operations, batch_previous.len() as u64);
            Ok(PostDispatchInfo { actual_weight: Some(actual_weight), pays_fee: Pays::Yes })
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::register_before_proof())]
        pub fn register_before_proof(
            origin: OriginFor<T>, content_id: ContentId,
        ) -> DispatchResultWithPostInfo {
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

        /// Describe the signed operation that caused an event.
        fn operation_signer(signed_op: &SignedDidOperation) -> OperationSigner {
            OperationSigner {
                key_ref: signed_op.signer_key_ref.as_bytes().to_vec(),
                nonce: signed_op.nonce,
            }
        }

        fn record_mutation(
            state: &mut DidState, key_ref: &KeyRef, nonce: u64,
        ) -> Result<(), sp_runtime::DispatchError> {
            let height: u32 = Self::block_number_to_u32(<frame_system::Pallet<T>>::block_number());
            let idx: u32 = frame_system::Pallet::<T>::extrinsic_index().unwrap_or(0);
            state.last_modified_at = (height, idx);
            state.update_nonce(key_ref, nonce).map_err(|_| Error::<T>::SignerKeyInvalid.into())
        }

        fn apply_did_operation(
            signed_op: &SignedDidOperation, height_u32: u32, submitter: &T::AccountId,
            previous_version_id: Option<(u32, u32)>,
        ) -> DispatchResult {
            let did = signed_op.operation.did().clone();

            match &signed_op.operation {
                DidOperation::AddKey { did: _, auth, expires_at_height, initial_nonce } => {
                    let mpk = auth.to_multi_public_key().ok_or(Error::<T>::InvalidPublicKey)?;
                    let key_type =
                        public_key_to_key_type(&mpk).ok_or(Error::<T>::InvalidPublicKey)?;
                    let raw_bytes: Vec<u8> = public_key_raw_bytes(&mpk);
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
                        nonce: *initial_nonce,
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
                        let state = maybe_state.as_mut().unwrap();
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    Self::deposit_event(Event::KeyAdded {
                        did,
                        key_ref: key_ref.as_bytes().to_vec(),
                        key_type,
                        public_key: public_key_raw_bytes(&mpk),
                        expires_at_height: *expires_at_height,
                        signer: Self::operation_signer(signed_op),
                        initial_nonce: *initial_nonce,
                        previous_version_id,
                    });
                }

                DidOperation::RevokeKey { did: _, key_ref } => {
                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        let pos = state
                            .keys
                            .iter()
                            .position(|k| k.key_ref == *key_ref)
                            .ok_or(Error::<T>::KeyNotFound)?;
                        state.keys.remove(pos);
                        // The nonce entry deliberately survives removal:
                        // deleting it would reset the replay window to 0,
                        // letting pre-removal signed operations become
                        // valid again once the key_ref is re-registered.
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    Self::deposit_event(Event::KeyRevoked {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        signer: Self::operation_signer(signed_op),
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

                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        state
                            .rights
                            .try_push(grant)
                            .map_err(|_| Error::<T>::StorageBoundsExceeded)?;
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    Self::deposit_event(Event::RightAdded {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        right: *right,
                        expires_at_height: *expires_at_height,
                        matures_at_height,
                        signer: Self::operation_signer(signed_op),
                        previous_version_id,
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
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    Self::deposit_event(Event::RightRevoked {
                        did: did.clone(),
                        key_ref: key_ref.as_bytes().to_vec(),
                        right: *right,
                        signer: Self::operation_signer(signed_op),
                        previous_version_id,
                    });
                }

                DidOperation::UpdateCommitment { did: _, commitment, sequence } => {
                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        state.commitment = Some((*sequence, *commitment));
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    Self::deposit_event(Event::CommitmentUpdated {
                        did,
                        commitment: *commitment,
                        sequence: *sequence,
                        signer: Self::operation_signer(signed_op),
                        previous_version_id,
                    });
                }

                DidOperation::AnnounceGoverned { did: _, operation } => {
                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    // Hold the deposit from the submitter's balance.
                    let deposit = T::GovernedOpDeposit::get();
                    T::Currency::hold(&HoldReason::GovernedOpDeposit.into(), submitter, deposit)
                        .map_err(|_| Error::<T>::DepositLockFailed)?;

                    let pending = PendingGovernedOp {
                        operation: operation.clone(),
                        announced_at_height: height_u32,
                        deposit_account: submitter.clone(),
                        deposit_amount: deposit,
                    };
                    PendingGovernedOps::<T>::insert(&did, pending);

                    Self::deposit_event(Event::GovernedOpAnnounced {
                        did,
                        operation: operation.clone(),
                        deposit_account: submitter.clone(),
                        deposit,
                        signer: Self::operation_signer(signed_op),
                        previous_version_id,
                    });
                }

                DidOperation::CancelGoverned { did: _ } => {
                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    let pending = PendingGovernedOps::<T>::take(&did)
                        .ok_or(Error::<T>::NoPendingGovernedOp)?;

                    // Transfer the held deposit to the canceler as an anti-griefing bounty.
                    T::Currency::transfer_on_hold(
                        &HoldReason::GovernedOpDeposit.into(),
                        &pending.deposit_account,
                        submitter,
                        pending.deposit_amount,
                        Precision::Exact,
                        Restriction::Free,
                        Fortitude::Force,
                    )
                    .map_err(|_| Error::<T>::DepositLockFailed)?;

                    Self::deposit_event(Event::GovernedOpCancelled {
                        did,
                        signer: Self::operation_signer(signed_op),
                        previous_version_id,
                    });
                }

                DidOperation::ExecuteGoverned { did: _ } => {
                    let pending_op = PendingGovernedOps::<T>::take(&did)
                        .ok_or(Error::<T>::NoPendingGovernedOp)?;
                    let op = pending_op.operation.clone();

                    // Release the deposit back to the announcer.
                    T::Currency::release(
                        &HoldReason::GovernedOpDeposit.into(),
                        &pending_op.deposit_account,
                        pending_op.deposit_amount,
                        Precision::Exact,
                    )
                    .map_err(|_| Error::<T>::DepositLockFailed)?;

                    DidStates::<T>::try_mutate(&did, |maybe_state| -> DispatchResult {
                        let state = maybe_state.as_mut().ok_or(Error::<T>::DidNotFound)?;
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
                        Self::record_mutation(state, &signed_op.signer_key_ref, signed_op.nonce)
                    })?;

                    // A reset publishes a new commitment and restarts the
                    // document chain. It is emitted as its own event rather
                    // than `CommitmentUpdated`: reset sequences stay gapless,
                    // so a sequence number cannot identify the restart, and a
                    // plain update would make the post-reset document fail the
                    // verifier's `previous_commitment` linkage check.
                    //
                    // Emitted before `GovernedOpExecuted` so neither `did` nor
                    // `op` has to be cloned; both are consumed below.
                    if let GovernedOperation::CommitmentReset { commitment, sequence, .. } = &op {
                        Self::deposit_event(Event::CommitmentReset {
                            did: did.clone(),
                            commitment: *commitment,
                            sequence: *sequence,
                            signer: Self::operation_signer(signed_op),
                            previous_version_id,
                        });
                    }

                    Self::deposit_event(Event::GovernedOpExecuted {
                        did,
                        operation: op,
                        signer: Self::operation_signer(signed_op),
                        previous_version_id,
                    });
                }
            }

            Ok(())
        }

        fn apply_before_proof(content_id: ContentId, height_u32: u32) -> DispatchResult {
            // Anchored proofs must reference the extrinsic that registered
            // them; outside an extrinsic (tests) the index falls back to 0.
            let idx: u32 = frame_system::Pallet::<T>::extrinsic_index().unwrap_or(0);
            BeforeProofs::<T>::insert(
                content_id,
                BeforeProofRecord { block_height: height_u32, extrinsic_index: idx },
            );

            Self::deposit_event(Event::BeforeProofRegistered { content_id });

            Ok(())
        }

        pub(crate) fn block_number_to_u32(block_number: BlockNumberFor<T>) -> u32 {
            use sp_runtime::traits::SaturatedConversion;
            block_number.saturated_into()
        }

        fn sweep_expired(
            did: &Did, current_height: u32, previous_version_id: Option<(u32, u32)>,
        ) -> Result<(), sp_runtime::DispatchError> {
            DidStates::<T>::try_mutate(did, |maybe_state| -> DispatchResult {
                let state = match maybe_state.as_mut() {
                    Some(s) => s,
                    None => return Ok(()),
                };

                // The sweep events reference the batch-start version captured
                // by `submit_did_operations` — the location of the last real
                // mutation before this call, never the sweep's own position.
                let mut removed_any = false;

                // Sweep expired keys.
                let mut i = 0;
                while i < state.keys.len() {
                    if state.keys[i].expires_at_height.is_some_and(|h| current_height >= h) {
                        let removed = state.keys.swap_remove(i);
                        // Nonce entry survives (replay protection) — see RevokeKey.
                        Self::deposit_event(Event::KeyExpired {
                            did: did.clone(),
                            key_ref: removed.key_ref.as_bytes().to_vec(),
                            previous_version_id,
                        });
                        removed_any = true;
                    } else {
                        i += 1;
                    }
                }

                // Sweep expired right grants.
                let mut i = 0;
                while i < state.rights.len() {
                    if state.rights[i].expires_at_height.is_some_and(|h| current_height >= h) {
                        let removed = state.rights.swap_remove(i);
                        Self::deposit_event(Event::RightExpired {
                            did: did.clone(),
                            key_ref: removed.key_ref.as_bytes().to_vec(),
                            right: removed.right,
                            previous_version_id,
                        });
                        removed_any = true;
                    } else {
                        i += 1;
                    }
                }

                // Only an actual removal is a mutation; an idle sweep must not
                // advance the version pointer or every subsequent operation
                // would record itself as its own previous version.
                if removed_any {
                    state.last_modified_at =
                        (current_height, frame_system::Pallet::<T>::extrinsic_index().unwrap_or(0));
                }

                Ok(())
            })
        }
    }
}
