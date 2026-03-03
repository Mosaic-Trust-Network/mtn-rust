//! Operation validation logic for the Mosaic DID pallet (v2 — direct state reads).
//!
//! Validation reads directly from `DidStates` storage instead of replaying
//! an operation log. This is O(1) per DID lookup instead of O(n) replay.
//!
//! ## Signature Verification
//!
//! Every operation is cryptographically authenticated by verifying the signature
//! against the public key bound to `signer_key_id` in the DID document state.
//! The signable payload is the SCALE-encoded tuple `(operation, signer_key_id, nonce)`.

use frame_support::ensure;
use parity_scale_codec::Encode;
use sp_std::vec::Vec;

use mosaic_did_types::{Did, DidOperation, KeyType, MultiPublicKey, Right, SignedDidOperation};

use crate::pallet::{Config, DidStates, Error};
use crate::state::OnChainDidState;

/// Validate a signed DID operation before applying it.
///
/// Reads materialized state directly — no history reconstruction needed.
/// Signature verification is performed against the resolved public key.
pub fn validate_did_operation<T: Config>(
    signed_op: &SignedDidOperation, height_u32: u32,
) -> Result<(), sp_runtime::DispatchError> {
    let did = signed_op.operation.did();

    // 1. Check if DID exists and is not tombstoned
    let maybe_state = DidStates::<T>::get(did);

    match &signed_op.operation {
        DidOperation::AddKey { did, key_id, public_key, key_type, .. } => {
            match &maybe_state {
                Some(state) => {
                    // DID exists: check not tombstoned, check nonce, check Update right
                    ensure!(!state.is_tombstoned_at(height_u32), Error::<T>::DidTombstoned);
                    validate_nonce::<T>(state, signed_op)?;
                    ensure!(
                        state.has_right_at(
                            signed_op.signer_key_id.as_bytes(),
                            Right::Update,
                            height_u32,
                        ),
                        Error::<T>::InsufficientRight
                    );
                    // Reject duplicate key IDs
                    ensure!(
                        state.find_key(key_id.as_bytes()).is_none(),
                        Error::<T>::KeyAlreadyExists
                    );
                    // Verify signature against signer's key resolved from state
                    validate_signature_from_state::<T>(signed_op, state)?;
                }
                None => {
                    // Implicit DID creation: DID must equal BLAKE3-256(public_key)
                    let derived_did = Did::from_public_key(public_key);
                    ensure!(*did == derived_did, Error::<T>::DidMismatch);
                    // Verify signature against the public key being registered
                    // (proves the submitter controls the private key)
                    validate_signature_for_creation::<T>(signed_op, public_key, *key_type)?;
                }
            }
        }

        DidOperation::RevokeKey { .. } => {
            let state = maybe_state.as_ref().ok_or(Error::<T>::DidNotFound)?;
            ensure!(!state.is_tombstoned_at(height_u32), Error::<T>::DidTombstoned);
            validate_nonce::<T>(state, signed_op)?;
            ensure!(
                state.has_right_at(signed_op.signer_key_id.as_bytes(), Right::Update, height_u32,),
                Error::<T>::InsufficientRight
            );
            validate_signature_from_state::<T>(signed_op, state)?;
        }

        DidOperation::AddRight { .. } => {
            let state = maybe_state.as_ref().ok_or(Error::<T>::DidNotFound)?;
            ensure!(!state.is_tombstoned_at(height_u32), Error::<T>::DidTombstoned);
            validate_nonce::<T>(state, signed_op)?;
            ensure!(
                state
                    .has_right_at(signed_op.signer_key_id.as_bytes(), Right::Delegate, height_u32,),
                Error::<T>::InsufficientRight
            );
            validate_signature_from_state::<T>(signed_op, state)?;
        }

        DidOperation::RevokeRight { .. } => {
            let state = maybe_state.as_ref().ok_or(Error::<T>::DidNotFound)?;
            ensure!(!state.is_tombstoned_at(height_u32), Error::<T>::DidTombstoned);
            validate_nonce::<T>(state, signed_op)?;
            ensure!(
                state
                    .has_right_at(signed_op.signer_key_id.as_bytes(), Right::Delegate, height_u32,),
                Error::<T>::InsufficientRight
            );
            validate_signature_from_state::<T>(signed_op, state)?;
        }

        DidOperation::TombstoneDid { .. } => {
            let state = maybe_state.as_ref().ok_or(Error::<T>::DidNotFound)?;
            ensure!(!state.is_tombstoned_at(height_u32), Error::<T>::DidTombstoned);
            validate_nonce::<T>(state, signed_op)?;
            ensure!(
                state.has_right_at(signed_op.signer_key_id.as_bytes(), Right::Update, height_u32,),
                Error::<T>::InsufficientRight
            );
            validate_signature_from_state::<T>(signed_op, state)?;
        }
    }

    Ok(())
}

/// Validate nonce is strictly greater than stored nonce (replay protection).
fn validate_nonce<T: Config>(
    state: &OnChainDidState, signed_op: &SignedDidOperation,
) -> Result<(), sp_runtime::DispatchError> {
    let stored_nonce = state.nonce_for_key(signed_op.signer_key_id.as_bytes());
    ensure!(signed_op.nonce > stored_nonce, Error::<T>::InvalidNonce);
    Ok(())
}

/// Compute the canonical signable payload for a signed operation.
///
/// The signature covers the SCALE-encoded tuple of (operation, signer_key_id, nonce)
/// to bind the signature to the exact operation, signer identity, and replay counter.
fn signable_payload(signed_op: &SignedDidOperation) -> Vec<u8> {
    (&signed_op.operation, &signed_op.signer_key_id, &signed_op.nonce).encode()
}

/// Resolve the signer's public key from DID state and verify the cryptographic signature.
///
/// This binds the claimed `signer_key_id` to an actual public key stored on-chain,
/// then verifies the signature was produced by the corresponding private key.
fn validate_signature_from_state<T: Config>(
    signed_op: &SignedDidOperation, state: &OnChainDidState,
) -> Result<(), sp_runtime::DispatchError> {
    // Resolve the signer's verification method from on-chain state
    let signer_key = state
        .find_key(signed_op.signer_key_id.as_bytes())
        .ok_or(Error::<T>::KeyNotFound)?;

    // Construct the typed public key from stored key_type + raw bytes
    let public_key =
        MultiPublicKey::from_key_type_and_bytes(signer_key.key_type, &signer_key.public_key)
            .ok_or(Error::<T>::InvalidPublicKey)?;

    let message = signable_payload(signed_op);
    ensure!(public_key.verify(&message, &signed_op.signature), Error::<T>::InvalidSignature);
    Ok(())
}

/// Verify signature for implicit DID creation using the public key from the operation.
///
/// For new DIDs, no state exists yet, so we verify against the public key being
/// registered in the AddKey operation itself. This proves the submitter controls
/// the private key corresponding to the DID identifier.
fn validate_signature_for_creation<T: Config>(
    signed_op: &SignedDidOperation, public_key_bytes: &[u8], key_type: KeyType,
) -> Result<(), sp_runtime::DispatchError> {
    let public_key = MultiPublicKey::from_key_type_and_bytes(key_type, public_key_bytes)
        .ok_or(Error::<T>::InvalidPublicKey)?;

    let message = signable_payload(signed_op);
    ensure!(public_key.verify(&message, &signed_op.signature), Error::<T>::InvalidSignature);
    Ok(())
}
