//! Benchmarking for pallet-mosaic-did.
//!
//! Uses real Ed25519 signatures with well-known test keys (RFC 8032 test vectors).
//! No signature verification bypassing — benchmarks reflect actual production costs.
//!
//! Since the pallet has a single batched extrinsic `submit_did_operations`, we benchmark
//! each operation type by submitting a batch with a single operation of that type.

use super::*;

use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use mosaic_did_types::{
    Authentication, ContentId, Did, DidOperation, KeyRef, KeyType, MAX_KEYS_PER_DID, Right,
    SignedDidOperation, SsiOperation, VerificationMethod, ed25519_blake3_signature,
};
use parity_scale_codec::{Encode, alloc::string::ToString};
use polkadot_sdk::{sp_core::Get, sp_runtime::BoundedVec};

/// RFC 8032 test vector 1 - Alice's Ed25519 key pair.
/// sk: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
/// pk: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
const ALICE_SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const ALICE_PK: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Sign a message using Alice's private key.
fn sign_with_alice(message: &[u8]) -> mosaic_keyvault::multicipher::MSignature {
    use mosaic_keyvault::PrivateKey;
    use mosaic_keyvault::ed25519::EdPrivateKey;

    let sk = EdPrivateKey::from_bytes(ALICE_SK).expect("valid alice sk");
    let sig = sk.sign(message);
    MSignature::Ed25519Blake3(sig)
}

/// Get Alice's DID (derived from her public key).
fn alice_did() -> Did {
    Did::from_public_key(&ALICE_PK).expect("valid alice pk")
}

/// Get Alice's authentication (PublicKey variant for AddKey).
fn alice_auth() -> Authentication {
    Authentication::from_key_type_and_bytes(KeyType::Ed25519, &ALICE_PK).expect("valid alice auth")
}

/// Get Alice's key reference (derived from her key ID).
fn alice_key_ref() -> KeyRef {
    let auth = alice_auth();
    KeyRef::new(format!("{}", auth.key_id()).into_bytes()).expect("valid key ref")
}

/// Create a signed AddKey operation for DID creation (first key).
fn create_add_key_op(nonce: u64) -> SignedDidOperation {
    let did = alice_did();
    let auth = alice_auth();
    let key_ref = alice_key_ref();

    let operation = DidOperation::AddKey { did, auth, expires_at_height: None, initial_nonce: 0 };

    let signed_op = SignedDidOperation {
        operation,
        signer_key_ref: key_ref,
        signature: ed25519_blake3_signature([0u8; 64]),
        nonce,
    };

    let message = (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
    let signature = sign_with_alice(&message);

    SignedDidOperation { signature, ..signed_op }
}

/// Create a signed RevokeKey operation.
fn create_revoke_key_op(did: &Did, key_ref: &KeyRef, nonce: u64) -> SignedDidOperation {
    let operation = DidOperation::RevokeKey { did: did.clone(), key_ref: key_ref.clone() };

    let signed_op = SignedDidOperation {
        operation,
        signer_key_ref: alice_key_ref(),
        signature: ed25519_blake3_signature([0u8; 64]),
        nonce,
    };

    let message = (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
    let signature = sign_with_alice(&message);

    SignedDidOperation { signature, ..signed_op }
}

/// Create a signed AddRight operation.
fn create_add_right_op(
    did: &Did, key_ref: &KeyRef, right: Right, nonce: u64,
) -> SignedDidOperation {
    let operation = DidOperation::AddRight {
        did: did.clone(),
        key_ref: key_ref.clone(),
        right,
        expires_at_height: None,
    };

    let signed_op = SignedDidOperation {
        operation,
        signer_key_ref: alice_key_ref(),
        signature: ed25519_blake3_signature([0u8; 64]),
        nonce,
    };

    let message = (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
    let signature = sign_with_alice(&message);

    SignedDidOperation { signature, ..signed_op }
}

/// Create a signed RevokeRight operation.
fn create_revoke_right_op(
    did: &Did, key_ref: &KeyRef, right: Right, nonce: u64,
) -> SignedDidOperation {
    let operation = DidOperation::RevokeRight { did: did.clone(), key_ref: key_ref.clone(), right };

    let signed_op = SignedDidOperation {
        operation,
        signer_key_ref: alice_key_ref(),
        signature: ed25519_blake3_signature([0u8; 64]),
        nonce,
    };

    let message = (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
    let signature = sign_with_alice(&message);

    SignedDidOperation { signature, ..signed_op }
}

/// Pre-populate DID state for operations that require an existing DID.
fn setup_existing_did<T: Config>() {
    let did = alice_did();
    let key_ref = alice_key_ref();

    let vm = VerificationMethod {
        key_ref: key_ref.clone(),
        key_type: KeyType::Ed25519,
        controller: did.clone(),
        public_key: ALICE_PK.to_vec().try_into().expect("pk fits"),
        added_at_height: 1,
        expires_at_height: None,
        revoked_at_height: None,
    };

    let mut state = mosaic_did_types::DidState::new(did.clone());
    state.keys.try_push(vm).expect("key fits");

    for i in 1..MAX_KEYS_PER_DID {
        state
            .keys
            .try_push(VerificationMethod {
                key_ref: i.to_string().parse().expect("valid keyref"),
                key_type: KeyType::Ed25519,
                controller: did.clone(),
                public_key: [0u8; 32].to_vec().try_into().expect("pk size is known"),
                added_at_height: i,
                expires_at_height: None,
                revoked_at_height: None,
            })
            .expect("max keys/did is known");
    }

    DidStates::<T>::insert(did, state);
}

/// Pre-populate DID state with a right grant for RevokeRight benchmark.
fn setup_did_with_right<T: Config>() {
    setup_existing_did::<T>();

    let did = alice_did();
    let key_ref = alice_key_ref();

    DidStates::<T>::mutate(&did, |maybe_state| {
        let state = maybe_state.as_mut().expect("did exists");
        state
            .rights
            .try_push(mosaic_did_types::RightGrant {
                key_ref: key_ref.clone(),
                right: Right::Issue,
                granted_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
                matures_at_height: None,
            })
            .expect("right fits");
    });
}

#[benchmarks]
mod benchmarks {
    use super::*;

    // Since this did does not exist yet, the call creates it and thus
    // it's the worst case measurement.
    #[benchmark]
    fn add_key<T: Config>() {
        let caller: T::AccountId = whitelisted_caller();
        let signed_op = create_add_key_op(1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let did = alice_did();
        assert!(DidStates::<T>::contains_key(&did));
    }

    #[benchmark]
    fn revoke_key<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        let did = alice_did();
        let key_ref = alice_key_ref();
        let signed_op = create_revoke_key_op(&did, &key_ref, 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        let key = state.find_key(&key_ref).expect("key exists");
        assert!(key.revoked_at_height.is_some());
    }

    #[benchmark]
    fn add_right<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        let did = alice_did();
        let key_ref = alice_key_ref();
        let signed_op = create_add_right_op(&did, &key_ref, Right::Issue, 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        assert!(state.rights.iter().any(|r| r.right == Right::Issue && r.key_ref == key_ref));
    }

    #[benchmark]
    fn revoke_right<T: Config>() {
        setup_did_with_right::<T>();

        let caller: T::AccountId = whitelisted_caller();
        let did = alice_did();
        let key_ref = alice_key_ref();
        let signed_op = create_revoke_right_op(&did, &key_ref, Right::Issue, 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        let grant = state
            .rights
            .iter()
            .find(|r| r.right == Right::Issue && r.key_ref == key_ref)
            .expect("right exists");
        assert!(grant.revoked_at_height.is_some());
    }

    #[benchmark]
    fn register_before_proof<T: Config>() {
        let caller: T::AccountId = whitelisted_caller();
        let content_id = ContentId::from_bytes(b"benchmark test document content");
        let operations = sp_std::vec![SsiOperation::BeforeProof(content_id)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        assert!(BeforeProofs::<T>::contains_key(content_id));
    }

    // impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
