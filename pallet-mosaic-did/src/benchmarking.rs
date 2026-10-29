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
    Authentication, ContentId, Did, DidOperation, GovernedOperation, KeyRef, KeyType,
    MAX_KEYS_PER_DID, Right, SignedDidOperation, SsiOperation, VerificationMethod,
    ed25519_blake3_signature,
};
use parity_scale_codec::{Encode, alloc::string::ToString};
use polkadot_sdk::sp_core::Get;
use polkadot_sdk::sp_runtime::Saturating;

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
    use mosaic_keyvault::multicipher::MSignature;

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

/// Sign an operation with Alice's key, using her current key reference.
fn sign_alice_operation(operation: DidOperation, nonce: u64) -> SignedDidOperation {
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

/// A protocol-valid commitment content ID for benchmark operations.
fn benchmark_commitment() -> ContentId {
    ContentId::structured_blake3([0xAB; 32])
}

/// A deterministic benchmark key; never used as a production secret.
fn target_public_key() -> [u8; 32] {
    use mosaic_keyvault::PrivateKey;
    use mosaic_keyvault::ed25519::EdPrivateKey;

    EdPrivateKey::from_bytes([0x42; 32])
        .expect("valid benchmark key")
        .public_key()
        .to_bytes()
        .try_into()
        .expect("Ed25519 public key is 32 bytes")
}

fn target_key_ref() -> KeyRef {
    let auth = Authentication::from_key_type_and_bytes(KeyType::Ed25519, &target_public_key())
        .expect("valid target auth");
    KeyRef::new(format!("{}", auth.key_id()).into_bytes()).expect("valid target key ref")
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

/// Create a signed UpdateCommitment operation.
fn create_update_commitment_op(
    did: &Did, commitment: ContentId, sequence: u64, nonce: u64,
) -> SignedDidOperation {
    sign_alice_operation(
        DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence },
        nonce,
    )
}

/// Create a signed AnnounceGoverned operation.
fn create_announce_governed_op(
    did: &Did, operation: GovernedOperation, nonce: u64,
) -> SignedDidOperation {
    sign_alice_operation(DidOperation::AnnounceGoverned { did: did.clone(), operation }, nonce)
}

/// Create a signed CancelGoverned operation.
fn create_cancel_governed_op(did: &Did, nonce: u64) -> SignedDidOperation {
    sign_alice_operation(DidOperation::CancelGoverned { did: did.clone() }, nonce)
}

/// Create a signed ExecuteGoverned operation.
fn create_execute_governed_op(did: &Did, nonce: u64) -> SignedDidOperation {
    sign_alice_operation(DidOperation::ExecuteGoverned { did: did.clone() }, nonce)
}

/// The benchmark commitment reset used by both announcement and execution.
fn benchmark_governed_operation() -> GovernedOperation {
    GovernedOperation::CommitmentReset {
        reason: benchmark_commitment(),
        commitment: ContentId::structured_blake3([0xCD; 32]),
        sequence: 1,
    }
}

/// Fund a benchmark caller with enough free balance to cover the governed
/// operation deposit. Benchmark setup only; never part of the measured call.
fn fund_for_deposit<T: Config>(caller: &T::AccountId) {
    use frame_support::traits::tokens::fungible::{Inspect as _, Unbalanced as _};

    let amount = T::GovernedOpDeposit::get().saturating_add(T::Currency::minimum_balance());
    let free = T::Currency::balance(caller);
    let issuance = T::Currency::total_issuance();

    T::Currency::write_balance(caller, free.saturating_add(amount))
        .expect("benchmark caller balance can be written");
    T::Currency::set_total_issuance(issuance.saturating_add(amount));
}

/// Submit one signed operation as benchmark setup.
fn submit_setup_operation<T: Config>(caller: T::AccountId, signed_op: SignedDidOperation) {
    let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();
    Pallet::<T>::submit_did_operations(RawOrigin::Signed(caller).into(), operations)
        .expect("benchmark setup operation succeeds");
}

/// Announce the benchmark governed operation so cancel and execute have state.
fn setup_pending_governed_op<T: Config>(caller: &T::AccountId) {
    let signed_op = create_announce_governed_op(&alice_did(), benchmark_governed_operation(), 1);
    submit_setup_operation::<T>(caller.clone(), signed_op);
}

/// Pre-populate DID state for operations that require an existing DID.
fn setup_existing_did<T: Config>() {
    frame_system::Pallet::<T>::set_block_number(1u32.into());
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
        nonce: 0,
    };

    let mut state = mosaic_did_types::DidState::new(did.clone());
    state.keys.try_push(vm).expect("key fits");

    for i in 1..MAX_KEYS_PER_DID {
        state
            .keys
            .try_push(VerificationMethod {
                key_ref: if i == 1 {
                    target_key_ref()
                } else {
                    i.to_string().parse().expect("valid keyref")
                },
                key_type: KeyType::Ed25519,
                controller: did.clone(),
                public_key: if i == 1 { target_public_key() } else { [0u8; 32] }
                    .to_vec()
                    .try_into()
                    .expect("pk size is known"),
                added_at_height: i,
                expires_at_height: None,
                revoked_at_height: None,
                nonce: 0,
            })
            .expect("max keys/did is known");
    }

    // Match the normal creation bootstrap. Inserting keys directly must not
    // omit the authority required by the operations being measured.
    for right in [Right::Update, Right::Impersonate, Right::Delegate] {
        state
            .rights
            .try_push(mosaic_did_types::RightGrant {
                key_ref: key_ref.clone(),
                right,
                granted_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
                matures_at_height: None,
            })
            .expect("bootstrap rights fit");
    }

    DidStates::<T>::insert(did, state);
}

/// Pre-populate DID state with a right grant for RevokeRight benchmark.
fn setup_did_with_right<T: Config>() {
    setup_existing_did::<T>();

    let did = alice_did();
    let key_ref = target_key_ref();

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
        let key_ref = target_key_ref();
        let signed_op = create_revoke_key_op(&did, &key_ref, 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        assert!(state.find_key(&key_ref).is_none());
        assert!(state.has_right_at(&alice_key_ref(), Right::Update, 1));
    }

    #[benchmark]
    fn add_right<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        let did = alice_did();
        let key_ref = target_key_ref();
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
        let key_ref = target_key_ref();
        let signed_op = create_revoke_right_op(&did, &key_ref, Right::Issue, 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        assert!(!state.rights.iter().any(|r| r.right == Right::Issue && r.key_ref == key_ref));
        assert!(state.has_right_at(&alice_key_ref(), Right::Delegate, 1));
    }

    #[benchmark]
    fn update_commitment<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        let did = alice_did();
        let commitment = benchmark_commitment();
        let signed_op = create_update_commitment_op(&did, commitment, 1, 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        assert_eq!(state.commitment, Some((1, commitment)));
    }

    #[benchmark]
    fn announce_governed_op<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        fund_for_deposit::<T>(&caller);
        let did = alice_did();
        let governed_op = benchmark_governed_operation();
        let signed_op = create_announce_governed_op(&did, governed_op.clone(), 1);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let pending = PendingGovernedOps::<T>::get(&did).expect("pending op exists");
        assert_eq!(pending.operation, governed_op);
    }

    #[benchmark]
    fn cancel_governed_op<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        fund_for_deposit::<T>(&caller);
        setup_pending_governed_op::<T>(&caller);

        let did = alice_did();
        let signed_op = create_cancel_governed_op(&did, 2);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        assert!(PendingGovernedOps::<T>::get(&did).is_none());
    }

    #[benchmark]
    fn execute_governed_op<T: Config>() {
        setup_existing_did::<T>();

        let caller: T::AccountId = whitelisted_caller();
        fund_for_deposit::<T>(&caller);
        setup_pending_governed_op::<T>(&caller);
        frame_system::Pallet::<T>::set_block_number((GOVERNED_OP_DELAY_BLOCKS + 1).into());

        let did = alice_did();
        let signed_op = create_execute_governed_op(&did, 2);
        let operations = sp_std::vec![SsiOperation::Did(signed_op)].try_into().unwrap();

        #[extrinsic_call]
        submit_did_operations(RawOrigin::Signed(caller), operations);

        let state = DidStates::<T>::get(&did).expect("did exists");
        assert_eq!(state.commitment, Some((1, ContentId::structured_blake3([0xCD; 32]))));
        assert!(PendingGovernedOps::<T>::get(&did).is_none());
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

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Every `WeightInfo` entry must have a benchmark and nothing else: the
        /// weight generator emits one function per benchmark, so an extra
        /// benchmark produces a weight file that no longer implements the
        /// trait.
        #[test]
        fn benchmarks_match_weight_info() {
            let names: sp_std::vec::Vec<sp_std::vec::Vec<u8>> =
                <Pallet<crate::mock::Test> as frame_benchmarking::Benchmarking>::benchmarks(false)
                    .into_iter()
                    .map(|benchmark| benchmark.name)
                    .collect();
            let expected: sp_std::vec::Vec<sp_std::vec::Vec<u8>> = sp_std::vec![
                b"add_key".to_vec(),
                b"revoke_key".to_vec(),
                b"add_right".to_vec(),
                b"revoke_right".to_vec(),
                b"update_commitment".to_vec(),
                b"announce_governed_op".to_vec(),
                b"cancel_governed_op".to_vec(),
                b"execute_governed_op".to_vec(),
                b"register_before_proof".to_vec(),
            ];

            assert_eq!(names, expected);
        }
    }

    impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
