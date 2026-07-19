//! Unit tests for the Mosaic DID pallet (v2 — materialized state).

#[allow(clippy::wildcard_imports)]
use polkadot_sdk::*;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::state::BeforeProofRecord;
    use mosaic_did_types::*;

    // ===== Module-level secret keys (RFC 8032 test vectors) =====
    //
    // Public keys, DIDs, and key IDs are ALL derived from these via iop_keyvault
    // production code — never hardcoded separately.

    /// Alice's secret key — RFC 8032 test vector 1 (sk = 32 zero bytes).
    const ALICE_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// Bob's secret key — RFC 8032 test vector 2.
    const BOB_SK: [u8; 32] = [
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ];

    // ===== Derivation helpers (use iop_keyvault production code) =====

    /// Derive raw 32-byte Ed25519 public key bytes from a secret key.
    fn pk_bytes(sk: &[u8; 32]) -> [u8; 32] {
        use iop_keyvault::PrivateKey;
        use iop_keyvault::ed25519::EdPrivateKey;
        let pk = EdPrivateKey::from_bytes(sk).expect("valid sk").public_key();
        pk.to_bytes().try_into().expect("ed25519 pk is 32 bytes")
    }

    /// Derive a `did:mosaic` DID from a secret key.
    fn did_from_sk(sk: &[u8; 32]) -> Did {
        Did::from_public_key(&pk_bytes(sk)).expect("valid pk")
    }

    /// Derive an `Authentication::PublicKey` from a secret key.
    fn auth_from_sk(sk: &[u8; 32]) -> Authentication {
        Authentication::from_key_type_and_bytes(KeyType::Ed25519, &pk_bytes(sk))
            .expect("valid auth")
    }

    /// Derive a `KeyRef` from a secret key.
    fn key_ref_from_sk(sk: &[u8; 32]) -> KeyRef {
        let auth = auth_from_sk(sk);
        KeyRef::new(format!("{}", auth.key_id()).into_bytes()).expect("valid key ref")
    }

    // Convenience aliases
    fn alice_did() -> Did {
        did_from_sk(&ALICE_SK)
    }
    fn bob_did() -> Did {
        did_from_sk(&BOB_SK)
    }
    fn alice_auth() -> Authentication {
        auth_from_sk(&ALICE_SK)
    }
    fn alice_keyid() -> KeyRef {
        key_ref_from_sk(&ALICE_SK)
    }

    // ===== Type-level tests (no runtime needed) =====

    #[test]
    fn did_creation_from_public_key() {
        let pk = pk_bytes(&ALICE_SK);
        let did = Did::from_public_key(&pk).unwrap();
        let did2 = Did::from_public_key(&pk).unwrap();
        assert_eq!(did, did2);

        let pk2 = pk_bytes(&BOB_SK);
        let did3 = Did::from_public_key(&pk2).unwrap();
        assert_ne!(did, did3);
    }

    #[test]
    fn did_string_roundtrip() {
        let did = alice_did();
        let did_str = did.to_did_string();
        assert!(did_str.starts_with("did:mosaic:ioz"));
        let parsed = Did::from_did_string(&did_str).unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn content_id_deterministic() {
        let content = b"Invoice #2026-001 from ELMU";
        let cid1 = ContentId::from_bytes(content);
        let cid2 = ContentId::from_bytes(content);
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn operation_creates_correct_types() {
        let did = alice_did();

        let add_key = DidOperation::AddKey {
            did: did.clone(),
            auth: alice_auth(),
            purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                .try_into()
                .unwrap(),
            expires_at_height: None,
        };

        assert_eq!(add_key.did(), &did);
        assert_eq!(add_key.required_right(), Right::Update);
        assert_eq!(DidOperationType::from(&add_key), DidOperationType::AddKey);
    }

    #[test]
    fn rights_system() {
        let did = alice_did();
        let key_ref: KeyRef = alice_keyid();

        let add_right = DidOperation::AddRight {
            did: did.clone(),
            key_ref: key_ref.clone(),
            right: Right::Issue,
            expires_at_height: None,
        };
        assert_eq!(add_right.required_right(), Right::Delegate);

        let revoke_right = DidOperation::RevokeRight { did, key_ref, right: Right::Issue };
        assert_eq!(revoke_right.required_right(), Right::Delegate);
    }

    #[test]
    fn tombstone_requires_update_right() {
        let did = bob_did();
        let tombstone = DidOperation::TombstoneDid { did };
        assert_eq!(tombstone.required_right(), Right::Update);
    }

    #[test]
    fn before_proof_record_structure() {
        let record = BeforeProofRecord { block_height: 12345, extrinsic_index: 3 };
        assert_eq!(record.block_height, 12345);
        assert_eq!(record.extrinsic_index, 3);
    }

    #[test]
    fn multi_signature_types() {
        let ed_sig = MultiSignature::ed25519([42u8; 64]);
        assert_eq!(ed_sig.algorithm(), "Ed25519Blake3");

        // r=1, s=1 are valid non-zero secp256k1 scalars
        let mut secp_bytes = [0u8; 64];
        secp_bytes[31] = 1;
        secp_bytes[63] = 1;
        let secp_sig = MultiSignature::secp256k1(secp_bytes);
        assert_eq!(secp_sig.algorithm(), "secp256k1");
    }

    #[test]
    fn signed_operation_construction() {
        let did = alice_did();
        let auth = alice_auth();
        let signer_key_ref = KeyRef::new(auth.key_id().to_string().into_bytes()).unwrap();

        let signed_op = SignedDidOperation {
            operation: DidOperation::AddKey {
                did: did.clone(),
                auth,
                purposes: vec![KeyPurpose::Authentication].try_into().unwrap(),
                expires_at_height: None,
            },
            signer_key_ref,
            signature: MultiSignature::ed25519([1u8; 64]),
            nonce: 1,
        };

        assert_eq!(signed_op.operation.did(), &did);
        assert_eq!(signed_op.nonce, 1);
    }

    #[test]
    fn ssi_operation_variants() {
        let did = alice_did();
        let auth = alice_auth();
        let signer_key_ref = KeyRef::new(auth.key_id().to_string().into_bytes()).unwrap();

        let did_op = SsiOperation::Did(SignedDidOperation {
            operation: DidOperation::AddKey {
                did: did.clone(),
                auth,
                purposes: vec![KeyPurpose::Authentication].try_into().unwrap(),
                expires_at_height: None,
            },
            signer_key_ref,
            signature: MultiSignature::ed25519([1u8; 64]),
            nonce: 1,
        });

        let before_proof_op =
            SsiOperation::BeforeProof(ContentId::from_bytes(b"test document content"));

        match &did_op {
            SsiOperation::Did(op) => assert_eq!(op.operation.did(), &did),
            _ => panic!("Expected Did variant"),
        }

        match &before_proof_op {
            SsiOperation::BeforeProof(cid) => assert_ne!(*cid, ContentId::default()),
            _ => panic!("Expected BeforeProof variant"),
        }
    }

    // ===== State tests (using DidState directly) =====

    mod state_tests {
        use super::*;
        use frame_support::BoundedVec;

        fn make_test_state() -> DidState {
            let did = alice_did();
            let pk = pk_bytes(&ALICE_SK);
            let mut state = DidState::new(did.clone());

            let vm = VerificationMethod {
                key_ref: alice_keyid(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: pk.to_vec().try_into().unwrap(),
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                    .try_into()
                    .unwrap(),
                added_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
            };
            state.keys.try_push(vm).unwrap();
            state
        }

        #[test]
        fn new_state_is_empty() {
            let state = DidState::new(alice_did());
            assert!(!state.exists());
            assert!(!state.is_tombstoned_at(0));
        }

        #[test]
        fn state_with_key_exists() {
            let state = make_test_state();
            assert!(state.exists());
        }

        #[test]
        fn key_validity_at_height() {
            let vm = VerificationMethod {
                key_ref: alice_keyid(),
                key_type: KeyType::Ed25519,
                controller: bob_did(),
                public_key: vec![0u8; 32].try_into().unwrap(),
                purposes: BoundedVec::default(),
                added_at_height: 10,
                expires_at_height: Some(100),
                revoked_at_height: None,
            };

            assert!(!vm.is_valid_at(9));
            assert!(vm.is_valid_at(10));
            assert!(vm.is_valid_at(50));
            assert!(vm.is_valid_at(99));
            assert!(!vm.is_valid_at(100));
        }

        #[test]
        fn key_revoked_at_height() {
            let vm = VerificationMethod {
                key_ref: alice_keyid(),
                key_type: KeyType::Ed25519,
                controller: bob_did(),
                public_key: vec![0u8; 32].try_into().unwrap(),
                purposes: BoundedVec::default(),
                added_at_height: 10,
                expires_at_height: None,
                revoked_at_height: Some(50),
            };

            assert!(vm.is_valid_at(10));
            assert!(vm.is_valid_at(49));
            assert!(!vm.is_valid_at(50));
        }

        #[test]
        fn tombstoned_did() {
            let mut state = make_test_state();
            state.tombstoned_at_height = Some(50);

            assert!(!state.is_tombstoned_at(49));
            assert!(state.is_tombstoned_at(50));
            assert!(state.is_tombstoned_at(100));
        }

        #[test]
        fn initial_key_has_implicit_rights() {
            let state = make_test_state();
            let key_ref = alice_keyid();

            assert!(state.has_right_at(&key_ref, Right::Update, 1));
            assert!(state.has_right_at(&key_ref, Right::Impersonate, 1));
            assert!(state.has_right_at(&key_ref, Right::Delegate, 1));
            assert!(!state.has_right_at(&key_ref, Right::Issue, 1));
        }

        #[test]
        fn explicit_right_grant() {
            let mut state = make_test_state();
            let key_ref: KeyRef = alice_keyid();

            let grant = RightGrant {
                key_ref: key_ref.clone(),
                right: Right::Issue,
                granted_at_height: 10,
                expires_at_height: Some(100),
                revoked_at_height: None,
                matures_at_height: None,
            };
            state.rights.try_push(grant).unwrap();

            assert!(!state.has_right_at(&key_ref, Right::Issue, 9));
            assert!(state.has_right_at(&key_ref, Right::Issue, 10));
            assert!(state.has_right_at(&key_ref, Right::Issue, 99));
            assert!(!state.has_right_at(&key_ref, Right::Issue, 100));
        }

        #[test]
        fn nonce_management() {
            let state = make_test_state();
            let key_ref = alice_keyid();
            let unknown = "key-nonexistent".parse().unwrap();
            assert_eq!(state.nonce_for_key(&key_ref), 0);
            assert_eq!(state.nonce_for_key(&unknown), 0);
        }

        #[test]
        fn key_rotation_flow() {
            let did = alice_did();
            let mut state = DidState::new(did.clone());

            // Add old key at height 1
            state
                .keys
                .try_push(VerificationMethod {
                    key_ref: "key-old".parse().unwrap(),
                    key_type: KeyType::Ed25519,
                    controller: did.clone(),
                    public_key: vec![1u8; 32].try_into().unwrap(),
                    purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                        .try_into()
                        .unwrap(),
                    added_at_height: 1,
                    expires_at_height: None,
                    revoked_at_height: None,
                })
                .unwrap();

            // Add new key at height 50
            state
                .keys
                .try_push(VerificationMethod {
                    key_ref: "key-new".parse().unwrap(),
                    key_type: KeyType::Ed25519,
                    controller: did,
                    public_key: vec![2u8; 32].try_into().unwrap(),
                    purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                        .try_into()
                        .unwrap(),
                    added_at_height: 50,
                    expires_at_height: None,
                    revoked_at_height: None,
                })
                .unwrap();

            // Revoke old key at height 50
            state.keys[0].revoked_at_height = Some(50);

            // Before rotation: only old key valid
            assert_eq!(state.valid_keys_at(49).len(), 1);
            assert_eq!(state.valid_keys_at(49)[0].key_ref.as_bytes(), b"key-old");

            // After rotation: only new key valid
            assert_eq!(state.valid_keys_at(50).len(), 1);
            assert_eq!(state.valid_keys_at(50)[0].key_ref.as_bytes(), b"key-new");
        }
    }

    // ===== Runtime tests (use mock test externalities) =====

    mod runtime_tests {
        use super::*;
        use crate::mock::{RuntimeEvent, System, Test, new_test_ext};
        use frame_support::{assert_noop, assert_ok, traits::ConstU32};
        use frame_system::RawOrigin;
        use mosaic_did_types::{ContentId, DidOperation, KeyRef, SignedDidOperation, SsiOperation};
        use parity_scale_codec::Encode;
        use sp_runtime::BoundedVec;

        /// Sign a message with a given Ed25519 secret key via iop_keyvault.
        fn sign_with_key(sk: &[u8; 32], message: &[u8]) -> mosaic_did_types::MultiSignature {
            use iop_keyvault::PrivateKey;
            use iop_keyvault::ed25519::EdPrivateKey;
            let sk = EdPrivateKey::from_bytes(sk).expect("valid sk");
            let sig = sk.sign(message);
            mosaic_did_types::MultiSignature::from(
                iop_keyvault::multicipher::MSignature::Ed25519Blake3(sig),
            )
        }

        /// Build a signed operation, signing with Alice's real key.
        fn sign_op(operation: DidOperation, nonce: u64) -> SignedDidOperation {
            let signer_key_ref = key_ref_from_sk(&ALICE_SK);
            let signed_op = SignedDidOperation {
                operation,
                signer_key_ref: signer_key_ref.clone(),
                signature: mosaic_did_types::MultiSignature::ed25519([0u8; 64]),
                nonce,
            };
            let message =
                (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
            let signature = sign_with_key(&ALICE_SK, &message);
            SignedDidOperation { signature, ..signed_op }
        }

        /// Create Alice's DID on-chain at height 1 and return (did, key_ref).
        fn setup_alice_did() -> (Did, KeyRef) {
            let did = did_from_sk(&ALICE_SK);
            let key_ref = key_ref_from_sk(&ALICE_SK);

            let add_key_op = DidOperation::AddKey {
                did: did.clone(),
                auth: auth_from_sk(&ALICE_SK),
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                    .try_into()
                    .unwrap(),
                expires_at_height: None,
            };
            let signed = sign_op(add_key_op, 1);
            let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                vec![SsiOperation::Did(signed)].try_into().unwrap();
            assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                RawOrigin::Signed(1u64).into(),
                batch,
            ));

            (did, key_ref)
        }

        #[test]
        fn update_commitment_happy_path() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                let (did, _key_ref) = setup_alice_did();

                // Submit UpdateCommitment with sequence=1 (first commitment)
                let commitment = ContentId::from_bytes(b"rights document v1");
                let update_op =
                    DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence: 1 };
                let signed = sign_op(update_op, 2);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                // Verify state was updated
                let state = crate::Pallet::<Test>::did_state(&did).expect("DID exists");
                assert_eq!(state.commitment, Some((1, commitment)));

                // Verify event was emitted
                let events: Vec<_> = System::read_events_no_consensus().collect();
                let commitment_updated = events.iter().any(|e| {
                    matches!(
                        &e.event,
                        RuntimeEvent::MosaicDid(crate::Event::CommitmentUpdated {
                            did: d,
                            commitment: c,
                            sequence: 1,
                            ..
                        }) if *d == did && *c == commitment
                    )
                });
                assert!(commitment_updated, "CommitmentUpdated event must be emitted");
            });
        }

        #[test]
        fn update_commitment_rejects_sequence_gap() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                let (did, _key_ref) = setup_alice_did();

                // Try sequence=2 when stored=0 — should fail
                let commitment = ContentId::from_bytes(b"rights document v1");
                let update_op =
                    DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence: 2 };
                let signed = sign_op(update_op, 2);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    crate::Error::<Test>::InvalidCommitmentSequence
                );
            });
        }

        #[test]
        fn update_commitment_rejects_nonexistent_did() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                let did = did_from_sk(&ALICE_SK);
                let commitment = ContentId::from_bytes(b"rights document v1");
                let update_op =
                    DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence: 1 };
                let signed = sign_op(update_op, 1);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    crate::Error::<Test>::DidNotFound
                );
            });
        }

        #[test]
        fn update_commitment_rejects_tombstoned_did() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                let (did, _key_ref) = setup_alice_did();

                // Tombstone the DID at height 2
                let tombstone_op = DidOperation::TombstoneDid { did: did.clone() };
                let signed = sign_op(tombstone_op, 2);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                // Try UpdateCommitment on tombstoned DID at height 3
                System::set_block_number(3);
                let commitment = ContentId::from_bytes(b"rights document v1");
                let update_op =
                    DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence: 1 };
                let signed = sign_op(update_op, 3);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    crate::Error::<Test>::DidTombstoned
                );
            });
        }

        #[test]
        fn update_commitment_accepts_gapless_sequence() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                let (did, _key_ref) = setup_alice_did();

                // seq=1
                let c1 = ContentId::from_bytes(b"rights document v1");
                let op1 = DidOperation::UpdateCommitment {
                    did: did.clone(),
                    commitment: c1,
                    sequence: 1,
                };
                let signed1 = sign_op(op1, 2);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed1)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                // seq=2 — should succeed
                System::set_block_number(2);
                let c2 = ContentId::from_bytes(b"rights document v2");
                let op2 = DidOperation::UpdateCommitment {
                    did: did.clone(),
                    commitment: c2,
                    sequence: 2,
                };
                let signed2 = sign_op(op2, 3);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed2)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                // Verify state
                let state = crate::Pallet::<Test>::did_state(&did).expect("DID exists");
                assert_eq!(state.commitment, Some((2, c2)));
            });
        }

        #[test]
        fn update_commitment_event_previous_version_id() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                let (did, _key_ref) = setup_alice_did();

                // First commitment: previous_version_id should be None
                let c1 = ContentId::from_bytes(b"doc v1");
                let op1 = DidOperation::UpdateCommitment {
                    did: did.clone(),
                    commitment: c1,
                    sequence: 1,
                };
                let signed1 = sign_op(op1, 2);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed1)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                let events: Vec<_> = System::read_events_no_consensus().collect();
                let first_event = events.iter().find_map(|e| {
                    if let RuntimeEvent::MosaicDid(crate::Event::CommitmentUpdated {
                        previous_version_id,
                        ..
                    }) = &e.event
                    {
                        Some(*previous_version_id)
                    } else {
                        None
                    }
                });
                assert_eq!(first_event, Some(None), "first commitment has no previous version");

                // Second commitment: previous_version_id should be Some((1, c1))
                System::set_block_number(2);
                let c2 = ContentId::from_bytes(b"doc v2");
                let op2 = DidOperation::UpdateCommitment {
                    did: did.clone(),
                    commitment: c2,
                    sequence: 2,
                };
                let signed2 = sign_op(op2, 3);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed2)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                let events: Vec<_> = System::read_events_no_consensus().collect();
                let second_event = events.iter().find_map(|e| {
                    if let RuntimeEvent::MosaicDid(crate::Event::CommitmentUpdated {
                        previous_version_id,
                        sequence: 2,
                        ..
                    }) = &e.event
                    {
                        Some(*previous_version_id)
                    } else {
                        None
                    }
                });
                assert_eq!(
                    second_event,
                    Some(Some((1, c1))),
                    "second commitment references previous"
                );
            });
        }

        #[test]
        fn update_commitment_rejects_key_without_update_right() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);

                // Create DID with Alice (initial key has implicit Update)
                let (did, _alice_kr) = setup_alice_did();

                // Add Bob's key with only AssertionMethod purpose (no Update)
                let bob_auth = auth_from_sk(&BOB_SK);
                let bob_kr = key_ref_from_sk(&BOB_SK);

                let add_bob = DidOperation::AddKey {
                    did: did.clone(),
                    auth: bob_auth,
                    purposes: vec![KeyPurpose::AssertionMethod].try_into().unwrap(),
                    expires_at_height: None,
                };
                // Sign as Alice (who has Update right)
                let signed = sign_op(add_bob, 2);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                // Now try UpdateCommitment signed by Bob (who has no Update right)
                System::set_block_number(2);
                let commitment = ContentId::from_bytes(b"doc v1");
                let op =
                    DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence: 1 };
                let signed_op = SignedDidOperation {
                    operation: op,
                    signer_key_ref: bob_kr,
                    signature: mosaic_did_types::MultiSignature::ed25519([0u8; 64]),
                    nonce: 1,
                };
                let message =
                    (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
                let signed_op =
                    SignedDidOperation { signature: sign_with_key(&BOB_SK, &message), ..signed_op };

                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed_op)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    crate::Error::<Test>::InsufficientRight
                );
            });
        }
    }

    #[test]
    fn eurosign_workflow_types() {
        let signer_did = alice_did();
        let auth = alice_auth();
        let signer_key_ref = KeyRef::new(auth.key_id().to_string().into_bytes()).unwrap();

        let create_op = SsiOperation::Did(SignedDidOperation {
            operation: DidOperation::AddKey {
                did: signer_did,
                auth,
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod]
                    .try_into()
                    .unwrap(),
                expires_at_height: None,
            },
            signer_key_ref,
            signature: MultiSignature::ed25519([1u8; 64]),
            nonce: 1,
        });

        let document_hash = ContentId::from_bytes(b"Signed contract PDF content...");
        let before_proof_op = SsiOperation::BeforeProof(document_hash);

        let batch = [create_op, before_proof_op];
        assert_eq!(batch.len(), 2);
    }
}
