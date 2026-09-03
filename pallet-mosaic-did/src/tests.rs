//! Unit tests for the Mosaic DID pallet (v2 — materialized state).

#[allow(clippy::wildcard_imports)]
use polkadot_sdk::*;

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::state::BeforeProofRecord;
    use mosaic_did_types::*;
    use mosaic_keyvault::multicipher::MSignature;

    // ===== Module-level secret keys (RFC 8032 test vectors) =====
    //
    // Public keys, DIDs, and key IDs are ALL derived from these via mosaic_keyvault
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

    // ===== Derivation helpers (use mosaic_keyvault production code) =====

    /// Derive raw 32-byte Ed25519 public key bytes from a secret key.
    fn pk_bytes(sk: &[u8; 32]) -> [u8; 32] {
        use mosaic_keyvault::PrivateKey;
        use mosaic_keyvault::ed25519::EdPrivateKey;
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

        let add_key =
            DidOperation::AddKey { did: did.clone(), auth: alice_auth(), expires_at_height: None };

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
    fn before_proof_record_structure() {
        let record = BeforeProofRecord { block_height: 12345, extrinsic_index: 3 };
        assert_eq!(record.block_height, 12345);
        assert_eq!(record.extrinsic_index, 3);
    }

    #[test]
    fn multi_signature_types() {
        let ed_sig = ed25519_blake3_signature([42u8; 64]);
        assert!(matches!(ed_sig, MSignature::Ed25519Blake3(_)));

        // r=1, s=1 are valid non-zero secp256k1 scalars
        let mut secp_bytes = [0u8; 64];
        secp_bytes[31] = 1;
        secp_bytes[63] = 1;
        let secp_sig = secp256k1_signature(secp_bytes);
        assert!(matches!(secp_sig, MSignature::Secp256k1(_)));
    }

    #[test]
    fn signed_operation_construction() {
        let did = alice_did();
        let auth = alice_auth();
        let signer_key_ref = KeyRef::new(auth.key_id().to_string().into_bytes()).unwrap();

        let signed_op = SignedDidOperation {
            operation: DidOperation::AddKey { did: did.clone(), auth, expires_at_height: None },
            signer_key_ref,
            signature: ed25519_blake3_signature([1u8; 64]),
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
            operation: DidOperation::AddKey { did: did.clone(), auth, expires_at_height: None },
            signer_key_ref,
            signature: ed25519_blake3_signature([1u8; 64]),
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

        fn make_test_state() -> DidState {
            let did = alice_did();
            let pk = pk_bytes(&ALICE_SK);
            let key_ref = alice_keyid();
            let mut state = DidState::new(did.clone());

            let vm = VerificationMethod {
                key_ref: key_ref.clone(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: pk.to_vec().try_into().unwrap(),
                added_at_height: 1,
                expires_at_height: None,
                revoked_at_height: None,
            };
            state.keys.try_push(vm).unwrap();

            // Bootstrapping rights (mirrors pallet's AddKey creation path).
            for right in [Right::Update, Right::Impersonate, Right::Delegate] {
                state
                    .rights
                    .try_push(RightGrant {
                        key_ref: key_ref.clone(),
                        right,
                        granted_at_height: 1,
                        expires_at_height: None,
                        revoked_at_height: None,
                        matures_at_height: None,
                    })
                    .unwrap();
            }

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
        fn bootstrap_rights_are_granted_on_creation() {
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
            let key_old = alice_keyid();
            let key_new = key_ref_from_sk(&BOB_SK);
            let mut state = DidState::new(did.clone());

            // Add old key at height 1
            state
                .keys
                .try_push(VerificationMethod {
                    key_ref: key_old.clone(),
                    key_type: KeyType::Ed25519,
                    controller: did.clone(),
                    public_key: vec![1u8; 32].try_into().unwrap(),
                    added_at_height: 1,
                    expires_at_height: None,
                    revoked_at_height: None,
                })
                .unwrap();

            // Add new key at height 50
            state
                .keys
                .try_push(VerificationMethod {
                    key_ref: key_new.clone(),
                    key_type: KeyType::Ed25519,
                    controller: did,
                    public_key: vec![2u8; 32].try_into().unwrap(),
                    added_at_height: 50,
                    expires_at_height: None,
                    revoked_at_height: None,
                })
                .unwrap();

            // Revoke old key at height 50
            state.keys[0].revoked_at_height = Some(50);

            // Before rotation: only old key valid
            assert_eq!(state.valid_keys_at(49).len(), 1);
            assert_eq!(state.valid_keys_at(49)[0].key_ref, key_old);

            // After rotation: only new key valid
            assert_eq!(state.valid_keys_at(50).len(), 1);
            assert_eq!(state.valid_keys_at(50)[0].key_ref, key_new);
        }
    }

    // ===== Runtime tests (use mock test externalities) =====

    mod runtime_tests {
        use super::*;
        use crate::mock::{RuntimeEvent, System, Test, new_test_ext};
        use frame_support::{assert_noop, assert_ok, traits::ConstU32};
        use frame_system::RawOrigin;
        use mosaic_did_types::{
            ContentId, DidOperation, GovernedOperation, KeyRef, SignedDidOperation, SsiOperation,
        };
        use parity_scale_codec::Encode;
        use sp_runtime::BoundedVec;

        /// Sign a message with a given Ed25519 secret key via mosaic_keyvault.
        fn sign_with_key(sk: &[u8; 32], message: &[u8]) -> MSignature {
            use mosaic_keyvault::PrivateKey;
            use mosaic_keyvault::ed25519::EdPrivateKey;
            let sk = EdPrivateKey::from_bytes(sk).expect("valid sk");
            let sig = sk.sign(message);
            MSignature::Ed25519Blake3(sig)
        }

        /// Build a signed operation, signing with Alice's real key.
        fn sign_op(operation: DidOperation, nonce: u64) -> SignedDidOperation {
            sign_op_with_key(&ALICE_SK, key_ref_from_sk(&ALICE_SK), operation, nonce)
        }

        /// Build a signed operation with an explicit key and key_ref.
        fn sign_op_with_key(
            sk: &[u8; 32], key_ref: KeyRef, operation: DidOperation, nonce: u64,
        ) -> SignedDidOperation {
            let signed_op = SignedDidOperation {
                operation,
                signer_key_ref: key_ref,
                signature: ed25519_blake3_signature([0u8; 64]),
                nonce,
            };
            let message =
                (&signed_op.operation, &signed_op.signer_key_ref, &signed_op.nonce).encode();
            let signature = sign_with_key(sk, &message);
            SignedDidOperation { signature, ..signed_op }
        }

        // ===== Test driver (eliminates boilerplate: block-number, setup, submit, state) =====

        /// Thin wrapper around Alice's DID inside an already-active test ext.
        /// The caller MUST wrap tests in `new_test_ext().execute_with(|| { … })`.
        struct TestDriver {
            did: Did,
            next_nonce: u64,
        }

        impl TestDriver {
            /// Register Alice's DID at block 1. Returns the driver.
            fn new() -> Self {
                let did = did_from_sk(&ALICE_SK);
                System::set_block_number(1);
                let mut this = Self { did, next_nonce: 1 };
                this.submit(&DidOperation::AddKey {
                    did: this.did.clone(),
                    auth: auth_from_sk(&ALICE_SK),
                    expires_at_height: None,
                });
                this
            }

            fn at_block(&self, n: u64) {
                System::set_block_number(n);
            }

            fn state(&self) -> DidState {
                crate::DidStates::<Test>::get(&self.did).expect("DID exists")
            }

            /// Submit `op` (signed by Alice). Panics on failure.
            fn submit(&mut self, op: &DidOperation) {
                let nonce = self.next_nonce;
                self.next_nonce = nonce + 1;
                let signed = sign_op(op.clone(), nonce);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));
            }

            /// Submit and expect `error`.
            fn submit_fails(&mut self, op: &DidOperation, error: crate::Error<Test>) {
                let nonce = self.next_nonce;
                self.next_nonce = nonce + 1;
                let signed = sign_op(op.clone(), nonce);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    error
                );
            }

            /// Submit `op` signed by an explicit key. Panics on failure.
            fn submit_as(&mut self, sk: &[u8; 32], key_ref: &KeyRef, op: &DidOperation) {
                let nonce = self.next_nonce;
                self.next_nonce = nonce + 1;
                let signed = sign_op_with_key(sk, key_ref.clone(), op.clone(), nonce);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));
            }

            /// Submit `op` signed by an explicit key and expect `error`.
            fn submit_as_fails(
                &mut self, sk: &[u8; 32], key_ref: &KeyRef, op: &DidOperation,
                error: crate::Error<Test>,
            ) {
                let nonce = self.next_nonce;
                self.next_nonce = nonce + 1;
                let signed = sign_op_with_key(sk, key_ref.clone(), op.clone(), nonce);
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(signed)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    error
                );
            }

            /// Add Bob's Ed25519 key with `Authentication` purpose.
            /// Returns Bob's key_ref. Caller may add additional rights.
            fn add_bob_key(&mut self) -> KeyRef {
                self.add_bob_key_expiring(None)
            }

            /// Add Bob's key with an optional expiry height.
            fn add_bob_key_expiring(&mut self, expires_at_height: Option<u32>) -> KeyRef {
                let bob_kr = key_ref_from_sk(&BOB_SK);
                self.submit(&DidOperation::AddKey {
                    did: self.did.clone(),
                    auth: auth_from_sk(&BOB_SK),
                    expires_at_height,
                });
                bob_kr
            }
        }

        // ===== Operation constructors (keep test bodies about intent, not struct syntax) =====

        fn cid(label: &str) -> ContentId {
            ContentId::from_bytes(label.as_bytes())
        }

        fn update_commitment(did: &Did, commitment: ContentId, sequence: u64) -> DidOperation {
            DidOperation::UpdateCommitment { did: did.clone(), commitment, sequence }
        }

        fn announce_tombstone(did: &Did) -> DidOperation {
            DidOperation::AnnounceGoverned {
                did: did.clone(),
                operation: GovernedOperation::Tombstone,
            }
        }

        fn announce_commitment_reset(
            did: &Did, reason: ContentId, commitment: ContentId, sequence: u64,
        ) -> DidOperation {
            DidOperation::AnnounceGoverned {
                did: did.clone(),
                operation: GovernedOperation::CommitmentReset { reason, commitment, sequence },
            }
        }

        fn cancel_governed(did: &Did) -> DidOperation {
            DidOperation::CancelGoverned { did: did.clone() }
        }

        fn execute_governed(did: &Did) -> DidOperation {
            DidOperation::ExecuteGoverned { did: did.clone() }
        }

        // ===== Tests =====

        #[test]
        fn update_commitment_happy_path() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let c = cid("doc v1");
                rt.submit(&update_commitment(&rt.did, c, 1));
                assert_eq!(rt.state().commitment, Some((1, c)));
            });
        }

        #[test]
        fn update_commitment_rejects_sequence_gap() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit_fails(
                    &update_commitment(&rt.did, cid("doc"), 2),
                    crate::Error::<Test>::InvalidCommitmentSequence,
                );
            });
        }

        #[test]
        fn update_commitment_rejects_nonexistent_did() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);
                let did = did_from_sk(&ALICE_SK);
                let signed = sign_op(update_commitment(&did, cid("doc"), 1), 1);
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
                let mut rt = TestDriver::new();
                // Tombstoning is only possible via the governed lifecycle:
                // announce → delay → execute.
                rt.submit(&announce_tombstone(&rt.did));
                rt.at_block(201);
                rt.submit(&execute_governed(&rt.did));

                rt.at_block(202);
                rt.submit_fails(
                    &update_commitment(&rt.did, cid("doc"), 1),
                    crate::Error::<Test>::DidTombstoned,
                );
            });
        }

        #[test]
        fn update_commitment_accepts_gapless_sequence() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let c1 = cid("doc v1");
                rt.submit(&update_commitment(&rt.did, c1, 1));
                rt.at_block(2);
                let c2 = cid("doc v2");
                rt.submit(&update_commitment(&rt.did, c2, 2));
                assert_eq!(rt.state().commitment, Some((2, c2)));
            });
        }

        #[test]
        fn update_commitment_event_previous_version_id() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let c1 = cid("doc v1");
                rt.submit(&update_commitment(&rt.did, c1, 1));

                let events: Vec<_> = System::read_events_no_consensus().collect();
                let first_pv = events.iter().find_map(|e| {
                    if let RuntimeEvent::MosaicDid(crate::Event::CommitmentUpdated {
                        previous_version_id,
                        sequence: 1,
                        ..
                    }) = &e.event
                    {
                        Some(*previous_version_id)
                    } else {
                        None
                    }
                });
                assert_eq!(first_pv, Some(Some((1, 0))), "first commitment has genesis prev");

                rt.at_block(2);
                let c2 = cid("doc v2");
                rt.submit(&update_commitment(&rt.did, c2, 2));

                let events: Vec<_> = System::read_events_no_consensus().collect();
                let second_pv = events.iter().find_map(|e| {
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
                // The second commitment must point back at the first commitment's
                // location, not at its own (block, extrinsic) — a self-pointer
                // here makes the §3.2 rewind algorithm unable to leave the
                // latest location.
                assert_eq!(second_pv, Some(Some((1, 0))), "second commitment points at the first");
            });
        }

        #[test]
        fn sweep_without_removal_does_not_advance_version() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&update_commitment(&rt.did, cid("v1"), 1));

                // Several blocks pass with nothing expiring; the sweep runs
                // before every operation but must leave last_modified_at alone.
                rt.at_block(5);
                rt.submit(&update_commitment(&rt.did, cid("v2"), 2));

                let events: Vec<_> = System::read_events_no_consensus().collect();
                let second_pv = events.iter().find_map(|e| {
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
                    second_pv,
                    Some(Some((1, 0))),
                    "idle sweeps must not break the version chain"
                );
            });
        }

        #[test]
        fn sweep_with_removal_points_at_true_previous_location() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.add_bob_key_expiring(Some(10));

                rt.at_block(11);
                rt.submit(&update_commitment(&rt.did, cid("v1"), 1));

                let events: Vec<_> = System::read_events_no_consensus().collect();
                let revoked_pv = events.iter().find_map(|e| {
                    if let RuntimeEvent::MosaicDid(crate::Event::KeyRevoked {
                        previous_version_id,
                        ..
                    }) = &e.event
                    {
                        Some(*previous_version_id)
                    } else {
                        None
                    }
                });
                // The sweep event must reference the last real mutation
                // (Bob's key added at (1, 0)), not the current location.
                assert_eq!(revoked_pv, Some(Some((1, 0))));
            });
        }

        #[test]
        fn nonce_survives_key_removal_replay_rejected() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let alice_kr = key_ref_from_sk(&ALICE_SK);
                let bob_kr = rt.add_bob_key();

                // Bob needs an active right to sign operations; AddRight grants
                // mature MATURITY blocks after granting.
                rt.submit(&DidOperation::AddRight {
                    did: rt.did.clone(),
                    key_ref: bob_kr.clone(),
                    right: Right::Delegate,
                    expires_at_height: None,
                });

                // Bob consumes his first nonce (stored 0 → strictly greater).
                rt.at_block(102);
                let consume = sign_op_with_key(
                    &BOB_SK,
                    bob_kr.clone(),
                    DidOperation::AddRight {
                        did: rt.did.clone(),
                        key_ref: alice_kr.clone(),
                        right: Right::Delegate,
                        expires_at_height: None,
                    },
                    1,
                );
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(consume)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));

                // Alice revokes Bob's key; the nonce lineage must survive.
                rt.submit(&DidOperation::RevokeKey {
                    did: rt.did.clone(),
                    key_ref: bob_kr.clone(),
                });
                assert_eq!(rt.state().nonce_for_key(&bob_kr), 1, "nonce must survive key removal");

                // Re-add the same key_ref and re-grant Delegate so the replay
                // below is otherwise fully valid once the grant matures.
                rt.submit(&DidOperation::AddKey {
                    did: rt.did.clone(),
                    auth: auth_from_sk(&BOB_SK),
                    expires_at_height: None,
                });
                rt.submit(&DidOperation::AddRight {
                    did: rt.did.clone(),
                    key_ref: bob_kr.clone(),
                    right: Right::Delegate,
                    expires_at_height: None,
                });

                // Replay the exact operation Bob signed before the removal.
                rt.at_block(203);
                let replay = sign_op_with_key(
                    &BOB_SK,
                    bob_kr.clone(),
                    DidOperation::AddRight {
                        did: rt.did.clone(),
                        key_ref: alice_kr.clone(),
                        right: Right::Delegate,
                        expires_at_height: None,
                    },
                    1,
                );
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(replay)].try_into().unwrap();
                assert_noop!(
                    crate::Pallet::<Test>::submit_did_operations(
                        RawOrigin::Signed(1u64).into(),
                        batch,
                    ),
                    crate::Error::<Test>::InvalidNonce
                );

                // A fresh nonce still works for the re-added key.
                let fresh = sign_op_with_key(
                    &BOB_SK,
                    bob_kr.clone(),
                    DidOperation::AddRight {
                        did: rt.did.clone(),
                        key_ref: alice_kr.clone(),
                        right: Right::Issue,
                        expires_at_height: None,
                    },
                    2,
                );
                let batch: BoundedVec<SsiOperation, ConstU32<100>> =
                    vec![SsiOperation::Did(fresh)].try_into().unwrap();
                assert_ok!(crate::Pallet::<Test>::submit_did_operations(
                    RawOrigin::Signed(1u64).into(),
                    batch,
                ));
            });
        }

        #[test]
        fn update_commitment_rejects_key_without_update_right() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();

                // Add Bob's key with only AssertionMethod (no Update right at all).
                let bob_kr = key_ref_from_sk(&BOB_SK);
                rt.submit(&DidOperation::AddKey {
                    did: rt.did.clone(),
                    auth: auth_from_sk(&BOB_SK),
                    expires_at_height: None,
                });

                rt.at_block(2);
                rt.submit_as_fails(
                    &BOB_SK,
                    &bob_kr,
                    &update_commitment(&rt.did, cid("doc"), 1),
                    crate::Error::<Test>::InsufficientRight,
                );
            });
        }

        #[test]
        fn revoke_key_removes_entry_from_vector() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let bob_kr = rt.add_bob_key();
                assert_eq!(rt.state().keys.len(), 2);
                rt.submit(&DidOperation::RevokeKey { did: rt.did.clone(), key_ref: bob_kr });
                assert_eq!(rt.state().keys.len(), 1);
            });
        }

        #[test]
        fn revoke_right_removes_entry_from_vector() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let bob_kr = rt.add_bob_key();

                let before = rt.state().rights.len(); // bootstrapping rights
                rt.submit(&DidOperation::AddRight {
                    did: rt.did.clone(),
                    key_ref: bob_kr.clone(),
                    right: Right::Issue,
                    expires_at_height: None,
                });
                assert_eq!(rt.state().rights.len(), before + 1);

                rt.submit(&DidOperation::RevokeRight {
                    did: rt.did.clone(),
                    key_ref: bob_kr,
                    right: Right::Issue,
                });
                assert_eq!(rt.state().rights.len(), before);
            });
        }

        #[test]
        fn sweep_removes_expired_key_on_next_operation() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.add_bob_key_expiring(Some(10));
                assert_eq!(rt.state().keys.len(), 2);

                rt.at_block(11);
                rt.submit(&update_commitment(&rt.did, cid("v1"), 1));
                assert_eq!(rt.state().keys.len(), 1); // Bob's key swept
            });
        }

        #[test]
        fn sweep_removes_expired_right_on_next_operation() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let bob_kr = rt.add_bob_key();

                let before = rt.state().rights.len(); // bootstrapping rights
                // Grant Issue right that expires at height 10.
                rt.submit(&DidOperation::AddRight {
                    did: rt.did.clone(),
                    key_ref: bob_kr.clone(),
                    right: Right::Issue,
                    expires_at_height: Some(10),
                });
                assert_eq!(rt.state().rights.len(), before + 1);

                // At block 11, right should be swept.
                rt.at_block(11);
                rt.submit(&update_commitment(&rt.did, cid("v1"), 1));
                assert_eq!(rt.state().rights.len(), before);
            });
        }

        #[test]
        fn right_maturity_blocks_immature_update_right() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                let bob_kr = rt.add_bob_key();

                // Grant Bob the Update right. Maturity = 1 + 100 = 101.
                rt.submit(&DidOperation::AddRight {
                    did: rt.did.clone(),
                    key_ref: bob_kr.clone(),
                    right: Right::Update,
                    expires_at_height: None,
                });
                assert_eq!(
                    rt.state()
                        .rights
                        .iter()
                        .find(|rg| rg.key_ref == bob_kr)
                        .unwrap()
                        .matures_at_height,
                    Some(1 + 100)
                );

                // Immature — rejected.
                rt.at_block(1);
                rt.submit_as_fails(
                    &BOB_SK,
                    &bob_kr,
                    &update_commitment(&rt.did, cid("doc"), 1),
                    crate::Error::<Test>::InsufficientRight,
                );

                // Matured — accepted.
                rt.at_block(101);
                rt.submit_as(&BOB_SK, &bob_kr, &update_commitment(&rt.did, cid("doc"), 1));
            });
        }

        #[test]
        fn announce_commitment_reset_stores_pending_op() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_commitment_reset(&rt.did, cid("reason"), cid("new"), 1));
                let pending = crate::PendingGovernedOps::<Test>::get(&rt.did).unwrap();
                assert_eq!(pending.announced_at_height, 1);
                assert!(matches!(pending.operation, GovernedOperation::CommitmentReset { .. }));
            });
        }

        #[test]
        fn announce_tombstone_stores_pending_op() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));
                let pending = crate::PendingGovernedOps::<Test>::get(&rt.did).unwrap();
                assert_eq!(pending.announced_at_height, 1);
                assert!(matches!(pending.operation, GovernedOperation::Tombstone));
            });
        }

        #[test]
        fn announce_rejects_second_pending() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));
                rt.at_block(2);
                rt.submit_fails(
                    &announce_tombstone(&rt.did),
                    crate::Error::<Test>::PendingGovernedOpExists,
                );
            });
        }

        #[test]
        fn announce_rejects_tombstoned_did() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));
                rt.at_block(201);
                rt.submit(&execute_governed(&rt.did));

                rt.at_block(202);
                rt.submit_fails(&announce_tombstone(&rt.did), crate::Error::<Test>::DidTombstoned);
            });
        }

        #[test]
        fn announce_rejects_nonexistent_did() {
            new_test_ext().execute_with(|| {
                System::set_block_number(1);
                let did = did_from_sk(&ALICE_SK);
                let signed = sign_op(announce_tombstone(&did), 1);
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
        fn cancel_clears_pending_op() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));
                rt.at_block(2);
                rt.submit(&cancel_governed(&rt.did));
                assert!(crate::PendingGovernedOps::<Test>::get(&rt.did).is_none());
            });
        }

        #[test]
        fn cancel_rejects_no_pending() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit_fails(
                    &cancel_governed(&rt.did),
                    crate::Error::<Test>::NoPendingGovernedOp,
                );
            });
        }

        #[test]
        fn execute_rejects_before_delay() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));
                rt.at_block(50);
                rt.submit_fails(
                    &execute_governed(&rt.did),
                    crate::Error::<Test>::GovernedOpNotYetExecutable,
                );
            });
        }

        #[test]
        fn execute_rejects_after_expiry() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));
                rt.at_block(402);
                rt.submit_fails(
                    &execute_governed(&rt.did),
                    crate::Error::<Test>::GovernedOpExpired,
                );
            });
        }

        #[test]
        fn execute_commitment_reset_rejects_sequence_gap() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                // Establish commitment sequence 1.
                rt.submit(&update_commitment(&rt.did, cid("v1"), 1));

                rt.at_block(2);
                // Announce CommitmentReset with sequence 5 — gap from 1 → 5 (missing 2,3,4).
                rt.submit(&announce_commitment_reset(&rt.did, cid("reason"), cid("v2"), 5));

                rt.at_block(202); // delay = 200
                // Execute should fail due to gapless sequence violation.
                rt.submit_fails(
                    &execute_governed(&rt.did),
                    crate::Error::<Test>::InvalidCommitmentSequence,
                );

                // State should be unchanged.
                assert_eq!(rt.state().commitment, Some((1, cid("v1"))));
            });
        }

        #[test]
        fn execute_commitment_reset_updates_state() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&update_commitment(&rt.did, cid("v1"), 1));

                rt.at_block(2);
                rt.submit(&announce_commitment_reset(&rt.did, cid("reason"), cid("v2"), 2));

                rt.at_block(202); // delay = 200
                rt.submit(&execute_governed(&rt.did));

                assert_eq!(rt.state().commitment, Some((2, cid("v2"))));
                assert!(crate::PendingGovernedOps::<Test>::get(&rt.did).is_none());
            });
        }

        #[test]
        fn execute_tombstone_sets_deactivation() {
            new_test_ext().execute_with(|| {
                let mut rt = TestDriver::new();
                rt.submit(&announce_tombstone(&rt.did));

                rt.at_block(201);
                rt.submit(&execute_governed(&rt.did));

                assert!(rt.state().is_tombstoned_at(201));
                assert!(crate::PendingGovernedOps::<Test>::get(&rt.did).is_none());
            });
        }
    }

    #[test]
    fn eurosign_workflow_types() {
        let signer_did = alice_did();
        let auth = alice_auth();
        let signer_key_ref = KeyRef::new(auth.key_id().to_string().into_bytes()).unwrap();

        let create_op = SsiOperation::Did(SignedDidOperation {
            operation: DidOperation::AddKey { did: signer_did, auth, expires_at_height: None },
            signer_key_ref,
            signature: ed25519_blake3_signature([1u8; 64]),
            nonce: 1,
        });

        let document_hash = ContentId::from_bytes(b"Signed contract PDF content...");
        let before_proof_op = SsiOperation::BeforeProof(document_hash);

        let batch = [create_op, before_proof_op];
        assert_eq!(batch.len(), 2);
    }

    /// SPEC-009 (DID signer) reference-vector dump for the TypeScript
    /// `shared/did-signer` Rust+TS agreement tests. Writes golden DID
    /// derivation, SCALE signable payloads for every operation variant
    /// (nonce 0 = creation carve-out, nonce 1 = existing DID), a signed
    /// example, and intra-batch nonce-allocation vectors to
    /// `/tmp/spec009-vectors.json`. Run: `./scripts/check.sh test:dump_scale_vectors`.
    #[test]
    fn dump_scale_vectors() {
        use parity_scale_codec::Encode;
        let hexstr = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();

        let pk = pk_bytes(&ALICE_SK);
        let did = did_from_sk(&ALICE_SK);
        let auth = auth_from_sk(&ALICE_SK);
        let key_ref = key_ref_from_sk(&ALICE_SK);
        let did_str = did.to_did_string();
        let key_id = auth.key_id().to_string();
        let pubkey_armored = auth.to_string();

        // REQ-001 golden vector (defense-in-depth pin in Rust, not just TS).
        assert_eq!(did_str, "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb");

        // Mirrors pallet-mosaic-did/src/validation.rs `signable_payload`:
        // the SCALE-encoded tuple (operation, signer_key_ref, nonce).
        let payload =
            |op: &DidOperation, nonce: u64| -> Vec<u8> { (op, &key_ref, &nonce).encode() };

        let addkey =
            DidOperation::AddKey { did: did.clone(), auth: auth.clone(), expires_at_height: None };
        let addkey_expires = DidOperation::AddKey {
            did: did.clone(),
            auth: auth.clone(),
            expires_at_height: Some(1000),
        };
        let revokekey = DidOperation::RevokeKey { did: did.clone(), key_ref: key_ref.clone() };
        let addright = DidOperation::AddRight {
            did: did.clone(),
            key_ref: key_ref.clone(),
            right: Right::Issue,
            expires_at_height: None,
        };
        let revokeright = DidOperation::RevokeRight {
            did: did.clone(),
            key_ref: key_ref.clone(),
            right: Right::Issue,
        };

        let op_entry = |name: &str, op: &DidOperation| -> serde_json::Value {
            serde_json::json!({
                "name": name,
                "signable_hex_nonce0": hexstr(&payload(op, 0)),
                "signable_hex_nonce1": hexstr(&payload(op, 1)),
            })
        };

        // Signed example: implicit-creation AddKey at nonce 0, signed by Alice.
        let creation_payload = payload(&addkey, 0);
        let signature_armored = {
            use mosaic_keyvault::PrivateKey;
            let ed_sig = mosaic_keyvault::ed25519::EdPrivateKey::from_bytes(ALICE_SK)
                .expect("valid sk")
                .sign(creation_payload.as_slice());
            let sig = MSignature::Ed25519Blake3(ed_sig);
            String::from(&sig)
        };

        let out = serde_json::json!({
            "schema": "spec009-vectors/v1",
            "source": "iop-rs pallet-mosaic-did/src/tests.rs::dump_scale_vectors",
            "golden": {
                "sk_hex": hexstr(&ALICE_SK[..]),
                "pk_hex": hexstr(&pk[..]),
                "did": did_str,
                "key_id_armored": key_id,
                "pubkey_armored": pubkey_armored,
                "signer_key_ref_utf8": auth.key_id().to_string(),
            },
            "operations": [
                op_entry("addKey", &addkey),
                op_entry("addKey_expires_1000", &addkey_expires),
                op_entry("revokeKey", &revokekey),
                op_entry("addRight_issue", &addright),
                op_entry("revokeRight_issue", &revokeright),
            ],
            "signed_example": {
                "operation": "addKey",
                "nonce": 0u64,
                "signable_hex": hexstr(&creation_payload),
                "signature_armored": signature_armored,
            },
            "batches": {
                "creation_0_1": [hexstr(&payload(&addkey, 0)), hexstr(&payload(&addright, 1))],
                "existing_1_2": [hexstr(&payload(&addright, 1)), hexstr(&payload(&revokekey, 2))],
            },
        });

        std::fs::write("/tmp/spec009-vectors.json", serde_json::to_string_pretty(&out).unwrap())
            .unwrap();
    }
}
