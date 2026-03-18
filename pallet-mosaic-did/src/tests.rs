//! Unit tests for the Mosaic DID pallet (v2 — materialized state).

#[cfg(test)]
mod unit_tests {
    use crate::state::BeforeProofRecord;
    use mosaic_did_types::*;

    // Valid Ed25519 public keys from RFC 8032 test vectors.
    // These are the only keys that can be used with Did::from_public_key.
    const PK_1: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
        0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
        0xf7, 0x07, 0x51, 0x1a,
    ];
    const PK_2: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
        0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
        0x2a, 0xf4, 0x66, 0x0c,
    ];
    const PK_3: [u8; 32] = [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
        0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
        0x48, 0x90, 0x80, 0x25,
    ];

    fn did_1() -> Did {
        Did::from_public_key(&PK_1).unwrap()
    }
    fn did_2() -> Did {
        Did::from_public_key(&PK_2).unwrap()
    }

    fn auth_1() -> Authentication {
        Authentication::from_key_type_and_bytes(KeyType::Ed25519, &PK_1).unwrap()
    }

    // ===== Type-level tests (no runtime needed) =====

    #[test]
    fn did_creation_from_public_key() {
        let did = Did::from_public_key(&PK_1).unwrap();
        let did2 = Did::from_public_key(&PK_1).unwrap();
        assert_eq!(did, did2);

        let did3 = Did::from_public_key(&PK_2).unwrap();
        assert_ne!(did, did3);
    }

    #[test]
    fn did_string_roundtrip() {
        let did = did_1();
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
        let did = did_1();

        let add_key = DidOperation::AddKey {
            did: did.clone(),
            auth: auth_1(),
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
        let did = did_1();
        let key_ref: KeyRef = "key-1".parse().unwrap();

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
        let did = did_2();
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
        let did = did_1();
        let auth = auth_1();
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
        let did = did_1();
        let auth = auth_1();
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
        use mosaic_did_types::*;

        fn make_test_state() -> DidState {
            let did = did_1();
            let mut state = DidState::new(did.clone());

            let vm = VerificationMethod {
                id: "key-1".parse().unwrap(),
                key_type: KeyType::Ed25519,
                controller: did,
                public_key: PK_1.to_vec().try_into().unwrap(),
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
            let state = DidState::new(did_1());
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
                id: "key-1".parse().unwrap(),
                key_type: KeyType::Ed25519,
                controller: did_2(),
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
                id: "key-1".parse().unwrap(),
                key_type: KeyType::Ed25519,
                controller: did_2(),
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
            let key_ref = "key-1".parse().unwrap();

            assert!(state.has_right_at(&key_ref, Right::Update, 1));
            assert!(state.has_right_at(&key_ref, Right::Impersonate, 1));
            assert!(state.has_right_at(&key_ref, Right::Delegate, 1));
            assert!(!state.has_right_at(&key_ref, Right::Issue, 1));
        }

        #[test]
        fn explicit_right_grant() {
            let mut state = make_test_state();
            let key_ref: KeyRef = "key-1".parse().unwrap();

            let grant = RightGrant {
                key_ref: key_ref.clone(),
                right: Right::Issue,
                granted_at_height: 10,
                expires_at_height: Some(100),
                revoked_at_height: None,
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
            let key_ref = "key-1".parse().unwrap();
            let unknown = "key-nonexistent".parse().unwrap();
            assert_eq!(state.nonce_for_key(&key_ref), 0);
            assert_eq!(state.nonce_for_key(&unknown), 0);
        }

        #[test]
        fn key_rotation_flow() {
            let did = did_1();
            let mut state = DidState::new(did.clone());

            // Add old key at height 1
            state
                .keys
                .try_push(VerificationMethod {
                    id: "key-old".parse().unwrap(),
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
                    id: "key-new".parse().unwrap(),
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
            assert_eq!(state.valid_keys_at(49)[0].id.as_bytes(), b"key-old");

            // After rotation: only new key valid
            assert_eq!(state.valid_keys_at(50).len(), 1);
            assert_eq!(state.valid_keys_at(50)[0].id.as_bytes(), b"key-new");
        }
    }

    #[test]
    fn eurosign_workflow_types() {
        let signer_did = did_1();
        let auth = auth_1();
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

        let batch = vec![create_op, before_proof_op];
        assert_eq!(batch.len(), 2);
    }
}
