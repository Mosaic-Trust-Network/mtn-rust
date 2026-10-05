use crate::*;
use mosaic_did_types::{
    Authentication, ContentId, Did, DidOperation, KeyRef, SignedDidOperation, SsiOperation,
};
use mosaic_keyvault::ed25519::EdPrivateKey;
use mosaic_keyvault::multicipher::MPrivateKey;
use mosaic_keyvault::{PrivateKey, PublicKey};
use parity_scale_codec::Encode;

#[test]
fn wasm_operation_native_vectors_and_rejections() {
    // Public synthetic test seed; never customer key material.
    let sk = MPrivateKey::Ed25519Blake3(EdPrivateKey::from_bytes([19; 32]).unwrap());
    let pk = sk.public_key();
    let raw = mosaic_did_types::public_key_raw_bytes(&pk);
    let did = Did::from_public_key(&raw).unwrap();
    let key_ref: KeyRef = pk.key_id().to_string().parse().unwrap();
    let content: ContentId =
        digest_json("{\"test\":\"Tresor commitment\"}", "blake3").unwrap().parse().unwrap();
    let cases = [
        (
            "initial",
            DidOperation::AddKey {
                did: did.clone(),
                auth: Authentication::PublicKey(pk.clone()),
                expires_at_height: None,
                initial_nonce: 9007199254740993,
            },
        ),
        (
            "commitment",
            DidOperation::UpdateCommitment {
                did: did.clone(),
                commitment: content,
                sequence: u64::MAX,
            },
        ),
    ];
    let mut vectors = Vec::new();
    for (name, operation) in cases {
        let scale = operation.encode();
        let prepared = if name == "initial" {
            initial_did_key_operation(&pk.to_string(), "9007199254740993").unwrap()
        } else {
            update_commitment_operation(
                &did.to_string(),
                &content.to_string(),
                &u64::MAX.to_string(),
            )
            .unwrap()
        };
        assert_eq!(prepared, scale);
        let nonce = u64::MAX;
        // Independent producer follows pallet validation.rs signable_payload.
        let payload = (&operation, &key_ref, &nonce).encode();
        let signature = sk.sign(&payload);
        let signed = SignedDidOperation {
            operation: operation.clone(),
            signer_key_ref: key_ref.clone(),
            signature: signature.clone(),
            nonce,
        };
        assert_eq!(
            did_operation_signing_payload(&scale, &key_ref.to_string(), &nonce.to_string())
                .unwrap(),
            payload
        );
        assert!(
            verify_did_operation_signature(
                &scale,
                &pk.to_string(),
                &signature.to_string(),
                &key_ref.to_string(),
                &nonce.to_string()
            )
            .unwrap()
        );
        assert_eq!(
            signed_did_operation_scale(
                &scale,
                &pk.to_string(),
                &signature.to_string(),
                &key_ref.to_string(),
                &nonce.to_string()
            )
            .unwrap(),
            signed.encode()
        );
        assert_eq!(
            did_ssi_operation_scale(
                &scale,
                &pk.to_string(),
                &signature.to_string(),
                &key_ref.to_string(),
                &nonce.to_string()
            )
            .unwrap(),
            SsiOperation::Did(signed).encode()
        );
        assert!(
            !verify_did_operation_signature(
                &scale,
                &pk.to_string(),
                &signature.to_string(),
                &key_ref.to_string(),
                "18446744073709551614"
            )
            .unwrap()
        );
        let mut trailing = scale.clone();
        trailing.push(0);
        assert!(
            did_operation_signing_payload(&trailing, &key_ref.to_string(), &nonce.to_string())
                .is_err()
        );
        vectors.push(serde_json::json!({"name":name,"operationScale":scale,"payload":payload,"signature":signature.to_string(),"signedScale":signed_did_operation_scale(&prepared,&pk.to_string(),&signature.to_string(),&key_ref.to_string(),&nonce.to_string()).unwrap(),"ssiScale":did_ssi_operation_scale(&prepared,&pk.to_string(),&signature.to_string(),&key_ref.to_string(),&nonce.to_string()).unwrap()}));
    }
    for nonce in ["0", "-1", "01", "1.5", "18446744073709551616", "9007199254740993.0"] {
        assert!(did_operation_signing_payload(&[0], &key_ref.to_string(), nonce).is_err());
    }
    assert!(
        update_commitment_operation(
            &did.to_string(),
            &content_id_from_hash(&[0; 32], "blake3-flat").unwrap(),
            "1"
        )
        .is_err()
    );
    assert!(
        did_operation_signing_payload(
            &DidOperation::CancelGoverned { did: did.clone() }.encode(),
            &key_ref.to_string(),
            "1"
        )
        .is_err()
    );
    let wrong_pk =
        MPrivateKey::Ed25519Blake3(EdPrivateKey::from_bytes([7; 32]).unwrap()).public_key();
    let initial = initial_did_key_operation(&pk.to_string(), "0").unwrap();
    assert!(did_operation_signing_payload(&initial, &wrong_pk.key_id().to_string(), "1").is_err());
    if let Ok(path) = std::env::var("TRESOR_OPERATION_VECTOR_PATH") {
        let wrong =
            MPrivateKey::Ed25519Blake3(EdPrivateKey::from_bytes([7; 32]).unwrap()).public_key();
        let fixture = serde_json::json!({"publicKey":pk.to_string(),"keyRef":key_ref.to_string(),"wrongPublicKey":wrong.to_string(),"wrongKeyRef":wrong.key_id().to_string(),"did":did.to_string(),"commitment":content.to_string(),"initialNonce":"9007199254740993","sequence":u64::MAX.to_string(),"nonce":u64::MAX.to_string(),"vectors":vectors});
        std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
    }
}
