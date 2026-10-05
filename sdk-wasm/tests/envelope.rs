use crate::*;
use mosaic_did_types::signed::{AfterEnvelope, AfterProof, Signed};
use mosaic_keyvault::ed25519::EdPrivateKey;
use mosaic_keyvault::multicipher::MPrivateKey;
use mosaic_keyvault::{PrivateKey, PublicKey};

#[test]
fn wasm_envelope_native_fixture_and_negatives() {
    // Public RFC8032 section 7.1 test seed: synthetic fixture, never a user key.
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let sk = MPrivateKey::Ed25519Blake3(EdPrivateKey::from_bytes(seed).unwrap());
    let pk = sk.public_key();
    let key_ref = pk.key_id().to_string();
    let raw_pk = mosaic_did_types::public_key_raw_bytes(&pk);
    let envelope = AfterEnvelope {
        content: serde_json::json!({"message":"Synthetic Tresor test","network":{"genesisHash":format!("0x{}", "11".repeat(32)),"kind":"mosaic-simulation"},"nonce":"18446744073709551615"}),
        proof: AfterProof { block_height: 42, block_hash: format!("0x04{}", "00".repeat(31)) },
    };
    let json = serde_json::to_string(&envelope).unwrap();
    // Independent native producer: use json-digest and keyvault directly.
    let digest = json_digest::digest_data(&envelope).unwrap();
    let signature = sk.sign(digest.as_bytes());
    let signed = Signed::new(envelope.clone(), pk.to_string(), &signature);
    let wrong =
        MPrivateKey::Ed25519Blake3(EdPrivateKey::from_bytes([7u8; 32]).unwrap()).public_key();
    assert_eq!(envelope_signing_payload(&json).unwrap(), digest.as_bytes());
    assert_eq!(mosaic_public_key(&raw_pk).unwrap(), pk.to_string());
    assert_eq!(mosaic_key_ref(&pk.to_string()).unwrap(), key_ref);
    assert!(
        verify_envelope_signature(&json, &pk.to_string(), &signature.to_string(), &key_ref)
            .unwrap()
    );
    assert!(
        !verify_envelope_signature(
            &json,
            &pk.to_string(),
            &signature.to_string(),
            &wrong.key_id().to_string()
        )
        .unwrap()
    );
    let altered = json.replace("Synthetic Tresor test", "Altered document");
    assert!(
        !verify_envelope_signature(&altered, &pk.to_string(), &signature.to_string(), &key_ref)
            .unwrap()
    );
    assert!(
        envelope_signing_payload(
            r#"{"content":{},"proof":{"blockHeight":4294967296,"blockHash":"0x00"}}"#
        )
        .is_err()
    );
    for height in [u32::MAX, 0] {
        let mut changed = envelope.clone();
        changed.proof.block_height = height;
        let input = serde_json::to_string(&changed).unwrap();
        if height == u32::MAX {
            assert!(envelope_signing_payload(&input).is_err());
        } else {
            assert!(envelope_signing_payload(&input).is_ok());
        }
    }
    let vector = serde_json::json!({"envelopeJson":json,"digest":digest,"payload":digest.as_bytes(),"publicKey":pk.to_string(),"rawPublicKey":raw_pk,"keyRef":key_ref,"signature":signature.to_string(),"wrongPublicKey":wrong.to_string(),"wrongKeyRef":wrong.key_id().to_string(),"signedJson":serde_json::to_string(&signed).unwrap(),"signedFingerprint":json_digest::digest_data(&signed).unwrap()});
    if let Ok(path) = std::env::var("TRESOR_ENVELOPE_VECTOR_PATH") {
        std::fs::write(path, serde_json::to_string_pretty(&vector).unwrap() + "\n").unwrap();
    }
}
