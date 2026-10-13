use super::*;
use parity_scale_codec::Encode;
use polkadot_sdk::{
    sp_core::H256,
    sp_runtime::{
        generic::{Digest, DigestItem, Header},
        traits::BlakeTwo256,
    },
};
type NativeHeader = Header<u32, BlakeTwo256>;

fn fixture() -> (NativeHeader, serde_json::Value) {
    let proof: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/vectors/before-proof.json")).unwrap();
    let root: Vec<u8> = serde_json::from_value(proof["stateRoot"].clone()).unwrap();
    (
        NativeHeader {
            parent_hash: H256::repeat_byte(1),
            number: 48,
            state_root: H256::from_slice(&root),
            extrinsics_root: H256::repeat_byte(2),
            digest: Digest {
                logs: vec![
                    DigestItem::PreRuntime(*b"aura", vec![3, 4]),
                    DigestItem::Consensus(*b"FRNK", vec![5]),
                    DigestItem::Other(vec![6, 7]),
                    DigestItem::Seal(*b"aura", vec![8, 9]),
                    DigestItem::RuntimeEnvironmentUpdated,
                ],
            },
        },
        proof,
    )
}

fn verify(
    header: &NativeHeader, proof: &serde_json::Value, expected_hash: &[u8], height: &str,
    registration: &str,
) -> Result<bool, String> {
    verify_before_proof_header_v1(
        expected_hash,
        height,
        &header.encode(),
        proof["contentId"].as_str().unwrap(),
        registration,
        "7",
        &proof["nodes"].to_string(),
    )
}

#[test]
fn header_before_proof_binds_native_scale_hash_and_state_root() {
    let (header, proof) = fixture();
    let rpc = serde_json::to_string(&header).unwrap();
    let frozen: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tests/vectors/before-proof-header.json"))
            .unwrap();
    assert_eq!(frozen["scale"], serde_json::json!(header.encode()));
    assert_eq!(frozen["blockHash"], serde_json::json!(header.hash().as_bytes()));

    if std::env::var_os("TRESOR_EMIT_HEADER_VECTOR").is_some() {
        println!(
            "HEADER_VECTOR={}",
            serde_json::json!({"rpc":serde_json::to_value(&header).unwrap(),"scale":header.encode(),"blockHash":header.hash().as_bytes(),"blockHeight":"48","stateRoot":proof["stateRoot"]})
        );
    }

    assert_eq!(mosaic_header_scale_v1(&rpc).unwrap(), header.encode());
    let info: serde_json::Value =
        serde_json::from_str(&inspect_mosaic_header_v1(&header.encode()).unwrap()).unwrap();
    assert_eq!(info["blockHeight"], "48");
    assert_eq!(info["blockHash"], serde_json::json!(header.hash().as_bytes()));
    assert_eq!(info["stateRoot"], proof["stateRoot"]);
    assert!(verify(&header, &proof, header.hash().as_bytes(), "48", "42").unwrap());
    assert!(!verify(&header, &proof, &[0; 32], "48", "42").unwrap());
    assert!(!verify(&header, &proof, header.hash().as_bytes(), "47", "42").unwrap());
}

#[test]
fn header_before_proof_rejects_substituted_header_and_future_registration() {
    let (header, proof) = fixture();
    let expected = header.hash();
    for field in 0..6 {
        let mut changed = header.clone();
        match field {
            0 => changed.parent_hash = H256::zero(),
            1 => changed.number += 1,
            2 => changed.state_root = H256::zero(),
            3 => changed.extrinsics_root = H256::zero(),
            4 => changed.digest.logs.reverse(),
            _ => {
                changed.digest.logs.pop();
            }
        }
        assert!(!verify(&changed, &proof, expected.as_bytes(), "48", "42").unwrap());
    }
    let mut changed = header.clone();
    changed.state_root = H256::repeat_byte(9);
    assert!(!verify(&changed, &proof, changed.hash().as_bytes(), "48", "42").unwrap());
    changed = header.clone();
    changed.number = 41;
    assert!(!verify(&changed, &proof, changed.hash().as_bytes(), "41", "42").unwrap());
}

#[test]
fn header_before_proof_rejects_malformed_scale_and_rpc() {
    let (header, proof) = fixture();
    let scale = header.encode();
    for bad in [
        vec![],
        scale[..scale.len() - 1].to_vec(),
        [scale.clone(), vec![0]].concat(),
        vec![0; 65537],
    ] {
        assert!(inspect_mosaic_header_v1(&bad).is_err());
        assert!(
            verify_before_proof_header_v1(
                header.hash().as_bytes(),
                "48",
                &bad,
                proof["contentId"].as_str().unwrap(),
                "42",
                "7",
                &proof["nodes"].to_string()
            )
            .is_err()
        );
    }
    assert!(verify(&header, &proof, &[0; 31], "48", "42").is_err());
    assert!(verify(&header, &proof, header.hash().as_bytes(), "048", "42").is_err());
    let rpc = serde_json::to_value(&header).unwrap();
    for (field, bad) in [
        ("number", serde_json::json!("0x100000000")),
        ("stateRoot", serde_json::json!("0x00")),
        ("extra", serde_json::json!(true)),
        ("digest", serde_json::json!({"logs":["0xff"]})),
        ("digest", serde_json::json!({"logs":[],"extra":true})),
        ("digest", serde_json::json!({"logs":["0x0800"]})),
    ] {
        let mut changed = rpc.clone();
        changed[field] = bad;
        assert!(mosaic_header_scale_v1(&changed.to_string()).is_err());
    }
    let duplicate = format!("{{\"number\":\"0x30\",{}", &rpc.to_string()[1..]);
    assert!(mosaic_header_scale_v1(&duplicate).is_err());
    assert!(mosaic_header_scale_v1(&" ".repeat(131073)).is_err());
}

#[test]
fn header_before_proof_bounds_digest_counts_and_allocations() {
    let (mut header, _) = fixture();
    for logs in [
        vec![DigestItem::Other(vec![]); 65],
        vec![DigestItem::Other(vec![0; 16385])],
        vec![DigestItem::Other(vec![0; 16384]); 5],
    ] {
        header.digest.logs = logs;
        assert!(inspect_mosaic_header_v1(&header.encode()).is_err());
        assert!(mosaic_header_scale_v1(&serde_json::to_string(&header).unwrap()).is_err());
    }
    // A tiny encoded input claiming an enormous log count must not allocate it.
    header.digest.logs.clear();
    let mut scale = header.encode();
    scale.pop();
    scale.extend_from_slice(&[0xff; 5]);
    assert!(inspect_mosaic_header_v1(&scale).is_err());
}

#[test]
fn header_before_proof_digest_limit_counts_the_complete_encoded_item() {
    let (mut header, _) = fixture();
    // Below 2^14 payload bytes, the SCALE vector length occupies two bytes.
    for (payload, accepted) in [(16381, true), (16382, false), (16384, false)] {
        let item = DigestItem::Other(vec![0; payload]);
        assert_eq!(item.encode().len() <= MAX_ENCODED_LOG, accepted);
        header.digest.logs = vec![item];
        let rpc = serde_json::to_string(&header).unwrap();
        assert_eq!(mosaic_header_scale_v1(&rpc).is_ok(), accepted);
        assert_eq!(inspect_mosaic_header_v1(&header.encode()).is_ok(), accepted);
    }
}
