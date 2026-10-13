use super::*;
use parity_scale_codec::Encode;
use polkadot_sdk::{
    sp_core::{Blake2Hasher, H256},
    sp_crypto_hashing::{blake2_128, twox_128},
    sp_trie::{LayoutV1, MemoryDB, Recorder, TrieDBMutBuilder, TrieMut, read_trie_value},
};

const CONTENT: &str = "cmuAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
type Layout = LayoutV1<Blake2Hasher>;

fn key() -> Vec<u8> {
    // Hand-specified SCALE Structured(Blake3([0,1,...31])).
    let scale = [vec![2, 1], (0..32).collect()].concat();
    [
        twox_128(b"Did").to_vec(),
        twox_128(b"BeforeProofs").to_vec(),
        blake2_128(&scale).to_vec(),
        scale,
    ]
    .concat()
}

fn fixture(stored: &[u8]) -> (H256, Vec<Vec<u8>>) {
    let mut db = MemoryDB::<Blake2Hasher>::default();
    let mut root = H256::default();
    {
        let mut trie = TrieDBMutBuilder::<Layout>::new(&mut db, &mut root).build();
        trie.insert(&key(), stored).unwrap();
        trie.insert(b"unrelated fixture key", &[7; 96]).unwrap();
    }
    let mut recorder = Recorder::<Layout>::new();
    assert_eq!(
        read_trie_value::<Layout, _>(&db, &root, &key(), Some(&mut recorder), None).unwrap(),
        Some(stored.to_vec())
    );
    (root, recorder.drain().into_iter().map(|entry| entry.data).collect())
}

fn json(nodes: &[Vec<u8>]) -> String {
    serde_json::to_string(
        &nodes
            .iter()
            .map(|node| {
                let hex: String = node.iter().map(|byte| format!("{byte:02x}")).collect();
                format!("0x{hex}")
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn before_proof_storage_accepts_exact_native_registration() {
    let (root, nodes) = fixture(&(42_u32, 7_u32).encode());
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/vectors/before-proof.json")).unwrap();
    assert_eq!(golden["stateRoot"], serde_json::json!(root.as_bytes()));
    assert_eq!(golden["storageKey"], serde_json::json!(key()));
    assert_eq!(golden["nodes"], serde_json::from_str::<serde_json::Value>(&json(&nodes)).unwrap());
    assert_eq!(before_proof_storage_key_v1(CONTENT).unwrap(), key());
    assert!(
        verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &json(&nodes)).unwrap()
    );
    let reversed: Vec<_> = nodes.into_iter().rev().collect();
    assert!(
        verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &json(&reversed))
            .unwrap()
    );
}

#[test]
fn before_proof_storage_rejects_wrong_relation_and_incomplete_proof() {
    let (root, nodes) = fixture(&(42_u32, 7_u32).encode());
    let proof = json(&nodes);
    for (height, index) in [("43", "7"), ("42", "8")] {
        assert!(
            !verify_before_proof_storage_v1(root.as_bytes(), CONTENT, height, index, &proof)
                .unwrap()
        );
    }
    assert!(!verify_before_proof_storage_v1(&[1; 32], CONTENT, "42", "7", &proof).unwrap());
    let other = crate::content_id_from_hash(&[9; 32], "blake3-json").unwrap();
    assert!(!verify_before_proof_storage_v1(root.as_bytes(), &other, "42", "7", &proof).unwrap());
    for omitted in 0..nodes.len() {
        let mut partial = nodes.clone();
        partial.remove(omitted);
        if !partial.is_empty() {
            assert!(
                !verify_before_proof_storage_v1(
                    root.as_bytes(),
                    CONTENT,
                    "42",
                    "7",
                    &json(&partial)
                )
                .unwrap()
            );
        }
    }
    let mut tampered = nodes;
    for node in &mut tampered {
        node[0] ^= 1;
    }
    assert!(
        !verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &json(&tampered))
            .unwrap()
    );
}

#[test]
fn before_proof_storage_rejects_trailing_scale_value() {
    let mut stored = (42_u32, 7_u32).encode();
    stored.push(0);
    let (root, nodes) = fixture(&stored);
    assert!(
        !verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &json(&nodes))
            .unwrap()
    );
}

#[test]
fn before_proof_storage_bounds_untrusted_input() {
    let (root, nodes) = fixture(&(42_u32, 7_u32).encode());
    for bad in
        ["[]", "{}", "[null]", "[\"0x\"]", "[\"0x0\"]", "[\"0xAB\"]", "[\"ab\"]", "[\"0xgg\"]"]
    {
        assert!(verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", bad).is_err());
    }
    let proof = json(&nodes);
    for decimal in ["", "-1", "01", "+1", " 1", "4294967296", "1.0"] {
        assert!(
            verify_before_proof_storage_v1(root.as_bytes(), CONTENT, decimal, "7", &proof).is_err()
        );
        assert!(
            verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", decimal, &proof)
                .is_err()
        );
    }
    assert!(verify_before_proof_storage_v1(&[0; 31], CONTENT, "42", "7", &proof).is_err());
    for bad in ["bad", "cmuAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8 "] {
        assert!(before_proof_storage_key_v1(bad).is_err());
    }
    let flat = crate::content_id_from_hash(&[9; 32], "blake3-flat").unwrap();
    assert!(before_proof_storage_key_v1(&flat).is_err());
    let duplicate = json(&[nodes[0].clone(), nodes[0].clone()]);
    assert!(
        verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &duplicate).is_err()
    );
    for oversized in [vec![vec![0; 1]; 513], vec![vec![0; 65537]], vec![vec![0; 65536]; 5]] {
        assert!(
            verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &json(&oversized))
                .is_err()
        );
    }
    assert!(
        verify_before_proof_storage_v1(root.as_bytes(), CONTENT, "42", "7", &" ".repeat(1048577))
            .is_err()
    );
}
