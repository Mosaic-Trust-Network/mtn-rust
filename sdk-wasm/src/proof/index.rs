//! Versioned storage-relation boundary; callers own header/network/finality trust.
use mosaic_did_types::ContentId;
use parity_scale_codec::Encode;
use polkadot_sdk::{
    sp_core::{Blake2Hasher, H256},
    sp_crypto_hashing::{blake2_128, twox_128},
    sp_trie::{LayoutV1, StorageProof, read_trie_value},
};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use wasm_bindgen::prelude::*;

const INVALID: &str = "invalid before-proof storage input";
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_NODES: usize = 512;
const MAX_NODE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;

#[path = "header/index.rs"]
mod header;
pub use header::*;
#[path = "metadata/index.rs"]
mod metadata;
pub use metadata::*;

/// Pinned Did.BeforeProofs layout: Twox128 prefixes + Blake2_128Concat(ContentId).
/// Only canonical structured commitments are accepted by this V1 boundary.
#[wasm_bindgen]
pub fn before_proof_storage_key_v1(content_id: &str) -> Result<Vec<u8>, String> {
    if content_id.len() > 128 {
        return Err(INVALID.into());
    }
    let id = content_id.parse::<ContentId>().map_err(|_| INVALID)?;
    if !matches!(id, ContentId::Structured(_)) || id.to_string() != content_id {
        return Err(INVALID.into());
    }
    let scale = id.encode();
    Ok([
        twox_128(b"Did").as_slice(),
        twox_128(b"BeforeProofs").as_slice(),
        blake2_128(&scale).as_slice(),
        scale.as_slice(),
    ]
    .concat())
}

/// Verify only the exact storage relation under the caller's expected state root.
/// This does not authenticate that root, a network, a header or consensus finality.
/// Nodes are raw RPC storage nodes, not the compact trie-proof format.
#[wasm_bindgen]
pub fn verify_before_proof_storage_v1(
    expected_state_root: &[u8], content_id: &str, expected_height: &str, expected_index: &str,
    proof_json: &str,
) -> Result<bool, String> {
    let root: [u8; 32] = expected_state_root.try_into().map_err(|_| INVALID)?;
    let key = before_proof_storage_key_v1(content_id)?;
    let expected = (decimal_u32(expected_height)?, decimal_u32(expected_index)?).encode();
    if proof_json.len() > MAX_JSON_BYTES {
        return Err(INVALID.into());
    }
    let nodes: ProofNodes = serde_json::from_str(proof_json).map_err(|_| INVALID)?;
    let proof = StorageProof::new_with_duplicate_nodes_check(nodes.0).map_err(|_| INVALID)?;
    let db = proof.into_memory_db::<Blake2Hasher>();
    Ok(matches!(
        read_trie_value::<LayoutV1<Blake2Hasher>, _>(&db, &H256::from(root), &key, None, None),
        Ok(Some(value)) if value == expected
    ))
}

fn decimal_u32(value: &str) -> Result<u32, String> {
    if value.is_empty()
        || value.len() > 10
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(INVALID.into());
    }
    value.parse().map_err(|_| INVALID.into())
}

struct ProofNodes(Vec<Vec<u8>>);

impl<'de> Deserialize<'de> for ProofNodes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NodesVisitor;
        impl<'de> Visitor<'de> for NodesVisitor {
            type Value = ProofNodes;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("bounded raw storage proof nodes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut nodes = Vec::new();
                let mut total = 0;
                while let Some(node) = seq.next_element::<&str>()? {
                    let Some(hex) = node.strip_prefix("0x") else {
                        return Err(de::Error::custom(INVALID));
                    };
                    let size = hex.len() / 2;
                    if nodes.len() >= MAX_NODES
                        || size == 0
                        || size > MAX_NODE_BYTES
                        || hex.len() % 2 != 0
                        || total + size > MAX_TOTAL_BYTES
                        || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err(de::Error::custom(INVALID));
                    }
                    let nibble = |b: u8| if b.is_ascii_digit() { b - b'0' } else { b - b'a' + 10 };
                    nodes.push(
                        hex.as_bytes()
                            .chunks_exact(2)
                            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
                            .collect(),
                    );
                    total += size;
                }
                if nodes.is_empty() {
                    return Err(de::Error::custom(INVALID));
                }
                Ok(ProofNodes(nodes))
            }
        }
        deserializer.deserialize_seq(NodesVisitor)
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod test;
