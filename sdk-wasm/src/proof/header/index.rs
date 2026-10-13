//! Header binding is distinct from authenticating a trusted network/finalized head.
use parity_scale_codec::{DecodeWithMemLimit, Encode};
use polkadot_sdk::{
    sp_core::bytes::from_hex,
    sp_runtime::{
        generic::{DigestItem, Header},
        traits::BlakeTwo256,
    },
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

type NativeHeader = Header<u32, BlakeTwo256>;
const INVALID: &str = "invalid Mosaic header input";
const MAX_HEADER: usize = 64 * 1024;
const MAX_JSON: usize = 128 * 1024;
const MAX_MEMORY: usize = 128 * 1024;
const MAX_LOGS: usize = 64;
const MAX_LOG: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcBounds {
    #[serde(rename = "parentHash")]
    _parent_hash: serde::de::IgnoredAny,
    #[serde(rename = "number")]
    _number: serde::de::IgnoredAny,
    #[serde(rename = "stateRoot")]
    _state_root: serde::de::IgnoredAny,
    #[serde(rename = "extrinsicsRoot")]
    _extrinsics_root: serde::de::IgnoredAny,
    digest: RpcDigestBounds,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcDigestBounds {
    logs: Vec<String>,
}

fn decode_header(scale: &[u8]) -> Result<NativeHeader, String> {
    if scale.is_empty() || scale.len() > MAX_HEADER {
        return Err(INVALID.into());
    }
    let mut input = scale;
    let header =
        NativeHeader::decode_with_mem_limit(&mut input, MAX_MEMORY).map_err(|_| INVALID)?;
    if !input.is_empty()
        || header.encode() != scale
        || header.digest.logs.len() > MAX_LOGS
        || header.digest.logs.iter().any(|log| log.encode().len() > MAX_LOG)
    {
        return Err(INVALID.into());
    }
    Ok(header)
}

/// Convert bounded JSON RPC header fields through the pinned native header codec.
#[wasm_bindgen]
pub fn mosaic_header_scale_v1(json: &str) -> Result<Vec<u8>, String> {
    if json.len() > MAX_JSON {
        return Err(INVALID.into());
    }
    let bounds: RpcBounds = serde_json::from_str(json).map_err(|_| INVALID)?;
    if bounds.digest.logs.len() > MAX_LOGS {
        return Err(INVALID.into());
    }
    let mut total = 0;
    for log in bounds.digest.logs {
        if !log.starts_with("0x") || log.len() > MAX_LOG * 2 + 2 {
            return Err(INVALID.into());
        }
        let bytes = from_hex(&log).map_err(|_| INVALID)?;
        total += bytes.len();
        if total > MAX_HEADER {
            return Err(INVALID.into());
        }
        let mut input = bytes.as_slice();
        let item =
            DigestItem::decode_with_mem_limit(&mut input, MAX_MEMORY).map_err(|_| INVALID)?;
        if !input.is_empty() || item.encode() != bytes {
            return Err(INVALID.into());
        }
    }
    let header: NativeHeader = serde_json::from_str(json).map_err(|_| INVALID)?;
    let scale = header.encode();
    decode_header(&scale)?;
    Ok(scale)
}

/// Inspect native header identity; no network, signature or finality assertion.
#[wasm_bindgen]
pub fn inspect_mosaic_header_v1(scale: &[u8]) -> Result<String, String> {
    let header = decode_header(scale)?;
    Ok(serde_json::json!({"blockHash":header.hash().as_bytes(),
        "blockHeight":header.number.to_string(),"stateRoot":header.state_root.as_bytes()})
    .to_string())
}

/// Only a root from this exact expected header is used for the storage proof.
/// The caller still owns trust in the expected block hash and its finalized network.
#[wasm_bindgen]
pub fn verify_before_proof_header_v1(
    expected_block_hash: &[u8], expected_header_height: &str, header_scale: &[u8],
    content_id: &str, expected_height: &str, expected_index: &str, proof_json: &str,
) -> Result<bool, String> {
    if expected_block_hash.len() != 32 {
        return Err(INVALID.into());
    }
    let number = super::decimal_u32(expected_header_height)?;
    let registration = super::decimal_u32(expected_height)?;
    let header = decode_header(header_scale)?;
    if header.hash().as_bytes() != expected_block_hash
        || header.number != number
        || registration > number
    {
        return Ok(false);
    }
    super::verify_before_proof_storage_v1(
        header.state_root.as_bytes(),
        content_id,
        expected_height,
        expected_index,
        proof_json,
    )
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod test;
