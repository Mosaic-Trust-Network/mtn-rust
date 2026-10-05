//! Current Mosaic DID and content codecs for JavaScript.
//! All protocol behavior is delegated to the native crates.
use mosaic_did_types::{ContentId, Did, KeyPurpose, Right};
use parity_scale_codec::Encode;
use wasm_bindgen::prelude::*;

mod envelope;
pub use envelope::*;

#[wasm_bindgen]
pub fn derive_did(public_key: &[u8]) -> Result<String, String> {
    Did::from_public_key(public_key).map(|did| did.to_string()).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn parse_did(value: &str) -> Result<String, String> {
    Did::from_did_string(value).map(|did| did.to_string()).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn did_scale(value: &str) -> Result<Vec<u8>, String> {
    Did::from_did_string(value).map(|did| did.encode()).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn content_id_from_hash(hash: &[u8], kind: &str) -> Result<String, String> {
    let value = match kind {
        "blake3-flat" => {
            ContentId::Blake3Flat(hash.try_into().map_err(|_| "expected 32-byte hash")?)
        }
        "blake2b-flat" => {
            ContentId::Blake2bFlat(hash.try_into().map_err(|_| "expected 64-byte hash")?)
        }
        "sha3-json" => {
            ContentId::from_json_digest_hash(hash.try_into().map_err(|_| "expected 32-byte hash")?)
        }
        "blake3-json" => {
            ContentId::structured_blake3(hash.try_into().map_err(|_| "expected 32-byte hash")?)
        }
        _ => return Err("unknown content hash kind".into()),
    };
    Ok(value.to_string())
}

#[wasm_bindgen]
pub fn content_id_parse(value: &str) -> Result<String, String> {
    value.parse::<ContentId>().map(|id| id.to_string()).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn content_id_scale(value: &str) -> Result<Vec<u8>, String> {
    value.parse::<ContentId>().map(|id| id.encode()).map_err(|e| e.to_string())
}

/// Parse JSON before applying the native object-valued digest operation.
#[wasm_bindgen]
pub fn digest_json(json: &str, algorithm: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if !matches!(value, serde_json::Value::Object(_) | serde_json::Value::Array(_)) {
        return Err("JSON digest root must be an object or array".into());
    }
    match algorithm {
        "sha3" => json_digest::digest_data(&value),
        "blake3" => json_digest::digest_data_blake3(&value),
        _ => return Err("unknown structured digest algorithm".into()),
    }
    .map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn right_names() -> String {
    serde_json::to_string(&Right::phase1_variants().iter().map(Right::as_str).collect::<Vec<_>>())
        .expect("static right names serialize")
}

#[wasm_bindgen]
pub fn right_scale(name: &str) -> Result<Vec<u8>, String> {
    name.parse::<Right>().map(|right| right.encode()).map_err(str::to_owned)
}

#[wasm_bindgen]
pub fn purpose_scale(name: &str) -> Result<Vec<u8>, String> {
    name.parse::<KeyPurpose>().map(|purpose| purpose.encode()).map_err(str::to_owned)
}

#[cfg(test)]
#[path = "../tests/mod.rs"]
mod test;
