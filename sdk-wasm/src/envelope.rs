//! Native AfterEnvelope byte preparation and Mosaic signature verification.
use mosaic_did_types::signed::{AfterEnvelope, AfterProof};
use mosaic_keyvault::PublicKey;
use mosaic_keyvault::multicipher::{MKeyId, MPublicKey, MSignature};
use wasm_bindgen::prelude::*;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeInput {
    content: serde_json::Value,
    proof: ProofInput,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofInput {
    #[serde(rename = "blockHeight")]
    block_height: u32,
    #[serde(rename = "blockHash")]
    block_hash: String,
}
fn parse_envelope(json: &str) -> Result<AfterEnvelope<serde_json::Value>, String> {
    let input: EnvelopeInput = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if !matches!(input.content, serde_json::Value::Object(_) | serde_json::Value::Array(_)) {
        return Err("Envelope document content must be an object or array".into());
    }
    if input.proof.block_height == u32::MAX {
        return Err("AfterProof lower bound exceeds u32".into());
    }
    let hash = input.proof.block_hash.strip_prefix("0x").ok_or("Expected 0x block hash")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Expected 32-byte hexadecimal block hash".into());
    }
    Ok(AfterEnvelope {
        content: input.content,
        proof: AfterProof {
            block_height: input.proof.block_height,
            block_hash: input.proof.block_hash,
        },
    })
}
fn parse_key(text: &str) -> Result<MPublicKey, String> {
    let key: MPublicKey =
        text.parse().map_err(|e: mosaic_keyvault::error::KeyvaultError| e.to_string())?;
    if !matches!(key, MPublicKey::Ed25519Blake3(_)) {
        return Err("Unsupported Mosaic envelope public key suite".into());
    }
    Ok(key)
}
fn parse_ref(text: &str) -> Result<MKeyId, String> {
    let key: MKeyId =
        text.parse().map_err(|e: mosaic_keyvault::error::KeyvaultError| e.to_string())?;
    if !matches!(key, MKeyId::Ed25519Blake3(_)) {
        return Err("Unsupported Mosaic key reference suite".into());
    }
    Ok(key)
}
#[wasm_bindgen]
pub fn mosaic_public_key(raw: &[u8]) -> Result<String, String> {
    mosaic_did_types::public_key_from_key_type(mosaic_did_types::KeyType::Ed25519, raw)
        .map(|key| key.to_string())
        .ok_or_else(|| "Invalid Ed25519 public key".into())
}
#[wasm_bindgen]
pub fn mosaic_key_ref(public_key: &str) -> Result<String, String> {
    Ok(parse_key(public_key)?.key_id().to_string())
}
#[wasm_bindgen]
pub fn key_matches_reference(public_key: &str, key_ref: &str) -> Result<bool, String> {
    Ok(parse_key(public_key)?.validate_id(&parse_ref(key_ref)?))
}
/// Current native verifier signs the UTF-8 SHA3 digest string, not raw hash bytes.
#[wasm_bindgen]
pub fn envelope_signing_payload(json: &str) -> Result<Vec<u8>, String> {
    json_digest::digest_data(&parse_envelope(json)?)
        .map(String::into_bytes)
        .map_err(|e| e.to_string())
}
#[wasm_bindgen]
pub fn verify_envelope_signature(
    json: &str, public_key: &str, signature: &str, expected_key_ref: &str,
) -> Result<bool, String> {
    let payload = envelope_signing_payload(json)?;
    let key = parse_key(public_key)?;
    let expected = parse_ref(expected_key_ref)?;
    let sig: MSignature =
        signature.parse().map_err(|e: mosaic_keyvault::error::KeyvaultError| e.to_string())?;
    if !matches!(sig, MSignature::Ed25519Blake3(_)) {
        return Err("Unsupported Mosaic envelope signature suite".into());
    }
    Ok(key.validate_id(&expected) && key.verify(&payload, &sig))
}
