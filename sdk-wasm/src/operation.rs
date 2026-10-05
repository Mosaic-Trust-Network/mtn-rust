//! Native SCALE signing for the initial DID key and document commitment slice.
use crate::envelope::{parse_key, parse_ref};
use mosaic_did_types::{
    Authentication, ContentId, Did, DidOperation, KeyRef, SignedDidOperation, SsiOperation,
};
use mosaic_keyvault::PublicKey;
use mosaic_keyvault::multicipher::MSignature;
use parity_scale_codec::{Decode, Encode};
use wasm_bindgen::prelude::*;

fn decimal_u64(text: &str, positive: bool) -> Result<u64, String> {
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("Expected canonical decimal u64".into());
    }
    let value: u64 = text.parse().map_err(|_| "Decimal u64 overflow")?;
    if positive && value == 0 {
        return Err("Expected positive u64".into());
    }
    Ok(value)
}
fn reference(text: &str) -> Result<KeyRef, String> {
    parse_ref(text)?;
    text.parse().map_err(str::to_owned)
}
fn parse_operation(bytes: &[u8]) -> Result<DidOperation, String> {
    if bytes.len() > 4096 {
        return Err("Operation exceeds SDK decode bound".into());
    }
    let mut input = bytes;
    let operation = DidOperation::decode(&mut input).map_err(|e| e.to_string())?;
    if !input.is_empty() || operation.encode() != bytes {
        return Err("Expected one canonical SCALE operation".into());
    }
    Did::from_did_string(&operation.did().to_string()).map_err(|e| e.to_string())?;
    match &operation {
        DidOperation::AddKey {
            did,
            auth: Authentication::PublicKey(pk),
            expires_at_height: None,
            ..
        } => {
            parse_key(&pk.to_string())?;
            let raw = mosaic_did_types::public_key_raw_bytes(pk);
            if *did != Did::from_public_key(&raw).map_err(|e| e.to_string())? {
                return Err("Expected initial DID key operation".into());
            }
        }
        DidOperation::UpdateCommitment { commitment, sequence, .. }
            if commitment.is_supported_commitment_algorithm() && *sequence > 0 => {}
        _ => return Err(
            "Unsupported SDK DID operation; only initial AddKey and structured UpdateCommitment"
                .into(),
        ),
    }
    Ok(operation)
}
fn parts(bytes: &[u8], key_ref: &str, nonce: &str) -> Result<(DidOperation, KeyRef, u64), String> {
    let operation = parse_operation(bytes)?;
    let key = reference(key_ref)?;
    let nonce = decimal_u64(nonce, true)?;
    if let DidOperation::AddKey { auth, initial_nonce, .. } = &operation {
        if key.as_bytes() != auth.key_id().to_string().as_bytes() {
            return Err("Initial operation signer must match embedded key".into());
        }
        if nonce <= *initial_nonce {
            return Err("Initial signer nonce must exceed key floor".into());
        }
    }
    Ok((operation, key, nonce))
}
#[wasm_bindgen]
pub fn initial_did_key_operation(public_key: &str, initial_nonce: &str) -> Result<Vec<u8>, String> {
    let pk = parse_key(public_key)?;
    let did = Did::from_public_key(&mosaic_did_types::public_key_raw_bytes(&pk))
        .map_err(|e| e.to_string())?;
    Ok(DidOperation::AddKey {
        did,
        auth: Authentication::PublicKey(pk),
        expires_at_height: None,
        initial_nonce: decimal_u64(initial_nonce, false)?,
    }
    .encode())
}
#[wasm_bindgen]
pub fn update_commitment_operation(
    did: &str, commitment: &str, sequence: &str,
) -> Result<Vec<u8>, String> {
    let did = Did::from_did_string(did).map_err(|e| e.to_string())?;
    let commitment: ContentId =
        commitment.parse().map_err(|e: mosaic_did_types::ContentIdParseError| e.to_string())?;
    if !commitment.is_supported_commitment_algorithm() {
        return Err("Expected supported structured commitment".into());
    }
    Ok(DidOperation::UpdateCommitment { did, commitment, sequence: decimal_u64(sequence, true)? }
        .encode())
}
#[wasm_bindgen]
pub fn did_operation_signing_payload(
    operation: &[u8], key_ref: &str, nonce: &str,
) -> Result<Vec<u8>, String> {
    Ok(parts(operation, key_ref, nonce)?.encode())
}
#[wasm_bindgen]
pub fn verify_did_operation_signature(
    operation: &[u8], public_key: &str, signature: &str, key_ref: &str, nonce: &str,
) -> Result<bool, String> {
    let payload = did_operation_signing_payload(operation, key_ref, nonce)?;
    let pk = parse_key(public_key)?;
    let sig: MSignature =
        signature.parse().map_err(|e: mosaic_keyvault::error::KeyvaultError| e.to_string())?;
    if !matches!(sig, MSignature::Ed25519Blake3(_)) {
        return Err("Unsupported Mosaic operation signature suite".into());
    }
    Ok(pk.validate_id(&parse_ref(key_ref)?) && pk.verify(&payload, &sig))
}
fn signed(
    operation: &[u8], public_key: &str, signature: &str, key_ref: &str, nonce: &str,
) -> Result<SignedDidOperation, String> {
    if !verify_did_operation_signature(operation, public_key, signature, key_ref, nonce)? {
        return Err("Invalid DID operation signature or signer reference".into());
    }
    let (operation, signer_key_ref, nonce) = parts(operation, key_ref, nonce)?;
    let signature =
        signature.parse().map_err(|e: mosaic_keyvault::error::KeyvaultError| e.to_string())?;
    Ok(SignedDidOperation { operation, signer_key_ref, signature, nonce })
}
#[wasm_bindgen]
pub fn signed_did_operation_scale(
    operation: &[u8], public_key: &str, signature: &str, key_ref: &str, nonce: &str,
) -> Result<Vec<u8>, String> {
    Ok(signed(operation, public_key, signature, key_ref, nonce)?.encode())
}
#[wasm_bindgen]
pub fn did_ssi_operation_scale(
    operation: &[u8], public_key: &str, signature: &str, key_ref: &str, nonce: &str,
) -> Result<Vec<u8>, String> {
    Ok(SsiOperation::Did(signed(operation, public_key, signature, key_ref, nonce)?).encode())
}
