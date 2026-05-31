use super::*;

use anyhow::{Context, ensure};
use mosaic_did_types::{
    ContentId as MosaicContentId, Did as MosaicDid, KeyPurpose, KeyRef as MosaicKeyRef, KeyType,
    Right,
};
use parity_scale_codec::Encode;
use std::str::FromStr;

#[unsafe(no_mangle)]
pub extern "C" fn delete_MosaicDid(did: *mut MosaicDid) {
    delete(did)
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_prefix() -> *mut raw::c_char {
    convert::string_out(MosaicDid::METHOD_PREFIX.to_owned())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_from_string(input: *const raw::c_char) -> CPtrResult<MosaicDid> {
    let fun = || {
        let input = unsafe { convert::str_in(input)? };
        let did = MosaicDid::from_did_string(input).map_err(anyhow_string)?;
        Ok(convert::move_out(did))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_from_public_key(data: *mut CSlice<u8>) -> CPtrResult<MosaicDid> {
    let fun = || {
        let data = unsafe { convert::borrow_in(data) };
        let did = MosaicDid::from_public_key(data.as_slice()).map_err(anyhow_string)?;
        Ok(convert::move_out(did))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_from_key_id(key_id: *const MKeyId) -> *mut MosaicDid {
    let key_id = unsafe { convert::borrow_in(key_id) };
    convert::move_out(MosaicDid { default_key_id: key_id.clone() })
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_default_key_id(did: *const MosaicDid) -> *mut MKeyId {
    let did = unsafe { convert::borrow_in(did) };
    convert::move_out(did.default_key_id.clone())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_to_string(did: *const MosaicDid) -> *mut raw::c_char {
    let did = unsafe { convert::borrow_in(did) };
    convert::string_out(did.to_did_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicDid_to_scale_bytes(did: *const MosaicDid) -> *mut CSlice<u8> {
    let did = unsafe { convert::borrow_in(did) };
    convert::move_out(CSlice::from(did.encode()))
}

#[unsafe(no_mangle)]
pub extern "C" fn delete_MosaicKeyRef(key_ref: *mut MosaicKeyRef) {
    delete(key_ref)
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyRef_from_string(input: *const raw::c_char) -> CPtrResult<MosaicKeyRef> {
    let fun = || {
        let input = unsafe { convert::str_in(input)? };
        let key_ref: MosaicKeyRef = input.parse().map_err(anyhow_string)?;
        Ok(convert::move_out(key_ref))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyRef_to_bytes(key_ref: *const MosaicKeyRef) -> *mut CSlice<u8> {
    let key_ref = unsafe { convert::borrow_in(key_ref) };
    convert::move_out(CSlice::from(key_ref.as_bytes().to_vec()))
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyRef_to_scale_bytes(key_ref: *const MosaicKeyRef) -> *mut CSlice<u8> {
    let key_ref = unsafe { convert::borrow_in(key_ref) };
    convert::move_out(CSlice::from(key_ref.encode()))
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyRef_to_string(key_ref: *const MosaicKeyRef) -> *mut raw::c_char {
    let key_ref = unsafe { convert::borrow_in(key_ref) };
    convert::string_out(key_ref.to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn delete_MosaicContentId(content_id: *mut MosaicContentId) {
    delete(content_id)
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_from_string(
    input: *const raw::c_char,
) -> CPtrResult<MosaicContentId> {
    let fun = || {
        let input = unsafe { convert::str_in(input)? };
        let content_id: MosaicContentId = input.parse().map_err(anyhow_string)?;
        Ok(convert::move_out(content_id))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_from_bytes(content: *mut CSlice<u8>) -> *mut MosaicContentId {
    let content = unsafe { convert::borrow_in(content) };
    convert::move_out(MosaicContentId::from_bytes(content.as_slice()))
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_from_byte_hash(
    hash: *mut CSlice<u8>,
) -> CPtrResult<MosaicContentId> {
    let fun = || {
        let hash = unsafe { convert::borrow_in(hash) };
        Ok(convert::move_out(MosaicContentId::ByteHash(hash32(hash.as_slice())?)))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_from_json_digest_hash(
    hash: *mut CSlice<u8>,
) -> CPtrResult<MosaicContentId> {
    let fun = || {
        let hash = unsafe { convert::borrow_in(hash) };
        Ok(convert::move_out(MosaicContentId::from_json_digest_hash(hash32(hash.as_slice())?)))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_from_json_digest(
    input: *const raw::c_char,
) -> CPtrResult<MosaicContentId> {
    let fun = || {
        let input = unsafe { convert::str_in(input)? };
        Ok(convert::move_out(parse_json_digest_content_id(input)?))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_to_bytes(content_id: *const MosaicContentId) -> *mut CSlice<u8> {
    let content_id = unsafe { convert::borrow_in(content_id) };
    convert::move_out(CSlice::from(content_id.as_bytes().to_vec()))
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_to_scale_bytes(
    content_id: *const MosaicContentId,
) -> *mut CSlice<u8> {
    let content_id = unsafe { convert::borrow_in(content_id) };
    convert::move_out(CSlice::from(content_id.encode()))
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_to_string(
    content_id: *const MosaicContentId,
) -> *mut raw::c_char {
    let content_id = unsafe { convert::borrow_in(content_id) };
    convert::string_out(content_id.to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_is_json_digest(content_id: *const MosaicContentId) -> bool {
    let content_id = unsafe { convert::borrow_in(content_id) };
    content_id.is_json_digest()
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicContentId_kind(content_id: *const MosaicContentId) -> *mut raw::c_char {
    let content_id = unsafe { convert::borrow_in(content_id) };
    let kind = match content_id {
        MosaicContentId::ByteHash(_) => "byteHash",
        MosaicContentId::JsonDigest(_) => "jsonDigest",
    };
    convert::string_out(kind.to_owned())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicRight_values() -> *mut CSlice<*mut raw::c_char> {
    string_slice(&["update", "impersonate", "delegate", "issue", "revoke", "recovery"])
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicRight_is_valid(input: *const raw::c_char) -> bool {
    parse_str::<Right>(input).is_ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicRight_to_scale_bytes(input: *const raw::c_char) -> CPtrResult<CSlice<u8>> {
    let fun = || {
        let right = parse_str::<Right>(input)?;
        Ok(convert::move_out(CSlice::from(right.encode())))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyType_values() -> *mut CSlice<*mut raw::c_char> {
    string_slice(&["ed25519", "secp256k1", "secp256r1", "x25519"])
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyType_is_valid(input: *const raw::c_char) -> bool {
    parse_str::<KeyType>(input).is_ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyType_to_scale_bytes(
    input: *const raw::c_char,
) -> CPtrResult<CSlice<u8>> {
    let fun = || {
        let key_type = parse_str::<KeyType>(input)?;
        Ok(convert::move_out(CSlice::from(key_type.encode())))
    };
    cresult(fun())
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyPurpose_values() -> *mut CSlice<*mut raw::c_char> {
    string_slice(&[
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ])
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyPurpose_is_valid(input: *const raw::c_char) -> bool {
    parse_str::<KeyPurpose>(input).is_ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn MosaicKeyPurpose_to_scale_bytes(
    input: *const raw::c_char,
) -> CPtrResult<CSlice<u8>> {
    let fun = || {
        let key_purpose = parse_str::<KeyPurpose>(input)?;
        Ok(convert::move_out(CSlice::from(key_purpose.encode())))
    };
    cresult(fun())
}

fn parse_str<T>(input: *const raw::c_char) -> Result<T>
where
    T: FromStr,
    T::Err: ToString,
{
    let input = unsafe { convert::str_in(input)? };
    input.parse::<T>().map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn string_slice(values: &[&str]) -> *mut CSlice<*mut raw::c_char> {
    convert::move_out(CSlice::from(
        values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>(),
    ))
}

fn anyhow_string(err: impl ToString) -> anyhow::Error {
    anyhow::anyhow!(err.to_string())
}

fn hash32(bytes: &[u8]) -> Result<[u8; 32]> {
    ensure!(bytes.len() == 32, "hash must be exactly 32 bytes");
    let mut hash = [0u8; 32];
    hash.copy_from_slice(bytes);
    Ok(hash)
}

fn parse_json_digest_content_id(content_id: &str) -> Result<MosaicContentId> {
    if let Ok(parsed) = content_id.parse::<MosaicContentId>() {
        ensure!(parsed.is_json_digest(), "expected a JSON digest ContentId");
        return Ok(parsed);
    }

    let digest =
        content_id.strip_prefix("cj").context("json-digest content id must start with 'cj'")?;
    let (_base, bytes) = multibase::decode(digest)?;
    Ok(MosaicContentId::from_json_digest_hash(hash32(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_json_digest_content_id() {
        let cid =
            parse_json_digest_content_id("cjumTq1s6Tn6xkXolxHj4LmAo7DAb-zoPLhEa1BvpovAFU").unwrap();

        assert!(cid.is_json_digest());
        assert_eq!(cid.as_bytes().len(), 32);
    }

    #[test]
    fn rejects_byte_hash_for_json_digest_conversion() {
        let cid = MosaicContentId::ByteHash([0x42; 32]).to_string();

        assert!(parse_json_digest_content_id(&cid).is_err());
    }
}
