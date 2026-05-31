use super::*;

use anyhow::{Context, ensure};
use mosaic_did_types::{
    ContentId as MosaicContentId, Did as MosaicDid, KeyPurpose, KeyRef as MosaicKeyRef, KeyType,
    Right,
};
use parity_scale_codec::Encode;

/// A `did:mosaic` identifier derived from an Ed25519Blake3 multicipher key id.
#[wasm_bindgen(js_name = MosaicDid)]
pub struct JsMosaicDid {
    inner: MosaicDid,
}

#[wasm_bindgen(js_class = MosaicDid)]
impl JsMosaicDid {
    /// Parse a string like `did:mosaic:ioz...`.
    #[wasm_bindgen(constructor)]
    pub fn new(did_str: &str) -> Result<JsMosaicDid, JsValue> {
        let inner = MosaicDid::from_did_string(did_str).map_err_to_js()?;
        Ok(Self { inner })
    }

    /// All Mosaic DID strings start with this prefix.
    #[wasm_bindgen]
    pub fn prefix() -> String {
        MosaicDid::METHOD_PREFIX.to_owned()
    }

    /// Derive a Mosaic DID from a raw 32-byte Ed25519 public key.
    #[wasm_bindgen(js_name = fromPublicKey)]
    pub fn from_public_key(public_key: &[u8]) -> Result<JsMosaicDid, JsValue> {
        let inner = MosaicDid::from_public_key(public_key).map_err_to_js()?;
        Ok(inner.into())
    }

    /// Create a Mosaic DID from its default multicipher key id.
    #[wasm_bindgen(js_name = fromKeyId)]
    pub fn from_key_id(key_id: &JsMKeyId) -> JsMosaicDid {
        MosaicDid { default_key_id: key_id.inner().clone() }.into()
    }

    /// Return the default multicipher key id embedded in this DID.
    #[wasm_bindgen(js_name = defaultKeyId)]
    pub fn default_key_id(&self) -> JsMKeyId {
        JsMKeyId::from(self.inner.default_key_id.clone())
    }

    /// Convert the DID into `did:mosaic:ioz...` form.
    #[wasm_bindgen(js_name = toString)]
    pub fn stringify(&self) -> String {
        self.inner.to_did_string()
    }

    /// SCALE-encode the DID for Substrate clients and golden vectors.
    #[wasm_bindgen(js_name = toScaleBytes)]
    pub fn to_scale_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }
}

impl From<MosaicDid> for JsMosaicDid {
    fn from(inner: MosaicDid) -> Self {
        Self { inner }
    }
}

impl Wraps<MosaicDid> for JsMosaicDid {
    fn inner(&self) -> &MosaicDid {
        &self.inner
    }
}

/// Key reference inside a Mosaic DID document.
#[wasm_bindgen(js_name = MosaicKeyRef)]
pub struct JsMosaicKeyRef {
    inner: MosaicKeyRef,
}

#[wasm_bindgen(js_class = MosaicKeyRef)]
impl JsMosaicKeyRef {
    /// Create a key reference from a UTF-8 DID document fragment.
    #[wasm_bindgen(constructor)]
    pub fn new(key_ref: &str) -> Result<JsMosaicKeyRef, JsValue> {
        let inner: MosaicKeyRef = key_ref.parse().map_err_to_js()?;
        Ok(Self { inner })
    }

    /// Raw bytes of the key reference.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// SCALE-encode the key reference for Substrate clients and golden vectors.
    #[wasm_bindgen(js_name = toScaleBytes)]
    pub fn to_scale_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Convert the key reference into display form.
    #[wasm_bindgen(js_name = toString)]
    pub fn stringify(&self) -> String {
        self.inner.to_string()
    }
}

impl From<MosaicKeyRef> for JsMosaicKeyRef {
    fn from(inner: MosaicKeyRef) -> Self {
        Self { inner }
    }
}

impl Wraps<MosaicKeyRef> for JsMosaicKeyRef {
    fn inner(&self) -> &MosaicKeyRef {
        &self.inner
    }
}

/// Typed Mosaic content id for BeforeProof submissions.
#[wasm_bindgen(js_name = MosaicContentId)]
pub struct JsMosaicContentId {
    inner: MosaicContentId,
}

#[wasm_bindgen(js_class = MosaicContentId)]
impl JsMosaicContentId {
    /// Parse a displayed Mosaic content id: `0x...` or `cj:0x...`.
    #[wasm_bindgen(constructor)]
    pub fn new(content_id: &str) -> Result<JsMosaicContentId, JsValue> {
        let inner: MosaicContentId = content_id.parse().map_err_to_js()?;
        Ok(Self { inner })
    }

    /// Hash arbitrary bytes with BLAKE3 and wrap the result as `ByteHash`.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(content: &[u8]) -> JsMosaicContentId {
        MosaicContentId::from_bytes(content).into()
    }

    /// Wrap an existing 32-byte BLAKE3 hash as `ByteHash`.
    #[wasm_bindgen(js_name = fromByteHash)]
    pub fn from_byte_hash(hash: &[u8]) -> Result<JsMosaicContentId, JsValue> {
        Ok(MosaicContentId::ByteHash(hash32(hash).map_err_to_js()?).into())
    }

    /// Wrap an existing 32-byte JSON digest hash as `JsonDigest`.
    #[wasm_bindgen(js_name = fromJsonDigestHash)]
    pub fn from_json_digest_hash(hash: &[u8]) -> Result<JsMosaicContentId, JsValue> {
        Ok(MosaicContentId::from_json_digest_hash(hash32(hash).map_err_to_js()?).into())
    }

    /// Convert a legacy `json-digest` id (`cju...`) or `cj:0x...` into `JsonDigest`.
    #[wasm_bindgen(js_name = fromJsonDigest)]
    pub fn from_json_digest(content_id: &str) -> Result<JsMosaicContentId, JsValue> {
        Ok(parse_json_digest_content_id(content_id).map_err_to_js()?.into())
    }

    /// Return the 32-byte hash payload without the variant discriminant.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// SCALE-encode the full typed content id, including the variant discriminant.
    #[wasm_bindgen(js_name = toScaleBytes)]
    pub fn to_scale_bytes(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Whether this content id carries JSON digest semantics.
    #[wasm_bindgen(js_name = isJsonDigest)]
    pub fn is_json_digest(&self) -> bool {
        self.inner.is_json_digest()
    }

    /// Return `byteHash` or `jsonDigest`.
    #[wasm_bindgen]
    pub fn kind(&self) -> String {
        match self.inner {
            MosaicContentId::ByteHash(_) => "byteHash",
            MosaicContentId::JsonDigest(_) => "jsonDigest",
        }
        .to_owned()
    }

    /// Convert the content id into `0x...` or `cj:0x...` display form.
    #[wasm_bindgen(js_name = toString)]
    pub fn stringify(&self) -> String {
        self.inner.to_string()
    }
}

impl From<MosaicContentId> for JsMosaicContentId {
    fn from(inner: MosaicContentId) -> Self {
        Self { inner }
    }
}

impl Wraps<MosaicContentId> for JsMosaicContentId {
    fn inner(&self) -> &MosaicContentId {
        &self.inner
    }
}

/// Return the stable Mosaic right names accepted by `mosaicRightScaleBytes`.
#[wasm_bindgen(js_name = mosaicRightValues)]
pub fn mosaic_right_values() -> Result<JsValue, JsValue> {
    to_value(&["update", "impersonate", "delegate", "issue", "revoke", "recovery"])
        .map_err(err_to_js)
}

/// Return true when the value is a known Mosaic DID right name.
#[wasm_bindgen(js_name = mosaicIsValidRight)]
pub fn mosaic_is_valid_right(right: &str) -> bool {
    right.parse::<Right>().is_ok()
}

/// SCALE-encode a Mosaic DID right by stable string name.
#[wasm_bindgen(js_name = mosaicRightScaleBytes)]
pub fn mosaic_right_scale_bytes(right: &str) -> Result<Vec<u8>, JsValue> {
    let right: Right = right.parse().map_err(err_to_js)?;
    Ok(right.encode())
}

/// Return the stable Mosaic key type names accepted by `mosaicKeyTypeScaleBytes`.
#[wasm_bindgen(js_name = mosaicKeyTypeValues)]
pub fn mosaic_key_type_values() -> Result<JsValue, JsValue> {
    to_value(&["ed25519", "secp256k1", "secp256r1", "x25519"]).map_err(err_to_js)
}

/// Return true when the value is a known Mosaic DID key type name.
#[wasm_bindgen(js_name = mosaicIsValidKeyType)]
pub fn mosaic_is_valid_key_type(key_type: &str) -> bool {
    key_type.parse::<KeyType>().is_ok()
}

/// SCALE-encode a Mosaic DID key type by stable string name.
#[wasm_bindgen(js_name = mosaicKeyTypeScaleBytes)]
pub fn mosaic_key_type_scale_bytes(key_type: &str) -> Result<Vec<u8>, JsValue> {
    let key_type: KeyType = key_type.parse().map_err(err_to_js)?;
    Ok(key_type.encode())
}

/// Return the stable Mosaic key purpose names accepted by `mosaicKeyPurposeScaleBytes`.
#[wasm_bindgen(js_name = mosaicKeyPurposeValues)]
pub fn mosaic_key_purpose_values() -> Result<JsValue, JsValue> {
    to_value(&[
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ])
    .map_err(err_to_js)
}

/// Return true when the value is a known Mosaic DID key purpose name.
#[wasm_bindgen(js_name = mosaicIsValidKeyPurpose)]
pub fn mosaic_is_valid_key_purpose(key_purpose: &str) -> bool {
    key_purpose.parse::<KeyPurpose>().is_ok()
}

/// SCALE-encode a Mosaic DID key purpose by stable string name.
#[wasm_bindgen(js_name = mosaicKeyPurposeScaleBytes)]
pub fn mosaic_key_purpose_scale_bytes(key_purpose: &str) -> Result<Vec<u8>, JsValue> {
    let key_purpose: KeyPurpose = key_purpose.parse().map_err(err_to_js)?;
    Ok(key_purpose.encode())
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
