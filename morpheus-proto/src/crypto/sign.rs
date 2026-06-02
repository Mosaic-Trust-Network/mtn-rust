use super::*;

use crate::{
    crypto::hash::{Content, ContentId},
    data::*,
};
use iop_keyvault::{
    PrivateKey, PublicKey,
    multicipher::{MKeyId, MPrivateKey, MPublicKey, MSignature},
};

pub trait Signable: Content {
    fn content_to_sign(&self) -> Result<Vec<u8>> {
        Ok(self.content_id()?.into_bytes())
    }
}

impl Signable for serde_json::Value {}

impl Signable for Box<[u8]> {
    fn content_to_sign(&self) -> Result<Vec<u8>> {
        Ok(self.as_ref().to_owned())
    }
}

impl Signable for Vec<u8> {
    fn content_to_sign(&self) -> Result<Vec<u8>> {
        Ok(self.to_owned())
    }
}

// TODO implement Hash for MPublicKey and MSignature
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "SignatureSerializationFormat<T>", into = "SignatureSerializationFormat<T>")]
pub struct Signed<T>
where
    T: Signable,
{
    content: T,
    public_key: MPublicKey,
    signature: MSignature,
    nonce: Option<Nonce264>,
    // TODO ClaimPresentation might be needed to prove proper right of delegated signing.
    // on_behalf_of: Did,
}

impl<T> Signed<T>
where
    T: Signable,
{
    pub fn new(public_key: MPublicKey, content: T, signature: MSignature) -> Self {
        Self { public_key, content, signature, nonce: None }
    }

    pub fn from_parts(
        public_key: MPublicKey, content: T, signature: MSignature, nonce: Option<Nonce264>,
    ) -> Self {
        Self { public_key, content, signature, nonce }
    }

    pub fn into_parts(self) -> (MPublicKey, T, MSignature, Option<Nonce264>) {
        (self.public_key, self.content, self.signature, self.nonce)
    }

    pub fn content(&self) -> &T {
        &self.content
    }

    pub fn public_key(&self) -> &MPublicKey {
        &self.public_key
    }

    pub fn signature(&self) -> &MSignature {
        &self.signature
    }

    pub fn validate(&self) -> bool {
        match self.content.content_to_sign() {
            Ok(content) => self.public_key.verify(content, &self.signature),
            Err(_) => false,
        }
    }

    pub fn validate_with_keyid(&self, signer_id: Option<&MKeyId>) -> bool {
        let mut valid = self.validate();
        if let Some(id) = signer_id {
            valid &= self.public_key.validate_id(id);
        }
        valid
    }

    // TODO add Before/AfterProofs as optional arguments here
    pub fn validate_with_did_doc(
        &self, on_behalf_of: &DidDocument, from_inc: Option<BlockHeight>,
        until_exc: Option<BlockHeight>,
    ) -> Result<ValidationResult> {
        let from = from_inc.unwrap_or(1);
        let until = until_exc.unwrap_or(on_behalf_of.queried_at_height);

        let auth = Authentication::PublicKey(self.public_key.to_owned());
        let mut issues = on_behalf_of.validate_right(&auth, Right::Impersonation, from, until)?;

        if !self.validate() {
            issues.add_issue(ValidationIssueSeverity::Error, "Signature is invalid");
        }
        Ok(issues)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SignatureTuple {
    #[serde(with = "serde_str", rename = "publicKey")]
    public_key: MPublicKey,
    #[serde(with = "serde_str")]
    bytes: MSignature,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureSerializationFormat<T> {
    signature: SignatureTuple,
    content: T,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    nonce: Option<Nonce264>,
}

impl<T: Signable> From<Signed<T>> for SignatureSerializationFormat<T> {
    fn from(src: Signed<T>) -> Self {
        SignatureSerializationFormat {
            content: src.content,
            signature: SignatureTuple { public_key: src.public_key, bytes: src.signature },
            nonce: src.nonce,
        }
    }
}

impl<T: Signable> From<SignatureSerializationFormat<T>> for Signed<T> {
    fn from(src: SignatureSerializationFormat<T>) -> Self {
        Signed {
            content: src.content,
            public_key: src.signature.public_key,
            signature: src.signature.bytes,
            nonce: src.nonce,
        }
    }
}

pub trait SyncMorpheusSigner {
    fn sign(&self, data: &[u8]) -> Result<(MPublicKey, MSignature)>;

    fn sign_witness_request(&self, request: WitnessRequest) -> Result<Signed<WitnessRequest>> {
        let content_to_sign = request.content_to_sign()?;
        let (public_key, signature) = self.sign(&content_to_sign)?;
        Ok(Signed::new(public_key, request, signature))
    }

    fn sign_witness_statement(
        &self, statement: WitnessStatement,
    ) -> Result<Signed<WitnessStatement>> {
        let content_to_sign = statement.content_to_sign()?;
        let (public_key, signature) = self.sign(&content_to_sign)?;
        Ok(Signed::new(public_key, statement, signature))
    }

    fn sign_claim_presentation(
        &self, presentation: ClaimPresentation,
    ) -> Result<Signed<ClaimPresentation>> {
        let content_to_sign = presentation.content_to_sign()?;
        let (public_key, signature) = self.sign(&content_to_sign)?;
        Ok(Signed::new(public_key, presentation, signature))
    }
}

impl<T: SyncMorpheusSigner + Sized> SyncMorpheusSigner for Box<T> {
    fn sign(&self, data: &[u8]) -> Result<(MPublicKey, MSignature)> {
        self.as_ref().sign(data)
    }
}

pub struct PrivateKeySigner {
    private_key: MPrivateKey,
}

impl PrivateKeySigner {
    pub fn new(private_key: MPrivateKey) -> Self {
        Self { private_key }
    }
}

impl SyncMorpheusSigner for PrivateKeySigner {
    fn sign(&self, data: &[u8]) -> Result<(MPublicKey, MSignature)> {
        let signature = self.private_key.sign(data);
        Ok((self.private_key.public_key(), signature))
    }
}

pub type BlockHash = ContentId;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AfterProof {
    #[serde(rename = "blockHash")]
    pub block_hash: BlockHash,
    #[serde(rename = "blockHeight")]
    pub block_height: BlockHeight,
}

impl Content for AfterProof {}
impl Signable for AfterProof {}

// TODO Eq, PartialEq and maybe PartialOrd for AfterEnvelope
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AfterEnvelope<T: Signable> {
    // TODO will contentId be fetched from the content or needs a separate field?
    //      should we just use the contentId here and provide another way to resolve the content from it?
    pub content: T,
    pub proof: AfterProof, // TODO is a transactionId also needed here?
}

impl<T: Signable> Content for AfterEnvelope<T> {}
impl<T: Signable> Signable for AfterEnvelope<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use iop_keyvault::PrivateKey;
    use iop_keyvault::ed25519::EdPrivateKey;
    use json_digest::digest_data;
    use serde_json::json;

    #[test]
    fn after_envelope_signing_golden_vectors() {
        let data = include_str!("../../after-envelope-signing.json");
        let vectors: serde_json::Value = serde_json::from_str(data).unwrap();
        let kp = &vectors["testKeyPair"];

        assert_eq!(kp["algorithm"].as_str().unwrap(), "ed25519-rfc8032");

        let seed_bytes = hex::decode(kp["seedHex"].as_str().unwrap()).unwrap();
        let ed_sk = EdPrivateKey::from_bytes(&seed_bytes).unwrap();
        let pk_bytes = ed_sk.public_key().to_bytes();
        assert_eq!(hex::encode(pk_bytes), kp["publicKeyHex"].as_str().unwrap());

        let msk = MPrivateKey::from(ed_sk);
        let mpk = msk.public_key();
        assert_eq!(mpk.to_string(), kp["publicKey"].as_str().unwrap());

        for v in vectors["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            let smt_root = v["input"]["smtRoot"].as_str().unwrap();
            let block_hash = v["input"]["afterProof"]["blockHash"].as_str().unwrap();
            let block_height = v["input"]["afterProof"]["blockHeight"].as_i64().unwrap() as u32;

            let after_envelope = AfterEnvelope {
                content: json!({ "root": smt_root, "height": 10 }),
                proof: AfterProof { block_hash: block_hash.to_string(), block_height },
            };

            assert_eq!(
                digest_data(&after_envelope).unwrap(),
                v["expected"]["afterEnvelopeDigest"].as_str().unwrap(),
                "{id}: afterEnvelopeDigest mismatch",
            );

            let to_sign = after_envelope.content_to_sign().unwrap();
            let signature = msk.sign(&to_sign);
            let signed = Signed::new(msk.public_key(), after_envelope, signature);

            assert!(signed.validate(), "{id}: signature must be valid");

            assert_eq!(
                signed.signature().to_string(),
                v["expected"]["signature"].as_str().unwrap(),
                "{id}: signature mismatch",
            );

            assert_eq!(
                digest_data(&signed).unwrap(),
                v["expected"]["fingerprint"].as_str().unwrap(),
                "{id}: fingerprint mismatch",
            );
        }
    }
}
