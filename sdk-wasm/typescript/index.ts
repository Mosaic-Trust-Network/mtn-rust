/** Byte/text codec boundary; protocol logic stays in the generated Rust WASM. */
export type ContentHashKind = 'blake3-flat' | 'blake2b-flat' | 'sha3-json' | 'blake3-json';
export type DigestAlgorithm = 'sha3' | 'blake3';
export type Right = 'update' | 'impersonate' | 'delegate' | 'issue' | 'revoke' | 'recovery';
export type KeyPurpose = 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';
export interface MosaicBindings {
 derive_did(key: Uint8Array): string;
 parse_did(value: string): string;
 did_scale(value: string): Uint8Array;
 content_id_from_hash(hash: Uint8Array, kind: string): string;
 content_id_parse(value: string): string;
 content_id_scale(value: string): Uint8Array;
 digest_json(json: string, algorithm: string): string;
 right_names(): string;
 right_scale(name: string): Uint8Array;
 purpose_scale(name: string): Uint8Array;
 mosaic_public_key(raw: Uint8Array): string;
 mosaic_key_ref(publicKey: string): string;
 key_matches_reference(publicKey: string, keyRef: string): boolean;
 initial_did_key_operation(publicKey: string, initialNonce: string): Uint8Array;
 update_commitment_operation(did: string, commitment: string, sequence: string): Uint8Array;
 did_operation_signing_payload(operation: Uint8Array, keyRef: string, nonce: string): Uint8Array;
 verify_did_operation_signature(operation: Uint8Array, publicKey: string, signature: string, keyRef: string, nonce: string): boolean;
 signed_did_operation_scale(operation: Uint8Array, publicKey: string, signature: string, keyRef: string, nonce: string): Uint8Array;
 did_ssi_operation_scale(operation: Uint8Array, publicKey: string, signature: string, keyRef: string, nonce: string): Uint8Array;
 envelope_signing_payload(json: string): Uint8Array;
 verify_envelope_signature(json: string, publicKey: string, signature: string, keyRef: string): boolean;
}
function text(value: string): string {
 if (typeof value !== 'string') throw new TypeError('Expected text input');
 return value;
}
function bytes(value: Uint8Array): Uint8Array {
 if (!(value instanceof Uint8Array)) throw new TypeError('Expected Uint8Array input');
 return value;
}
function invoke<T>(operation: () => T): T {
 try { return operation(); } catch (cause) {
  if (cause instanceof Error) throw cause;
  throw new Error(String(cause));
 }
}
export interface SignedDidOperation { readonly signedScale: Uint8Array; readonly ssiScale: Uint8Array; readonly signerKeyRef: string; readonly nonce: string; }
export interface SignedEnvelope { readonly publicKey: string; readonly bytes: string; }
export type EnvelopeSigner = (payload: Uint8Array) => Promise<string> | string;
export function createMosaicSdk(bindings: MosaicBindings) {
 return Object.freeze({
  initialDidKeyOperation: (publicKey: string, initialNonce: string = '0') => invoke(() => bindings.initial_did_key_operation(text(publicKey), text(initialNonce))),
  updateCommitmentOperation: (did: string, commitment: string, sequence: string) => invoke(() => bindings.update_commitment_operation(text(did), text(commitment), text(sequence))),
  didOperationSigningPayload: (operation: Uint8Array, keyRef: string, nonce: string) => invoke(() => bindings.did_operation_signing_payload(bytes(operation), text(keyRef), text(nonce))),
  verifyDidOperationSignature: (operation: Uint8Array, publicKey: string, signature: string, keyRef: string, nonce: string) => invoke(() => bindings.verify_did_operation_signature(bytes(operation), text(publicKey), text(signature), text(keyRef), text(nonce))),
  signDidOperation: async (operation: Uint8Array, publicKey: string, keyRef: string, nonce: string, signer: EnvelopeSigner): Promise<SignedDidOperation> => {
   const snapshot = Uint8Array.from(bytes(operation));
   text(publicKey); text(keyRef); text(nonce);
   if (!invoke(() => bindings.key_matches_reference(publicKey, keyRef))) throw new Error('DID operation signer key reference mismatch');
   const payload = invoke(() => bindings.did_operation_signing_payload(snapshot, keyRef, nonce));
   const signature = text(await signer(payload));
   // Native assembly verifies the signature before returning transport bytes.
   const signedScale = invoke(() => bindings.signed_did_operation_scale(snapshot, publicKey, signature, keyRef, nonce));
   const ssiScale = invoke(() => bindings.did_ssi_operation_scale(snapshot, publicKey, signature, keyRef, nonce));
   return Object.freeze({ signedScale, ssiScale, signerKeyRef: keyRef, nonce });
  },
  mosaicPublicKey: (raw: Uint8Array) => invoke(() => bindings.mosaic_public_key(bytes(raw))),
  mosaicKeyRef: (publicKey: string) => invoke(() => bindings.mosaic_key_ref(text(publicKey))),
  keyMatchesReference: (publicKey: string, keyRef: string) => invoke(() => bindings.key_matches_reference(text(publicKey), text(keyRef))),
  envelopeSigningPayload: (jsonText: string) => invoke(() => bindings.envelope_signing_payload(text(jsonText))),
  verifyEnvelopeSignature: (jsonText: string, publicKey: string, signature: string, keyRef: string) => invoke(() => bindings.verify_envelope_signature(text(jsonText), text(publicKey), text(signature), text(keyRef))),
  signEnvelope: async (jsonText: string, publicKey: string, keyRef: string, signer: EnvelopeSigner): Promise<SignedEnvelope> => {
   if (!invoke(() => bindings.key_matches_reference(text(publicKey), text(keyRef)))) throw new Error('Envelope signer key reference mismatch');
   const payload = invoke(() => bindings.envelope_signing_payload(text(jsonText)));
   const signature = text(await signer(payload));
   if (!invoke(() => bindings.verify_envelope_signature(jsonText, publicKey, signature, keyRef))) throw new Error('Envelope signer returned an invalid signature');
   return Object.freeze({ publicKey, bytes: signature });
  },
  deriveDid: (key: Uint8Array) => invoke(() => bindings.derive_did(bytes(key))),
  parseDid: (value: string) => invoke(() => bindings.parse_did(text(value))),
  didScale: (value: string) => invoke(() => bindings.did_scale(text(value))),
  contentIdFromHash: (hash: Uint8Array, kind: ContentHashKind) => invoke(() => bindings.content_id_from_hash(bytes(hash), text(kind))),
  parseContentId: (value: string) => invoke(() => bindings.content_id_parse(text(value))),
  contentIdScale: (value: string) => invoke(() => bindings.content_id_scale(text(value))),
  digestJson: (jsonText: string, algorithm: DigestAlgorithm = 'blake3') => invoke(() => bindings.digest_json(text(jsonText), text(algorithm))),
  rights: (): readonly Right[] => Object.freeze(JSON.parse(bindings.right_names()) as Right[]),
  rightScale: (name: Right) => invoke(() => bindings.right_scale(text(name))),
  purposeScale: (name: KeyPurpose) => invoke(() => bindings.purpose_scale(text(name))),
 });
}
export type MosaicSdk = ReturnType<typeof createMosaicSdk>;
