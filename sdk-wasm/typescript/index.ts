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
 mosaic_header_scale_v1(json: string): Uint8Array;
 inspect_mosaic_header_v1(scale: Uint8Array): string;
 verify_before_proof_header_v1(expectedBlockHash: Uint8Array, expectedHeaderHeight: string, headerScale: Uint8Array, contentId: string, height: string, index: string, proofJson: string): boolean;
 qualify_before_proof_metadata_v1(expectedHash: Uint8Array, scale: Uint8Array): boolean;
 before_proof_storage_key_v1(contentId: string): Uint8Array;
 verify_before_proof_storage_v1(expectedRoot: Uint8Array, contentId: string, height: string, index: string, proofJson: string): boolean;
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
/** Expected root must be authenticated separately; this verifies only a storage relation. */
export interface BeforeProofStorageV1 {
 readonly expectedStateRoot: Uint8Array;
 readonly contentId: string;
 readonly blockHeight: string;
 readonly extrinsicIndex: string;
 readonly nodes: readonly string[];
}
/** Header identity is caller-pinned; no network/finality trust is inferred. */
export interface BeforeProofHeaderV1 extends Omit<BeforeProofStorageV1, 'expectedStateRoot'> {
 readonly expectedBlockHash: Uint8Array;
 readonly expectedHeaderHeight: string;
 readonly headerScale: Uint8Array;
}
export interface MosaicHeaderV1 {
 readonly blockHash: Uint8Array;
 readonly blockHeight: string;
 readonly stateRoot: Uint8Array;
}
function fixedHash(value: Uint8Array): Uint8Array {
 if(bytes(value).length!==32) throw new TypeError('Expected 32-byte hash');
 return Uint8Array.from(value);
}
function boundedBytes(value: Uint8Array, maximum: number): Uint8Array {
 if(bytes(value).length===0||value.length>maximum) throw new TypeError('Encoded input exceeds bounds');
 return value;
}
function proofNodesJson(nodes: readonly string[]): string {
 if(!Array.isArray(nodes)||nodes.length===0||nodes.length>512) throw new TypeError('Invalid before-proof storage input');
 const snapshot: string[]=[];let encodedBytes=0;
 for(const node of nodes) {
  if(typeof node!=='string'||node.length>131074) throw new TypeError('Invalid before-proof storage input');
  encodedBytes+=node.length;
  if(encodedBytes>524288+1024) throw new TypeError('Invalid before-proof storage input');
  snapshot.push(node);
 }
 return JSON.stringify(snapshot);
}
export function createMosaicSdk(bindings: MosaicBindings) {
 return Object.freeze({
  mosaicHeaderScaleV1: (rpcJson: string): Uint8Array => {
   if(text(rpcJson).length>131072) throw new TypeError('Header JSON exceeds bounds');
   return invoke(()=>bindings.mosaic_header_scale_v1(rpcJson));
  },
  inspectMosaicHeaderV1: (scale: Uint8Array): MosaicHeaderV1 => {
   const info=JSON.parse(invoke(()=>bindings.inspect_mosaic_header_v1(boundedBytes(scale,65536)))) as {blockHash:number[];blockHeight:string;stateRoot:number[]};
   return Object.freeze({blockHash:Uint8Array.from(info.blockHash),blockHeight:info.blockHeight,stateRoot:Uint8Array.from(info.stateRoot)});
  },
  verifyBeforeProofHeaderV1: (input: BeforeProofHeaderV1): boolean => invoke(()=>bindings.verify_before_proof_header_v1(
   fixedHash(input.expectedBlockHash),text(input.expectedHeaderHeight),boundedBytes(input.headerScale,65536),
   text(input.contentId),text(input.blockHeight),text(input.extrinsicIndex),proofNodesJson(input.nodes))),
  /** ABI qualification only; caller authenticates association with runtime/header. */
  qualifyBeforeProofMetadataV1: (expectedHash: Uint8Array, scale: Uint8Array): boolean => invoke(()=>bindings.qualify_before_proof_metadata_v1(fixedHash(expectedHash),boundedBytes(scale,524288))),
  beforeProofStorageKeyV1: (contentId: string) => invoke(() => bindings.before_proof_storage_key_v1(text(contentId))),
  verifyBeforeProofStorageV1: (input: BeforeProofStorageV1): boolean => {
   const {expectedStateRoot,contentId,blockHeight,extrinsicIndex,nodes}=input;
   return invoke(()=>bindings.verify_before_proof_storage_v1(fixedHash(expectedStateRoot),text(contentId),text(blockHeight),text(extrinsicIndex),proofNodesJson(nodes)));
  },
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
