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
export function createMosaicSdk(bindings: MosaicBindings) {
 return Object.freeze({
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
