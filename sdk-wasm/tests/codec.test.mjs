import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createMosaicSdk } from '../dist/index.js';
const require = createRequire(import.meta.url);
const vectors = JSON.parse(readFileSync(new URL('./vectors/native.json', import.meta.url)));
const nodeBindings = require('../generated/node/mosaic_sdk_wasm.cjs');
const webBindings = await import('../generated/web/mosaic_sdk_wasm.js');
const { initializeMosaic } = await import('@mosaic-private/sdk/browser');
const coldWebSdk = await initializeMosaic({ module_or_path: readFileSync(new URL('../generated/web/mosaic_sdk_wasm_bg.wasm', import.meta.url)) });
const hash = Uint8Array.from({ length: 32 }, (_, i) => i);
for (const [target, bindings] of [['node', nodeBindings], ['web-in-node', webBindings]]) {
 const sdk = createMosaicSdk(bindings);
 test(`${target}: DID derivation and SCALE match native`, () => {
  assert.equal(sdk.deriveDid(hash), vectors.did);
  assert.equal(sdk.parseDid(vectors.did), vectors.did);
  assert.deepEqual([...sdk.didScale(vectors.did)], vectors.didScale);
 });
 for (const item of vectors.foreignDids) test(`${target}: rejects foreign DID ${item.did}`, () => assert.throws(() => sdk.parseDid(item.did)));
 for (const [kind, display, scale] of [['blake3-flat', 'flatDisplay', 'flatScale'], ['sha3-json', 'sha3Display', 'sha3Scale'], ['blake3-json', 'blake3Display', 'blake3Scale']]) {
  test(`${target}: ${kind} native display and SCALE`, () => {
   assert.equal(sdk.contentIdFromHash(hash, kind), vectors[display]);
   assert.equal(sdk.parseContentId(vectors[display]), vectors[display]);
   assert.deepEqual([...sdk.contentIdScale(vectors[display])], vectors[scale]);
  });
 }
 for (const [i, item] of vectors.digests.entries()) for (const algorithm of ['sha3', 'blake3']) test(`${target}: JSON ${i} ${algorithm} matches native`, () => assert.equal(sdk.digestJson(item.jsonText, algorithm), item[algorithm].digest));
 test(`${target}: rights names and SCALE match native`, () => {
  assert.deepEqual(sdk.rights(), vectors.rights.map(x => x.name));
  for (const item of vectors.rights) assert.deepEqual([...sdk.rightScale(item.name)], item.scale);
 });
 test(`${target}: native purposes encode distinctly`, () => {
  for (const [i, name] of ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'].entries()) assert.deepEqual([...sdk.purposeScale(name)], [i]);
 });
 test(`${target}: BLAKE2b-512 flat is distinct and validates length`, () => {
  const bytes = Uint8Array.from({ length: 64 }, (_, i) => i);
  const id = sdk.contentIdFromHash(bytes, 'blake2b-flat');
  assert.ok(id.startsWith('cB'));
  assert.deepEqual([...sdk.contentIdScale(id)], [1, ...bytes]);
  assert.throws(() => sdk.contentIdFromHash(hash, 'blake2b-flat'));
 });
 test(`${target}: rejects malformed and unknown inputs`, () => {
  for (const did of ['', 'did:morpheus:ioz', vectors.did + '#key', 'did:mosaic:ioz!']) assert.throws(() => sdk.parseDid(did));
  assert.throws(() => sdk.deriveDid(hash.slice(1)));
  assert.throws(() => sdk.contentIdFromHash(hash.slice(1), 'sha3-json'));
  assert.throws(() => sdk.contentIdFromHash(hash, 'unknown'));
  for (const id of ['', '0x00', 'cj:0x00', 'cmu!']) assert.throws(() => sdk.parseContentId(id));
  assert.throws(() => sdk.digestJson('{'));
  assert.throws(() => sdk.digestJson('{}', 'unknown'));
  assert.throws(() => sdk.digestJson({ x: 1 }));
  assert.throws(() => sdk.rightScale('owner'));
  assert.throws(() => sdk.purposeScale('issue'));
 });
}

test('public Node package entry point supplies current codecs', async () => {
 const { mosaic } = await import('@mosaic-private/sdk/node');
 assert.equal(mosaic.deriveDid(hash), vectors.did);
 assert.equal(mosaic.digestJson(vectors.digests[0].jsonText), vectors.digests[0].blake3.digest);
});
test('public browser entry point initializes the generated web artifact', async () => {
 assert.equal(coldWebSdk.deriveDid(hash), vectors.did);
 assert.equal(coldWebSdk.digestJson(vectors.digests[0].jsonText, 'sha3'), vectors.digests[0].sha3.digest);
});
for (const [target, bindings] of [['node', nodeBindings], ['web-in-node', webBindings]]) {
 const sdk = createMosaicSdk(bindings);
 test(`${target}: integers above 2^53 retain their JSON preimage`, () => {
  for (const algorithm of ['sha3', 'blake3']) assert.notEqual(sdk.digestJson('{"n":9007199254740992}', algorithm), sdk.digestJson('{"n":9007199254740993}', algorithm));
 });
 test(`${target}: non-NFKD object keys follow native rejection policy`, () => assert.throws(() => sdk.digestJson('{"é":1}')));
 test(`${target}: bridge scalar rejection and native array ordering`, () => {
  assert.throws(() => sdk.digestJson('1'));
  assert.throws(() => sdk.digestJson('"1"'));
  assert.notEqual(sdk.digestJson('[1,2]'), sdk.digestJson('[2,1]'));
  assert.equal(sdk.digestJson('{"b":2,"a":1}'), sdk.digestJson('{"a":1,"b":2}'));
 });
}
