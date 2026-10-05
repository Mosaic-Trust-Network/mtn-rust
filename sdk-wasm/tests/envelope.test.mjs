import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createMosaicSdk } from '../dist/index.js';
import nodeBindings from '../generated/node/mosaic_sdk_wasm.cjs';
import init, * as webBindings from '../generated/web/mosaic_sdk_wasm.js';
await init({module_or_path:readFileSync(new URL('../generated/web/mosaic_sdk_wasm_bg.wasm',import.meta.url))});
const v=JSON.parse(readFileSync(new URL('./vectors/envelope.json',import.meta.url)));
for(const [target,bindings] of [['node',nodeBindings],['web-in-node',webBindings]]) {
 const sdk=createMosaicSdk(bindings);
 test(`${target}: exact native textual envelope payload and signature`,()=>{
  assert.deepEqual([...sdk.envelopeSigningPayload(v.envelopeJson)],v.payload);
  assert.equal(new TextDecoder().decode(sdk.envelopeSigningPayload(v.envelopeJson)),v.digest);
  assert.equal(sdk.verifyEnvelopeSignature(v.envelopeJson,v.publicKey,v.signature,v.keyRef),true);
  assert.equal(sdk.mosaicPublicKey(Uint8Array.from(v.rawPublicKey)),v.publicKey);
  assert.equal(sdk.mosaicKeyRef(v.publicKey),v.keyRef);
  assert.equal(sdk.keyMatchesReference(v.publicKey,v.keyRef),true);
  assert.equal(sdk.digestJson(v.signedJson,'sha3'),v.signedFingerprint);
 });
 test(`${target}: changed signed content, network, proof or nonce fails`,()=>{
  for(const changed of [v.envelopeJson.replace('Synthetic Tresor test','Changed'),v.envelopeJson.replace('mosaic-simulation','other-network'),v.envelopeJson.replace('"blockHeight":42','"blockHeight":43'),v.envelopeJson.replace('0x04','0x05'),v.envelopeJson.replace('18446744073709551615','0')]) {
   assert.notEqual(changed,v.envelopeJson);
   assert.equal(sdk.verifyEnvelopeSignature(changed,v.publicKey,v.signature,v.keyRef),false);
  }
 });
 test(`${target}: key binding and signature corruption fail`,()=>{
  assert.equal(sdk.verifyEnvelopeSignature(v.envelopeJson,v.publicKey,v.signature,v.wrongKeyRef),false);
  assert.equal(sdk.verifyEnvelopeSignature(v.envelopeJson,v.wrongPublicKey,v.signature,v.wrongKeyRef),false);
  const replacement=v.signature.at(-1)==='1'?'2':'1';
  try { assert.equal(sdk.verifyEnvelopeSignature(v.envelopeJson,v.publicKey,v.signature.slice(0,-1)+replacement,v.keyRef),false); } catch(error) { if(error.code==='ERR_ASSERTION') throw error; }
 });
 test(`${target}: foreign suites and malformed proof inputs rejected`,()=>{
  assert.throws(()=>sdk.mosaicKeyRef(v.publicKey.replace(/^po/,'pe')));
  assert.throws(()=>sdk.verifyEnvelopeSignature(v.envelopeJson,v.publicKey,v.signature.replace(/^so/,'se'),v.keyRef));
  assert.throws(()=>sdk.verifyEnvelopeSignature(v.envelopeJson,v.publicKey,'invalid-signature',v.keyRef));
  assert.throws(()=>sdk.mosaicPublicKey(new Uint8Array(31)));
  for(const height of [-1,4294967295,4294967296,1.5]) assert.throws(()=>sdk.envelopeSigningPayload(JSON.stringify({content:{},proof:{blockHeight:height,blockHash:'0x'+'00'.repeat(32)}})));
  for(const envelope of [{content:'pretend-digest',proof:{blockHeight:1,blockHash:'0x'+'00'.repeat(32)}},{content:{},proof:{blockHeight:1,blockHash:'0x00'}},{content:{},proof:{blockHeight:1,blockHash:'0x'+'00'.repeat(32),extra:1}},{...JSON.parse(v.envelopeJson),extra:1}]) assert.throws(()=>sdk.envelopeSigningPayload(JSON.stringify(envelope)));
 });
 test(`${target}: signer port is verified before returning native signature material`,async()=>{
  const signed=await sdk.signEnvelope(v.envelopeJson,v.publicKey,v.keyRef,async payload=>{assert.deepEqual([...payload],v.payload);return v.signature;});
  assert.deepEqual(signed,{publicKey:v.publicKey,bytes:v.signature});
  assert.equal(Object.isFrozen(signed),true);
  await assert.rejects(sdk.signEnvelope(v.envelopeJson,v.publicKey,v.keyRef,()=>v.signature.replace(/^so/,'se')));
  let called=false;
  await assert.rejects(sdk.signEnvelope(v.envelopeJson,v.publicKey,v.wrongKeyRef,()=>{called=true;return v.signature;}));
  assert.equal(called,false);
 });
}
