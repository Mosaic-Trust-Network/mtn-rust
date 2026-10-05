import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createMosaicSdk } from '../dist/index.js';
import nodeBindings from '../generated/node/mosaic_sdk_wasm.cjs';
import init, * as webBindings from '../generated/web/mosaic_sdk_wasm.js';
await init({module_or_path:readFileSync(new URL('../generated/web/mosaic_sdk_wasm_bg.wasm',import.meta.url))});
const v=JSON.parse(readFileSync(new URL('./vectors/operation.json',import.meta.url)));
for(const [target,bindings] of [['node',nodeBindings],['web-in-node',webBindings]]) {
 const sdk=createMosaicSdk(bindings);
 test(`${target}: native initial key and commitment operation SCALE`,()=>{
  assert.deepEqual([...sdk.initialDidKeyOperation(v.publicKey,v.initialNonce)],v.vectors[0].operationScale);
  assert.deepEqual([...sdk.updateCommitmentOperation(v.did,v.commitment,v.sequence)],v.vectors[1].operationScale);
  for(const item of v.vectors) {
   const op=Uint8Array.from(item.operationScale);
   assert.deepEqual([...sdk.didOperationSigningPayload(op,v.keyRef,v.nonce)],item.payload);
   assert.equal(sdk.verifyDidOperationSignature(op,v.publicKey,item.signature,v.keyRef,v.nonce),true);
   assert.equal(sdk.verifyDidOperationSignature(op,v.publicKey,item.signature,v.keyRef,'18446744073709551614'),false);
   if(item.name==='initial') assert.throws(()=>sdk.didOperationSigningPayload(op,v.wrongKeyRef,v.nonce));
   else {
    assert.equal(sdk.verifyDidOperationSignature(op,v.wrongPublicKey,item.signature,v.wrongKeyRef,v.nonce),false);
    assert.equal(sdk.verifyDidOperationSignature(op,v.publicKey,item.signature,v.wrongKeyRef,v.nonce),false);
   }
  }
 });
 test(`${target}: native output assembly and asynchronous snapshot`,async()=>{
  for(const item of v.vectors) for(const container of [Uint8Array,Buffer]) {
   const op=container.from(item.operationScale);
   const signed=await sdk.signDidOperation(op,v.publicKey,v.keyRef,v.nonce,async payload=>{
    assert.deepEqual([...payload],item.payload);
    op.fill(255); // Caller-owned input cannot change after signing starts.
    await Promise.resolve();return item.signature;
   });
   assert.deepEqual([...signed.signedScale],item.signedScale);
   assert.deepEqual([...signed.ssiScale],item.ssiScale);
   assert.equal(signed.nonce,v.nonce);assert.equal(signed.signerKeyRef,v.keyRef);assert.equal(Object.isFrozen(signed),true);
  }
 });
 test(`${target}: malformed and unsupported operations cannot enter signer`,()=>{
  for(const item of v.vectors) {
   for(const op of [Uint8Array.from([...item.operationScale,0]),new Uint8Array(4097),new Uint8Array(),Uint8Array.of(255),Uint8Array.of(6,...item.operationScale.slice(1,35))]) assert.throws(()=>sdk.didOperationSigningPayload(op,v.keyRef,v.nonce));
   const changed=Uint8Array.from(item.operationScale);changed[changed.length-1]^=1;
   // Both operations end in u64; mutate the signed value without changing layout.
   assert.equal(sdk.verifyDidOperationSignature(changed,v.publicKey,item.signature,v.keyRef,v.nonce),false);
   assert.throws(()=>sdk.verifyDidOperationSignature(Uint8Array.from(item.operationScale),v.publicKey,item.signature.replace(/^so/,'se'),v.keyRef,v.nonce));
  }
  for(const n of ['0','01','-1','1.5','18446744073709551616','9007199254740993.0',1]) assert.throws(()=>sdk.didOperationSigningPayload(Uint8Array.from(v.vectors[1].operationScale),v.keyRef,n));
  assert.throws(()=>sdk.didOperationSigningPayload(Uint8Array.from(v.vectors[0].operationScale),v.keyRef,v.initialNonce));
  assert.throws(()=>sdk.updateCommitmentOperation(v.did,sdk.contentIdFromHash(new Uint8Array(32),'blake3-flat'),'1'));
  assert.throws(()=>sdk.updateCommitmentOperation(v.did,v.commitment,'0'));
  assert.throws(()=>sdk.initialDidKeyOperation(v.publicKey.replace(/^po/,'pe')));
 });
 test(`${target}: wrong or malformed external signatures never return transport`,async()=>{
  const item=v.vectors[1], op=Uint8Array.from(item.operationScale);
  await assert.rejects(sdk.signDidOperation(op,v.publicKey,v.keyRef,v.nonce,()=>v.vectors[0].signature));
  await assert.rejects(sdk.signDidOperation(op,v.publicKey,v.keyRef,v.nonce,()=>item.signature.replace(/^so/,'se')));
  await assert.rejects(sdk.signDidOperation(op,v.publicKey,v.keyRef,v.nonce,()=>new Uint8Array(64)));
  let called=false;
  await assert.rejects(sdk.signDidOperation(op,v.publicKey,v.wrongKeyRef,v.nonce,()=>{called=true;return item.signature;}));
  assert.equal(called,false);
  const aliased=Buffer.from(item.operationScale);aliased[aliased.length-1]^=1;
  await assert.rejects(sdk.signDidOperation(aliased,v.publicKey,v.keyRef,v.nonce,()=>{
   Buffer.from(item.operationScale).copy(aliased);return item.signature;
  }));
  const initial=Uint8Array.from(v.vectors[0].operationScale);
  await assert.rejects(sdk.signDidOperation(initial,v.wrongPublicKey,v.wrongKeyRef,v.nonce,()=>{called=true;return item.signature;}));
  assert.equal(called,false);
 });
}
