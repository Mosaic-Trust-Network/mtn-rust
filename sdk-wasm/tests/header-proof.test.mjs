import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {createMosaicSdk} from '../dist/index.js';
const require=createRequire(import.meta.url);
const fixture=name=>JSON.parse(readFileSync(new URL(`./vectors/${name}.json`,import.meta.url)));
const header=fixture('before-proof-header'),proof=fixture('before-proof'),metadata=fixture('before-proof-runtime');
const scale=Uint8Array.from(header.scale),hash=Uint8Array.from(header.blockHash);
const runtime=new Uint8Array(readFileSync(new URL('./vectors/before-proof-runtime.scale',import.meta.url)));
const expectedMetadataHash=Uint8Array.from(metadata.metadataHash);
const web=await import('../generated/web/mosaic_sdk_wasm.js');
await web.default({module_or_path:readFileSync(new URL('../generated/web/mosaic_sdk_wasm_bg.wasm',import.meta.url))});
const input=()=>({expectedBlockHash:hash,expectedHeaderHeight:header.blockHeight,headerScale:scale,contentId:proof.contentId,blockHeight:proof.blockHeight,extrinsicIndex:proof.extrinsicIndex,nodes:proof.nodes.slice()});
for(const [target,bindings] of [['node',require('../generated/node/mosaic_sdk_wasm.cjs')],['web-in-node',web]]) {
 const sdk=createMosaicSdk(bindings);
 test(`${target}: header codec and inspection match frozen native vector`,()=>{
  assert.deepEqual([...sdk.mosaicHeaderScaleV1(JSON.stringify(header.rpc))],header.scale);
  const info=sdk.inspectMosaicHeaderV1(scale);
  assert.deepEqual(info,{blockHash:hash,blockHeight:'48',stateRoot:Uint8Array.from(header.stateRoot)});
  assert.equal(Object.isFrozen(info),true);
  assert.equal(sdk.verifyBeforeProofHeaderV1(input()),true);
  assert.equal(sdk.verifyBeforeProofHeaderV1({...input(),nodes:proof.nodes.slice().reverse()}),true);
 });
 test(`${target}: RPC logs and SCALE logs share the encoded 16 KiB boundary`,()=>{
  // Frozen native DigestItem::Other vectors: tag + SCALE compact length + payload.
  const accepted='00f5ff'+'00'.repeat(16381);
  const rpc={...header.rpc,digest:{logs:['0x'+accepted]}};
  const acceptedScale=sdk.mosaicHeaderScaleV1(JSON.stringify(rpc));
  assert.equal(sdk.inspectMosaicHeaderV1(acceptedScale).blockHeight,'48');
  const prefix=acceptedScale.slice(0,acceptedScale.length-accepted.length/2);
  for(const encoded of ['00f9ff'+'00'.repeat(16382),'0002000100'+'00'.repeat(16384)]) {
   assert.throws(()=>sdk.mosaicHeaderScaleV1(JSON.stringify({...rpc,digest:{logs:['0x'+encoded]}})));
   const scale=Uint8Array.from([...prefix,...Buffer.from(encoded,'hex')]);
   assert.throws(()=>sdk.inspectMosaicHeaderV1(scale));
   assert.throws(()=>bindings.inspect_mosaic_header_v1(scale));
  }
 });
 test(`${target}: expected header identity and registration cannot be substituted`,()=>{
  const changed=scale.slice();changed[0]^=1;
  for(const altered of [{expectedBlockHash:new Uint8Array(32)},{expectedHeaderHeight:'47'},{headerScale:changed},{blockHeight:'49'},{extrinsicIndex:'8'},{nodes:['0x01']}])
   assert.equal(sdk.verifyBeforeProofHeaderV1({...input(),...altered}),false);
 });
 test(`${target}: malformed header/proof input is bounded on native and JS boundaries`,()=>{
  for(const altered of [{expectedBlockHash:new Uint8Array(31)},{expectedHeaderHeight:'048'},{expectedHeaderHeight:48},{headerScale:new Uint8Array()},{headerScale:Uint8Array.from([...scale,0])},{headerScale:new Uint8Array(65537)},{nodes:[]},{nodes:[...proof.nodes,proof.nodes[0]]},{nodes:['0x'+'00'.repeat(65537)]}])
   assert.throws(()=>sdk.verifyBeforeProofHeaderV1({...input(),...altered}));
  for(const bad of [new Uint8Array(),Uint8Array.from([...scale,0]),new Uint8Array(65537)]) {
   assert.throws(()=>sdk.inspectMosaicHeaderV1(bad));
   assert.throws(()=>bindings.inspect_mosaic_header_v1(bad));
  }
  assert.throws(()=>sdk.mosaicHeaderScaleV1(JSON.stringify({...header.rpc,digest:{logs:['0xff']}})));
  assert.throws(()=>sdk.mosaicHeaderScaleV1(' '.repeat(131073)));
  assert.throws(()=>sdk.mosaicHeaderScaleV1(header.rpc));
 });
 test(`${target}: pinned runtime metadata qualifies native BeforeProofs layout`,()=>{
  assert.equal(sdk.qualifyBeforeProofMetadataV1(expectedMetadataHash,runtime),true);
  assert.equal(sdk.qualifyBeforeProofMetadataV1(new Uint8Array(32),runtime),false);
  const changed=runtime.slice();changed[changed.length-1]^=1;
  assert.equal(sdk.qualifyBeforeProofMetadataV1(expectedMetadataHash,changed),false);
 });
 test(`${target}: metadata input types and decode allocation are bounded`,()=>{
  for(const [expected,bytes] of [[new Uint8Array(31),runtime],[expectedMetadataHash,new Uint8Array()],[expectedMetadataHash,new Uint8Array(524289)],[metadata.metadataHash,runtime],[expectedMetadataHash,metadata.metadataHex]])
   assert.throws(()=>sdk.qualifyBeforeProofMetadataV1(expected,bytes));
  assert.throws(()=>bindings.qualify_before_proof_metadata_v1(new Uint8Array(31),runtime));
 });
}
