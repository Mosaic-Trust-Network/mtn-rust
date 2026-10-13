import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {createMosaicSdk} from '../dist/index.js';
const require=createRequire(import.meta.url);
const vector=JSON.parse(readFileSync(new URL('./vectors/before-proof.json',import.meta.url)));
const nodeBindings=require('../generated/node/mosaic_sdk_wasm.cjs');
const webBindings=await import('../generated/web/mosaic_sdk_wasm.js');
await webBindings.default({module_or_path:readFileSync(new URL('../generated/web/mosaic_sdk_wasm_bg.wasm',import.meta.url))});
const input=()=>({expectedStateRoot:Uint8Array.from(vector.stateRoot),contentId:vector.contentId,blockHeight:vector.blockHeight,extrinsicIndex:vector.extrinsicIndex,nodes:vector.nodes.slice()});
for(const [target,bindings] of [['node',nodeBindings],['web-in-node',webBindings]]) {
 const sdk=createMosaicSdk(bindings);
 test(`${target}: storage relation matches frozen native proof`,()=>{
  assert.deepEqual([...sdk.beforeProofStorageKeyV1(vector.contentId)],vector.storageKey);
  assert.equal(sdk.verifyBeforeProofStorageV1(input()),true);
  assert.equal(sdk.verifyBeforeProofStorageV1({...input(),nodes:vector.nodes.slice().reverse()}),true);
 });
 test(`${target}: another root or registration never verifies`,()=>{
  for(const changed of [{expectedStateRoot:new Uint8Array(32)},{blockHeight:'43'},{extrinsicIndex:'8'},{contentId:sdk.contentIdFromHash(new Uint8Array(32),'blake3-json')},{nodes:['0x01']}])
   assert.equal(sdk.verifyBeforeProofStorageV1({...input(),...changed}),false);
 });
 test(`${target}: bounded malformed proof inputs reject`,()=>{
  for(const changed of [{expectedStateRoot:new Uint8Array(31)},{blockHeight:'01'},{extrinsicIndex:7},{nodes:[]},{nodes:['0xAB']},{nodes:[vector.nodes[0],vector.nodes[0]]},{nodes:['0x'+'00'.repeat(65537)]},{nodes:Array(513).fill('0x01')},{nodes:[null]},{nodes:'0x01'}])
   assert.throws(()=>sdk.verifyBeforeProofStorageV1({...input(),...changed}));
  assert.throws(()=>sdk.beforeProofStorageKeyV1('bad'));
 });
}
