import { initializeMosaic } from '../../dist/browser.js';
const result = document.getElementById('result');
const checks = [];
function check(name, operation) {
 try { operation(); checks.push({ name, pass: true }); }
 catch (error) { checks.push({ name, pass: false, error: String(error) }); }
}
async function checkAsync(name, operation) {
 try { await operation(); checks.push({ name, pass: true }); }
 catch (error) { checks.push({ name, pass: false, error: String(error) }); }
}
async function rejectsAsync(operation) { let failed=false; try { await operation(); } catch { failed=true; } if(!failed) throw new Error('Expected rejection'); }
function equal(actual, expected) { if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`Mismatch: ${JSON.stringify(actual)}`); }
function rejects(operation) { let failed = false; try { operation(); } catch { failed = true; } if (!failed) throw new Error('Expected rejection'); }
try {
 const sdk = await initializeMosaic(); // Real browser fetch/streaming path, no injected bytes.
 const native = await (await fetch('../vectors/native.json')).json();
 const envelope = await (await fetch('../vectors/envelope.json')).json();
 const hash = Uint8Array.from({ length: 32 }, (_, i) => i);
 check('native DID derivation/SCALE', () => { equal(sdk.deriveDid(hash), native.did); equal([...sdk.didScale(native.did)], native.didScale); });
 for (const item of native.foreignDids) check(`foreign DID ${item.did}`, () => rejects(() => sdk.parseDid(item.did)));
 for (const [kind, display, scale] of [['blake3-flat','flatDisplay','flatScale'],['sha3-json','sha3Display','sha3Scale'],['blake3-json','blake3Display','blake3Scale']]) check(kind, () => { equal(sdk.contentIdFromHash(hash,kind),native[display]); equal([...sdk.contentIdScale(native[display])],native[scale]); });
 for (const [i,item] of native.digests.entries()) for (const algorithm of ['sha3','blake3']) check(`JSON ${i} ${algorithm}`, () => equal(sdk.digestJson(item.jsonText,algorithm),item[algorithm].digest));
 check('right/purpose SCALE', () => { for (const item of native.rights) equal([...sdk.rightScale(item.name)],item.scale); equal([...sdk.purposeScale('assertionMethod')],[1]); });
 check('scalar root guard', () => rejects(() => sdk.digestJson('"pretend digest"')));
 check('large integer preservation', () => { if (sdk.digestJson('{"n":9007199254740992}')===sdk.digestJson('{"n":9007199254740993}')) throw new Error('Integer preimage rounded'); });
 check('native envelope payload', () => equal([...sdk.envelopeSigningPayload(envelope.envelopeJson)],envelope.payload));
 check('native envelope signature and expected signer', () => equal(sdk.verifyEnvelopeSignature(envelope.envelopeJson,envelope.publicKey,envelope.signature,envelope.keyRef),true));
 check('wrong signer reference', () => equal(sdk.verifyEnvelopeSignature(envelope.envelopeJson,envelope.publicKey,envelope.signature,envelope.wrongKeyRef),false));
 check('altered network field', () => equal(sdk.verifyEnvelopeSignature(envelope.envelopeJson.replace('mosaic-simulation','other-network'),envelope.publicKey,envelope.signature,envelope.keyRef),false));
 check('raw public key and key ID', () => { equal(sdk.mosaicPublicKey(Uint8Array.from(envelope.rawPublicKey)),envelope.publicKey); equal(sdk.mosaicKeyRef(envelope.publicKey),envelope.keyRef); });
 for (const [name,from,to] of [['document','Synthetic Tresor test','Changed'],['proof height','"blockHeight":42','"blockHeight":43'],['proof hash','0x04','0x05'],['genesis field','0x11','0x12'],['nonce field','18446744073709551615','0']]) check(`altered ${name}`, () => {
  const changed=envelope.envelopeJson.replace(from,to);
  if(changed===envelope.envelopeJson) throw new Error('Mutation did not change fixture');
  equal(sdk.verifyEnvelopeSignature(changed,envelope.publicKey,envelope.signature,envelope.keyRef),false);
 });
 check('wrong public key', () => equal(sdk.verifyEnvelopeSignature(envelope.envelopeJson,envelope.wrongPublicKey,envelope.signature,envelope.wrongKeyRef),false));
 check('corrupted signature', () => {
  const replacement=envelope.signature.at(-1)==='1'?'2':'1'; let valid=false;
  try { valid=sdk.verifyEnvelopeSignature(envelope.envelopeJson,envelope.publicKey,envelope.signature.slice(0,-1)+replacement,envelope.keyRef); } catch { /* Invalid encoding is also rejected. */ }
  equal(valid,false);
 });
 check('foreign public key suite', () => rejects(() => sdk.mosaicKeyRef(envelope.publicKey.replace(/^po/,'pe'))));
 check('foreign signature suite', () => rejects(() => sdk.verifyEnvelopeSignature(envelope.envelopeJson,envelope.publicKey,envelope.signature.replace(/^so/,'se'),envelope.keyRef)));
 check('malformed signature', () => rejects(() => sdk.verifyEnvelopeSignature(envelope.envelopeJson,envelope.publicKey,'invalid-signature',envelope.keyRef)));
 for(const height of [-1,4294967295,4294967296,1.5]) check(`invalid height ${height}`, () => rejects(() => sdk.envelopeSigningPayload(JSON.stringify({content:{},proof:{blockHeight:height,blockHash:'0x'+'00'.repeat(32)}}))));
 for(const [name,input] of [['scalar content',{content:'pretend-digest',proof:{blockHeight:1,blockHash:'0x'+'00'.repeat(32)}}],['short block hash',{content:{},proof:{blockHeight:1,blockHash:'0x00'}}],['unknown proof field',{content:{},proof:{blockHeight:1,blockHash:'0x'+'00'.repeat(32),extra:1}}],['unknown envelope field',{...JSON.parse(envelope.envelopeJson),extra:1}]]) check(name, () => rejects(() => sdk.envelopeSigningPayload(JSON.stringify(input))));
 await checkAsync('external signer returns verified native envelope material',async () => {
  const signature=await sdk.signEnvelope(envelope.envelopeJson,envelope.publicKey,envelope.keyRef,async payload => { equal([...payload],envelope.payload); return envelope.signature; });
  equal(signature,{publicKey:envelope.publicKey,bytes:envelope.signature}); equal(Object.isFrozen(signature),true);
 });
 await checkAsync('foreign signer return rejected', () => rejectsAsync(() => sdk.signEnvelope(envelope.envelopeJson,envelope.publicKey,envelope.keyRef,() => envelope.signature.replace(/^so/,'se'))));
 await checkAsync('wrong reference prevents signer invocation',async () => {
  let called=false;
  await rejectsAsync(() => sdk.signEnvelope(envelope.envelopeJson,envelope.publicKey,envelope.wrongKeyRef,() => {called=true; return envelope.signature;})); equal(called,false);
 });
 result.textContent=JSON.stringify({complete:true,browser:navigator.userAgent,pass:checks.filter(x=>x.pass).length,fail:checks.filter(x=>!x.pass).length,checks});
} catch(error) { result.textContent=JSON.stringify({complete:true,fail:1,error:String(error),checks}); }
