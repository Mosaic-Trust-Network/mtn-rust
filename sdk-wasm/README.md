# Mosaic SDK WASM codecs

Version 2.0.0 is a private codec package built from current native Rust.
It provides DID derivation/parsing and SCALE, all native ContentId variants,
structured SHA3/BLAKE3 JSON digests, and right/key-purpose SCALE encodings.
The Rust entry point is src/lib.rs; the typed facade is typescript/index.ts.
Tests and native agreement fixtures live under tests/.

## Build

Use the repository Cargo.lock and the wasm-bindgen CLI version pinned there.
Install the wasm32-unknown-unknown Rust target and restore npm dependencies
with npm ci --ignore-scripts. Run npm run build, npm run check,
npm run typecheck and npm test. Run the complete repository scripts/check.sh
pipeline before integration. Generated artifacts and node_modules are ignored.
Rust and npm publication are disabled by their manifests.

## Node

```typescript
import { mosaic } from '@mosaic-private/sdk/node';
const did = mosaic.deriveDid(publicKeyBytes);
const contentId = mosaic.digestJson('{"document":"example"}', 'blake3');
```

## Browser

```typescript
import { initializeMosaic } from '@mosaic-private/sdk/browser';
const mosaic = await initializeMosaic();
const contentId = mosaic.digestJson('{"document":"example"}', 'sha3');
```

The browser initializes WASM explicitly; callers may supply the initializer's
module input. The neutral entry exports createMosaicSdk for an initialized
binding module. Pass Uint8Array for key/hash bytes and strings for wire values.
Malformed data raises Error. Unknown algorithms and legacy ContentId text
are rejected. Native parsers determine accepted alternate encodings.

## JSON contract

The digest API takes JSON text rather than a JavaScript object. This preserves
integers before JavaScript rounding and delegates parsing/normalization to
native serde_json and json-digest. The bridge accepts composite objects and
arrays; scalar roots are rejected. SHA3 and BLAKE3 results retain their typed
cj/cm prefixes. Hashing a structured tree and hashing raw bytes are different
operations. This package accepts precomputed flat hashes; it does not claim
those hashes are structured JSON commitments.

## Compatibility

This is a breaking codec package, not the old iop-sdk-wasm binary relabelled.
Node and web builds come from the same fresh Rust release module. Existing
Morpheus identities must use their separate backend; never rename them.
Codec agreement does not establish signing, proof validation, runtime metadata,
chain inclusion or finality. These are separate integration contracts.

## Off-chain envelope signatures

Prepare an AfterEnvelope containing object/array content and a proof with
blockHeight and a 32-byte hexadecimal blockHash. The signing payload is the
UTF-8 SHA3 digest string required by the current native envelope verifier.
It is distinct from the BLAKE3 content commitment and a DID operation's SCALE
payload. Unknown envelope/proof fields and overflowing lower-bound heights
are rejected. Do not attach unsigned metadata to the envelope root.

Use mosaicPublicKey and mosaicKeyRef for native Mosaic wire identities.
keyMatchesReference checks public-key derivation only; it does not check DID
membership or key-purpose grants. verifyEnvelopeSignature also binds the
expected signer key reference and rejects foreign suites.

signEnvelope calls a supplied signer with the prepared bytes and verifies its
returned multicipher signature before exposing SignedEnvelope material.
The caller owns key custody; production WASM accepts no private keys.
No operation submission, proof inclusion or finality follows from this result.
Embedded network fields are covered by the signature, not independently
verified as chain identity.

Run npm run test:browser for the isolated local Chrome gate. It uses a temporary
profile and localhost-only static test assets, with public synthetic vectors.
The returned JSON records real browser checks separately from Node tests.

## DID operation signing

initialDidKeyOperation prepares native initial AddKey SCALE; updateCommitmentOperation
prepares a structured document commitment. Pass canonical decimal strings for
all u64 nonce/floor/sequence values, including values beyond JavaScript precision.
Only these two operations are supported by this SDK slice. No rotation or
expiry support is implied. Rejecting malformed/trailing/noncanonical SCALE
prevents the signed payload and submitted operation from disagreeing.

signDidOperation copies caller bytes, including Node Buffer, before awaiting
an external signer. Initial AddKey binds its signer to the embedded key.
Native Rust verifies the returned signature before assembling SignedDidOperation
and SsiOperation::Did SCALE. The returned typed arrays are caller-owned transport
copies. These bytes are not an account-signed extrinsic or a batch encoding.
The native payload is SCALE (operation, signer_key_ref, nonce); it contains no
genesis hash. Require pinned network/runtime checks in the submission adapter.
Cryptographic validity does not establish DID rights, nonce freshness, state
sequence, chain inclusion or finality. Production WASM holds no private keys.

# Native BeforeProof storage relation V1

`beforeProofStorageKeyV1(contentId)` derives the pinned native
`Did.BeforeProofs` key for a canonical structured commitment.
`verifyBeforeProofStorageV1({expectedStateRoot, contentId, blockHeight,
extrinsicIndex, nodes})` verifies raw RPC storage nodes using Substrate
LayoutV1/Blake2 and the exact SCALE `(u32,u32)` registration record.
Height/index are canonical decimal strings; the expected root is 32 bytes.
Malformed/oversized inputs reject; a well-formed proof for a different relation
returns false. Node order is immaterial. Raw nodes use lowercase `0x` hex.

The caller must independently authenticate the expected state root, network,
header/finality and runtime layout. A proof-supplied root is not a trust anchor.
This function does not verify a document checksum or a user signature and must
not alone promote a receipt to independently verified chain evidence. Synthetic
golden vectors qualify codec/proof parity; they are not production consensus.

### Header-bound BeforeProof and pinned runtime ABI (V1)

`mosaicHeaderScaleV1(rpcJson)` converts bounded standard RPC header JSON through
native `Header<u32, BlakeTwo256>`. `inspectMosaicHeaderV1(scale)` returns its hash,
decimal height and state root. Inspection asserts no trust or finality.
`verifyBeforeProofHeaderV1({expectedBlockHash, expectedHeaderHeight, headerScale,
contentId, blockHeight, extrinsicIndex, nodes})` binds the raw storage proof to the
exact expected native header and rejects registrations after that header's height.
Only the header's decoded state root is used; no proof-supplied substitute root.

`qualifyBeforeProofMetadataV1(expectedMetadataHash, metadataScale)` validates an
independently pinned Blake2b256 metadata hash and the exact native V14
Did.BeforeProofs key/value ABI. It does not authenticate metadata's association
with runtime code, header, genesis or consensus. Callers must authenticate those
associations and the expected block identity separately. A local simulation or
provider-reported finalized hash alone is not an independent consensus verifier.

Native bounds: header SCALE64KiB, RPC JSON128KiB,64digest logs/16KiBper log,
128KiB tracked header decoding; metadata SCALE512KiB,8MiB tracked decoding and
32levels type-graph comparison. Malformed inputs throw; valid mismatches return
false. No RPC client or dynamically trusted ABI fallback is introduced.
