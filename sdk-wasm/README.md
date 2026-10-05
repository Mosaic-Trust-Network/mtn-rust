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
