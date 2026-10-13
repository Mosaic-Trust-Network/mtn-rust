# Changelog

## 0.1.0 (2026-10-13)

First release of the Mosaic Trust Network Rust core, **forked from the IOP Morpheus stack
(`iop-*` 0.0.17)**. The generic ledger/SSI crates were dropped, the DID layer was rebuilt around
the `did:mosaic` method for Substrate, and the surviving crates were renamed into the
`mosaic-*` namespace. Because every crate changed name, data format or public API, the fork
starts a fresh `0.1.x` line and is not compatible with the upstream `iop-*` 0.0.x crates.

### Fork

- This repository is a fork of the IOP Morpheus stack, taken from `iop-*` 0.0.17.
- BREAKING: `keyvault` is now `mosaic-keyvault`.
- BREAKING: `vault` is now `mosaic-vault`.
- BREAKING: `sdk` is now `mosaic-sdk`.
- BREAKING: the `iop-*` crate names were dropped in favour of the `mosaic-*` prefix
  (SPEC-012 "mosaic namespace rename"). `json-digest` keeps its name.
- Project metadata moved to the workspace manifest: repository
  `https://github.com/Mosaic-Trust-Network/mtn-rust`, homepage `https://mosaic-trust.network/`.
  The project is now the Mosaic Trust Network rather than Internet of People.

### Removed

- BREAKING: removed the Hydra Ledger and legacy Morpheus/Coeus/Journal crates:
  `hydra-proto`, `hydra-sdk`, `coeus-node`, `coeus-proto`, `journal-proto`,
  `morpheus-node`, `morpheus-proto`, `morpheus-sdk`.
- BREAKING: removed the WASM and C FFI binding crates: `sdk-wasm`, `sdk-ffi`, `node-wasm`,
  `proto-wasm`, `keyvault-wasm`, `json-digest-wasm`.
- BREAKING: removed `anyhow` from the library crates; errors are now explicit `thiserror` types.
- BREAKING: removed the hand-rolled secp256k1 backend (`libsecp256k1`) in favour of `k256`.
- Removed `serde_json`'s `preserve_order` feature, which force-enabled `std` and broke the
  bare `wasm32v1-none` runtime build.

### Added

- New crate `mosaic-did-types`: core types for the `did:mosaic` DID method, usable under `no_std`.
  - `Did` identifiers derived with BLAKE3-256 and the `did:mosaic:` prefix.
  - Six rights: `Update`, `Impersonate`, `Delegate`, `Issue`, `Revoke`, `Recovery`.
  - Five W3C key purposes: authentication, assertion, key agreement, capability invocation,
    capability delegation.
  - `Authentication`, `KeyRef`, `KeyType` and `MultiSignature`/`MultiPublicKey` newtypes over
    the keyvault multicipher types.
  - `ContentId` enum (`Blake3Flat`, `Blake2bFlat`, structured SHA3/BLAKE3 JSON digests).
  - SCALE codec plus `scale-info` support for every on-chain type.
- New crate `pallet-mosaic-did`: Substrate pallet keeping materialized `DidState`:
  - Atomic `submit_did_operations` batch with per-DID, per-key nonce floors and replay protection.
  - Anti-censorship design: any account can submit operations for any DID because authorization
    is checked by the embedded signatures, not by the transaction origin.
  - Operations: `AddKey`, `RevokeKey`, `AddRight`, `RevokeRight`, `UpdateCommitment`,
    `AnnounceGoverned`, `CancelGoverned`, `ExecuteGoverned`.
  - Governed (destructive) operations use an announce/delay/execute lifecycle backed by a
    currency hold; cancelling pays the deposit to the canceller as an anti-griefing bounty.
  - Permissionless `register_before_proof` timestamp anchoring.
  - Permissionless expiry sweep for expired keys and rights.
  - Runtime benchmarks and generated, hardware-measured weights.
- Sparse Merkle Tree (SMT) batching for off-chain content with inclusion proofs.
- Versioned rights documents (`RightsDocumentV1`, `RightsDocumentSet`) and a commitment hash
  chain so off-chain rights can be anchored on-chain and verified later.
- `DidHistory` reconstruction from the event stream, plus W3C DID Core 1.0 document rendering
  (`DidState::to_did_document_at`, `DidDocument`).
- Verifier pipeline with three proof strengths (`Minimal`, `AfterProof`, `Finalized`),
  `VerifierPolicy`, `BeforeProof`/`AfterProof` validation and envelope signature checks.
- New `Ed25519Blake3` cipher suite (`'o'`) in `mosaic-keyvault`, using BLAKE3-256 key-ID
  derivation while keeping Ed25519 signing/verification compatible.
- `no_std` support for `mosaic-keyvault`, `json-digest` and `mosaic-did-types`.
- SCALE and serde support for the keyvault multicipher types.
- Workspace tooling: `rust-toolchain.toml`, `scripts/check.sh` pipeline (`format`, `propagate`,
  `fmt`, `deny`, `clippy`, `test`, `serde-test`, `nostd`), `zepter` feature propagation,
  and `cargo-deny`.
- New crate `mosaic-sdk-wasm`: a private WASM codec package with a typed TypeScript facade for
  Node and browsers.
  - DID derivation/parsing, SCALE codecs for the `did:mosaic` types, all `ContentId` variants,
    structured SHA3/BLAKE3 JSON digests, and right/key-purpose encodings.
  - Off-chain `AfterEnvelope` signature preparation/verification with signer-key binding and
    foreign-suite rejection; production WASM holds no private keys.
  - Native signing of the initial `AddKey` and `UpdateCommitment` DID operations.
  - `BeforeProof` storage-proof verification (Substrate LayoutV1/Blake2), plus header-bound and
    pinned-runtime-metadata variants.
- The workspace now tracks `Cargo.lock`, and CI builds `mosaic-sdk-wasm`, runs its Node and
  browser test gates, and scopes artifact retention.

### Changed

- BREAKING: migrated from `did:morpheus` with Blake2b to `did:mosaic` with BLAKE3-256.
- BREAKING: replaced event-log replay with materialized `DidState` storage in the pallet.
- BREAKING: the on-chain wire format is now SCALE; serde is used for off-chain documents.
- BREAKING: replaced hand-rolled `MultiSignature`/`MultiPublicKey` with keyvault newtypes and
  `Authentication`; `KeyId` was renamed to `KeyRef`.
- BREAKING: on-chain collections use `bounded-collections` so every state entry has a compile-time
  bound; `MAX_KEYS_PER_DID` and `MAX_NONCES_PER_DID` are asserted at compile time.
- BREAKING: enabling `serde` on a `no_std` crate no longer pulls in `std`; the crate's own `std`
  feature enables `serde/std` instead.
- `json-digest` now uses BLAKE3, has a structured pipeline, works under `no_std`, and canonicalizes
  floating point numbers using the ECMAScript representation.
- Workspace MSRV raised from 1.85 to 1.88 (edition stays 2024), with the toolchain pinned at 1.93.0
  and the `wasm32-unknown-unknown` / `wasm32v1-none` targets provisioned by the toolchain file.
- `mosaic-keyvault` migrated its secp256k1 arithmetic and signatures to `k256`.
- Publishing uses `cargo publish --workspace`; the Substrate pallet is `publish = false` and is consumed
  from git or a path dependency because it depends on the Mosaic `polkadot-sdk` fork.
- Upgraded the `polkadot-sdk` fork from `private-address-range-2512-2` (crate `2512.3.3`) to
  `private-address-range-2606-1` (crate `2606.0.0`). The pallet needed no source changes: the
  `frame-support`/`frame-system` APIs it uses and the `fungible::hold::Mutate` deposit flow are
  unchanged. `runtime-benchmarks`, `try-runtime` and the bare `wasm32v1-none` build all still
  compile.
- `deny.toml` now allows `RUSTSEC-2025-0055`: the upgraded fork pins `tracing-subscriber` to
  `=0.3.19`, while the advisory wants `>=0.3.20`; upstream keeps the pin because `0.3.20`
  regressed ANSI colour codes (tokio-rs/tracing#3378).
- Removed the vendored `core2` patch (`[patch.crates-io]` entry plus the `vendor/` directory);
  no crate in the workspace dependency graph needs it anymore.

## 0.0.17 (2026-02-27)

> Tagged in this repository but **never published to crates.io**; the release was
> skipped. It is the last `iop-*` release and the basis of the 0.1.0 fork.

### Added

- `SignedBytes_new` FFI binding to build a signed byte slice from a public key, content and signature.
- `SignedJson_new` FFI binding to build a signed JSON document from a public key, a JSON string and a signature.
- `SignedJson_*` FFI accessors now accept `const` pointers, and `SignedJson_validate_with_keyid` takes a
  `const` key id, so immutable signed documents can be inspected safely.

### Changed

- BREAKING: all crates upgraded from Rust edition 2021 to **edition 2024**; workspace `rust-version` is 1.85.
  `#[no_mangle]` was replaced with `#[unsafe(no_mangle)]` where required by the new edition.
- Consolidated crate metadata into the workspace: `version`, `edition`, `rust-version`, `authors`, `license`,
  `repository` and `homepage` now come from `[workspace.package]`, and dependencies are resolved through
  `[workspace.dependencies]` (and `[patch.crates-io]` for the local `iop-*` crates).
- Replaced `wasm-bindgen`'s `serde-serialize` feature with `serde-wasm-bindgen` in `iop-sdk-wasm`.
- Modernized workspace dependencies (RustCrypto hashes and ciphers, `ed25519-dalek`, `wasm-bindgen`,
  `serde`, `serde_json`, `rand`, `chrono`, `jwt-compact`, and others).
- Clippy and edition-2024 idiom cleanups across the workspace (e.g. removing redundant `to_string()` calls
  and passing `&str`/`String` references where ownership is not needed).

### Fixed

- Resolved ambiguous glob imports in `iop-sdk-wasm` where `iop-keyvault-wasm` and `json-digest-wasm` both
  exported identical `err_to_js` and `MapJsError` symbols; the keyvault versions are now imported explicitly
  and only the intended `json-digest-wasm` items are re-exported.

## 0.0.16 (2022-06-30)

### Added

- New WASM bindings:
  - `allNetworkNames()` lists all network names that are accepted as a parameter in some methods.
  - `Bip39.shortEntropy()`, `Bip39.shortPhrase()` improves compatibility with old wallets like Coinomi.
  - `wrapWithNonce()` helps adding extra entropy to a JSON document, where selective masking will be used.
  - `MorpheusPrivate.path` and `MorpheusPrivateKind.path` returns BIP32 derivation paths to allow compatibility with other wallets.
  - `MorpheusOperationSigner.signWithId()` makes it easier to sign with a key if only its identifier is known to the caller.
  - `JwtBuilder.timeToLive` property helps to override the default 5s expiration of tokens.
  - `new MorpheusSignableOperation(json)` and `new MorpheusSignedOperation(json)` mirrors `MorpheusSignableOperation.toJSON()` and
    `MorpheusSignedOperation.toJSON()`, so it is easier to build complex SSI transactions.
- Documented all WASM methods in the SDK, except those related to Coeus for now.

### Changed

- Vault freshly created from a random seed is dirty (unsaved).
- All crates are now using Rust edition 2021.

## 0.0.15 (2021-11-09)

### Fixed

- `JsSubtreePolicies` methods should not take ownership of self

### Added

- Exposed all 4 DID kinds (persona, device, group, resource) through WASM, FFI and vault file format.
- Exposed SignedJson serialization format through WASM and FFI.
- Made the native Rust SDK more usable by re-exporting symbols through it.
- Morpheus node stores transaction ID of PoE SSI operations, so it can be queried in IBeforeProofHistory.
- scripts/publish.sh helps publishing all crates in the correct order.

## 0.0.14 (2021-07-21)

### Fixed

- DID documents generated were missing the `index` property in the objects in the `keys` list.

### Changed

- Separated `sign` and `signWithKey` methods on `MorpheusOperationSigner` both in WASM and FFI

## 0.0.13 (2021-07-09)

### Added

- You can now set the vendor field (aka. smart bridge field) and set a manual fee on Hydra core transactions using the 2 new optional
  arguments TypeScript SDK HydraTxBuilder factory methods got.
- Added some missing bindings to WASM and FFI, `SecpKeyId.toAddress` being the most important one.
- Multicipher objects (`MPrivateKey`, `MPublicKey` and `MKeyId`) can be safely downcasted in Rust to secp256p1 and ed25519 cipher
  objects. Not supported in WASM and FFI yet.

### Changed

- Separated node-wasm and sdk-wasm, so hydra-core plugins can have code that does not bloat the SDK
- Merged morpheus-rust and keyvault-rust repositories as iop-rs

## 0.0.12-hotfix1 (2021-05-06)

### Added

- You can now set the vendor field (aka. smart bridge field) and set a manual fee on Hydra core transactions using the 2 new optional
  arguments TypeScript SDK HydraTxBuilder factory methods got.

## 0.0.12 (2021-03-17)

### Added

- Crate `iop-sdk` now exports important types and is generally usable as an early draft in clients. Note that it currently does not
  follow any conventions of the Dart and Typescript SDKs but exposes some internal implementation details.
- Hydra and Morpheus vault plugins are now thread-safe and thus easily usable in async environments as well.

### Changed

- BREAKING: renamed Hydra and Morpheus `vault::Plugin` function `rewind()` to `init()` for clarity. Naming changes also affect FFI
  and WASM interfaces.
- BREAKING: suffixed functions that mutate Hydra and Morpheus vaults (by generating keys into them) with `_mut`. This does not affect
  FFI and WASM though.
- updated dependencies

### Fixed

- cleaned up dependencies
- removed legacy SDK codebase

## 0.0.11 (2020-11-24)

### Added

- WASM binding for CoeusAsset::fee
- scripts/set-version.sh helps in releasing new versions

## 0.0.10 (2020-11-20)

### Added

- FFI bindings for creating Coeus transactions
- Automated build of sdk-wasm on github

## 0.0.9 (2020-11-13)

### Fixed

- Enforcing canonical Json introduced in 0.0.7 would have broken layer-1 consensus in unexpected ways.
  Fixed this regression before getting it on devnet or mainnet.

## 0.0.8 (2020-11-12)

- Rereleased, because the sdk-wasm package was released with some changes missing on npmjs.com

## 0.0.7 (2020-11-12)

### Fixed

- Implemented mostly size-based fees on Coeus transactions
- Enforce canonical Json format and limit sizes on CoeusAsset and MorpheusAsset deserialization from bytes

## 0.0.6 (2020-11-06)

We're heavily refactoring our crate structure while implementing Coeus, our decentralized naming system as our second Layer-2
component. Our end goal is to make fine-grained crates for reducing dependency footprint for integrators by separating client/server
sides and making Morpheus and Coeus optional plugins.

### Added

- Coeus: generic decentralized naming system built on top of a distributed ledger. Allows binding arbitrary data to names, allowing
  naming schemas, wallets, DIDs, devices, etc. This helps public figures and services to be more accessible and transparent. For more
  details, see the [IOP Developer Portal](https://developer.iop.technology/dns).

### Changed

- BREAKING: changed crate hierarchy
  - coeus-core: a temporary crate with proto, sdk and node parts are not separated yet
  - coeus-core-wasm: WebAssembly bindings for Coeus, sdk and node parts are not separated yet
  - hydra-proto: extracted hydra-dependent blockchain features (e.g. Morpheus and Coeus transactions) into their own crate
  - hydra-sdk: Hydra BIP32 subtree plugin for the Vault
  - morpheus-sdk-legacy: the old morpheus-sdk is now considered to be legacy code and was thus renamed
  - morpheus-sdk: Morpheus BIP32 subtree plugin for the Vault
  - sdk: IOP aggregate crate for clients (stub)
  - vault: extracted keyvault state serialization into its own crate

### Fixed

- serde structure of Morpheus transactions, parsing them will not collide with core transactions
- core transactions without an asset will not serialize an `"asset": "none"`JSON field  
- cleaned up some basic API types like BlockHeight and BlockCount
- fixed contact email in crate descriptions

## 0.0.5 (2020-09-21)

### Changed

- Extracted and released `json-digest` as separate crate

## 0.0.4 (2020-09-07)

### Added

- Create and verify JWT tokens with multicipher
- Hydra transaction builder, exposed on FFI and Wasm
  - transfer
  - vote
  - unvote
- `HydraSigner` available on Wasm
- xprv on `HydraPrivate`

## 0.0.2 (2020-07-28)

Initial release
