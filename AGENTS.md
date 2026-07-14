# IoP Rust — Agent Orientation

## For External Contributors

This repository is part of the Mosaic Trust Network workspace. The `.agents`
symlink is an internal core-team coordination bridge. If it does not resolve on
your machine, ignore it — you do not need it to contribute to this repository.

For core team agents only, follow the repo-local `.agents/AGENTS.md` entry point
(via this symlink) for full doctrine.

## Workspace Crates

| Crate | Path | `no_std` | Purpose |
|-------|------|----------|---------|
| `iop-keyvault` | `keyvault/` | Yes | HD key derivation (BIP-32/39/43/44). Ed25519 + secp256k1. `multicipher` types (`MPublicKey`, `MPrivateKey`, `MSignature`, `MKeyId`) abstract over cipher suites. |
| `json-digest` | `json-digest/` | No | Canonical JSON (sorted keys, NFKD normalization) with BLAKE3-256 Merkle-tree hashing and selective disclosure. Content IDs prefixed `cj`. |
| `iop-vault` | `vault/` | No | Encrypted HD wallet with plugin system. Stores BIP-39 seed, `VaultPlugin` trait objects via `typetag`. `BoundPlugin<T, TPublic, TPriv>` for type-safe access. |
| `mosaic-did-types` | `mosaic-did-types/` | Yes | `did:mosaic` types: BLAKE3-256 DID derivation, SCALE codec, 6 rights (Update, Impersonate, Delegate, Issue, Revoke, Recovery), 5 W3C key purposes, `DidState`, `DidOperation`, `SsiOperation`. |
| `pallet-mosaic-did` | `pallet-mosaic-did/` | No | Substrate pallet: materialized `StorageMap<Did, DidState>`, atomic `submit_did_operations`, anti-censorship (any account submits for any DID). Depends on `polkadot-sdk` (forked). |
| `iop-sdk` | `sdk/` | No | Unified re-export of keyvault, vault, mosaic-did-types, and json-digest. Single dependency entry point. |

### Dependency Graph

```
keyvault
├──► vault
├──► mosaic-did-types ──► pallet-mosaic-did
└──► json-digest

iop-sdk re-exports: keyvault, vault, mosaic-did-types, json-digest
```

## Verification

```bash
./scripts/check.sh              # run all checks (format, propagate, fmt, deny, clippy, test, nostd)
./scripts/check.sh clippy       # run a single step
./scripts/check.sh test nostd   # run specific steps
```

## Conventions

- **Edition 2024**, MSRV 1.88, workspace version `0.1.0`.
- `no_std`: `keyvault` and `mosaic-did-types` support it. No `std`-only deps without feature gates.
- Serde/SCALE impls are `#[cfg(feature = "...")]` — check before moving types between crates.
- Errors: `anyhow::Result` in `std` crates. Custom error types only in `no_std`.
- Testing: inline `#[cfg(test)] mod test`. `Seed::DEMO_PHRASE` for vault tests.
- Crypto: keys from `Seed` via BIP-32. SHA3-256 (json-digest), BLAKE3 (mosaic DID derivation).
- Keep cryptographic claims backed by tests and test vectors.
- Prefer small, reviewable commits with working feature-local tests.

## Sober

This repo uses Sober for repository governance. The `.sober/` directory contains
local Sober state. Run `sober status` to check repository health.

If `sober assist` is available, use it as the default first pass for agent-assisted
development suggestions. If the repository has no `.sober/` directory yet, initialize
as needed (`sober init`) or rely on local verification commands.

## Repo Boundary and `.agents` Rule

- This is the `_Dlabs/mosaic-trust-network` organizational boundary. Internal coordination lives in the parent-level private `agents/` layer.
- External contributors should use this file and repo-local docs only.
- Core-team agents may use `<repo>/.agents/AGENTS.md` when it resolves.
- If `.agents/AGENTS.md` is missing, broken, or points outside this workspace, ignore it and continue with repository-local `AGENTS.md`.
- Do not duplicate this project as a copy under another organization root unless explicitly requested.
