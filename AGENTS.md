# IoP Rust — Agent Orientation

## Hard Rules — read and follow these on every turn

These rules survive context compaction. They apply to ALL coding agents (DeepSeek,
OpenCode BigPickle, Claude, etc.). Violating any of them wastes the user's time.

### 1. Bash commands MUST NOT start with `cd`

The `cd <path> && <command>` pattern triggers permission prompts that interrupt
your work. Use the `workdir` parameter instead — it is faster, safer, and avoids
disruption.

| WRONG (will trigger permission prompt) | CORRECT (use workdir) |
|---|---|
| `cd /home/wigy/work/mtn/iop-rs && cargo test` | `workdir="/home/wigy/work/mtn/iop-rs"`, command: `cargo test` |
| `cd /home/wigy/work/mtn/iop-rs && ./scripts/check.sh` | `workdir="/home/wigy/work/mtn/iop-rs"`, command: `./scripts/check.sh` |
| `cd $PWD && cargo fmt` | `workdir="$PWD"`, command: `cargo fmt` |

Do not write a command that starts with the characters `cd ` — not even as a
harmless prefix. Strip it entirely. The tool already positions the working
directory via `workdir`.

### 2. Verification MUST use `./scripts/check.sh`

Never run raw `cargo test`, `cargo clippy`, or `cargo fmt` directly. These skip
the project's verification pipeline.

| WRONG (skips pipeline) | CORRECT (uses project pipeline) |
|---|---|
| `cargo test -p pallet-mosaic-did` | `./scripts/check.sh test` |
| `cargo clippy --all-targets` | `./scripts/check.sh clippy` |
| `cargo fmt` | `./scripts/check.sh fmt` |
| `cargo test --workspace` | `./scripts/check.sh test` |

The full pipeline runs format, propagate, fmt, deny, clippy, test, serde-test, and `no_std`:

```bash
./scripts/check.sh              # run all steps
./scripts/check.sh clippy       # run a single step
./scripts/check.sh test nostd   # run specific steps
```

Run the full `./scripts/check.sh` before considering work done.

### 2b. Tight TDD loops: use `check.sh test:<filter>`

For rapid red-green-refactor cycles, append a test filter with `:` to avoid
running every test in the workspace:

```bash
./scripts/check.sh test:announce_governed    # run only matching tests
./scripts/check.sh test:history              # run only matching tests
```

This still builds the full workspace (consistent features, no flip-flop in
`target/`) but only executes tests matching the filter. Never use
`cargo test -p <crate>` — it resolves features differently and triggers
massive recompilation when you switch back to `./scripts/check.sh test`.

The same filter syntax works for serde-gated tests (`feature = "serde"`):

```bash
./scripts/check.sh serde-test:after_proof    # run only matching serde tests
./scripts/check.sh serde-test:finalized      # run only matching serde tests
```

### 3. Conventions below are mandatory, not advisory

All conventions in the "Conventions" section must be followed. Specifically:

- Test-driven development: write a failing test first, confirm it fails, then
  write minimum code to pass, then refactor. Never write untested production code.
- `#[cfg(test)] mod test` for test modules.
- Small, reviewable commits with working feature-local tests.

---

## For External Contributors

This repository is part of the Mosaic Trust Network workspace. The `.agents`
symlink is an internal core-team coordination bridge. If it does not resolve on
your machine, ignore it — you do not need it to contribute to this repository.

For core team agents only, follow the repo-local `.agents/AGENTS.md` entry point
(via this symlink) for full doctrine.

## Workspace Crates

| Crate | Path | `no_std` | Purpose |
|-------|------|----------|---------|
| `mosaic-keyvault` | `keyvault/` | Yes | HD key derivation (BIP-32/39/43/44). Ed25519 + secp256k1. `multicipher` types (`MPublicKey`, `MPrivateKey`, `MSignature`, `MKeyId`) abstract over cipher suites. |
| `json-digest` | `json-digest/` | No | Canonical JSON (sorted keys, NFKD normalization) with BLAKE3-256 Merkle-tree hashing and selective disclosure. Content IDs prefixed `cj`. |
| `mosaic-vault` | `vault/` | No | Encrypted HD wallet with plugin system. Stores BIP-39 seed, `VaultPlugin` trait objects via `typetag`. `BoundPlugin<T, TPublic, TPriv>` for type-safe access. |
| `mosaic-did-types` | `mosaic-did-types/` | Yes | `did:mosaic` types: BLAKE3-256 DID derivation, SCALE codec, 6 rights (Update, Impersonate, Delegate, Issue, Revoke, Recovery), 5 W3C key purposes, `DidState`, `DidOperation`, `SsiOperation`. |
| `pallet-mosaic-did` | `pallet-mosaic-did/` | No | Substrate pallet: materialized `StorageMap<Did, DidState>`, atomic `submit_did_operations`, anti-censorship (any account submits for any DID). Depends on `polkadot-sdk` (forked). |
| `mosaic-sdk` | `sdk/` | No | Unified re-export of keyvault, vault, mosaic-did-types, and json-digest. Single dependency entry point. |

### Dependency Graph

```
keyvault
├──► vault
├──► mosaic-did-types ──► pallet-mosaic-did
└──► json-digest

mosaic-sdk re-exports: keyvault, vault, mosaic-did-types, json-digest
```

## Conventions

- **Edition 2024**, MSRV 1.88, workspace version `0.1.0`.
- `no_std`: `keyvault` and `mosaic-did-types` support it. No `std`-only deps without feature gates.
- **Serde in `no_std` crates**: enabling `serde` on a dependency must NOT transitively pull in `std`. The `serde` feature MUST NOT enable `serde/std`; the crate's own `std` feature should enable `serde/std` instead. Verify with `cargo tree -e features -i <crate> --target wasm32-unknown-unknown --no-default-features`.
- Serde/SCALE impls are `#[cfg(feature = "...")]` in most crates. In `mosaic-did-types` serde is unconditional (`serde` and `serde_json` are required deps) — check before moving types.
- Errors: `anyhow::Result` in `std` crates. Custom error types only in `no_std`.
- Crypto: keys from `Seed` via BIP-32. SHA3-256 (json-digest), BLAKE3 (mosaic DID derivation).
- Keep cryptographic claims backed by tests and test vectors.

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
