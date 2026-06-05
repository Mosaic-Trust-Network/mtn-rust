# IoP Rust — Agent Orientation

## For External Contributors

This repository is part of the Mosaic Trust Network workspace. The `.agents`
symlink is an internal core-team coordination bridge. If it does not resolve on
your machine, ignore it — you do not need it to contribute to this repository.

## Tech Stack

- **Language:** Rust
- **Build tool:** Cargo
- **Workspace:** Cargo workspace with crates such as `json-digest`,
  `coeus-node`, `coeus-proto`, `hydra-sdk`, and others.

## Tools & Verification Commands

| Command | Purpose |
| --- | --- |
| `cargo test` | Run tests |
| `cargo check` | Fast compile check |
| `cargo clippy` | Lint |
| `cargo fmt --check` | Verify formatting |

## Working Conventions

- **Panopticum:** one feature, one folder, one index. Keep related code,
  tests, and docs together.
- Keep cryptographic claims backed by tests and test vectors.
- Prefer small, reviewable commits with working feature-local tests.

## Sober

This repo uses Sober for repository governance. The `.sober/` directory contains
local Sober state. Run `sober status` to check repository health.
