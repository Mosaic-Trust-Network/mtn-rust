# IoP Rust — Agent Orientation

## For External Contributors

This repository is part of the Mosaic Trust Network workspace. The `.agents`
symlink is an internal core-team coordination bridge. If it does not resolve on
your machine, ignore it — you do not need it to contribute to this repository.

For core team agents only, follow the repo-local `.agents/AGENTS.md` entry point
(via this symlink) for full doctrine.

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

If `sober assist` is available, use it as the default first pass for agent-assisted
development suggestions. If the repository has no `.sober/` directory yet, initialize
as needed (`sober init`) or rely on local verification commands.

## Repo Boundary and `.agents` Rule

- This is the `_Dlabs/mosaic-trust-network` organizational boundary. Internal coordination lives in the parent-level private `agents/` layer.
- External contributors should use this file and repo-local docs only.
- Core-team agents may use `<repo>/.agents/AGENTS.md` when it resolves.
- If `.agents/AGENTS.md` is missing, broken, or points outside this workspace, ignore it and continue with repository-local `AGENTS.md`.
- Do not duplicate this project as a copy under another organization root unless explicitly requested.
