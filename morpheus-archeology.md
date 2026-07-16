# Morpheus Archeology: What `morpheus-proto` Covered and What's Missing

> **Commit:** `3a51ede9e76c4e15b4f5521fe2d4e78a89f931d2` — removed the entire `morpheus-proto` crate
> (and other hydraledger-related crates). This document tracks what was lost and what must
> be reimplemented in `mosaic-did-types` for the off-chain impersonation and keyvault plans.

## Cross-Reference Documents

- [off-chain-impersonation-plan.md](./off-chain-impersonation-plan.md)
- [keyvault-plan.md](./keyvault-plan.md)

---

## 1. Deleted `morpheus-proto` Structure

```
morpheus-proto/src/
├── crypto/
│   ├── mod.rs          — re-exports: hash, jwt, sign
│   ├── hash.rs         — ContentId (String alias), Content trait, hash_bytes()
│   ├── sign.rs         — Signed<T>, Signable trait, SyncMorpheusSigner, AfterProof, AfterEnvelope<T>
│   └── jwt/
│       ├── mod.rs      — re-exports, Algorithm impl bridge
│       ├── alg.rs      — JwtMultiCipher: Multicipher algorithm for jwt_compact
│       └── token.rs    — JwtBuilder, JwtParser
├── data/
│   ├── mod.rs          — re-exports + serde helpers
│   ├── auth.rs         — Authentication (KeyId / PublicKey variants, serde untagged)
│   ├── before_proof.rs — (not fully inspected, likely thin)
│   ├── claim.rs        — Claim, WitnessRequest, WitnessStatement, Constraints
│   ├── did.rs          — Did (wraps MKeyId, "did:morpheus:" prefix)
│   ├── diddoc.rs       — DidDocument (legacy KeyData/KeyRightHistory style, 2 rights)
│   ├── error.rs        — OperationError
│   ├── present.rs      — ClaimPresentation, ProvenClaim, License
│   ├── process.rs      — ProcessId (likely a type alias)
│   ├── schema.rs       — MorpheusValue (likely a JSON value wrapper)
│   └── validation.rs   — ValidationResult, ValidationStatus, ValidationIssue
├── txtype/
│   ├── mod.rs          — Operations for Morpheus transactions
│   ├── asset.rs        — Asset type definitions
│   └── ops.rs          — Operation types
└── lib.rs              — Crate root
```

## 2. Already Covered in `mosaic-did-types` (✓)

| Component | `morpheus-proto` location | `mosaic-did-types` equivalent | Notes |
|-----------|--------------------------|-------------------------------|-------|
| DID identifier | `data/did.rs` | `did.rs` — proper `Did` struct | `did:mosaic:` prefix, BLAKE3-256 derivation, SCALE + Serde |
| Authentication | `data/auth.rs` | `auth.rs` — same KeyId/PublicKey variants | Cross-variant equality preserved, SCALE added |
| DID Document state | `data/diddoc.rs` (legacy) | `document.rs` — `DidState` + `VerificationMethod` + `RightGrant` | Modern bounded-collection design |
| Rights | 2 rights (Update, Impersonation) | 6 rights (Update, Impersonate, Delegate, Issue, Revoke, Recovery) | Expanded per the plan |
| Content hashing / IDs | `crypto/hash.rs` (String alias) | `did.rs` — proper `ContentId` enum (Blake3Flat, Blake2bFlat, Structured) | 4 variants vs string |
| Signatures | delegated to `iop_keyvault` | `signature.rs` — `MultiSignature` wrapping `MSignature` | Ed25519Blake3 + secp256k1 |
| BeforeProof anchoring | `data/before_proof.rs` | `operation.rs` — `SsiOperation::BeforeProof(ContentId)` | Permissionless, anyone submits |
| W3C DID Document | not in morpheus-proto | `document.rs` — `DidState::to_did_document_at()` | New in mosaic-did-types |
| Operation batching | not in morpheus-proto | `operation.rs` — `DidOperation` + `SignedDidOperation` + `SsiOperation` | Pallet-level concept |

---

## 3. Missing — High Priority

### 3.1 `Signed<T>` Generic Envelope

**Where it was:** `morpheus-proto/src/crypto/sign.rs`
**Where it should go:** `mosaic-did-types/src/signed.rs` (new)

The plan's verifier algorithm (§7.2 Step 2) and AfterProof mechanism (§6.2) both depend
on a generic signed-envelope type. The existing `SignedDidOperation` is pallet-specific —
there is no equivalent for arbitrary off-chain payloads.

```rust
/// A generic signed envelope: content + cryptographic proof.
pub struct Signed<T> {
    content: T,
    public_key: MPublicKey,
    signature: MSignature,
    nonce: Option<Nonce264>,
}
```

JSON serialization format (matching the old morpheus-proto format):
```json
{
  "signature": {
    "publicKey": "pezFVen3X669...",
    "bytes": "sez8TKYaZiP..."
  },
  "content": { ... },
  "nonce": "optional 8-byte base64url nonce"
}
```

Key methods needed:
- `new(public_key, content, signature) -> Self`
- `validate() -> bool` — verify signature against content serialization
- `content_to_digest() -> Vec<u8>` — bytes that were signed (JSON canonical form)
- `fingerprint() -> ContentId` — SMT leaf hash for batching (§6.4)

The `Signed<T>` type is used throughout the plan:
- `Signed<AfterEnvelope<SmtContent>>` for time-bounded proofs (§6.2)
- `Signed<VC>` for minimal proofs (§6.5)
- Fingerprint computation for SMT leaf hashes (§6.4)

### 3.2 `AfterProof` and `AfterEnvelope<T>`

**Where it was:** `morpheus-proto/src/crypto/sign.rs`
**Where it should go:** `mosaic-did-types/src/proof.rs` (new)

Explicitly defined in §6.2:
```rust
pub struct AfterProof {
    pub block_height: u32,
    pub block_hash: ContentId,
}

pub struct AfterEnvelope<T> {
    pub content: T,
    pub proof: AfterProof,
}
```

The AfterProof is the cryptographic lower time-bound: the signer could not have known
`block_hash` at `block_height` before that block was produced. Therefore:
```
H_start = AfterProof.blockHeight + 1
```

The plan expects test vectors from `after-envelope-signing.json` (which was in the
deleted `morpheus-proto` directory). This golden file needs to be recovered or
reconstructed from the git history.

### 3.3 `ValidationResult` Types

**Where it was:** `morpheus-proto/src/data/validation.rs`
**Where it should go:** `mosaic-did-types/src/validation.rs` (extend existing)

The plan's verifier algorithm (§7.2) returns structured results with a `strength` field.
The deleted types:

```rust
pub enum ValidationStatus {
    Valid,        // All possible checks passed
    MaybeValid,   // Some checks skipped (e.g. no timestamps), all others passed
    Invalid,      // Any step of validation failed
}

pub enum ValidationIssueSeverity {
    Warning,
    Error,
}

pub struct ValidationIssue {
    code: u32,
    reason: String,
    severity: ValidationIssueSeverity,
}

pub struct ValidationResult {
    issues: Vec<ValidationIssue>,
}
```

The `status()` method degrades: `Valid` (empty) → `MaybeValid` (only warnings) → `Invalid` (any error).

The plan extends this with:
- A `strength` field on `ValidationResult` indicating which proof layer was verified (Minimal/AfterProof/FinalizedProof)
- A `VerifierPolicy` type (§7.3) that gates acceptable proof strengths per use case

### 3.4 `DidHistory` and Event-Stream Reconstruction Types

**Where it should go:** `mosaic-did-types/src/history.rs` (new)

The plan's §5.1 describes the complete event-stream reconstruction type. This is
**critical** — the verifier's union-semantics check (§3.7, implemented in §5.1
`has_right_at`) depends on `CommitmentResolver` and `DidHistory`.

```rust
/// The complete commitment timeline for one DID, reconstructed from events.
pub struct DidHistory {
    pub did: Did,
    pub commitments: Vec<CommitmentVersion>,
    pub keys: Vec<KeyLifecycle>,
    pub rights: Vec<RightLifecycle>,
    pub tombstoned_at: Option<u32>,
}

pub struct CommitmentVersion {
    pub sequence: u64,
    pub commitment: ContentId,
    pub published_at_height: u32,
    pub signer_key_ref: KeyRef,
}

pub struct KeyLifecycle {
    pub key_ref: KeyRef,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub purposes: Vec<KeyPurpose>,
    pub added_at_height: u32,
    pub revoked_at_height: Option<u32>,
    pub expires_at_height: Option<u32>,
}

pub struct RightLifecycle {
    pub key_ref: KeyRef,
    pub right: Right,
    pub granted_at_height: u32,
    pub expires_at_height: Option<u32>,
    pub revoked_at_height: Option<u32>,
}

/// Resolves a ContentId to the full off-chain rights document.
pub trait CommitmentResolver {
    fn resolve(&self, content_id: &ContentId) -> Option<RightsDocument>;
}
```

Key methods on `DidHistory`:
- `commitment_at(height: u32) -> Option<&CommitmentVersion>`
- `valid_keys_at(height: u32) -> Vec<&KeyLifecycle>`
- `has_right_at(key_ref, right, height, commitment_resolver) -> bool` — union semantics

The plan explicitly states `DidHistory` lives in `mosaic-did-types`, compiles under
`no_std`, and has no pallet dependency. Both the indexer and the light-client rewind
path produce `DidHistory` — it is the canonical reconstructed state type.

### 3.5 Verifier Algorithm

**Where it should go:** `mosaic-did-types/src/verifier.rs` (new)

The plan's §7.2 describes a 5-step algorithm:
1. **Classify** the proof bundle (Minimal/AfterProof/FinalizedProof), derive `H_start`/`H_end`
2. **Verify signature** over the payload (AfterEnvelope → SMT → signed content chain)
3. **Key validity** — is the key valid in `[H_start, H_end]`?
4. **Time-bounded right existence** — every commitment active in `[H_start, H_end]` must grant the right; hash chain verified
5. **DID liveness** — not tombstoned in the interval

Policy gating (§7.3) maps proof bundle types to acceptable strength per verifier context:
| Verifier context | Acceptable bundles |
|-----------------|-------------------|
| Chat app | MinimalProof |
| Business invoice | AfterProof or FinalizedProof |
| Regulatory notarization | FinalizedProof only |

This depends on items 3.1–3.4 above and on the existing `DidState`, `ContentId`, and `Did` types.

---

## 4. Missing — Medium Priority

### 4.1 `Content` / `Signable` Traits (Content-to-Sign Derivation)

**Where it was:** `morpheus-proto/src/crypto/hash.rs` and `sign.rs`
**Where it should go:** `mosaic-did-types/src/content.rs` (new) or `signed.rs`

The old traits provided consistent "what bytes get signed" semantics across all types:
```rust
pub trait Content: Serialize + Clone + Sized {
    fn content_id(&self) -> Result<ContentId> { digest_data(self) }
    fn validate_id(&self, content_id: &ContentId) -> Result<bool> { ... }
}

pub trait Signable: Content {
    fn content_to_sign(&self) -> Result<Vec<u8>> { Ok(self.content_id()?.into_bytes()) }
}
```

The plan needs this for the `fingerprint` computation in §6.4 (SMT leaf =
`digestJson(Signed<AfterEnvelope>)`).  These could go into `mosaic-did-types` (they're
`no_std`-compatible with `alloc` + `json_digest`) or stay as SDK utilities.

### 4.2 W3C DID Document Custom Mosaic Properties

**Where it should go:** `mosaic-did-types/src/document.rs` (extend existing)

The current `DidDocument` struct lacks the mosaic-specific properties described in §5.2:

**Custom mosaic properties** (registered under `https://mosaic.network/ns/did/v1`):
- `mosaic:createdAtHeight` — block at which the DID was created
- `mosaic:lastModifiedAtHeight` — block at which the most recent state change occurred
- `mosaic:tombstonedAtHeight` — block at which the DID was deactivated (null if alive)

**Service type:**
- `MosaicRightsCommitment2026` — current commitment hash, sequence, publication block, and signer

**DID Document Metadata** (resolution metadata, §5.2.2):
- `created` — ISO 8601 timestamp of first on-chain operation
- `updated` — ISO 8601 timestamp of most recent state change
- `deactivated` — boolean
- `versionId` — block height of this version
- `nextVersionId` — block height of next state change (for forward-polling)
- `equivalentId` — alternative DID identifiers (same subject)

---

## 5. Not Migrating — SDK-Level Concerns

### 5.1 JWT Builder/Parser (`crypto/jwt/`)

**Where it was:** `morpheus-proto/src/crypto/jwt/` (`alg.rs`, `token.rs`)
**Where it should go:** `iop-sdk` or a higher-level crate — NOT `mosaic-did-types`

The deleted JWT module (`JwtBuilder`, `JwtParser`, `JwtMultiCipher`) pulled in
`jwt_compact`, `chrono`, and `anyhow` — heavy `std`-only crates with real-time clock
dependencies. JWT is a transport/serialization concern, not a core type. The plan does
not mandate JWT as the wire format for Verifiable Presentations. JSON-based `Signed<T>`
envelopes with `json_digest` canonicalization serve the same purpose without external
dependencies.

### 5.2 Claim/Credential Types (`data/claim.rs`, `data/present.rs`)

**Where it was:** `morpheus-proto/src/data/claim.rs`, `data/present.rs`
**Where it should go:** `iop-sdk` or a Verifiable Credential crate

Types like `Claim`, `WitnessRequest`, `WitnessStatement`, `ClaimPresentation`,
`ProvenClaim`, and `License` are VC-layer abstractions. They depend on JSON schemas,
process definitions, and authority models that are not part of the DID document core.
The plan references them conceptually but does not define them as `mosaic-did-types`
responsibilities. The verifier in §7.2 operates on the `key_ref → right` mapping, not
on claim-specific types.

### 5.3 Transaction Types (`txtype/`)

**Where it was:** `morpheus-proto/src/txtype/` (`mod.rs`, `asset.rs`, `ops.rs`)
**Where it should go:** Already covered by `pallet-mosaic-did`'s extrinsic definitions

The old Morpheus blockchain transaction types (asset creation, operations) were
hydraledger-specific. The `DidOperation` enum in `mosaic-did-types/src/operation.rs`
and the pallet's `submit_did_operations` extrinsic replace this entirely.

---

## 6. Implementation Order

| # | Module | What | Plan § | Effort |
|---|--------|------|--------|--------|
| 1 | `validation.rs` (extend existing) | `ValidationResult`, `ValidationStatus`, `ValidationIssue`, `VerifierPolicy` | §7.2–7.3 | Small |
| 2 | `signed.rs` (new) | `Signed<T>`, `Signable` trait, JSON envelope format, `fingerprint()` | §6.2, §6.4 | Medium |
| 3 | `proof.rs` (new) | `AfterProof`, `AfterEnvelope<T>`, content-ID computation, golden vectors | §6.2 | Medium |
| 4 | `history.rs` (new) | `DidHistory`, `CommitmentVersion`, `KeyLifecycle`, `RightLifecycle`, `CommitmentResolver` trait | §5.1 | Medium |
| 5 | `history.rs` (add to #4) | `has_right_at()` with union semantics (on-chain grants + commitment fallthrough) | §3.7, §5.1 | Small |
| 6 | `verifier.rs` (new) | 5-step verifier algorithm with policy gating | §7.2–7.3 | Large |
| 7 | `document.rs` (extend) | Mosaic custom properties in W3C DID Document: `mosaic:createdAtHeight`, `mosaic:lastModifiedAtHeight`, `mosaic:tombstonedAtHeight`, `MosaicRightsCommitment2026` service, DID Document Metadata | §5.2 | Small |

Items 1–4 can be done in parallel. Item 5 depends on 4. Item 6 depends on 1–5. Item 7 is independent.

---

## 7. Recoverable Artifacts from Git History

| File | Commit^ path | Status |
|------|-------------|--------|
| `after-envelope-signing.json` | `morpheus-proto/after-envelope-signing.json` | Golden test vectors for AfterEnvelope signing. Must be recovered for test-driven implementation of `proof.rs`. |
| `morpheus-proto/README.md` | `morpheus-proto/README.md` | Documentation context for the old crate. |
| Test vectors in `crypto/sign.rs` | `morpheus-proto/src/crypto/sign.rs` (bottom `#[cfg(test)]` block) | Ed25519 signing golden vectors using RFC 8032 test keypair. |
| JWT integration tests | `morpheus-proto/src/crypto/jwt/` | Not migrating, but useful reference for SDK-level JWT implementation. |

To recover any file from before the deletion:
```bash
git show 3a51ede9e76c4e15b4f5521fe2d4e78a89f931d2^:morpheus-proto/<path>
```
