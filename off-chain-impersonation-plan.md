# Off-Chain Impersonation Plan

> **Status:** Architectural design — not yet implemented.
> **Scope:** Pallet, indexer, and verifier responsibilities for rights that are never enforced on-chain.

## 1. Problem Statement

Six rights exist in the `did:mosaic` model (`Update`, `Impersonate`, `Delegate`,
`Issue`, `Revoke`, `Recovery`). Of these, only two—`Update` and `Delegate`—are
validated on-chain (the pallet checks them before allowing state mutations). The
other four serve primarily off-chain use cases: a holder presents a Verifiable
Credential or Presentation and the verifier checks whether the signing key had
the asserted right at the time the claim was made.

**Not all off-chain rights are about efficiency.** Some use cases require a
right to be publicly visible on-chain — regulatory compliance, high-value
credentials where verifiers refuse to trust a hash, or scenarios where the
verifier is a smart contract that can read chain state but cannot resolve
off-chain documents. The plan must accommodate both paths.

The `rights: BoundedVec<RightGrant, 64>` in `DidState` is currently the only
mechanism. It forces every right grant — even purely off-chain ones — to
consume a bounded storage slot. The commitment model (§2) adds a second
mechanism. The two coexist via **union semantics:** a right is valid if it
appears in either the on-chain state or the current commitment document.

## 2. Design: Commitments, Not Enumeration

Instead of storing individual right grants for off-chain rights, the DID controller
publishes a **commitment to an off-chain rights document**. Only the latest
commitment hash and a monotonic sequence number live on-chain. The full document
(which maps keyRefs to rights) stays off-chain and is carried by presenters
in Verifiable Presentations — it is never published publicly.

### 2.1 The on-chain footprint

Two new fields in `DidState` (an addition, not a breaking change — the
`rights` vector remains at its current bound; DIDs that use the commitment
path will have fewer entries, DIDs that prefer on-chain visibility keep the
full budget):

```rust
pub struct DidState {
    // ... (existing fields: did, keys, rights, tombstoned_at_height, nonces)

    /// Latest rights-document commitment published by the DID controller.
    /// `None` means no commitment has ever been published.
    pub commitment: Option<(u64, ContentId)>,
    //                     ^^^^  ^^^^^^^^^
    //                   sequence  blake3(structured(rights-document))

    /// Block height and extrinsic index of the most recent state change.
    /// Used by the rewind algorithm to check whether the current state
    /// covers a given target height, and as the entry point for walking
    /// backwards through the event stream.
    pub last_modified_at: (u32, u32),
}
```

`previous_version_id` is **not** stored in `DidState`. It lives in events
only (see §2.1.2). The reason: if multiple transactions in the same block
modify the same DID, each transaction writes its own `previous_version_id`
to storage — but only the last write survives. The intermediate pointers
are lost. Events don't have this problem: each event is individually
preserved in the block body and carries its own pointer independently.

**Why store both sequence and hash?** Only the sequence is needed for
consensus — the pallet enforces `new_sequence > stored_sequence` to prevent
replay. The commitment hash is not read during validation. It is stored so
that the chain is **self-contained for resolution:** any full node can return
the current commitment hash from `DidStates::get(did)` without replaying
events. The `CommitmentUpdated` event still carries the full envelope for
indexers to build the historical timeline, but the current state is always
one storage read away. This also enables light-client verification — a
Merkle proof into `DidStates` proves the commitment hash without trusting
an indexer.

For the 32 bytes of fixed overhead per DID, the benefit of self-contained
resolution outweighs the storage cost.

#### 2.1.1 The backwards-linked version list — rewinding without an indexer

For long-living DIDs with frequent key rotations and commitment updates,
a client needs DID state at an arbitrary past block height. Querying
`DidStates` gives the *current* state, not the historical state. The
traditional answer is "run an indexer." But with two small additions,
the chain itself provides a rewinding path.

**The mechanism:** Every state-changing operation (AddKey, RevokeKey,
UpdateCommitment, TombstoneDid) updates `last_modified_at` in `DidState`
to the current `(block_height, extrinsic_index)`. The event emitted by
each operation carries a `previous_version_id` field pointing to the
`last_modified_at` value that was in `DidState` *before* the operation
was applied. This forms a backwards-linked list through the event stream
— each event knows which event preceded it.

The `CommitmentUpdated` (and `KeyAdded`, `KeyRevoked`, etc.) events also
carry `previous_version_id` so that indexer-oblivious clients can follow
the chain.

**The rewind algorithm** (no indexer needed):

```
rewind_to_height(did, target_height):
    state = DidStates::get(did)                    // O(1) read
    if target_height >= state.last_modified_at.0:
        return state                                // current state covers the target

    // Walk backwards through the event stream.
    (h, tx) = state.last_modified_at                // start from current version
    loop:
        events  = get_events_at(h, tx)              // query block h, extrinsic tx
        prior   = apply_events(events)              // reconstruct state at (h, tx)
        next    = events.previous_version_id        // pointer in the event, not storage

        if next is None:
            return prior                            // reached genesis
        if target_height >= next.0:
            return prior                            // covers the target height

        (h, tx) = next                              // continue walking back
```

**Cost:** O(k) where k is the number of state changes between the target
height and now. For a DID updated every ~100 blocks, rewinding 10,000
blocks is ~100 queries — easily done in a client. For a DID updated every
block, 10,000 blocks means 10,000 queries — an indexer is the right tool.

**What this enables:**

| Client type | How it gets historical DID state |
|-------------|----------------------------------|
| Full node with indexer | `DidHistory::commitment_at(height)` — O(log n) |
| Full node, no indexer | Rewind algorithm above — O(k) backwards walk |
| Smoldot light client | Requests `DidStates::get(did)` with a storage proof against the current header's `state_root`. From the proven `DidState`, reads `last_modified_at` to find the current version's location, then queries the block body at that extrinsic to read the event (and its `previous_version_id`). Smoldot already has the block body (consensus-trusted) — the events within it explain what changed and where to go next. Walks backwards through the event pointer chain without trusting any full node. |

> **Intra-block gap:** If multiple transactions in the same block modify the same DID, `previous_version_id` points to the state before the last modification. Intermediate states between transactions within the same block are recoverable from the events in the block body, which smoldot already trusts from consensus. The pointer chain is a navigation aid — the block body is the authoritative record.

> **Production note:** Reconstruction at each version pointer requires replaying the events from that point. The indexer path (§4) materializes the full `DidHistory` once rather than walking backwards on every query.

**Storage cost:** `last_modified_at` adds 8 bytes per DID. No separate
storage map needed — it's a field on the existing `DidState` struct.
`previous_version_id` is carried in events only, not in storage.

#### 2.1.2 What each event must additionally carry

Every state-changing event carries a `previous_version_id` field. This
forms the backwards-linked list through the event stream — it is not
stored in `DidState` (see §2.1 for why):

```
KeyAdded        { ..., previous_version_id: Option<(u32, u32)> }
KeyRevoked      { ..., previous_version_id: Option<(u32, u32)> }
RightAdded      { ..., previous_version_id: Option<(u32, u32)> }
RightRevoked    { ..., previous_version_id: Option<(u32, u32)> }
CommitmentUpdated { ..., previous_version_id: Option<(u32, u32)> }
DidTombstoned   { ..., previous_version_id: Option<(u32, u32)> }
```

The `previous_version_id` is the value of `last_modified_at` *before* this
operation was applied. For the `AddKey` that creates the DID (the first
operation), `previous_version_id` is `None`.

An indexer processes these events to build `DidHistory` and can ignore the
pointer (it has the full history from the event stream). A client without an
indexer follows the pointer chain backwards to reach any past version.

### 2.2 The `UpdateCommitment` operation and event

```rust
enum DidOperation {
    // … (existing variants)

    /// Publish a new rights-document commitment.
    ///
    /// Requires Right::Update. The `sequence` MUST be strictly greater than
    /// the stored sequence (monotonic, prevents replay of older commitments).
    UpdateCommitment {
        did: Did,
        commitment: ContentId,
        sequence: u64,
    },
}
```

Emitted event (carries `previous_version_id` as described in §2.1.2):

```rust
CommitmentUpdated {
    did: Did,
    commitment: ContentId,
    sequence: u64,
    signer_key_ref: Vec<u8>,
    block_height: BlockNumberFor<T>,
    previous_version_id: Option<(u32, u32)>,
}
```

### 2.3 On-chain validation of `UpdateCommitment`

Existing validation patterns apply directly:

1. **DID must exist** (`DidStates::get`) and not be tombstoned.
2. **Signer MUST hold `Right::Update`** at the current block height.
3. **Nonce check** — `signed_op.nonce > stored_nonce`.
4. **Signature verification** against the signer's public key in `DidState.keys`.
5. **Sequence MUST be > `stored_sequence`** (gaps allowed; monotonicity is sufficient).

Each `UpdateCommitment` is a **full replacement** of the rights document, not
a delta. A new commitment implicitly revokes all rights from the previous one.
To keep a right, the DID controller must include it in the new document. The
pallet does not validate the commitment content — it only enforces the sequence
monotonicity and the signer's Update right.

### 2.4 The off-chain rights document

Defined by the SDK / indexer, not the pallet. This is a JSON structure that
canonicalises to a `json_digest::JsonDigest`:

```jsonc
{
  "$schema": "https://mosaic.network/ns/did-rights/v1",
  "did": "did:mosaic:iozABC...",
  "sequence": 3,
  "previousCommitment": "cmXXXX...",   // content-ID of sequence-2 document
  "rights": [
    { "keyRef": "key-update-1",  "rights": ["update", "delegate"] },
    { "keyRef": "key-impersonate-1", "rights": ["impersonate"] },
    { "keyRef": "key-issuer-1",  "rights": ["issue", "revoke"] }
  ]
}
```

- **`sequence`** — matches the on-chain sequence; the pallet enforces
  monotonicity.
- **`previousCommitment`** — hash-chains to the prior document. Makes omission
  cryptographically detectable: if a presenter shows sequence 1 as the immediate
  predecessor of their sequence-3 document, the verifier detects the gap because
  `blake3_struct(D1) ≠ D3.previousCommitment`. The verifier demands the
  intermediate document to close the chain.
- **`rights`** — maps key references to the set of rights that key holds.
  Update/Delegate are not duplicated here; verifiers check those against
  on-chain state per the union model (§2.6).

Canonicalization: `json_digest` (NFKD-normalized, sorted keys, BLAKE3-256
Merkle tree). Produces a `ContentId::Structured(JsonDigest::Blake3(hash))`:

```
blake3_struct(rights_document) → ContentId::Structured(JsonDigest::Blake3(hash))
→ displayed as "cmXXXX..."
```

The `cm` prefix distinguishes BLAKE3-structured content IDs from flat-hash
variants (`cb` for Blake3Flat, `cj` for SHA3-structured).

#### Selective disclosure within the commitment document

Because `json_digest` produces a Merkle tree (not a flat hash), the update
key holder can reveal only specific entries to specific key holders. An
impersonation key holder receives:

```json
{
  "keyRef": "key-impersonate-1",
  "rights": ["impersonate"]
}
```

…along with a Merkle inclusion proof against the on-chain commitment root.
The verifier checks `verify_merkle_proof(entry, root)` without learning
about other key holders or their rights. Different key holders never learn
about each other from the commitment document. Only the update key holder
has the full document.

### 2.5 Why the hash chain (`previousCommitment`) matters

The rights documents are **private** — held in wallets, revealed only in
Verifiable Presentations. The indexer cannot resolve them from content IDs.
The `previousCommitment` hash chain is a **presenter-to-verifier** guarantee:
it prevents the presenter from selectively omitting commitment versions when
proving a right to a verifier.

Without it, a presenter who wants to prove a right existed during `[H_start,
H_end]` could show only the documents where the right was granted and hide
an intermediate version that revoked it. The hash chain closes this gap:

```
D1: { sequence: 1, previousCommitment: null, rights: {key: impersonate} }
    → cmAAAA

D2: { sequence: 2, previousCommitment: "cmAAAA", rights: {} }   // revoked privately
    → cmBBBB

D3: { sequence: 3, previousCommitment: "cmBBBB", rights: {key: impersonate} }
    → cmCCCC  (anchored on-chain)
```

If the presenter provides only D1 and D3 (hiding the revocation in D2):
`blake3_struct(D1) = "cmAAAA" ≠ D3.previousCommitment = "cmBBBB"` → **gap
detected.** The verifier demands D2. D2 reveals the revocation.

**The indexer only records which sequences were anchored on-chain and at
which blocks.** It does not verify the hash chain — it cannot, because
the documents are private. The hash chain is for the verifier to enforce
completeness when the presenter provides documents.

Note: if sequence gaps are permitted on-chain (e.g., anchoring only
sequences 1 and 5 — see §10 question 4), the indexer records a sparse
timeline. The verifier fills the gap by demanding intermediate documents
from the presenter. The hash chain proves the gap is bridged correctly.

### 2.6 Union semantics — the commitment and on-chain rights coexist

The commitment document does **not** replace on-chain right grants — it
supplements them. The two paths have union semantics: a right is valid if
it exists in **either** the on-chain `RightGrant` vector or the current
commitment document.

```
has_right(did, key_ref, right, height):
    │
    ├─ Check 1: on-chain RightGrant (always authoritative)
    │   Does DidState.rights contain an active grant for (key_ref, right)?
    │   → return true
    │
    ├─ Check 2: commitment document (off-chain path)
    │   Does DidState.commitment exist?
    │   Does resolve(doc).rights contain (key_ref, right)?
    │   → return true
    │
    ├─ Check 3: implicit initial-key rights
    │   Is key_ref the first key AND right ∈ {Update, Impersonate, Delegate}?
    │   → return true
    │
    └─ false
```

**No conflict resolution is needed.** The two paths are additive — they
cannot produce contradictory results because both only *grant* rights,
never deny them. A DID controller who wants a right to be
publicly ascertainable without off-chain resolution publishes it on-chain
via `AddRight`. A controller who prioritizes storage efficiency publishes
it in the commitment document. A controller who wants both (redundant
but harmless) does both.

**What the DID controller chooses per right:**

| Right | Default path | Can also be on-chain? | Typical rationale |
|-------|-------------|:----------------------:|-------------------|
| Update | On-chain | Mandatory | Consensus requirement — pallet checks it |
| Delegate | On-chain | Mandatory | Consensus requirement |
| Impersonate | Commitment | Yes | Off-chain by default; on-chain for regulatory visibility |
| Issue | Commitment | Yes | Same |
| Revoke | Commitment | Yes | Same |
| Recovery | Commitment | Yes (Phase 2) | Same |

**Pallet responsibilities:**
- `RightGrant` struct carries any of the six rights — no restrictions
- `AddRight` / `RevokeRight` operations work for all six rights
- `MAX_RIGHTS_PER_DID = 64` — the same bound applies regardless of
  whether the commitment path is used
- `has_right_at` method — the pallet's version on `DidState` checks
  on-chain grants + implicit rights only; the verifier's version on
  `DidHistory` adds the commitment fallthrough via `CommitmentResolver`

---

## 3. Pallet Responsibilities — What Changes

### 3.1 State mutations

The pallet validates only `Update` and `Delegate` — this is a consensus
requirement and does not change. All six rights can be stored on-chain
via `AddRight`; all six can be revoked via `RevokeRight`. The commitment
document provides a second, off-chain path for the four rights that are
not consensus-critical.

| Right | On-chain validated? | Storable on-chain? | Commitment path? | Notes |
|-------|:-------------------:|:-------------------:|:----------------:|-------|
| `Update` | Yes — AddKey, RevokeKey, TombstoneDid, UpdateCommitment | Yes (mandatory) | No | Consensus requirement |
| `Delegate` | Yes — AddRight, RevokeRight | Yes (mandatory) | No | Consensus requirement |
| `Impersonate` | No | Yes (optional) | Yes | Controller chooses; union semantics |
| `Issue` | No | Yes (optional) | Yes | Same |
| `Revoke` | No | Yes (optional) | Yes | Same |
| `Recovery` | No | Yes (optional, Phase 2) | Yes (Phase 2) | Same |

**The `rights` bounded vector retains its current bound** (`MAX_RIGHTS_PER_DID = 64`).
DIDs that use the commitment document for off-chain rights will have few
entries (only Update/Delegate grants, typically 1–4). DIDs that need
on-chain visibility for all rights can still use the full budget. The
bound was never the problem — the problem was forcing all rights to go
through it.

### 3.2 Pruning revoked entries from bounded vectors

Both `DidState.keys` (bounded at 32) and `DidState.rights` (bounded at 64)
currently retain revoked entries indefinitely via soft flags
(`revoked_at_height`). This means a DID that rotates through 32 keys is
permanently bricked — no more keys can be added, even if only 1 is active.

Since the `previous_version_id` event chain (§2.1.1) enables historical
reconstruction and the indexer materializes full lifecycle from events,
revoked entries serve no consensus purpose. The plan removes them from
the vectors on revocation:

- **`RevokeKey`** removes the entry from `DidState.keys` entirely.
  `MAX_KEYS_PER_DID = 32` applies to *active* keys only.
- **`RevokeRight`** removes the entry from `DidState.rights` entirely.
  `MAX_RIGHTS_PER_DID = 64` applies to *active* right grants only.

Expired entries (where `expires_at_height` has passed) are cleaned up
lazily: when any state-changing operation arrives for a DID, the pallet
first sweeps that DID's `keys` and `rights` vectors, removing entries
where `expires_at_height ≤ current_height` and the entry is not already
explicitly revoked. The cleanup cost is bounded by the vector sizes
(32 keys + 64 rights = at most 96 iterations) — negligible per
operation. The operation's fee covers the cleanup.

**Ordering is critical:** cleanup must happen *before* validation. The
signer's own key or right grant could have expired at the current block
height. The pallet flow for every state-changing operation is:

```
1. load DidState
2. sweep expired keys + expired right grants  ← must be first
3. validate rights, nonce, signature           ← against clean state
4. apply the operation
5. emit events for removed entries + the new operation
```

A key that expires is treated identically to a revoked key: it is removed
from the vector and a synthetic `KeyRevoked` event is emitted so the
indexer records the expiration. Same for expired right grants: a synthetic
`RightRevoked` event is emitted.

**Implicit-rights edge case:** if the initial key (which holds implicit
Update, Impersonate, Delegate) expires, it is cleaned up. The DID then has
no key with implicit rights. Unless another key has an explicit on-chain
grant for Update, the DID becomes undeadendable — no further operations can
be submitted. This is correct: expiration means the key is gone. The
controller should delegate Update to another key before the initial key
expires.

This is consistent with the event-driven architecture: the `KeyRevoked`
and `RightRevoked` events carry the full entry payload for indexer
reconstruction. Verifiers needing historical key state use the
`previous_version_id` chain or an indexer.

### 3.3 Signature verification

The pallet verifies signatures for on-chain operations using the
public key stored in `VerificationMethod.public_key`. The commitment
model does not affect how on-chain operations are authenticated.

### 3.3 Public key revelation

The `AddKey` operation requires `Authentication::PublicKey`.
Allowing registration by `KeyId` with deferred public-key revelation is
a separate architectural concern (keys vs. rights). The commitment model
is orthogonal — it covers *rights*, not *keys*. Key validity is always
checked against `DidState.keys` regardless of how the public key arrived
there.

### 3.4 Tombstoning interaction

After tombstoning, the `commitment` field is frozen (no more
`UpdateCommitment` operations are accepted). A verifier evaluating a
pre-tombstone claim uses the commitment that was active at that height
(queried from an indexer). The tombstoned DID's last commitment remains
permanently queryable from on-chain state.

### 3.5 The zero-transaction DID

A `did:mosaic` identifier is derived from the public key: `did:mosaic:iozABC...`
where `iozABC... = MKeyId(Ed25519Blake3(blake3(pk)))`. This identifier exists
**before** any on-chain transaction. The DID is valid and offline-verifiable
from the moment the keypair is generated, without a single block being produced.

The *genesis state* of any DID is:

| Field | Value |
|-------|-------|
| `keys` | One implicit entry: `key_ref = iozABC...`, `key_type = Ed25519`, `public_key = <the pk>` |
| `rights` | Empty (no on-chain grants) |
| `commitment` | `None` |
| Rights held by the default key | Update, Impersonate, Delegate (implicit, per `has_right_at` check 3) |
| `last_modified_at` | `(0, 0)` — genesis, no on-chain operation |
| `tombstoned_at_height` | `None` |

This means:

- **A verifier can check claims against a DID that has never been registered
  on-chain.** The public key is extractable from the DID URI itself (the
  `MKeyId` component is `blake3(pk)` for Ed25519Blake3 keys — the `ioz` prefix
  identifies the cipher suite, and the payload is the 32-byte Blake3 hash of
  the 32-byte public key). For this limited case the key ID IS the public key
  hash, so the verifier can verify signatures without chain access.
- **The initial `AddKey` is a registration,** not a creation. It makes the
  chain aware of the DID so that subsequent operations (adding keys, granting
  delegate rights, publishing commitments) can be validated. But verifiers
  don't need it.
- **The `previous_version_id == None` case in the rewind algorithm** (§2.1.1)
  means "the pointer chain reaches genesis" — the zero-transaction state
  described here.

In the verifier algorithm (§6.2), Step 3 (key validity check) queries
`DidState.keys`. When `DidStates::get(did)` returns `None` (DID never
registered), the verifier falls back to the genesis state: the key embedded
in the DID URI is valid from genesis (height 0), with the three implicit
rights.

---

## 4. Indexer: The `DidHistory` Type

The `DidHistory` type is the authoritative Rust data structure for
reconstructing DID state from the event stream. It lives in
`mosaic-did-types` — all fields use concrete types from that crate (`Did`,
`KeyRef`, `u32` for heights), so it compiles under `no_std` with no pallet
dependency.

**The indexer consumes SCALE-encoded chain events and delegates to
`DidHistory`.** The chain RPC emits events as SCALE-encoded bytes (the
Substrate wire format). The indexer decodes these into the Rust event types
defined by the pallet, then calls methods on `DidHistory` instances to
apply each event and answer queries. `DidHistory` itself is a pure data
type — it has no knowledge of SCALE encoding, Substrate RPCs, or block
subscriptions.

Other language implementations (TypeScript, etc.) must produce identical
DID documents from the same event stream. The canonicalization rules
(sorted keys, NFKD normalization, Merkle tree structure) are defined by
`json_digest` and are language-independent. The types defined here are the
cross-language contract.

### 4.1 Event stream → History

The pallet emits the following SCALE-encoded events. The indexer decodes
them and delegates to the corresponding `DidHistory` builder methods:

```
CommitmentUpdated { did, commitment, sequence, signer_key_ref,
                    block_height, previous_version_id }
KeyAdded          { did, key_ref, key_type, public_key, purposes,
                    block_height, previous_version_id }
KeyRevoked        { did, key_ref, block_height, previous_version_id }
RightAdded        { did, key_ref, right, block_height, previous_version_id }
RightRevoked      { did, key_ref, right, block_height, previous_version_id }
DidTombstoned     { did, block_height, previous_version_id }
```

From this stream, the indexer builds:

> **Note on pruning:** The pallet removes revoked entries from `DidState.keys`
> and `DidState.rights` to keep the bounded vectors unblocked (§3.2). The
> indexer retains the full lifecycle — `DidHistory.keys` includes every key
> ever added, with `revoked_at_height` and `expires_at_height` set from the
> corresponding events. Historical DID state is reconstructed from
> `DidHistory`, not from the pallet's current storage.

```rust
/// The complete commitment timeline for one DID, reconstructed from events.
#[derive(Clone, Debug)]
pub struct DidHistory {
    pub did: Did,
    /// Ordered commitment versions (oldest first).
    pub commitments: Vec<CommitmentVersion>,
    /// All keys ever added to this DID, with their lifecycle events.
    pub keys: Vec<KeyLifecycle>,
    /// The tombstone block, if any.
    pub tombstoned_at: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct CommitmentVersion {
    pub sequence: u64,
    pub commitment: ContentId,
    pub published_at_height: u32,
    pub signer_key_ref: KeyRef,
}

#[derive(Clone, Debug)]
pub struct KeyLifecycle {
    pub key_ref: KeyRef,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub purposes: Vec<KeyPurpose>,
    pub added_at_height: u32,
    pub revoked_at_height: Option<u32>,
    pub expires_at_height: Option<u32>,
}

impl DidHistory {
    /// Find the commitment active at a given block height.
    ///
    /// Returns the latest commitment published at or before `height`.
    pub fn commitment_at(&self, height: u32) -> Option<&CommitmentVersion> {
        self.commitments
            .iter()
            .rev()
            .find(|cv| cv.published_at_height <= height)
    }

    /// Return all keys valid at a given height.
    pub fn valid_keys_at(&self, height: u32) -> Vec<&KeyLifecycle> {
        self.keys.iter().filter(|k| {
            height >= k.added_at_height
                && k.revoked_at_height.map_or(true, |h| height < h)
                && k.expires_at_height.map_or(true, |h| height < h)
        }).collect()
    }

    /// Check whether a key held a specific right at `height`.
    ///
    /// Union semantics: checks on-chain `RightGrant` entries first, then
    /// falls through to the commitment document. For Update/Delegate, the
    /// on-chain check is authoritative; off-chain rights may be in either
    /// place (or both).
    pub fn has_right_at(
        &self,
        key_ref: &KeyRef,
        right: Right,
        height: u32,
        commitment_resolver: &dyn CommitmentResolver,
    ) -> bool {
        // Check 1: on-chain RightGrant (any right type)
        if self.rights.iter().any(|rg| {
            rg.key_ref == *key_ref
                && rg.right == right
                && rg.is_active_at(height)
        }) {
            return true;
        }

        // Check 2: commitment document (off-chain path)
        if let Some(cv) = self.commitment_at(height) {
            if let Some(doc) = commitment_resolver.resolve(&cv.commitment) {
                if doc.rights.iter().any(|entry| {
                    entry.key_ref == *key_ref && entry.rights.contains(&right)
                }) {
                    return true;
                }
            }
        }

        false
    }
}

/// Resolves a ContentId to the full off-chain rights document.
///
/// In practice, the presenter provides the document (or Merkle-proof
/// subset) in the Verifiable Presentation. The verifier checks the
/// hash/Merkle proof against the on-chain commitment root. No external
/// resolver is needed for the private case. The trait exists for
/// testing and for the rare case where a DID controller intentionally
/// publishes the rights document publicly.
pub trait CommitmentResolver {
    fn resolve(&self, content_id: &ContentId) -> Option<RightsDocument>;
}
```

### 4.2 W3C DID Document generation

The indexer's `DidHistory` can produce a fully W3C-compliant DID Document at
any block height. This replaces the current `DidState::to_did_document_at()` for
off-chain rendering — the on-chain method still exists for RPC queries, but
indexers produce richer documents with commitment metadata and lifecycle
timestamps.

#### 4.2.1 Versioned resolution

W3C DID Core §3.2.1 defines two standard query parameters for time-travel
resolution:

| Parameter | Example | Resolves to |
|-----------|---------|-------------|
| `versionId` | `?versionId=5500` | DID document as it existed at block 5500 |
| `versionTime` | `?versionTime=2026-07-15T12:00:00Z` | DID document valid at that wall-clock time |

The `did:mosaic` method specification maps `versionId` to block height
directly and `versionTime` to the block whose timestamp most closely precedes
the requested time. Both are resolved by the indexer's `commitment_at(height)`
and `valid_keys_at(height)` methods.

```
did:mosaic:iozABC...?versionId=5500
                        │
                        ▼
              indexer reconstructs state at block 5500
              → active keys + active commitment + lifecycle metadata
              → W3C DID Document (JSON)
```

#### 4.2.2 DID Document Metadata

W3C DID Core §7.1.3 defines resolution metadata returned alongside the
document. The indexer populates this from `DidHistory`:

```json
{
  "didDocument": { /* the DID document — see §4.2.4 */ },
  "didDocumentMetadata": {
    "created": "2026-01-15T10:00:00Z",
    "updated": "2026-07-14T16:30:00Z",
    "deactivated": false,
    "versionId": "5500",
    "nextVersionId": "5501",
    "equivalentId": ["did:mosaic:iozABC..."]
  },
  "didResolutionMetadata": {
    "contentType": "application/did+json",
    "retrieved": "2026-07-15T12:00:01Z"
  }
}
```

The `updated` timestamp reflects the most recent state-changing operation
(AddKey, RevokeKey, UpdateCommitment, TombstoneDid). The `nextVersionId`
points to the block where the *next* state change occurred — verifiers can
poll forward to detect revocations without scanning every block.

#### 4.2.3 Offline verification model

A verifier who has obtained a DID document at `?versionId=H_end` can perform
the entire verification algorithm offline:

1. **DID document is self-contained** — it contains all active keys and the
   commitment hash at that height.
2. **Signature check** — the verifier has the public key from
   `verificationMethod`, the message, and the signature. No chain access needed.
3. **Commitment check** — `blake3_struct(rightsDocument) == commitment.contentId`.
   If the presenter provides the rights document, the check is purely local.
4. **Key validity** — `addedAtHeight ≤ H_start` and `revokedAtHeight > H_end`
   can be checked against metadata embedded in the DID document (see §4.2.4
   for custom mosaic properties).
5. **Time-bound check** — the `versionId` in the DID URL or resolution metadata
   cryptographically binds the document to a block height. The verifier trusts
   the resolver (or verifies the DID document hash against a trusted chain state
   root, if available).

#### 4.2.4 Full W3C DID Document example

(The `alsoKnownAs` field shown below is optional — it is only included when
the controller intentionally publishes the rights document publicly. For
private documents, this field is omitted.)

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://mosaic.network/ns/did/v1"
  ],
  "id": "did:mosaic:iozA3AqW1GfPxgbgoJr1TTPFF1zFZC775C2UPvutHfaxQGPb",

  "alsoKnownAs": [
    "ipfs://cm1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T"
  ],

  "verificationMethod": [{
    "id": "did:mosaic:iozA3Aq...#ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:mosaic:iozA3Aq...",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }, {
    "id": "did:mosaic:iozA3Aq...#iozXyZ9AbC3DfG7HjK2MnP5QrSt8UvW1Yz4BcE6FgH9Jk",
    "type": "EcdsaSecp256k1VerificationKey2019",
    "controller": "did:mosaic:iozA3Aq...",
    "publicKeyMultibase": "zQ3shP2mWsZosg7CeiBKAcTkUhfLqXwD9VnRyF5JtHpaMGb"
  }],

  "authentication": [
    "#ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH"
  ],
  "assertionMethod": [
    "#ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH"
  ],
  "capabilityInvocation": [
    "#iozXyZ9AbC3DfG7HjK2MnP5QrSt8UvW1Yz4BcE6FgH9Jk"
  ],

  "service": [{
    "id": "did:mosaic:iozA3Aq...#rights-commitment",
    "type": "MosaicRightsCommitment2026",
    "serviceEndpoint": {
      "contentId": "cm1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T",
      "sequence": 3,
      "publishedAtHeight": 4200,
      "publishedBy": "#ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH"
    }
  }],

  "mosaic:createdAtHeight": 4000,
  "mosaic:lastModifiedAtHeight": 4200,
  "mosaic:tombstonedAtHeight": null
}
```

**Breakdown of the custom mosaic extensions** (registered under
`https://mosaic.network/ns/did/v1`):

| Property | W3C category | Purpose |
|----------|-------------|---------|
| `service[type=MosaicRightsCommitment2026]` | §5.4 Services | Carries the current commitment hash, sequence, publication block, and signer. Any conformant DID consumer ignores unknown service types — the document remains interoperable. |
| `alsoKnownAs` | §5.1.3 | Optional reference to the full rights document. Only included when the DID controller intentionally publishes the document publicly (e.g., for regulatory transparency). For private documents — the default — this field is omitted; the presenter provides the document (or Merkle-proof subset) in the Verifiable Presentation instead. |
| `mosaic:createdAtHeight` | §4.1 Extensibility (custom property) | The block at which the DID was created. Allows a verifier to reject claims predating DID creation. |
| `mosaic:lastModifiedAtHeight` | §4.1 Extensibility (custom property) | The block at which the most recent state change occurred. Maps directly to `didDocumentMetadata.updated`. |
| `mosaic:tombstonedAtHeight` | §4.1 Extensibility (custom property) | If set, the block at which the DID was deactivated. `null` or absent means the DID is alive. |

All custom properties are prefixed with `mosaic:` to avoid collisions with
future W3C property registrations. They are registered in the DID Specification
Registries under the Mosaic namespace. Consumers that do not understand them
safely ignore them — the core `verificationMethod`, `authentication`,
`assertionMethod`, and `service` sections remain fully interoperable with
any W3C DID resolver.

### 4.3 Privacy — eIDAS and the DID/VC separation

An important privacy property emerges from this architecture: **no personally
identifiable information (PII) ever appears in the DID Document or on the
chain.** This is architecturally guaranteed, not policy-enforced.

#### The separation of concerns

```
┌─ On-chain (public, permanent) ────────────────────────────┐
│                                                            │
│  DidState:                                                 │
│   ├─ keys          → pubkeys, keyRefs         (no PII)    │
│   ├─ rights        → Update, Delegate         (no PII)    │
│   ├─ commitment    → blake3(rights-document)  (no PII)    │
│   └─ nonces        → u64 counters             (no PII)    │
│                                                            │
│  Public. Any observer can read. No privacy impact.         │
└────────────────────────────────────────────────────────────┘

┌─ Off-chain (private, holder's custody) ────────────────────┐
│                                                            │
│  PID Credential (eIDAS):                                   │
│   ├─ familyName: "Smith"                     (PII)         │
│   ├─ dateOfBirth: "1987-03-14"              (PII)         │
│   ├─ personalIdentifier: "NL/XYZ/..."       (PII)         │
│   └─ issuer: did:mosaic:iozBRP...           (public DID)  │
│                                                            │
│  Rights Document:                                          │
│   ├─ keyRefs → right mappings               (no PII)      │
│   └─ previousCommitment hash chain          (no PII)      │
│                                                            │
│  Private. Holder controls disclosure via Verifiable        │
│  Presentations. Verifier sees only what is revealed.        │
└────────────────────────────────────────────────────────────┘
```

#### What eIDAS 2.0 (Regulation EU 2024/1183) requires

The EU Digital Identity Wallet framework mandates:

- **Person Identification Data (PID)** — minimum identity attributes the wallet
  must be able to present (name, date of birth, unique identifier).
- **Selective disclosure** — the user controls exactly which attributes are
  revealed per interaction. For age verification, the wallet discloses
  `ageOver18: true`, not the full date of birth.
- **Privacy by design** — data minimisation and purpose limitation are
  regulatory requirements, not optional.

Critically, the regulation is **technology-neutral** about how identifiers
are managed. It does not mandate that DID documents contain PII, nor does
it require on-chain linkage between DIDs and natural persons.

#### Why this architecture is already eIDAS-compatible

| eIDAS requirement | How the architecture satisfies it |
|------------------|-----------------------------------|
| PID must be presentable | PID is issued as a Verifiable Credential, held in the user's wallet, disclosed selectively via Verifiable Presentation |
| Privacy by design | DID Document contains only cryptographic material (public keys, hashes). The chain never sees names, birth dates, or national ID numbers |
| Selective disclosure | The wallet presents only requested attributes. The verifier checks `keyRef` → `right` in the commitment document, then verifies the credential proof — the DID document only provides the key binding |
| Data minimisation | `ageOver18` (1 bit) instead of `dateOfBirth: "1987-03-14"` (full PII). The verifier's proof bundle carries minimal data |
| Qualified electronic signatures | Traceability to a natural person is handled at the trust service provider level (the PID issuer), not at the DID document level. The verifier follows: `signature → keyRef → PID credential → identity` |

#### One person, many DIDs — supported by design

eIDAS does not require a single DID per natural person. A person can have:

- `did:mosaic:iozAAA...` for their business (EuroSign invoice signing)
- `did:mosaic:iozBBB...` for their personal government interactions
- `did:mosaic:iozCCC...` for their university enrollment

All three are backed by the same PID credential (proving they belong to the
same person), but the DIDs themselves are unlinkable on-chain — different
`key_id` → `DID` derivations produce unrelated identifiers. This is the
correct architecture for privacy-preserving identity.

#### One edge note: the `alsoKnownAs` privacy consideration

W3C DID Core §10.3 warns that `alsoKnownAs` entries can create correlation
risks. By default, `alsoKnownAs` is **omitted** from the DID document —
rights documents are private and only revealed in Verifiable Presentations.
If a DID controller intentionally publishes the rights document publicly
(e.g., for regulatory transparency), `alsoKnownAs` can be populated, but
this is an explicit opt-in, not the default. The rights document itself
contains only `keyRef → right` mappings — no PII — so even when public,
the correlation risk is limited to linking DIDs to each other, not to
natural persons.

---

## 5. Time-Bounding: How H_start and H_end Are Proven

The verifier does NOT trust the presenter's claim about when the signature
was created. Instead, `H_start` and `H_end` are **cryptographically proven**
by composable mechanisms borrowed from the authority-poc proof system.

### 5.0 Composability — not all proofs need all layers

The three time-bounding layers are **independent and optional.** A verifier
must accept the strongest proof the presenter can provide, but the presenter
chooses which layers to assemble based on the use case:

| Use case | AfterProof | SMT inclusion | BeforeProof | Commitment | Why sufficient |
|----------|:----------:|:-------------:|:-----------:|:----------:|----------------|
| Chat message, informal attestation | | | | ✓ | No time-bound needed. The commitment proves the right existed *at some point*. Trust model: verifier trusts the presenter's claim about recency. |
| Invoice with external timestamp | ✓ | | | ✓ | AfterProof proves "after block N." The verifier uses a trust-on-first-use (TOFU) upper bound: "now" or a credible timestamp service. No chain anchoring cost. |
| Notarized document batch | ✓ | ✓ | ✓ | ✓ | Full cryptographic time-window. Used when the presenter and verifier are adversarial or the claim has legal/financial consequences. |

**Key principle:** The SMT and BeforeProof are an *anchoring service* that
adds an upper time-bound and batch-inclusion proof. They are not part of the
DID rights commitment model itself. A signer who does not need on-chain
anchoring can skip the SMT entirely — sign the AfterEnvelope, include the
rights commitment document, and present it. The verifier applies the
strongest verification the proof bundle supports.

The sections below describe each layer in full, then §6 shows how a verifier
gracefully degrades to the available proof strength.

### 5.1 AfterProof — lower time-bound (signature AFTER block N)

At signing time, the signer observes a recent blockhash from the chain. They
construct an `AfterEnvelope` wrapping their content alongside this block
witness:

```
AfterEnvelope<SmtContent> = {
  content: {
    root:   "cjuXXXX...",   // SMT root of the batch containing this document
    height: 10              // SMT tree depth (fixed for the proof system)
  },
  proof: AfterProof {
    blockHeight: 42,
    blockHash:   "0x0400000000000000000000000000000000000000000000000000000000000000"
  }
}
```

The signer then signs the canonical JSON digest of this envelope (`digestJson(AfterEnvelope)`),
creating a `Signed<AfterEnvelope<SmtContent>>`:

```
Signed<AfterEnvelope<SmtContent>> = {
  signature: {
    publicKey: "pezFVen3X669...",   // Ed25519 multicipher public key
    bytes:     "sez8TKYaZiP..."     // Ed25519 multicipher signature
  },
  content: AfterEnvelope<SmtContent>
}
```

**The lower-bound proof:** The signer could not have known `blockHash` at
height 42 before that block was produced. Therefore the signature MUST have
been created at or after block 42 + 1. This gives:

```
H_start = AfterProof.blockHeight + 1
```

The signer is incentivized to use the most recent blockhash available (giving
the tightest lower bound), but the verifier does not depend on this — any
blockhash proves "after that block."

### 5.2 BeforeProof — upper time-bound (signature BEFORE block M)

The SMT root containing the signed document is anchored on-chain via
`SsiOperation::BeforeProof(ContentId)`. This emits a `BeforeProofRegistered`
event at block `M` and stores the record permanently. The pallet's
`submit_did_operations` accepts BeforeProof submissions from any account
(permissionless anchoring).

**The upper-bound proof:** The SMT root `R` (containing the signed
AfterEnvelope as one leaf) was registered on-chain at block `M`. A valid
inclusion proof (`leafIndex + leafHash + siblingHashes`) proves that the
signed envelope is a leaf in the tree rooted at `R`. The signature must
predate the anchoring:

```
H_end = BeforeProof.blockHeight
```

### 5.3 SMT inclusion proof — ties the AfterEnvelope to the BeforeProof

```
Sparse Merkle Tree (height 10, 1024 leaves)
───────────────────────────────────────────
                                   ┌──────┐
                                   │ root │ = "cjuF2OXG..."
                                   └──┬───┘
                              ┌───────┴───────┐
                           [...]          [... ]
                          ...   ...    ...   ...
                         ┌─┴─┐               ┌─┴─┐
                         │   │               │   │
                      leaf_0  ...      leaf_42  leaf_43 ...

                      leaf_42 = digestJson(Signed<AfterEnvelope<SmtContent>>)
                               = "cjuwowG6jm..."
                               = fingerprint
```

The SMT inclusion proof contains:
- `leafIndex` (42)
- `leafHash` (the fingerprint = `digestJson(Signed)`)
- `siblingHashes[0..9]` (10 siblings for a height-10 tree)

The verifier recomputes the root by hashing up the tree path and checks
`recomputed_root == BeforeProof.content_id`. This cryptographically proves
the signed envelope was included in the batch anchored at block `M`.

### 5.4 Proof bundles — from minimal to maximal

The presenter assembles whichever proof layers the use case requires. All
of these are valid inputs to the verifier:

```typescript
// Minimal — no time-bounding at all. Verifier trusts recency claim.
interface MinimalProof {
  signedDocument: Signed<VC>         // the VC itself
  commitmentDocument: RightsDocument // proves right exists (off-chain)
}

// With lower time-bound — proves "after block N."
interface AfterProofBundle {
  signedAfterEnvelope: Signed<AfterEnvelope<Payload>>
  commitmentDocument: RightsDocument
}

// Full time-bounded and batch-anchored — proves "between N and M."
interface FinalizedProof {
  leafIndex: number
  leafHash: string
  siblingHashes: string[]
  signedEnvelope: Signed<AfterEnvelope<SmtContent>>
  beforeProofBlockHeight: number
  beforeProofContentId: string
  commitmentDocument?: RightsDocument   // may be resolved separately
}
```

The `FinalizedProof` is what the authority-poc customer-signer returns after
the provider confirms the BeforeProof anchoring. It is the **strongest**
bundle — but also the most expensive to produce (requires SMT construction
and an on-chain transaction). The verifier in §6 accepts all three forms.

---

## 6. Verifier Algorithm

A verifier receives a proof bundle and must determine whether the signing key
held the asserted right. The verifier extracts whatever time-bounding and
inclusion proofs are present and applies the **strongest available checks.**
Missing proof layers degrade verification strength rather than causing
rejection — the verifier's security model determines what strength is required.

### 6.1 Inputs (varying by proof strength)

| Proof strength | Time bounds | Identity verification | Right verification |
|---------------|-------------|----------------------|-------------------|
| Minimal | TOFU: `H_end = now`, `H_start = genesis` | Signature against pubKey in commitment document | `blake3_struct(D) == on-chain commitment` |
| AfterProof | `H_start = blockHeight + 1`, `H_end = now` | Signature against pubKey in signed AfterEnvelope | Commitment at `H_start` (lower-bound check) |
| FinalizedProof | `H_start = blockHeight + 1`, `H_end = beforeProofBlockHeight` | Full SMT + AfterEnvelope + signature verification | Every commitment active in `[H_start, H_end]` |

### 6.2 Algorithm

```
verify_right(presentationProof, right):
    ┌─────────────────────────────────────────────────────────────┐
    │ Step 0 — Classify the proof bundle                           │
    │                                                              │
    │ Detect which layers are present:                             │
    │   hasBeforeProof = (beforeProofBlockHeight != null)          │
    │   hasSmtProof    = (leafIndex != null && siblingHashes != null)│
    │   hasAfterProof  = (signedEnvelope?.content?.proof != null)  │
    │                                                              │
    │ Derive time bounds:                                          │
    │   H_start = hasAfterProof                                   │
    │       ? signedEnvelope.content.proof.blockHeight + 1          │
    │       : 0  (TOFU: assume since genesis)                      │
    │   H_end   = hasBeforeProof                                  │
    │       ? beforeProofBlockHeight                              │
    │       : now  (TOFU: assume not yet revoked)                   │
    │                                                              │
    │ Policy gate: does the verifier's security model accept       │
    │ the available proof strength? (e.g., legal notarization      │
    │ requires FinalizedProof; informal attestation accepts        │
    │ MinimalProof.)                                               │
    └─────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Step 1 — Verify any SMT inclusion proof (if present)         │
    │                                                              │
    │ IF hasSmtProof AND hasBeforeProof:                           │
    │                                                              │
    │ a. Recompute fingerprint = digestJson(signedEnvelope)        │
    │    Verify: fingerprint == leafHash                           │
    │                                                              │
    │ b. Recompute SMT root from leafIndex + siblingHashes:        │
    │    current = leafHash                                        │
    │    for each sibling in siblingHashes:                        │
    │        if leafIndex is left child:                           │
    │            current = mergeHashes(current, sibling)           │
    │        else:                                                 │
    │            current = mergeHashes(sibling, current)           │
    │        leafIndex = floor(leafIndex / 2)                      │
    │                                                              │
    │ c. Verify: recomputed_root == beforeProofContentId           │
    │    Verify: BeforeProof exists on-chain at beforeProofHeight  │
    │    → The AfterEnvelope was in the anchored SMT batch ✓       │
    │                                                              │
    │ ELSE: skip (no SMT anchoring to verify).                     │
    └─────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Step 2 — Verify the signature over the payload               │
    │                                                              │
    │ IF hasAfterProof:                                            │
    │   Extract from signedEnvelope:                               │
    │     pubKey  = signature.publicKey (multicipher)              │
    │     sig     = signature.bytes     (multicipher)              │
    │     message = digestJson(signedEnvelope.content)             │
    │   Verify: Ed25519Blake3.verify(message, sig, pubKey)         │
    │                                                              │
    │   Verify: AfterProof.blockHash IS a valid on-chain blockhash │
    │           at AfterProof.blockHeight (query chain state).     │
    │                                                              │
    │ ELSE (MinimalProof):                                         │
    │   Extract pubKey + sig directly from the signed VC.          │
    │   Verify: Ed25519Blake3.verify(VC_digest, sig, pubKey)      │
    │                                                              │
    │ Map pubKey → key_id → key_ref (via multicipher).             │
    └─────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Step 3 — Key validity check                                  │
    │                                                              │
    │ Query DidState.keys for key_ref:                             │
    │   a. added_at_height ≤ H_start                               │
    │   b. expires_at_height absent OR > H_end                     │
    │   c. revoked_at_height absent OR > H_end                     │
    │                                                              │
    │ If hasAfterProof: the public key in the AfterEnvelope IS     │
    │   the key. No separate lookup needed.                        │
    │ If MinimalProof: resolve the pubKey from DidState.keys       │
    │   (must have been revealed by a prior RevealPublicKey).      │
    └─────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Step 4 — Time-bounded right existence                        │
    │                                                              │
    │ Load the rights commitment document D. The presenter must    │
    │ provide it in the proof bundle (or the relevant subset with  │
    │ Merkle inclusion proofs — see §2.4). Verify blake3_struct(D) │
    │ or verify_merkle_proof(entry, commitment_root).              │
    │                                                              │
    │ IF hasBeforeProof (time-bounded verification):               │
    │   Determine ALL *anchored* commitments active in [H_start,   │
    │   H_end] from the indexer's DidHistory.                      │
    │                                                              │
    │   ⚠ Unanchored sequence rule: a commitment version without   │
    │   an on-chain CommitmentUpdated event has no provable        │
    │   timestamp. The verifier MUST reject if any commitment      │
    │   active in [H_start, H_end] is unanchored.                  │
    │                                                              │
    │   Case A — single anchored commitment:                       │
    │     D was active the entire interval.                        │
    │     Verify: D.rights grants (key_ref, right).                │
    │     Each UpdateCommitment is a full replacement — the right  │
    │     must appear in every anchored version in the window.     │
    │                                                              │
    │   Case B — multiple anchored commitments [C1..Ck]:           │
    │     The presenter must provide documents for ALL anchored    │
    │     versions (the verifier rejects gaps — §10 question 4).   │
    │     Verify hash chain: Ci+1.previousCommitment == blake3(Di) │
    │     Verify: EVERY Ci.rights grants (key_ref, right).         │
    │     If any Ci omits the right, the claim fails — each        │
    │     commitment is a full replacement of the rights document. │
    │                                                              │
    │ ELSE (no upper bound, MinimalProof or AfterProof):           │
    │   Verify: blake3_struct(D) == current on-chain commitment    │
    │   Verify: D.rights grants (key_ref, right)                   │
    │   NOTE: This only proves the right existed *at some point*.  │
    │   The verifier trusts (via TOFU or external timestamp) that  │
    │   the right was not yet revoked at signing time.             │
    └─────────────────────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Step 5 — DID liveness                                        │
    │                                                              │
    │ IF hasBeforeProof:                                           │
    │   tombstoned_at_height absent OR > H_end                     │
    │ ELSE:                                                        │
    │   tombstoned_at_height absent (DID must be alive now)        │
    └─────────────────────────────────────────────────────────────┘
```

### 6.3 Verifier policy: choosing acceptable proof strength

The verifier's security model determines which bundle types it accepts:

| Verifier context | Acceptable bundles | Rationale |
|-----------------|-------------------|-----------|
| Chat app (friend-to-friend) | MinimalProof | Social trust; cost of fraud is low |
| Business invoice (B2B) | AfterProof or FinalizedProof | Needs lower time-bound; upper bound can be TOFU if invoice is recent |
| Regulatory notarization | FinalizedProof only | Full cryptographic time-window required for auditability |
| Credential revocation check | AfterProof + current commitment | Must prove the credential was signed before the key was revoked |

The verifier library exposes a `VerifierPolicy` that gates which bundle
types are accepted. The verification function itself is policy-agnostic
— it applies all available checks and returns a `VerificationResult` with
a `strength` field indicating what was verified.

---

## 7. Full Example: EuroSign Invoice Signature

Alice runs a business with DID `did:mosaic:iozAAA...`. Her DID has:

- `key-update-1`: Update + Delegate rights (on-chain, in `DidState.rights`)
- `key-sign-1`: Impersonate right (off-chain only, in the commitment document)

At block 5000, Alice publishes commitment C1 granting `key-sign-1` the
Impersonate right. At block 6000, she publishes C2 removing it.

### 7.1 Scenario A: Informal invoice (MinimalProof)

Alice signs an invoice at block 5480 and emails it to Bob with the rights
commitment document D1. No on-chain anchoring, no AfterProof.

```
Bob's verification (MinimalProof):
  H_start = 0 (TOFU), H_end = now

  Step 2: Verify Ed25519Blake3(invoice_digest, sig, pubKey) ✓
  Step 3: key-sign-1 is valid at now (not revoked until 6000) ✓
  Step 4: blake3_struct(D1) == on-chain commitment C1 ✓
          D1.rights grants Impersonate to key-sign-1 ✓
  Step 5: DID not tombstoned ✓

  → ACCEPTED at MinimalProof strength.
    Bob trusts Alice (business relationship), so TOFU time-bounds
    are sufficient. No chain transaction cost incurred.
```

### 7.2 Scenario B: Invoice with lower time-bound (AfterProof)

Alice signs at block 5480 with an AfterProof referencing blockhash at
height 5479. No SMT batching or BeforeProof anchoring needed.

```
Bob's verification (AfterProof):
  H_start = 5480, H_end = now

  Step 0: Policy accepts AfterProof for B2B invoices ✓
  Step 2: Verify AfterEnvelope signature ✓
          Verify blockhash 0xabcd... is valid at height 5479 ✓
  Step 3: key-sign-1 added at 5000 ≤ 5480 ✓, not revoked ✓
  Step 4: Commitment C1 active at 5480. D1.rights includes Impersonate ✓
  Step 5: DID alive ✓

  → ACCEPTED at AfterProof strength.
    Bob knows the invoice was signed after block 5480. The upper bound
    is TOFU (now), which is acceptable for a recent invoice.
```

### 7.3 Scenario C: Notarized invoice (FinalizedProof)

Alice signs at block 5480, batches it into an SMT with 3 other documents,
and anchors the SMT root via BeforeProof at block 5500. This is the full
FinalizedProof bundle from the authority-poc customer-signer:

```typescript
const finalizedProof = {
  leafIndex: 2,
  leafHash: "cjua2swGJ...",
  siblingHashes: [/* 10 siblings */],
  signedEnvelope: {
    signature: {
      publicKey: "pozFVen3X...",
      bytes:     "soz8TKYaZiP..."
    },
    content: {
      content: { root: "cjuF2OXG...", height: 10 },
      proof:   { blockHeight: 5479, blockHash: "0xabcd..." }
    }
  },
  beforeProofBlockHeight: 5500,
  beforeProofContentId: "cbXXXX..."
}
```

Bob's verification:

```
  H_start = 5480, H_end = 5500

  Step 1: SMT proof → recomputed_root == beforeProofContentId ✓
          BeforeProof exists on-chain at block 5500 ✓
  Step 2: AfterEnvelope signature + blockhash at 5479 ✓
  Step 3: key-sign-1 valid in [5480, 5500] ✓
  Step 4: Commitment C1 active the whole interval. D1.rights ✓
  Step 5: DID alive ✓

  → ACCEPTED at FinalizedProof strength.
    Full cryptographic time-window [5480, 5500]. Acceptable for
    regulatory notarization or legal disputes.
```

### 7.4 Fraud attempt: backdating a post-revocation signature

Alice revokes `key-sign-1`'s Impersonate right at block 6000 (publishes C2).
At block 6500 she signs a backdated invoice, attempting to reuse an old
AfterProof blockhash from block 5479. She anchors at block 6550.

```
H_start = 5480, H_end = 6550

Step 4: Commitments active in [5480, 6550]:
          C1 @ 5000 (grants Impersonate)
          C2 @ 6000 (revokes Impersonate)

        Case B — multi-commitment span.
        C2.rights does NOT grant Impersonate.

→ REJECTED. The right was NOT held continuously across [5480, 6550].
  The BeforeProof at 6550 forces the verifier to check C2.
```

### 7.5 Honest anchor before revocation

Alice signs at block 5480, anchors at block 5500 (before C2 at 6000). Bob
receives the proof at block 7000, long after the revocation:

```
H_start = 5480, H_end = 5500

Step 4: Only C1 active in [5480, 5500]. C2 not yet published.
        D1.rights grants Impersonate ✓

→ ACCEPTED. The signing window [5480, 5500] predates the revocation.
  The verifier checks the commitment active at H_end=5500, which is
  still C1. Bob does not need to check current chain state for a
  historical claim.

---

## 8. Storage Economy

The commitment model does not reduce the on-chain budget — it provides an
alternative path so the budget isn't consumed unnecessarily.

| Scenario | On-chain right grants | Commitment overhead | Total on-chain footprint |
|----------|:---------------------:|:-------------------:|--------------------------|
| Minimal DID (1 key, Update+Delegate implicit) | 0 entries | `(seq, hash)` + `last_modified_at` = 8+32+8 = 48 bytes | 48 bytes |
| Typical DID (2 keys, 1 Delegate grant on-chain, 2 Impersonate keys via commitment) | 1 entry (~77 bytes) | 48 bytes | 125 bytes |
| All-rights-on-chain DID (3 keys, 5 rights each, 15 grants) | 15 entries (~1155 bytes) | 0 bytes (null commitment) | 1155 bytes |

**The key insight:** DIDs that use the commitment path save on-chain
storage proportional to the number of off-chain rights they hold. DIDs
that need all rights on-chain use the full `MAX_RIGHTS_PER_DID = 64`
budget — the commitment overhead is zero for them.

The net state addition:
- `+` `commitment: Option<(u64, ContentId)>` (1 + 8 + 32 = 41 bytes if `Some`)
- `+` `last_modified_at: (u32, u32)` (8 bytes)
- Total: ~49 bytes per DID that uses commitments (trivial)

`previous_version_id` is carried in events only (§2.1.2), not in storage.
Writes to different extrinsics in the same block that modify the same DID
would overwrite each other in storage, but each event preserves its own
pointer independently in the block body.

---

## 9. Design Rationale

This pallet has not been deployed to production. All features described in
this document — the commitment model, union semantics, `previous_version_id`
event chain, selective disclosure, and time-bounding composability — are
part of the initial design, not retrofits. No migration is needed.

The following decisions are worth calling out as they differ from what a
naive reading of the current codebase might suggest:

- **`MAX_RIGHTS_PER_DID = 64`** — this bound was already present in the
  current `DidState`. The plan does not change it. DIDs that use the
  commitment path for off-chain rights will have fewer on-chain entries;
  DIDs that need all rights on-chain use the full budget.
- **Union semantics** — on-chain `RightGrant` entries and the off-chain
  commitment document are additive. A right is valid if it appears in
  either. The pallet validates only Update and Delegate (consensus
  requirement); all six rights can be stored on-chain via `AddRight`.
- **`DidState::has_right_at` vs `DidHistory::has_right_at`** — the
  pallet's method checks on-chain grants only. The verifier's method
  (on `DidHistory`) adds the commitment fallthrough. This separation
  keeps the pallet free of document-resolution concerns.
- **`previous_version_id` in events, not storage** — events survive
  intra-block overwrites; storage does not. The pointer chain lives
  where it can't be corrupted by multiple transactions in the same
  block modifying the same DID.

---

## 10. Implementation Notes

### What is concrete (ready to implement)

| Change | Crate(s) | Effort |
|--------|----------|--------|
| Add `commitment` and `last_modified_at` to `DidState` | `mosaic-did-types` | Small — two fields on `DidState` |
| Add `UpdateCommitment` variant to `DidOperation` | `mosaic-did-types` | Small — new enum variant |
| Add `CommitmentUpdated` variant to pallet `Event` | `pallet-mosaic-did` | Small — new event variant |
| Add `previous_version_id` to all state-changing events | `pallet-mosaic-did` | Small — one field on each event; populated from `last_modified_at` before the state change |
| `UpdateCommitment` validation (§2.3) | `pallet-mosaic-did/src/validation.rs` | Small — follows existing validation patterns |
| `UpdateCommitment` application (mutate `DidState`) | `pallet-mosaic-did/src/lib.rs` | Small — follows `AddRight`/`TombstoneDid` patterns |
| `DidHistory`, `CommitmentVersion`, `KeyLifecycle`, `CommitmentResolver` trait | `mosaic-did-types` | Medium — new types for event-stream reconstruction; `no_std`, no pallet dependency |
| `DidHistory::has_right_at` union fallthrough (§4.1) | `mosaic-did-types` | Small — on-chain check then `CommitmentResolver` |
| Test vectors: commitment document → `ContentId` roundtrip | `mosaic-did-types` | Small — pinned golden vectors |
| Test: `UpdateCommitment` extrinsic happy-path + error cases | `pallet-mosaic-did` | Small — follows existing test patterns |

### Implementation order

1. **`mosaic-did-types`** — `DidState` fields, `DidOperation` variant,
   `DidHistory` + associated types, pinned test vectors. No pallet
   dependency, compiles under `no_std`. Other language implementations
   must produce identical DID documents from the same event stream
   (canonicalization is defined by `json_digest`).
2. **`pallet-mosaic-did`** — validation, application, events, tests.
   Depends on step 1.
3. **Verifier library** — implements the algorithm in §6.2 with
   `VerifierPolicy` gating (§6.3). Depends on steps 1–2.
4. **Time-bounding integration** — AfterProof signing, SMT construction,
   BeforeProof anchoring. Most exists in authority-poc TypeScript;
   Rust side needs `json_digest` integration.

### One runtime-level note (not a pallet change)

Light-client verification without trusting an indexer: Substrate's
`state_getReadProof` RPC returns `DidState` + Merkle proof against the
block header's `state_root`. A smoldot client can verify this proof
locally, trusting only consensus. The pallet already uses
`Blake2_128Concat` hashing (Merkle-proof-compatible). Exposing a
convenience `DidStates::get_with_proof(did)` RPC is a runtime
configuration decision, not a pallet change. See §2.1.1 for the smoldot
rewind model using the event pointer chain.
