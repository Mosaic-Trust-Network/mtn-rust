# Substrate Pallet Writing Guide — Mosaic Trust Network

> **Audience:** AI coding agents, developers new to Substrate, anyone touching `pallet-mosaic-did`.
> **Purpose:** Prevent framework confusion (esp. ARK.io patterns leaking into Substrate code).
> **Based on:** Polkadot SDK stable2503, `pallet-mosaic-did` real implementation.

---

## 1. Pallet Anatomy — The Non-Negotiable Structure

Every Substrate pallet lives inside a `#[frame_support::pallet]` module. This is not optional decoration — the macro generates runtime integration glue.

```rust
#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    // 1. Config trait (MANDATORY)
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
        #[pallet::constant]
        type MaxOperationsPerTx: Get<u32>;
    }

    // 2. Pallet struct (MANDATORY)
    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // 3. Storage items
    #[pallet::storage]
    pub type DidStates<T: Config> = StorageMap<
        _, Blake2_128Concat, Did, OnChainDidState, OptionQuery,
    >;

    // 4. Events
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> { ... }

    // 5. Errors
    #[pallet::error]
    pub enum Error<T> { ... }

    // 6. Extrinsics (dispatchable calls)
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_did_operations(n))]
        pub fn submit_did_operations(
            origin: OriginFor<T>,
            operations: Vec<SsiOperation>,
        ) -> DispatchResult { ... }
    }
}
```

**Hard rules:**
- `Config` must extend `frame_system::Config`
- Every extrinsic needs an explicit `#[pallet::call_index(N)]` (reordering breaks wire encoding)
- `OriginFor<T>` is always the first parameter of extrinsics
- Return `DispatchResult` (= `Result<(), DispatchError>`)

---

## 2. Storage — On-Chain State That Persists

Substrate storage is a key-value trie. The pallet macros generate the key prefixes. You never manage raw keys.

### Storage Types

| Type | Use Case | Our Example |
|------|----------|-------------|
| `StorageValue<_, V, QueryKind>` | Global singletons, counters | — |
| `StorageMap<_, Hasher, K, V, QueryKind>` | Entity by ID | `DidStates`, `BeforeProofs` |
| `StorageDoubleMap<_, H1, K1, H2, K2, V>` | Two-key relationships | — |
| `CountedStorageMap<_, H, K, V>` | Map + O(1) count | — |

### QueryKind

- **`OptionQuery`** (default): `get()` returns `Option<V>`. Use when "absent" is different from "zero".
- **`ValueQuery`**: `get()` returns `V::default()` when absent. Use for counters/configs.

**Our pallet uses `OptionQuery`** — a DID either exists or it doesn't. There's no "default DID state".

### Hasher Selection

- **`Blake2_128Concat`**: Safe default. Use when keys are user-controlled (DIDs, content IDs).
- **`Twox64Concat`**: Faster, non-cryptographic. Only for pallet-internal keys.
- **`Identity`**: No hashing. Only when the key is already a hash (e.g., `[u8; 32]`).

### Bounded Collections — Mandatory for On-Chain Types

Any `Vec` or `BTreeMap` stored on-chain MUST be bounded:

```rust
// Our actual constants:
pub const MAX_KEYS_PER_DID: u32 = 32;
pub const MAX_RIGHTS_PER_DID: u32 = 64;
pub const MAX_NONCES_PER_DID: u32 = 32;

pub struct OnChainDidState {
    pub keys: BoundedVec<OnChainVerificationMethod, ConstU32<MAX_KEYS_PER_DID>>,
    pub rights: BoundedVec<OnChainRightGrant, ConstU32<MAX_RIGHTS_PER_DID>>,
    pub nonces: BoundedBTreeMap<
        BoundedVec<u8, ConstU32<MAX_KEY_ID_LEN>>,
        u64,
        ConstU32<MAX_NONCES_PER_DID>,
    >,
}
```

**Why:** Parachains need statically bounded PoV (Proof of Validity) sizes. Unbounded storage makes weight calculation impossible. The compiler will reject unbounded types in storage unless you explicitly opt out with `#[pallet::unbounded]` (don't).

**Insertion pattern:** Always use `try_push` / `try_insert`, never `push`:
```rust
state.keys.try_push(vm).map_err(|_| Error::<T>::StorageBoundsExceeded)?;
```

---

## 3. Type Derive Requirements

Every type stored on-chain needs this derive stack:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct OnChainVerificationMethod { ... }
```

| Derive | Why |
|--------|-----|
| `Encode` + `Decode` | SCALE codec for wire format |
| `MaxEncodedLen` | PoV weight calculation |
| `TypeInfo` | Metadata for RPC clients / Polkadot.js |

**For types shared between on-chain and off-chain** (like our `mosaic-did-types` crate), use feature-gated derives:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "substrate", derive(
    parity_scale_codec::Encode, parity_scale_codec::Decode,
    parity_scale_codec::MaxEncodedLen, scale_info::TypeInfo,
))]
pub struct Rights(pub u16);
```

This lets the same type work in `no_std` Substrate runtimes and `std` SDK code.

---

## 4. `try_mutate` — The Correct State Mutation Pattern

**NEVER use `mutate` for fallible operations.** Use `try_mutate`:

```rust
// CORRECT: rollback on error
DidStates::<T>::try_mutate(did, |maybe_state| -> DispatchResult {
    let state = maybe_state.get_or_insert_with(|| OnChainDidState::new(did));
    state.keys.try_push(vm).map_err(|_| Error::<T>::StorageBoundsExceeded)?;
    Self::update_nonce(state, &signed_op.signer_key_id, signed_op.nonce)?;
    Ok(())
})?;

// WRONG: mutate commits even on error
DidStates::<T>::mutate(did, |maybe_state| {
    // If this fails, the partial state change is STILL written!
    let state = maybe_state.get_or_insert_with(|| OnChainDidState::new(did));
    state.keys.try_push(vm)?; // Error here doesn't rollback the insert above
    Ok(())
});
```

**Rule:** If any `?` appears inside the closure, you need `try_mutate`.

---

## 5. `ensure!` vs `assert!` — Life or Death

```rust
// CORRECT: returns error, caller handles it
ensure!(!state.is_tombstoned_at(height), Error::<T>::DidTombstoned);

// WRONG: panics, kills block production, halts the chain
assert!(!state.is_tombstoned_at(height), "DID is tombstoned");
```

| Macro | Behavior on failure | Use in |
|-------|-------------------|--------|
| `ensure!(cond, err)` | `return Err(err.into())` | Extrinsic logic, validation |
| `assert!(cond)` | Panic, kill runtime | Tests only |
| `defensive_assert!` | Log warning in prod, panic in test | Invariant checks |

---

## 6. Events — The Indexer's API

Events are for off-chain indexers to reconstruct history. They are NOT the source of truth for on-chain state.

```rust
#[pallet::event]
#[pallet::generate_deposit(pub(super) fn deposit_event)]
pub enum Event<T: Config> {
    /// A key was added to a DID document.
    KeyAdded {
        did: Did,
        key_id: Vec<u8>,
        key_type: KeyType,
        public_key: Vec<u8>,
        commitment: [u8; 32],
        expires_at_height: Option<u32>,
        block_height: BlockNumberFor<T>,
    },
    // ...
}
```

**Pattern in our pallet:** Mutate state first, then emit event. Events are emitted AFTER the `try_mutate` succeeds:

```rust
DidStates::<T>::try_mutate(did, |maybe_state| -> DispatchResult {
    // ... state mutation ...
    Ok(())
})?;

// Only reached if mutation succeeded
Self::deposit_event(Event::KeyAdded { ... });
```

**Event naming:** Past tense / passive voice. `KeyAdded`, not `AddKey`. `CommitmentUpdated`, not `UpdateCommitment`.

---

## 7. Error Design

```rust
#[pallet::error]
pub enum Error<T> {
    DidTombstoned,
    InsufficientRight,
    InvalidSignature,
    InvalidNonce,
    KeyNotFound,
    KeyAlreadyExists,
    StorageBoundsExceeded,
    // ...
}
```

**Rules:**
- Error variants are encoded as sequential `u8` indices. Reordering in a live runtime is a breaking change.
- No data in error variants (no `KeyNotFound(KeyId)`) — SCALE error encoding is just the index byte.
- Errors map to `DispatchError::Module { index, error }` on-chain.

---

## 8. Validate-Then-Apply — Two-Phase Execution

Our pallet uses the validate-then-apply pattern for atomic batches:

```rust
pub fn submit_did_operations(
    origin: OriginFor<T>,
    operations: Vec<SsiOperation>,
) -> DispatchResult {
    let submitter = ensure_signed(origin)?;

    // PHASE 1: Validate ALL operations (read-only — no state mutation)
    for op in &operations {
        match op {
            SsiOperation::Did(signed_op) => {
                validation::validate_did_operation::<T>(signed_op, height_u32)?;
            }
            SsiOperation::BeforeProof(content_id) => {
                ensure!(!BeforeProofs::<T>::contains_key(content_id),
                    Error::<T>::BeforeProofAlreadyExists);
            }
        }
    }

    // PHASE 2: Apply ALL operations (mutates state)
    for op in &operations {
        // ... apply ...
    }

    Ok(())
}
```

**Why:** If operation 3 out of 5 fails validation, the entire batch is rejected atomically. No partial application.

---

## 9. Weight System

Every extrinsic declares its computational cost:

```rust
#[pallet::call_index(0)]
#[pallet::weight(T::WeightInfo::submit_did_operations(operations.len() as u32))]
pub fn submit_did_operations(...) -> DispatchResult { ... }
```

The `WeightInfo` trait abstracts the actual numbers:

```rust
pub trait WeightInfo {
    fn submit_did_operations(n: u32) -> Weight;
    fn register_before_proof() -> Weight;
}

// Test/dev implementation (zero cost)
impl WeightInfo for () {
    fn submit_did_operations(n: u32) -> Weight {
        Weight::from_parts(10_000 * n as u64, 0)
    }
    fn register_before_proof() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}
```

**For production:** Run benchmarks with `frame-omni-bencher` to generate real weight functions. The `()` implementation is a placeholder.

**Weight has two dimensions:**
- `ref_time`: CPU time (picoseconds)
- `proof_size`: storage proof size (bytes, relevant for parachains)

---

## 10. Testing Without a Full Runtime

Our pallet tests are split into two tiers:

### Tier 1: Pure type tests (no runtime needed)

Test types, operations, and state logic directly:

```rust
#[test]
fn rights_bitflags() {
    let both = Rights::UPDATE | Rights::DELEGATE;
    assert!(both.contains(Rights::UPDATE));
    assert!(both.contains(Rights::DELEGATE));
    assert!(Rights::NONE.is_empty());
}

#[test]
fn initial_key_has_implicit_rights() {
    let state = make_test_state(); // Direct OnChainDidState construction
    assert!(state.has_right_at(b"key-1", Rights::UPDATE, 1));
    assert!(state.has_right_at(b"key-1", Rights::DELEGATE, 1));
}
```

These tests run fast, don't need `sp_io::TestExternalities`, and cover 80% of business logic.

### Tier 2: Runtime integration tests (mock runtime)

For testing extrinsics, storage reads/writes, events, and error dispatch. Requires mock setup:

```rust
use frame::testing_prelude::*;

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(RuntimeCall, RuntimeEvent, RuntimeError, RuntimeOrigin)]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Test>;

    #[runtime::pallet_index(1)]
    pub type MosaicDid = pallet_mosaic_did::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = MockBlock<Test>;
}

impl pallet_mosaic_did::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxOperationsPerTx = ConstU32<100>;
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage().unwrap().into()
}

#[test]
fn submit_operations_works() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1); // Events need block > 0
        assert_ok!(MosaicDid::submit_did_operations(
            RuntimeOrigin::signed(1), ops
        ));
        System::assert_last_event(Event::SsiBatchApplied { ... }.into());
    });
}
```

**Key testing macros:**
- `assert_ok!(call)` — call succeeded
- `assert_noop!(call, Error::<Test>::Something)` — call failed AND no storage changed
- `System::assert_last_event(evt)` — verify event emission
- `System::set_block_number(1)` — MUST call before testing events (block 0 = genesis)

---

## 11. What NOT to Do — Anti-Patterns

### Unbounded storage
```rust
// WRONG
pub keys: Vec<OnChainVerificationMethod>,

// CORRECT
pub keys: BoundedVec<OnChainVerificationMethod, ConstU32<MAX_KEYS_PER_DID>>,
```

### assert! in extrinsic logic
```rust
// WRONG — panics, halts chain
assert!(amount > 0, "amount must be positive");

// CORRECT — returns error
ensure!(amount > 0, Error::<T>::InvalidAmount);
```

### mutate for fallible operations
```rust
// WRONG — partial writes on error
Storage::<T>::mutate(key, |val| {
    val.field = new_value;
    ensure!(val.is_valid(), Error::<T>::Invalid)?; // error doesn't undo field change
    Ok(())
});

// CORRECT — atomic rollback
Storage::<T>::try_mutate(key, |val| -> DispatchResult {
    val.field = new_value;
    ensure!(val.is_valid(), Error::<T>::Invalid)?;
    Ok(())
})?;
```

### Missing call_index
```rust
// WRONG — index changes if you reorder functions
#[pallet::call]
impl<T: Config> Pallet<T> {
    pub fn foo(...) -> DispatchResult { ... }
    pub fn bar(...) -> DispatchResult { ... }
}

// CORRECT — explicit, stable indices
#[pallet::call_index(0)]
pub fn foo(...) -> DispatchResult { ... }
#[pallet::call_index(1)]
pub fn bar(...) -> DispatchResult { ... }
```

### Using #[pallet::getter]
```rust
// DEPRECATED
#[pallet::storage]
#[pallet::getter(fn did_state)]
pub type DidStates<T: Config> = StorageMap<...>;

// CORRECT — make it pub, access directly
#[pallet::storage]
pub type DidStates<T: Config> = StorageMap<...>;
// Access: DidStates::<T>::get(key)
```

### Unbounded iteration in hooks
```rust
// WRONG — O(n) in on_initialize, chain-halting DoS vector
fn on_initialize(_: BlockNumberFor<T>) -> Weight {
    for (key, val) in SomeMap::<T>::iter() { ... }
}

// CORRECT — cursor-based pagination or use on_idle
fn on_idle(_: BlockNumberFor<T>, remaining: Weight) -> Weight {
    // Process items until weight budget exhausted
}
```

---

## 12. ARK.io vs Substrate — Framework Confusion Guide

AI agents trained on mixed blockchain code confuse these frameworks. Here's how to tell them apart:

| Concept | ARK.io | Substrate |
|---------|--------|-----------|
| Module unit | Plugin | Pallet (`#[frame_support::pallet]`) |
| State storage | Off-chain DB, hashes on-chain | On-chain state trie (`StorageMap`) |
| Transaction | `TransactionData` + JSON | Extrinsic (`#[pallet::call]` + SCALE) |
| Auth model | Explicit sig verification | Origin-based (`ensure_signed!`) |
| Fees | Fixed per tx type | Dynamic via `Weight` |
| Events | Informational, off-chain | First-class, stored in `frame_system` |
| Testing | Integration against real chain | Mock runtime + `TestExternalities` |
| Encoding | JSON / custom | SCALE codec |

**Red flags that you're writing ARK.io code in a Substrate context:**
- Using JSON serialization for on-chain data
- Manually verifying transaction signatures in extrinsic logic (Substrate handles origin)
- No `#[pallet::storage]` declarations
- No bounded collections
- Events used as source of truth (instead of materialized state)
- No `WeightInfo` trait or weight annotations

**Note on our pallet:** `pallet-mosaic-did` does verify signatures inside operations because of the anti-censorship design (any account submits for any DID). The origin (`ensure_signed`) identifies the submitter, but authorization comes from the cryptographic signature inside the `SignedDidOperation`. This is intentional and different from both standard Substrate and ARK patterns.

---

## 13. Our Pallet's Key Design Patterns

### Rights as Bitvector
```rust
pub struct Rights(pub u16);
impl Rights {
    pub const UPDATE: Rights = Rights(0x0001);
    pub const DELEGATE: Rights = Rights(0x0002);
    pub const INITIAL_KEY: Rights = Rights(0x0001 | 0x0002);
}
```
Only UPDATE and DELEGATE enforced on-chain. All other capabilities live in off-chain commitment documents (Taproot principle).

### Commitment Hash per Key
```rust
pub struct OnChainVerificationMethod {
    pub commitment: [u8; 32], // BLAKE3(JCS(KeyCapabilitiesDocument))
    // ...
}
```
`[0u8; 32]` = null commitment (fast onboarding, no off-chain doc yet).

### First-Key Implicit Rights
The first key added to a DID gets `UPDATE | DELEGATE` without explicit `AddRight`. This is checked in `has_right_at()`:
```rust
if let Some(first_key) = self.keys.first() {
    if first_key.id.as_slice() == key_id_bytes && first_key.is_valid_at(height) {
        if Rights::INITIAL_KEY.contains(rights) {
            return true;
        }
    }
}
```

### Validate-Then-Apply for Atomic Batches
Phase 1 reads state, Phase 2 mutates. If any operation in the batch fails validation, the entire transaction is rejected.

### Separate Types Crate
`mosaic-did-types` is `no_std` compatible with optional `substrate` feature flag. This lets the same types work in:
- On-chain pallet (SCALE encoded)
- Off-chain SDK (JSON serialized via serde)
- WASM browser client

---

## 14. Quick Reference — File Layout

```
pallet-mosaic-did/
├── Cargo.toml          # Substrate deps, excluded from workspace
├── src/
│   ├── lib.rs          # Pallet definition (Config, storage, events, errors, calls)
│   ├── state.rs        # OnChainDidState, OnChainVerificationMethod, bounded types
│   ├── validation.rs   # validate_did_operation() — reads state, returns errors
│   └── tests.rs        # Unit tests (type-level + on-chain state)
└── PALLET_GUIDE.md     # This file

mosaic-did-types/
├── Cargo.toml          # no_std + optional substrate feature
└── src/
    ├── lib.rs          # Crate root, re-exports
    ├── did.rs          # Did, KeyId, ContentId
    ├── operation.rs    # Rights, DidOperation, SignedDidOperation, SsiOperation
    ├── document.rs     # DidDocumentState (SDK-side), W3C DID Document builder
    └── signature.rs    # MultiSignature, MultiPublicKey, Ed25519 verification
```

---

## 15. Dependency Versions (polkadot-stable2503)

```toml
frame-support = { version = "38", default-features = false }
frame-system = { version = "38", default-features = false }
sp-runtime = { version = "39", default-features = false }
sp-std = { version = "14", default-features = false }
parity-scale-codec = { version = "3", features = ["derive", "max-encoded-len"] }
scale-info = { version = "2", features = ["derive"] }
```

Build the pallet with: `cargo test --manifest-path pallet-mosaic-did/Cargo.toml`
(It's excluded from the workspace due to Substrate dep conflicts with legacy IoP crates.)
