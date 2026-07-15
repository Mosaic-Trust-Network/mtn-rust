# Plan: Sr25519 (Schnorrkel) Support in keyvault

## Overview

Add two sr25519 cipher suites to keyvault:

1. **`Sr25519Substrate`** — Compatible with Substrate/Subkey/Polkadot-JS derivation
2. **`Sr25519Bip32`** — BIP32-compatible with schnorrkel chain codes, hardened + soft derivation

Both use the same underlying schnorrkel signing/verification but differ in key derivation,
extended key structure, and master key generation.

**SS58-formatted addresses** are produced via `SrPublicKey::to_ss58(network_prefix)`.
SS58 addresses encode the raw public key as their payload — they are not "key IDs,"
they are public keys wrapped in network-specific encoding.

**Key IDs** (`SrKeyId`) are the wallet's internal representation of an account identity
and come in two strategies:
- **Raw pubkey** (`Substrate` hasher) — the key ID IS the public key. This is what
  chains with `IdentityLookup` use natively. The public key is trivially extractable.
- **Blake3 hash** (`Blake3` hasher) — the key ID is blake3(pubkey). The public key
  is hidden until explicitly revealed by a transaction. Architecturally necessary for
  post-quantum signature schemes with large public keys (ML-DSA = 2592 bytes). Shares
  the `0x1e` version byte with Ed25519Blake3.

---

## Prerequisite: Add schnorrkel dependency

### `Cargo.toml` (workspace root)

Add to `[workspace.dependencies]`:

```toml
schnorrkel = { version = "0.11.5", default-features = false, features = ["alloc", "preaudit_deprecated"] }
merlin = { version = "3", default-features = false }
```

The `preaudit_deprecated` feature is required — it's what Polkadot/Substrate uses. Without
it, the signing context differs and produced signatures will not be interoperable.

### `keyvault/Cargo.toml`

Add under `[dependencies]`:

```toml
schnorrkel = { workspace = true }
merlin = { workspace = true }
```

`schnorrkel` is `no_std`-compatible, so no feature-gating drama.

---

## Part 1: Shared sr25519 primitives (`keyvault/src/sr25519/`)

Both cipher suites share the same signing key types, public key types, and signature types.
They differ only in derivation. This module provides the shared core.

### New files

```
keyvault/src/sr25519/
  mod.rs       — Module root, marker types, AsymmetricCrypto impls
  pk.rs        — SrPublicKey (wraps schnorrkel::PublicKey)
  sk.rs        — SrPrivateKey (wraps schnorrkel::SecretKey)
  sig.rs       — SrSignature (wraps schnorrkel::Signature)
  id.rs        — SrKeyId with raw pubkey + Blake3 hashing strategies
```

### `sr25519/mod.rs`

**Two separate marker types**, each implementing both `AsymmetricCrypto` and
`KeyDerivationCrypto`:

```rust
pub struct Sr25519Substrate;  // Substrate/Polkadot-JS compatible
pub struct Sr25519Bip32;      // BIP32-compatible with schnorrkel chain codes
```

Both share the same associated types:
- `KeyId = SrKeyId`
- `PublicKey = SrPublicKey`
- `PrivateKey = SrPrivateKey`
- `Signature = SrSignature`

They differ in `KeyDerivationCrypto`:
- `Sr25519Substrate` → `ExtendedPrivateKey = SrSubstrateExtPrivateKey`, `ExtendedPublicKey = SrSubstrateExtPublicKey`
- `Sr25519Bip32` → `ExtendedPrivateKey = SrBip32ExtPrivateKey`, `ExtendedPublicKey = SrBip32ExtPublicKey`

**Important:** Both are separate `AsymmetricCrypto` implementations so the multicipher
layer can dispatch them as different `CipherSuite` variants. This is unlike `Ed25519`
vs `Ed25519Blake3` (which share a single marker type) because here the extended key
types differ — not just the key ID hashing.

Signing context: `b"substrate"` (the Substrate default).

### `sr25519/sk.rs` (~50 lines)

Wraps `schnorrkel::SecretKey` (64 bytes: 32-byte scalar + 32-byte nonce seed).

```rust
pub const PRIVATE_KEY_SIZE: usize = schnorrkel::SECRET_KEY_LENGTH; // 64

pub struct SrPrivateKey(schnorrkel::SecretKey);

impl SrPrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> { /* 64 bytes */ }
    pub fn from_bytes<D: AsRef<[u8]>>(bytes: D) -> Result<Self> { /* schnorrkel::SecretKey::from_bytes */ }
}

impl PrivateKey<Sr25519Substrate> for SrPrivateKey { /* ... */ }
impl PrivateKey<Sr25519Bip32>     for SrPrivateKey { /* identical impl */ }
    fn public_key(&self) -> SrPublicKey { /* self.0.to_public() */ }
    fn sign<D: AsRef<[u8]>>(&self, data: D) -> SrSignature {
        let ctx = schnorrkel::signing_context(b"substrate");
        let sig = self.0.sign_simple(b"substrate", data.as_ref(), &self.0.to_public());
        SrSignature(sig)
    }
}
```

### `sr25519/pk.rs` (~100 lines)

Wraps `schnorrkel::PublicKey` (32 bytes, Ristretto compressed).

SS58 addresses are **just glorified public keys** — `base58(network_prefix ‖ pubkey ‖ checksum)`.
So the SS58 conversion methods live on `SrPublicKey`, not `SrKeyId`. The key ID is a
separate concept (a hashed or raw identifier for mapping to an account).

```rust
pub const PUBLIC_KEY_SIZE: usize = schnorrkel::PUBLIC_KEY_LENGTH; // 32

pub struct SrPublicKey(schnorrkel::PublicKey);

impl SrPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> { /* 32 bytes */ }
    pub fn from_bytes<D: AsRef<[u8]>>(bytes: D) -> Result<Self> { /* schnorrkel::PublicKey::from_bytes */ }

    /// Convert to a Substrate SS58 address.
    /// Network prefix 0 is the default (Polkadot).
    /// Format: base58(VERSION_BYTE(network_prefix) || pubkey_32_bytes || blake2b_256_checksum[..2])
    pub fn to_ss58(&self, network_prefix: u8) -> String {
        ss58_encode(network_prefix, &self.0.to_bytes())
    }

    /// The raw 32-byte public key — this IS the Substrate AccountId32.
    pub fn account_id(&self) -> [u8; 32] { self.0.to_bytes() }

    /// Create a MultiAddress<AccountId, Index> for use in Polkadot SDK extrinsics.
    /// Uses the `Id` variant (raw pubkey) — the standard Substrate default.
    pub fn to_multiaddress_id(&self) -> MultiAddress<AccountId32, u32> {
        MultiAddress::Id(AccountId32::from(self.account_id()))
    }

    /// Create a MultiAddress from an SS58-encoded string.
    pub fn from_ss58(address: &str) -> Result<(Self, u8)> {
        // Decode SS58, extract network prefix and pubkey
    }
}

impl PublicKey<Sr25519Substrate> for SrPublicKey { /* ... */ }
impl PublicKey<Sr25519Bip32>     for SrPublicKey { /* identical impl */ }
    fn key_id(&self) -> SrKeyId { SrKeyId::from(self) }
    fn validate_id(&self, id: &SrKeyId) -> bool { &self.key_id() == id }
    fn verify<D: AsRef<[u8]>>(&self, data: D, sig: &SrSignature) -> bool {
        let ctx = schnorrkel::signing_context(b"substrate");
        self.0.verify(ctx.bytes(data.as_ref()), &sig.0).is_ok()
    }
}
```

#### SS58 encoding (inline helper, ~30 lines)

SS58 is simple: version byte + payload + 2-byte blake2b-256 checksum, then base58.

```rust
fn ss58_encode(network_prefix: u8, pubkey: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(33);
    payload.push(network_prefix);
    payload.extend_from_slice(pubkey);

    let hash = blake2b_256(&payload);
    let mut full = payload;
    full.extend_from_slice(&hash[..2]);

    multibase::encode(multibase::Base::Base58Btc, &full)[1..].to_owned()
}
```

Uses `blake2` (already a workspace dependency) for blake2b-256.

**SS58 note:** The simple single-byte prefix encoding shown above works for network
prefixes 0–63 only (which covers the stated requirement of prefix 0 for Polkadot).
Full SS58 supports prefixes up to 2^14 with multi-byte encoding. If broader support
is needed later, the SS58 encoding can be extended without changing the key ID format.

### `sr25519/sig.rs` (~55 lines)

Wraps `schnorrkel::Signature` (64 bytes + 1 version byte = 65 bytes serialized).

```rust
pub const SIGNATURE_VERSION1: u8 = b'\x01';
pub const SIGNATURE_SIZE: usize = 64 + 1; // version byte + schnorrkel signature

pub struct SrSignature(schnorrkel::Signature);

impl SrSignature {
    pub fn to_bytes(&self) -> Vec<u8> { /* version byte + 64 bytes */ }
    pub fn from_bytes<D: AsRef<[u8]>>(bytes: D) -> Result<Self> { /* validate version, parse */ }
}
```

### `sr25519/id.rs` (~140 lines)

**Two hashing strategies for sr25519 key IDs.** The choice affects whether the public key
is trivially derivable from the key ID:

| Strategy | What it stores | Size | Recoverable? | Use case |
|----------|---------------|------|-------------|----------|
| `Substrate` | Raw 32-byte public key | 33 bytes | Yes — trivially | Identity-lookup chains: key ID IS the AccountId |
| `Blake3` | Blake3 hash of public key (like Ed25519Blake3) | 33 bytes | No — need explicit pubkey | Privacy + post-quantum: pubkey hidden until reveal |

Both use the same `SrKeyId` struct (variable-length byte buffer), versioned by prefix byte.

```rust
/// Version byte for raw public key key IDs.
/// 0x01 = raw 32-byte public key follows.
pub const KEY_ID_VERSION_RAW: u8 = b'\x01';

/// Version byte for Blake3-hashed key IDs (BIP32-style).
/// 0x1e = Blake3 multihash prefix, for cross-ref with ed25519 Blake3.
pub const KEY_ID_VERSION_BLAKE3: u8 = b'\x1e';

/// Size: version byte (1) + payload (32 bytes) = 33 bytes for both strategies.
pub const KEY_ID_SIZE: usize = 33;

pub struct SrKeyId(Vec<u8>);
```

The `SrIdHasher` trait with default `NETWORK_PREFIX: u8 = 0`:

```rust
pub trait SrIdHasher {
    /// The SS58 network prefix baked into this ID strategy for contextual display.
    /// Default is 0 (Polkadot).
    const NETWORK_PREFIX: u8 = 0;

    /// Version byte for serialization.
    const VERSION_BYTE: u8;

    /// Produce the inner payload bytes of the key ID from a public key.
    fn payload(pk: &SrPublicKey) -> Vec<u8>;
}

/// Raw public key strategy: stores the 32-byte public key as the ID payload.
/// The key ID IS the AccountId — no hashing, direct extraction.
/// Preferred for chains using `IdentityLookup` where AccountId = raw pubkey.
pub struct Substrate;

impl SrIdHasher for Substrate {
    const VERSION_BYTE: u8 = KEY_ID_VERSION_RAW;

    fn payload(pk: &SrPublicKey) -> Vec<u8> {
        pk.to_bytes() // raw 32-byte Ristretto public key
    }
}

/// Blake3-hashed: 32-byte blake3(pubkey) as the ID payload.
/// Public key is hidden until explicitly revealed. Compatible with
/// Ed25519Blake3's key ID strategy (same 0x1e version byte).
pub struct Blake3;

impl SrIdHasher for Blake3 {
    const VERSION_BYTE: u8 = KEY_ID_VERSION_BLAKE3;

    fn payload(pk: &SrPublicKey) -> Vec<u8> {
        blake3::hash(&pk.to_bytes()).as_bytes().to_vec()
    }
}
```

Key methods on `SrKeyId`:

```rust
impl SrKeyId {
    pub fn to_bytes(&self) -> Vec<u8> { self.0.clone() }

    pub fn from_bytes<D: AsRef<[u8]>>(bytes: D) -> Result<Self> {
        let bytes = bytes.as_ref();
        match bytes.first() {
            Some(&KEY_ID_VERSION_RAW) => {
                if bytes.len() != KEY_ID_SIZE { return Err(...); }
                Ok(Self(bytes.to_owned()))
            }
            Some(&KEY_ID_VERSION_BLAKE3) => {
                if bytes.len() != KEY_ID_SIZE { return Err(...); }
                Ok(Self(bytes.to_owned()))
            }
            Some(v) => Err(KeyvaultError::UnknownKeyIdVersion { version: *v }),
            None => Err(KeyvaultError::EmptyKeyIdBytes),
        }
    }

    pub fn from_pk<H: SrIdHasher>(pk: &SrPublicKey) -> Self {
        let mut bytes = Vec::with_capacity(1 + H::payload(pk).len());
        bytes.push(H::VERSION_BYTE);
        bytes.extend_from_slice(&H::payload(pk));
        Self(bytes)
    }

    /// Extract the raw 32-byte AccountId — only works for raw KeyIds.
    pub fn account_id(&self) -> Option<[u8; 32]> {
        match self.0.first() {
            Some(&KEY_ID_VERSION_RAW) => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&self.0[1..33]);
                Some(id)
            }
            _ => None, // Blake3-hashed IDs can't recover the pubkey
        }
    }
}

/// Default key ID derivation uses raw pubkey.
/// For a hashed key ID, use from_pk::<Blake3>(pk).
impl From<&SrPublicKey> for SrKeyId {
    fn from(pk: &SrPublicKey) -> Self {
        Self::from_pk::<Substrate>(pk)
    }
}
```

**SS58 is on `SrPublicKey`, not `SrKeyId`.** SS58 addresses encode the public key directly
(not the key ID), so `SrPublicKey::to_ss58(prefix)` is the correct API. The `NETWORK_PREFIX`
const on `SrIdHasher` is informational — it tells you which SS58 prefix was baked into
the ID strategy (primarily for UI display), but actual address encoding happens at the
public key level.

---

## Part 2: Substrate-compatible derivation (`keyvault/src/sr25519/substrate.rs`)

This variant matches Polkadot-JS/Subkey exactly.

### Master key derivation

```
BIP39 mnemonic + password
    │
    ▼
PBKDF2-HMAC-SHA512(entropy, "mnemonic" + password)
    │
    ▼
First 32 bytes = MiniSecretKey seed
    │
    ▼
schnorrkel::MiniSecretKey::from_raw(seed)
    │
    ▼
.expand(ExpansionMode::Ed25519)
    │
    ▼
Sr25519Substrate master keypair
```

No chain code at the master level. The Subkey convention generates one via
`hard_derive_mini_secret_key` when needed.

### Hard derivation

```rust
// Uses schnorrkel's native hard derivation with chain codes
fn derive_hard(parent_sk: &SecretKey, chain_code: &ChainCode, path_bytes: &[u8]) -> (SecretKey, ChainCode) {
    parent_sk.hard_derive_mini_secret_key(Some(*chain_code), path_bytes)
        .expand(ExpansionMode::Ed25519)
}
```

For Subkey compatibility, the path encoding must match:
- `//Alice` → `b"Alice"` (string bytes)
- `//0` → `b"0"` (string bytes, NOT numeric index)
- `//0/1` → hard derive with `b"0"`, then soft derive with `b"1"`

### Soft (public) derivation

```rust
// Schnorrkel's native soft derivation — works from public key
fn derive_soft(parent_pk: &PublicKey, chain_code: &ChainCode, cc: &[u8]) -> (PublicKey, ChainCode) {
    parent_pk.derived_key_simple(*chain_code, cc)
}
```

### New files

```
keyvault/src/sr25519/
  substrate.rs    — SrSubstrateExtPrivateKey, SrSubstrateExtPublicKey
```

### `SrSubstrateExtPrivateKey`

```rust
pub struct SrSubstrateExtPrivateKey {
    chain_code: ChainCode,
    sk: SrPrivateKey,
}
```

Implements `ExtendedPrivateKey<Sr25519Substrate>`:

```rust
fn derive_hardened_child(&self, idx: i32) -> Result<SrSubstrateExtPrivateKey> {
    // Encode idx as string bytes (Subkey convention)
    let path_bytes = idx.to_string().as_bytes().to_vec();
    // hard_derive_mini_secret_key returns (MiniSecretKey, ChainCode)
    let (new_mini, new_cc) = self.sk.0
        .hard_derive_mini_secret_key(Some(self.chain_code), &path_bytes);
    let new_sk = new_mini.expand(ExpansionMode::Ed25519);
    Ok(SrSubstrateExtPrivateKey {
        chain_code: ChainCode::from_bytes(new_cc)?,
        sk: SrPrivateKey::from(new_sk),
    })
}

fn derive_normal_child(&self, idx: i32) -> Result<SrSubstrateExtPrivateKey> {
    // Schnorrkel soft derivation works from SecretKey directly
    // SecretKey::derive_secret_key produces (SecretKey, ChainCode)
    // The index must be encoded the same way as for the BIP32 variant.
    let (new_sk, new_cc) = self.sk.0.derive_secret_key(
        self.soft_transcript(idx as u32),
        self.chain_code,
    );
    Ok(SrSubstrateExtPrivateKey {
        chain_code: new_cc,
        sk: SrPrivateKey::from(new_sk),
    })
}
```

**Important note on soft derivation:** schnorrkel's `SecretKey::derive_secret_key` operates
on the full keypair/secret key and takes a `SigningTranscript`, not raw bytes. The
`derived_key_simple` method on `PublicKey` is the public-key-only equivalent (for watch-only).
When the secret key is available, use `SecretKey::derive_secret_key(t, cc)` directly — the
produced `(SecretKey, ChainCode)` should derive the same public key as `PublicKey::derived_key_simple`.
You do NOT need to call both. Build the Merlin transcript consistent with what `derived_key_simple`
does internally:

```rust
fn soft_transcript(idx: u32) -> merlin::Transcript {
    let mut t = merlin::Transcript::new(b"SchnorrRistrettoHDKD");
    t.append_message(b"sign-bytes", &idx.to_be_bytes());
    t
}
```

### `SrSubstrateExtPublicKey`

```rust
pub struct SrSubstrateExtPublicKey {
    chain_code: ChainCode,
    pk: SrPublicKey,
}
```

Implements `ExtendedPublicKey<Sr25519Substrate>`:

```rust
fn derive_normal_child(&self, idx: i32) -> Result<SrSubstrateExtPublicKey> {
    // schnorrkel soft derivation from public key — this is the key advantage
    let (new_pk, new_cc) = self.pk.0.derived_key_simple(self.chain_code, &idx.to_be_bytes());
    Ok(SrSubstrateExtPublicKey {
        chain_code: new_cc,
        pk: SrPublicKey::from(new_pk),
    })
}
```

### Master derivation function

```rust
impl Sr25519Substrate {
    fn master(seed: &Seed) -> SrSubstrateExtPrivateKey {
        // PBKDF2 → 32 bytes, then schnorrkel MiniSecretKey
        let mini_secret = schnorrkel::MiniSecretKey::from_raw(seed_bytes_32);
        let secret_key = mini_secret.expand(ExpansionMode::Ed25519);
        // Derive master chain code deterministically — see Design Decisions
        let chain_code = derive_master_chain_code(seed);
        SrSubstrateExtPrivateKey { chain_code, sk: SrPrivateKey::from(secret_key) }
    }
}
```

---

## Part 3: BIP32-compatible derivation (`keyvault/src/sr25519/bip32.rs`)

This variant uses SLIP-10 HMAC-SHA512 for master key derivation, giving a proper chain
code from the start. Supports hardened + soft derivation with BIP32 numeric paths.

### Master key derivation

```
BIP39 mnemonic + password
    │
    ▼
PBKDF2-HMAC-SHA512(entropy, "mnemonic" + password) → 64-byte BIP39 seed
    │
    ▼
HMAC-SHA512(Key = "ed25519 seed", Data = seed)
    │
    ├─── Left 32 bytes → scalar → schnorrkel::SecretKey
    └─── Right 32 bytes → ChainCode (the BIP32 chain code!)
```

This is the same SLIP-10 master derivation that ed25519 uses in keyvault, but the
resulting scalar is fed into schnorrkel instead of ed25519-dalek.

### Hard derivation

Uses schnorrkel's `hard_derive_mini_secret_key(Some(chain_code), index.to_be_bytes())`.
The index is encoded as a 4-byte big-endian u32 (BIP32 convention), NOT as a string.

### Soft derivation

Uses schnorrkel's `derived_key_simple(chain_code, index.to_be_bytes())`.
Works from both private and public keys.

### Security properties

- **Hard derivation:** Compromising a child key does NOT compromise siblings or the parent
  (because the parent secret key feeds into the transcript, not just the chain code).
- **Soft derivation:** Compromising a child private key + parent chain code DOES compromise
  the parent (standard BIP32 property). This is why hardened derivation should be used
  for key material that must not leak.

### New files

```
keyvault/src/sr25519/
  bip32.rs     — SrBip32ExtPrivateKey, SrBip32ExtPublicKey
```

### `SrBip32ExtPrivateKey`

```rust
pub struct SrBip32ExtPrivateKey {
    depth: u8,
    parent_fingerprint: Vec<u8>,
    idx: u32,
    chain_code: ChainCode,
    sk: SrPrivateKey,
}
```

Same structure as `SecpExtPrivateKey`. Implements `ExtendedPrivateKey<Sr25519Bip32>`.

```rust
fn derive_hardened_child(&self, idx: i32) -> Result<SrBip32ExtPrivateKey> {
    if idx < 0 { return Err(KeyvaultError::NegativeDerivationIndex); }
    let idx = 0x8000_0000u32 + idx as u32;

    let (new_mini, new_cc) = self.sk.0.hard_derive_mini_secret_key(
        Some(self.chain_code),
        &idx.to_be_bytes()  // 4-byte big-endian, NOT string
    );
    let new_sk = new_mini.expand(ExpansionMode::Ed25519);

    let depth = self.depth + 1;
    let parent_fingerprint = self.fingerprint();

    Ok(SrBip32ExtPrivateKey {
        depth, parent_fingerprint, idx,
        chain_code: ChainCode::from_bytes(new_cc)?,
        sk: SrPrivateKey::from(new_sk),
    })
}

fn derive_normal_child(&self, idx: i32) -> Result<SrBip32ExtPrivateKey> {
    if idx < 0 { return Err(KeyvaultError::NegativeDerivationIndex); }
    let idx = idx as u32;

    let (new_sk, new_cc) = self.sk.0.derive_secret_key(
        self.soft_transcript(idx),
        self.chain_code
    );

    let depth = self.depth + 1;
    let parent_fingerprint = self.fingerprint();

    Ok(SrBip32ExtPrivateKey {
        depth, parent_fingerprint, idx,
        chain_code: new_cc,
        sk: SrPrivateKey::from(new_sk),
    })
}
```

Fingerprint: `blake2b_256(raw_32_byte_public_key)[..4]` — same BIP32 pattern as secp256k1
but using the raw 32-byte Ristretto public key directly (there is no "compressed" vs
"uncompressed" form for Ristretto — it's always 32 bytes).

### `SrBip32ExtPublicKey`

```rust
pub struct SrBip32ExtPublicKey {
    depth: u8,
    parent_fingerprint: Vec<u8>,
    idx: u32,
    chain_code: ChainCode,
    pk: SrPublicKey,
}
```

Implements `ExtendedPublicKey<Sr25519Bip32>`:

```rust
fn derive_normal_child(&self, idx: i32) -> Result<SrBip32ExtPublicKey> {
    let (new_pk, new_cc) = self.pk.0.derived_key_simple(self.chain_code, &idx.to_be_bytes());
    let depth = self.depth + 1;
    let parent_fingerprint = self.fingerprint();
    Ok(SrBip32ExtPublicKey {
        depth, parent_fingerprint, idx: idx as u32,
        chain_code: new_cc,
        pk: SrPublicKey::from(new_pk),
    })
}
```

### Extended key serialization

For `SrBip32ExtPrivateKey`, implement `to_xprv` / `from_xprv` with custom version
prefixes (like secp256k1 uses `xpub`/`xprv`):

```rust
// Custom version prefixes for sr25519 BIP32 extended keys
pub const SR25519_XPRV_PREFIX: [u8; 4] = [0x04, 0x35, 0x87, 0xD1]; // "sprv"
pub const SR25519_XPUB_PREFIX: [u8; 4] = [0x04, 0x35, 0x87, 0xFE]; // "spub"
```

Format: `version(4) + depth(1) + parent_fingerprint(4) + index(4) + chain_code(32) + pubkey(33)`
— base58check encoded. Same layout as BIP32 but with different version bytes.

---

## Part 4: Multicipher integration

### `CipherSuite` enum additions

In `multicipher/mod.rs`:

```rust
pub enum CipherSuite {
    Ed25519,
    Secp256k1,
    Ed25519Blake3,
    Sr25519Substrate,  // new
    Sr25519Bip32,      // new
}
```

Byte tags:
- `Sr25519Substrate` → `b'u'` (produces `iu...`, `pu...`, `su...` strings)
- `Sr25519Bip32` → `b't'` (produces `it...`, `pt...`, `st...` strings)

### Enum variant additions (mechanical, ~30 lines per file)

In each of `multicipher/{id,pk,sk,sig}.rs`, add:

```rust
// In MKeyId:
Sr25519Substrate(SrKeyId),
Sr25519Bip32(SrKeyId),

// In MPublicKey:
Sr25519Substrate(SrPublicKey),
Sr25519Bip32(SrPublicKey),

// In MPrivateKey:
Sr25519Substrate(SrPrivateKey),
Sr25519Bip32(SrPrivateKey),

// In MSignature:
Sr25519Substrate(SrSignature),
Sr25519Bip32(SrSignature),
```

Both sr25519 suites share the same underlying types (`SrKeyId`, `SrPublicKey`, etc.)
but are discriminated as different variants so they can never cross-verify.

### New error variants

In `error.rs`:

```rust
/// Invalid sr25519 public key length.
#[error("Invalid sr25519 public key length: expected {expected}")]
Sr25519PublicKeyLength { expected: usize },

/// Invalid sr25519 secret key length.
#[error("Invalid sr25519 secret key length: expected {expected}")]
Sr25519SecretKeyLength { expected: usize },

/// Normal derivation is not supported for this sr25519 variant.
#[error("Normal derivation not supported for Sr25519Substrate")]
Sr25519SubstrateNormalDerivationInvalid,
```

---

## Part 5: `lib.rs` module registration

```rust
pub mod sr25519;
```

And add `schnorrkel` and `merlin` to the `extern crate` if needed.

---

## Part 6: Tests

### `sr25519/mod.rs` tests (~200 lines)

```rust
#[cfg(test)]
mod tests {
    // Cross-implementation test vectors from Polkadot-JS/Subkey
    // These must produce the EXACT same keys and addresses.

    #[test]
    fn substrate_master_from_mnemonic() {
        // Known mnemonic → known public key → known SS58 address
        // Verify against Polkadot-JS output
    }

    #[test]
    fn substrate_hard_derivation() {
        // mnemonic + "//Alice" → known public key
    }

    #[test]
    fn substrate_soft_derivation() {
        // mnemonic + "/1" from public key → known derived public key
    }

    #[test]
    fn bip32_master_from_seed() {
        // Same BIP39 seed → different master key than Substrate variant
        // (because SLIP-10 HMAC-SHA512 vs PBKDF2→32 bytes)
    }

    #[test]
    fn bip32_hard_derivation() {
        // m/44'/0'/0' path → known keys
    }

    #[test]
    fn bip32_soft_derivation() {
        // m/44'/0'/0'/0/0 — derive from public key, verify matches private derivation
    }

    #[test]
    fn cross_suite_verification_fails() {
        // Sr25519Substrate signature does NOT verify with Sr25519Bip32 public key
    }

    #[test]
    fn sign_verify_roundtrip() {
        // Basic sign/verify for both suites
    }
}
```

### `sr25519/id.rs` tests (~100 lines)

```rust
#[test]
fn key_id_string_roundtrip() {
    // Create key ID, serialize to string, parse back
}

#[test]
fn account_id_matches_substrate() {
    // SrKeyId(Substrate)::account_id() == raw public key bytes
    // SrPublicKey::to_ss58(0) matches Polkadot-JS address for same key
}

#[test]
fn different_network_prefixes() {
    // Same key, different SS58 prefixes → different addresses
}
```

### `multicipher/` tests (~100 lines)

```rust
#[test]
fn sr25519_substrate_multicipher_roundtrip() {
    // MPrivateKey::Sr25519Substrate → sign → MPublicKey → verify
    // String roundtrip: "pu..." public key, "iu..." key id
}

#[test]
fn sr25519_bip32_multicipher_roundtrip() {
    // Same for Sr25519Bip32: "pt..." public key, "it..." key id
}

#[test]
fn cross_suite_sign_verify_fails() {
    // Substrate key cannot verify Bip32 signature and vice versa
}
```

---

## File-by-file summary

| File | New/Modified | ~Lines | Description |
|------|-------------|--------|-------------|
| `Cargo.toml` (workspace) | Modified | 2 | Add schnorrkel + merlin deps |
| `keyvault/Cargo.toml` | Modified | 2 | Add schnorrkel + merlin deps |
| `sr25519/mod.rs` | New | 80 | Marker type, AsymmetricCrypto impl |
| `sr25519/pk.rs` | New | 120 | PublicKey, SS58 encoding, MultiAddress |
| `sr25519/sk.rs` | New | 70 | PrivateKey, sign |
| `sr25519/sig.rs` | New | 60 | Signature serialize/deserialize |
| `sr25519/id.rs` | New | 160 | KeyId, Substrate + Blake3 hashers |
| `sr25519/substrate.rs` | New | 150 | Substrate-compatible ext keys |
| `sr25519/bip32.rs` | New | 200 | BIP32-compatible ext keys |
| `multicipher/mod.rs` | Modified | 15 | CipherSuite variants |
| `multicipher/id.rs` | Modified | 30 | MKeyId variants + dispatch |
| `multicipher/pk.rs` | Modified | 30 | MPublicKey variants + dispatch |
| `multicipher/sk.rs` | Modified | 15 | MPrivateKey variants + dispatch |
| `multicipher/sig.rs` | Modified | 15 | MSignature variants + dispatch |
| `error.rs` | Modified | 15 | New error variants |
| `lib.rs` | Modified | 1 | `pub mod sr25519;` |
| Tests | New | ~500 | Cross-impl vectors, roundtrips |
| **Total** | | **~1400** | |

---

## Design decisions & open questions

### Chain code type interop

schnorrkel defines its own `schnorrkel::derive::ChainCode([u8; 32])` type, distinct from
keyvault's `crate::ChainCode([u8; 32])`. They are layout-compatible but type-distinct.
Add conversion helpers:

```rust
impl From<schnorrkel::derive::ChainCode> for ChainCode {
    fn from(cc: schnorrkel::derive::ChainCode) -> Self {
        ChainCode::from_bytes(&cc.0).expect("32 bytes always valid")
    }
}

impl From<ChainCode> for schnorrkel::derive::ChainCode {
    fn from(cc: ChainCode) -> Self {
        schnorrkel::derive::ChainCode(cc.to_bytes())
    }
}
```

Place these in `sr25519/mod.rs` or a dedicated `sr25519/derive.rs`.

### `Sr25519Substrate` master chain code

The Subkey convention doesn't generate a chain code at the master level — it only
produces chain codes on demand via `hard_derive_mini_secret_key`. For the keyvault HD
wallet, a deterministic chain code is needed at the master level for consistent
derivation. Derive it via `blake3::hash(&full_64_byte_bip39_seed)[..32]`. This ensures:
- The same seed always produces the same master chain code
- The master chain code is independent of the MiniSecretKey seed
- The chain code exists before any derivation step

### Key reuse: shared `SrPrivateKey` between suites

Both `Sr25519Substrate` and `Sr25519Bip32` share the same `SrPrivateKey` / `SrPublicKey` /
`SrSignature` types. A `SrPrivateKey` created via Substrate derivation can be wrapped
as either `MPrivateKey::Sr25519Substrate(...)` or `Sr25519Bip32(...)` — the signing key
is the same, only the suite tag and key ID derivation context differ. This is intentional
and mirrors how `Ed25519` vs `Ed25519Blake3` reuse `EdPrivateKey`.

### Concrete test vectors needed

For the Substrate-compatible variant, pin these well-known vectors:
- **`//Alice` dev account:** The standard Substrate dev mnemonic `bottom drive obey lake curtain smoke basket hold race lonely fit walk` with derivation `//Alice` → known public key and SS58 address (prefix 42 for generic Substrate, or prefix 0 per the plan)
- **Subkey generate output:** A known mnemonic → known `Secret seed`, `Public key (hex)`, and SS58 Address

For the BIP32-compatible variant, pin SLIP-10 test vectors using schnorrkel:
- Seed `00010203...0e0f` → HMAC-SHA512(`"ed25519 seed"`, seed) → known scalar + chain code
- Verify the scalar expands to a valid schnorrkel SecretKey via `MiniSecretKey::from_raw` → `expand(Ed25519)`

### `no_std` verification

Both `schnorrkel` and `merlin` support `no_std` with `alloc`. The keyvault crate already
handles this. Run `cargo check -p iop-keyvault --no-default-features` after adding the
dependencies to confirm nothing breaks.

### `From` impls for multicipher

Follow the existing pattern — add `From<SrPublicKey>` for `MPublicKey`, `From<SrPrivateKey>`
for `MPrivateKey`, `From<SrSignature>` for `MSignature`, `From<SrKeyId>` for `MKeyId`.
Default `From` conversions go to the Substrate variant (following how `EdPublicKey` →
`MPublicKey::Ed25519` is the default).

### AccountId vs PublicKey: the Substrate `AccountIdLookup` story

In Substrate, `frame_system::Config` has:

```rust
type AccountId: ... ;        // the on-chain identifier
type Lookup: AccountIdLookup<Self::AccountId>;  // maps external addresses → AccountId
```

`AccountIdLookup` takes a `Source` type and maps it to `AccountId`:

```rust
pub trait AccountIdLookup<AccountId> {
    type Source;                          // what users send in extrinsics
    fn lookup(id: Self::Source) -> AccountId;  // resolve to on-chain AccountId
}
```

**Default setup** (99% of chains, including Polkadot and your Mosaic DID pallet):

```rust
type AccountId = AccountId32;  // wraps [u8; 32] — the raw pubkey
type Lookup = IdentityLookup<AccountId>;  // Source == AccountId == raw pubkey
```

With `IdentityLookup`, the address IS the pubkey. No lookup needed — it's the identity
function. This is why SS58 addresses use the raw pubkey as payload.

### When AccountId IS the hash (post-quantum compatible)

The user wants `AccountId = SrKeyId(blake3(pubkey))`. This redefines AccountId itself,
not just the Lookup. Storage keys become 32-byte hashes, and the pubkey moves into the
`Signature` bundle. This is architecturally necessary for post-quantum signatures with
large public keys (e.g., ML-DSA-87 = 2592 bytes).

```
Storage:  StorageMap<AccountId, AccountInfo>
          → key = blake3(pubkey), 32 bytes always (sr25519, ed25519, or 2.5KB PQ pubkey)

Extrinsic signature field:
   (AccountId = hash, Signature = {pubkey + crypto_sig}, Extra = {nonce, tip, mortality})
                                          ^^^^^^
                                    bundled by the wallet,
                                    verified by the runtime:
                                    blake3(pubkey) == AccountId && verify(crypto_sig, msg, pubkey)
```

The `Verify` trait impl for this setup:

```rust
/// Signature type for hash-based AccountIds.
/// Bundles the public key with the cryptographic signature so the runtime
/// can verify: hash(pubkey) == AccountId AND sr25519_verify(sig, msg, pubkey).
pub struct Sr25519Signed {
    pub pubkey: [u8; 32],
    pub sig: Msr25519Sig,  // 64-byte schnorrkel signature
}

impl Verify<AccountId> for Sr25519Signed {
    fn verify(msg: &[u8], signer: &AccountId, self_: &Self) -> bool {
        // signer.0 is SrKeyId bytes: [version_byte | blake3_hash]
        let expected = &signer.0[1..33];
        blake3::hash(&self_.pubkey).as_bytes() == expected
            && sr25519_verify(&self_.sig, msg, &self_.pubkey)
    }
}
```

The `Lookup` trait handles multi-format destination addresses (SS58 blob, raw hash, etc.)
all resolving to the same `AccountId`. It's an encoding layer, not a privacy layer.

### When the pubkey is revealed

In the hash-based AccountId model:

| Scenario | Pubkey exposed? |
|----------|-----------------|
| Share AccountId/key ID | **No** — only the 32-byte Blake3 hash |
| Receive tokens (anyone sends to your AccountId) | **No** — storage is keyed by hash |
| Balance inquiry | **No** — only need the AccountId (= hash) |
| Sign and submit first extrinsic | **Yes** — pubkey is in the Signature bundle, published on-chain |
| DID document published on-chain | **Yes** — DID document contains `publicKey` |
| Never transact | **Hidden forever** |

This is identical to Bitcoin's P2PKH model: the address is `hash160(pubkey)`, the pubkey
is only revealed when you spend.

### Post-quantum consistency

The 32-byte Blake3 AccountId is cipher-agnostic. Whether today's sr25519 (32-byte pubkey)
or tomorrow's ML-DSA (2592-byte pubkey), the AccountId is always 32 bytes. Only the
`Signature` bundle size changes. The wallet can use the same key ID format across all
cipher suites, and post-quantum migration is a matter of adding a new `Signature` variant.

---

## Implementation order

1. **Dependencies** — Add schnorrkel + merlin to workspace and keyvault Cargo.toml
2. **Shared core** — `sr25519/{mod,pk,sk,sig,id}.rs` with sign/verify, no derivation
3. **Tests** — Pin test vectors for sign/verify from known sr25519 keypairs
4. **Substrate ext keys** — `sr25519/substrate.rs`, verify against Polkadot-JS vectors
5. **BIP32 ext keys** — `sr25519/bip32.rs`, verify SLIP-10 master + schnorrkel derivation
6. **Multicipher** — Add variants, string roundtrips, cross-suite failure tests
7. **SS58** — Verify `to_ss58(0)` matches Polkadot-JS for known keys

Each step should compile and pass tests before moving to the next.
