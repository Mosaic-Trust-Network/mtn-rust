# EUDI Credential Plan — SD‑JWT & ISO mDL Support

> **Status:** Architectural assessment — not yet implemented.
> **Scope:** Credential-format layer required for EUDI Wallet (eIDAS 2.0) compliance on top
> of the `off-chain-impersonation-plan.md` authorization layer.

---

## 1. Problem Statement

The `off-chain-impersonation-plan.md` defines the authorization architecture: a DID controller
publishes a commitment to an off‑chain **rights document** that maps `key_ref → rights`. A
verifier checks whether the holder's signing key had the `Impersonate` right at the time a
claim was made. The plan defines a custom credential format (`json_digest` +
AfterProof/BeforeProof/SMT) for time‑bounded native attestations.

The European Digital Identity Wallet (EUDI Wallet, Regulation EU 2024/1183) mandates specific
credential formats that the native model does not support:

- **PID & QEAA:** SD‑JWT‑VC (RFC 9596) — JSON‑based selective disclosure with salted hashes,
  JWS signing, and Key Binding JWTs for holder binding.
- **mDL / mdoc:** ISO/IEC 18013‑5 — CBOR‑encoded credentials with `MobileSecurityObject`,
  COSE‑Sign1 signatures, namespace‑based data‑element release, and device‑engagement protocols.

Both formats differ fundamentally from the plan's BLAKE3‑Merkle‑tree approach in selective
disclosure, signature encoding, and holder binding. The plan's architecture is correct,
but incomplete: it provides the **authorization chec** (does key X have the right to act for DID Y?)
without the **credential‑format adapter** (how does a verifier extract key X from an SD‑JWT
or mDL presentation to feed it into the rights check?).

After analyzing both plan files (`off-chain-impersonation-plan.md`, `keyvault-plan.md`) and
the current codebase (`keyvault`, `mosaic-did-types`, `json-digest`, `vault`, `pallet-mosaic-did`),
the following gaps exist between the planned architecture and EUDI‑compliant credential presentation:

| Gap | Description |
|-----|-------------|
| **Gap A** | No SD‑JWT / JOSE stack — RFC 9596 encoding, `_sd_hash`, disclosures, Key Binding JWT |
| **Gap B** | No ISO/IEC 18013‑5 (mdoc) support — CBOR/COSE parsing, `MobileSecurityObject`, device engagement |
| **Gap C** | No credential‑format abstraction — verifier algorithm assumes only the native proof‑bundle format |
| **Gap D** | Claims (PII) vs. rights (authorization) — the plan's rights document is not a credential, and EUDI credentials are not rights documents |
| **Gap E** | No credential‑type → required‑right mapping or issuer accreditation check |
| **Gap F** | No wallet‑side credential storage, selective‑disclosure construction, or presentation assembly |

---

## 2. How the Architecture Composes

The off‑chain impersonation proofs and regulated credential verifications compose **in series**,
not in parallel. A valid EUDI presentation must satisfy both:

```
                    ┌─────────────── REGULATED VERIFICATION PIPELINE ───────────────┐
                    │                                                               │
                    │   ┌── Authorization check (impersonation plan) ───────────┐   │
                    │   │                                                        │   │
  SD‑JWT / mDL      │   │  1. Extract holder key from credential format         │   │
  presentation ─────┤───▶  2. Map holder key → key_ref → DID                    │   │
                    │   │  3. Check DID liveness (§7.2 Step 5 of the plan)      │   │
                    │   │  4. Check key validity window (§7.2 Step 3)           │   │
                    │   │  5. Check Impersonate right via commitment doc (§7.2  │   │
                    │   │     Step 4) with time‑bounding per proof strength     │   │
                    │   │                                                        │   │
                    │   └────────────────────────────────────────────────────────┘   │
                    │                        │                                        │
                    │                        ▼                                        │
                    │   ┌── Credential check (credential‑format layer) ──────────┐   │
                    │   │                                                        │   │
                    │   │  6. Verify issuer signature (JWS / COSE‑Sign1)         │   │
                    │   │  7. Verify selective‑disclosure integrity              │   │
                    │   │  8. Check issuer accreditation (trust framework)       │   │
                    │   │  9. Check credential revocation (status list)          │   │
                    │   │                                                        │   │
                    │   └────────────────────────────────────────────────────────┘   │
                    │                                                               │
                    └───────────────────────────────────────────────────────────────┘
```

The **impersonation proof** (steps 1–5) answers: _"Does the holder key have the right to
present this DID's credentials?"_  
The **credential proof** (steps 6–9) answers: _"Are the claims authentic and attested by a
legitimate issuer?"_

Both layers are necessary; neither is sufficient alone.

### 2.1 Proof‑Strength Degradation for Regulated Verifications

The plan's three proof strengths (§6.1) map to EUDI contexts:

| Proof strength | EUDI equivalent | Requirements |
|---------------|-----------------|--------------|
| `MinimalProof` | Peer‑to‑peer presentation | TOFU time bounds; verifier trusts that the credential was not revoked since presentation |
| `AfterProof` | Regulated B2B/travel‑authority check | Lower time‑bound required by regulation (proves credential was presented *after* a given timestamp) |
| `FinalizedProof` | Notarized / court‑admissible audit | Full cryptographic time‑window; both lower and upper bounds anchored on‑chain |

For eIDAS High‑LoA credentials, regulation typically requires at least `AfterProof`‑strength
time‑bounding. The verifier policy (§7.3) must be configurable per credential type and
verifier jurisdiction.

---

## 3. Gap‑by‑Gap Detail

### 3.1 Gap A: No SD‑JWT / JOSE Stack

SD‑JWT (RFC 9596) is a **credential format**, not a selective‑disclosure primitive on its own.
It builds on:

```
JWS (RFC 7515)                        → signed payload (Issuer‑signed JWT)
  └── SD‑JWT (RFC 9596)              → salted disclosure hashes, `_sd` + `_sd_hash`
       └── Key Binding JWT            → holder‑signed JWT binding the presentation to a verifier
```

The plan's selective disclosure uses `json_digest` — a BLAKE3‑256 Merkle tree over a
canonicalized JSON document (§3.5.1 of the plan). This is structurally incompatible with
SD‑JWT:

| Aspect | Plan's `json_digest` model | SD‑JWT (RFC 9596) |
|--------|---------------------------|-------------------|
| Hash function | BLAKE3‑256 | SHA‑256 |
| Selective disclosure | Merkle‑tree leaf replacement (`cmXXXX...` content IDs for undisclosed siblings) | Individual salted hashes per undisclosed claim; `_sd_hash` = SHA‑256 over concatenated salted digests |
| Signature envelope | `Signed<AfterEnvelope<SmtContent>>` | JWS Compact Serialization |
| Holder binding | `AfterProof` / `BeforeProof` with SMT | Key Binding JWT with `cnf.kid`, `nonce`, `aud` |
| Disclosure object | Opaque `cmXXXX...` hash | Clear‑text `Disclosure` array element: `[salt, claim_name, claim_value]` |
| Credential ID | Custom (`cm` prefix) | JWT `jti` claim or issuer‑specific mechanism |

**Required:** A new crate `iop-sd-jwt` that implements:

```rust
/// Issuer‑signed SD‑JWT token.
pub struct SdJwt {
    /// The JWS compact serialization of the Issuer‑signed JWT.
    pub iss_signed: String,
    /// Disclosure objects for selectively disclosable claims.
    pub disclosures: Vec<Disclosure>,
    /// Optional Key Binding JWT (holder‑signed).
    pub kb_jwt: Option<String>,
}

/// A single disclosure for one claim in an SD‑JWT.
pub struct Disclosure {
    /// The raw JSON array [salt, claim_name, claim_value].
    pub raw: String,
    /// The base64url‑encoded SHA‑256 digest used in `_sd_hash`.
    pub digest: Vec<u8>,
    /// Parsed claim name.
    pub claim_name: String,
    /// Parsed claim value.
    pub claim_value: serde_json::Value,
}

pub struct SdJwtVerifier {
    /// Verify the Issuer‑signed JWT signature against the issuer's public key.
    pub fn verify_issuer_signature(sd_jwt: &SdJwt, issuer_key: &MPublicKey) -> bool;
    /// Validate `_sd_hash` against all present disclosures.
    pub fn verify_disclosure_integrity(sd_jwt: &SdJwt) -> bool;
    /// Verify the Key Binding JWT signature against the holder's public key.
    pub fn verify_kb_jwt(sd_jwt: &SdJwt, holder_key: &MPublicKey, nonce: &str, aud: &str) -> bool;
    /// Extract the holder key reference from the KB‑JWT `cnf.kid`.
    pub fn holder_key_ref(sd_jwt: &SdJwt) -> Option<KeyRef>;
}
```

**Dependencies not yet in the workspace:**
- JOSE crate (e.g., `josekit` or `jsonwebtoken`) for JWS handling
- SHA‑256 is already available via `sha2` (workspace dep)

Eurosign / eIDAS PID profile specifics (e.g., `vct`, `cnf` claims, issuer‑attested attributes
like `given_name`, `family_name`, `birth_date`) must be supported as a concrete profile on top
of the generic SD‑JWT implementation.

### 3.2 Gap B: No ISO/IEC 18013‑5 (mdoc / mDL) Support

ISO 18013‑5 is structurally different from both the plan's native format and SD‑JWT:

| Aspect | Plan | mDL/mdoc |
|--------|------|----------|
| Encoding | JSON (canonicalized) | CBOR (RFC 8949) |
| Signature | Ed25519/Sr25519 native | COSE‑Sign1 (RFC 8152) with X.509 or C509 certificates |
| Document structure | Flat object with Merkle‑tree array entries | `IssuerSigned` → `NameSpaces` → `IssuerSignedItemBytes` |
| Selective disclosure | Merkle‑proof subset | Namespace‑based data‑element release |
| Holder binding | AfterProof/BeforeProof | `DeviceAuthentication` with `SessionTranscript` + `DeviceKey` |
| Transport | Application‑layer | NFC / QR (device engagement / retrieval) |

An mDL/MobileSecurityObject has:

```
MobileSecurityObject {
    version: "1.0",
    digestAlgorithm: "SHA‑256",
    valueDigests: {
        "org.iso.18013.5.1": {
            "family_name": <SHA‑256 hash>,
            "given_name": <SHA‑256 hash>,
            "birth_date": <SHA‑256 hash>,
            "issue_date": <SHA‑256 hash>,
            ...
        }
    },
    deviceKeyInfo: <COSE_Key>,
    docType: "org.iso.18013.5.1.mDL",
    validityInfo: { signed: <tdate>, validFrom: <tdate>, validUntil: <tdate> }
}
```

**Required:** A new crate `iop-mdoc` that implements:

```rust
pub struct MdocDocument {
    pub doc_type: String,
    pub issuer_signed: IssuerSigned,
    pub device_signed: Option<DeviceSigned>,
}

pub struct IssuerSigned {
    pub namespaces: BTreeMap<String, Vec<IssuerSignedItem>>,
    pub issuer_auth: CoseSign1, // COSE‑Sign1 with MobileSecurityObject payload
}

pub struct MobileSecurityObject { /* see above */ }

pub struct MdocVerifier {
    pub fn verify_issuer_auth(doc: &MdocDocument, trust_anchor: &[u8]) -> bool;
    pub fn verify_value_digests(doc: &MdocDocument) -> bool;
    pub fn verify_device_auth(
        doc: &MdocDocument,
        session_transcript: &[u8],
    ) -> bool;
    pub fn holder_key_ref(doc: &MdocDocument) -> Option<KeyRef>;
}
```

**Dependencies not yet in the workspace:**
- CBOR crate (e.g., `ciborium` or `serde_cbor`)
- COSE crate (or manual COSE‑Sign1 construction)
- X.509 / C509 certificate chain validation (for issuer trust)
- The `tdate` (CBOR tagged `1004`) date type needs mapping to block heights or external trust anchors

### 3.3 Gap C: No Credential‑Format Abstraction

The verifier algorithm in §7.2 of the plan operates on a single `presentationProof` type
(`MinimalProof` / `AfterProof` / `FinalizedProof`). A regulated verifier must accept
at least three distinct presentation formats. Each extracts holder identity, time‑bounds,
and claims differently:

| Format | Holder key extraction | Time bounds | Claim extraction |
|--------|----------------------|-------------|-----------------|
| Native (`Signed<AfterEnvelope>`) | `signedEnvelope.signature.publicKey` | `AfterProof.blockHeight` + `BeforeProof.blockHeight` | `blake3_struct(rightsDocument)` |
| SD‑JWT | `kb_jwt.cnf.kid` → key_ref | `iat`/`nbf` (JWT claims) + optional AfterProof | Disclosure‑reconstructed JSON |
| mdoc | `MobileSecurityObject.deviceKeyInfo` → key_ref | `validityInfo.validFrom`/`validUntil` | Namespace‑filtered claims |

**Required:** A `CredentialFormat` type in `mosaic-did-types`:

```rust
/// A normalized representation of any credental presentation,
/// independent of the format it was received in.
#[derive(Clone, Debug)]
pub struct NormalizedPresentation {
    pub holder_key_ref: KeyRef,
    pub issuer_did: Did,
    /// The earliest provable block height for this presentation.
    /// None if no lower time‑bound was provided.
    pub lower_time_bound: Option<u32>,
    /// The latest provable block height for this presentation.
    /// None if no upper time‑bound was provided (TOFU — trust "now").
    pub upper_time_bound: Option<u32>,
    /// The claims attested by the issuer (key‑value pairs).
    pub claims: Vec<(String, serde_json::Value)>,
    /// The credential format that carried this presentation.
    pub format: CredentialFormat,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialFormat {
    /// Native off‑chain‑impersonation proof bundle.
    NativeProof,
    /// SD‑JWT‑VC (RFC 9596, EUDI PID profile).
    SdJwt,
    /// ISO/IEC 18013‑5 mdoc / mDL.
    Mdoc,
    /// W3C Verifiable Credential Data Model 1.1 / 2.0.
    W3cVc,
}

/// Implemented by each credential‑format verifier.
/// Produces a NormalizedPresentation that feeds into the
/// existing DidHistory::has_right_at() pipeline.
pub trait CredentialVerifier {
    fn normalize(&self, raw_presentation: &[u8]) -> Result<NormalizedPresentation>;
}
```

With `CredentialVerifier::normalize()`, the verifier algorithm in §7.2 becomes
format‑agnostic:

```
verify_presentation(raw_bytes, format_hint):
    verifier = resolve_verifier(format_hint)       // SD‑JWT, mdoc, or native
    np = verifier.normalize(raw_bytes)              // → NormalizedPresentation

    // Now feed into the existing rights‑check pipeline:
    verify_key_validity(np.holder_key_ref, np.lower_time_bound, np.upper_time_bound)
    verify_right(np.holder_key_ref, Right::Impersonate, …)
    verify_did_liveness(np.issuer_did, …)
    return VerificationResult { claims: np.claims, format: np.format, … }
```

### 3.4 Gap D: Claims (PII) vs. Rights (Authorization)

The plan's rights document (§3.5) is:

```json
{
  "$schema": "https://mosaic-trust.net/ns/did-rights/v1",
  "rights": [
    { "keyRef": "ioz9vVgYENonuJJRpaX1skzMfehqZc5bYsMCotYG97EAunqH", "rights": ["impersonate"] },
    { "keyRef": "iozXyZ9AbC3DfG7HjK2MnP5QrSt8UvW1Yz4BcE6FgH9Jk",  "rights": ["issue", "revoke"] }
  ]
}
```

This grants authorization — it does not carry PII claims. An SD‑JWT PID credential carries:

```json
{
  "sub": "did:mosaic:iozBRP...",
  "vct": "urn:eu.europa.ec.eudi:pid:1",
  "given_name": "Alice",
  "family_name": "Smith",
  "birth_date": "1980-03-15",
  "_sd": ["ixpEV...", "GNZxd...", ...],
  "_sd_hash": "sha256_of_concat_salted_hashes",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } }
}
```

These are different documents with different purposes. The bridge is:

1. **Holder binding:** the SD‑JWT `cnf.kid` or `cnf.jwk.x` identifies the holder key.
   This key's public key is looked up to find its `key_ref`.
2. **Authorization check:** `DidHistory::has_right_at(key_ref, Right::Impersonate, height, resolver)`
   confirms this key had the right at signing time.
3. **Claim extraction:** The normalized presentation carries the actual PII claims
   (name, DoB, etc.) for the verifier's business logic.

Three specific bridges need explicit design:

#### 3.4.1 Key reference resolution

```rust
/// Map a public key (from SD‑JWT cnf.jwk or mdoc deviceKey)
/// to a mosaic key_ref for rights lookup.
pub trait KeyRefResolver {
    fn resolve(&self, public_key: &MPublicKey) -> Option<KeyRef>;
}
```

For Ed25519Blake3 keys where `key_ref = blake3(pk)`, resolution is a hash computation.
For raw‑pubkey sr25519 (from `keyvault-plan.md`), resolution requires an index of
`DID → key_ref → pubkey` mappings from the chain or DID document.

#### 3.4.2 Credential‑type → required‑right mapping

```rust
/// Which right must the holder key have to present this credential type?
pub fn required_right_for_credential(format: CredentialFormat, vct: &str) -> Right {
    match format {
        CredentialFormat::NativeProof => Right::Impersonate,
        CredentialFormat::SdJwt | CredentialFormat::W3cVc => {
            // EUDI PID / QEAA → Impersonate
            // For issue rights, the verifier checks the issuer DID, not the holder
            Right::Impersonate,
        }
        CredentialFormat::Mdoc => Right::Impersonate, // same for mDL
    }
}
```

#### 3.4.3 Privacy

**No PII ever touches the chain.** The DID document and commitment document contain only:

```
┌─ On‑chain (public, permanent) ───────────────────────────────┐
│  DidState:                                                     │
│   ├─ keys          → pubkeys, key_refs           (no PII)     │
│   ├─ rights        → (Update, Delegate)          (no PII)     │
│   ├─ commitment    → blake3(rights‑document)     (no PII)     │
│   └─ nonces        → u64 counters                (no PII)     │
└───────────────────────────────────────────────────────────────┘

┌─ Off‑chain (private, holder's wallet) ───────────────────────┐
│  SD‑JWT PID Credential:                                      │
│   ├─ given_name, family_name, birth_date           (PII)     │
│   ├─ cn.kid → holder DID key                     (pubkey)    │
│   └─ issuer: did:mosaic:iozBRP…              (public DID)    │
│                                                              │
│  Rights Document:                                            │
│   ├─ keyRefs → right mappings                  (no PII)     │
│   └─ previousCommitment hash chain              (no PII)     │
└──────────────────────────────────────────────────────────────┘
```

This is the same privacy boundary already described in §5.3 of the impersonation plan,
extended to SD‑JWT and mDL credentials. The architecture guarantees that the chain
never sees names, birth dates, national ID numbers, or device serial numbers.

### 3.5 Gap E: Credential Type Registry & Issuer Accreditation

EUDI‑compliant verifiers need two additional checks beyond what the plan provides:

#### 3.5.1 Credential‑type → required‑right registry

The plan's `has_right_at()` checks whether a key holds a specific right. It does not
know *which* right a given credential format requires. This mapping is static for
standard credential types but must be extensible for custom attestations:

```rust
#[derive(Clone, Debug)]
pub struct CredentialTypePolicy {
    /// e.g., "urn:eu.europa.ec.eudi:pid:1"
    pub vct: String,
    /// The right the holder must have.
    pub required_holder_right: Right,
    /// The right the issuer must have.
    pub required_issuer_right: Right,
    /// Whether the verifier must check issuer accreditation.
    pub requires_issuer_accreditation: bool,
}

pub trait CredentialTypeRegistry {
    fn policy(&self, vct: &str) -> Option<CredentialTypePolicy>;
}
```

#### 3.5.2 Issuer accreditation

EU member states accredit PID issuers. A verifier must confirm that the issuing DID
is operated by an accredited entity. This is trust‑framework‑level logic outside the
pallet:

```rust
pub trait AccreditationVerifier {
    /// Check whether the issuer DID is accredited for a given credential type
    /// at a given block height.
    fn is_accredited(&self, issuer_did: &Did, vct: &str, height: u32) -> bool;
}
```

Implementation options:
- **On‑chain:** accredited issuer DIDs listed in chain governance (a trust‑list pallet or `Sudo`‑managed storage)
- **Off‑chain:** EUDI trust‑list XML/JSON, resolved by the verifier at presentation time
- **Hybrid:** trust‑list root anchored on‑chain, leaf accreditation resolved off‑chain with Merkle proof

The `AccreditationVerifier` trait allows all three without changing the credential‑verification
pipeline.

### 3.6 Gap F: Wallet‑Side Credential Management

The plan is verifier‑side. A full EUDI flow requires the holder (wallet) to:

| Operation | EUDI requirement | What exists today |
|-----------|-----------------|-------------------|
| **Issuance:** Receive an SD‑JWT from an issuer | OpenID4VCI (draft) issuance protocol | Nothing |
| **Storage:** Persist encrypted credentials | Must protect at rest | `vault` crate (password‑encrypted HD wallet) — stores keys, not credentials |
| **Selective disclosure:** Select which claims to reveal per presentation request | SD‑JWT disclosure selection; mdoc namespace filtering | Nothing |
| **Presentation:** Construct the presentation response | OpenID4VP (draft) presentation protocol + format‑specific proof generation | Nothing |
| **Time‑bounding:** Attach AfterProof / BeforeProof to a presentation | Subject to verifier policy (§7.3) | Only specified for native proof bundles, not SD‑JWT or mdoc |

The `vault` crate already provides encrypted storage of BIP‑39 seeds and a plugin system
(`VaultPlugin` trait). A `CredentialPlugin` could store SD‑JWT tokens alongside keys.

---

## 4. Recommended Implementation Plan

### 4.1 Phase 1 — Authorization Layer (Prerequisite)

Implement the `off-chain-impersonation-plan.md` Sections 1–5. This provides:

- `DidState.commitment`, `last_modified_at`
- `DidHistory`, `CommitmentVersion`, `KeyLifecycle`, `CommitmentResolver`
- `DidHistory::has_right_at()` with union semantics
- `UpdateCommitment` operation + validation + event
- `previous_version_id` on all state‑changing events
- Pruning (§4.2) of revoked/expired entries

Without this, the credential‑format layer has no authorization to check against.

**Crates:** `mosaic-did-types`, `pallet-mosaic-did`

### 4.2 Phase 2 — Verifier Algorithm

Implement the verifier algorithm (§7 of the impersonation plan):

- `VerifierPolicy` gating acceptable proof strengths
- Step 0–5 in the verifier algorithm
- `NormalizedPresentation` struct as described in Gap C
- `CredentialVerifier` trait

**Crates:** `mosaic-did-types` (types + traits), new `iop-verifier` or in `sdk`

### 4.3 Phase 3 — SD‑JWT Crate

New crate `iop-sd-jwt`:

```toml
[package]
name = "iop-sd-jwt"
version = "0.1.0"
edition = "2024"
```

Files:

| File | Purpose | ~Lines |
|------|---------|--------|
| `lib.rs` | Crate root, re‑exports | 10 |
| `sd_jwt.rs` | `SdJwt` type — parse, serialize, validate structure | 200 |
| `disclosure.rs` | `Disclosure` — parse `[salt, name, value]` arrays, compute digests | 150 |
| `issuer.rs` | Issuer‑signed JWT validation, JWS signature verification | 150 |
| `holder.rs` | Key Binding JWT construction + verification, `cnf.kid` extraction | 200 |
| `profiles/eudi_pid.rs` | EUDI PID profile: known claim names, `vct` validation, accreditation hints | 100 |
| `verifier.rs` | `impl CredentialVerifier for SdJwtVerifier` — produces `NormalizedPresentation` | 100 |
| Tests | RFC 9596 test vectors, EUDI interop vectors | 300 |

**Dependencies:** JOSE/JWS crate (new or external), `sha2`, `serde_json`, `mosaic-keyvault` (for `MPublicKey` verification).

### 4.4 Phase 4 — mdoc Crate

New crate `iop-mdoc`:

| File | Purpose | ~Lines |
|------|---------|--------|
| `lib.rs` | Crate root | 10 |
| `doc.rs` | `MdocDocument`, `MobileSecurityObject` types | 200 |
| `issuer.rs` | COSE‑Sign1 verification, X.509 chain validation, CBOR tag handling | 250 |
| `holder.rs` | `DeviceAuthentication`, session transcript, `DeviceKey` extraction | 150 |
| `namespace.rs` | Namespace‑based data‑element filtering | 100 |
| `verifier.rs` | `impl CredentialVerifier for MdocVerifier` | 100 |
| Tests | ISO 18013‑5 examples, cross‑format test vectors | 250 |

**Dependencies:** CBOR crate, COSE implementation (or manual COSE‑Sign1), X.509 crate (e.g., `x509‑parser`), `mosaic-keyvault`.

### 4.5 Phase 5 — Wallet Credential Plugin

Extend the `vault` crate with credential‑storage capabilities:

| Change | Crate | Purpose |
|--------|-------|---------|
| `CredentialStore` trait | `vault` | Encrypted credential persistence |
| `SdJwtCredential` | `vault` | SD‑JWT‑specific credential with disclosure selection |
| `PresentationBuilder` | `vault` | Assembles presentations from stored credentials |
| `AfterProofAttacher` | `vault` or `sdk` | Attaches time‑bounding proofs to presentations |
| Selective‑disclosure UI model | `sdk` | Claim selection logic (must be validated by the wallet, not the verifier) |

**Note:** OpenID4VCI/VP protocol support (network‑side issuance and presentation) is outside
the scope of this cryptographic architecture — it belongs in an application‑layer crate or
separate service.

### 4.6 Phase 6 — Trust Framework Adapter

| Change | Crate | Purpose |
|--------|-------|---------|
| `AccreditationVerifier` trait | `mosaic-did-types` | Interface for issuer accreditation checks |
| `CredentialTypeRegistry` trait | `mosaic-did-types` | Maps credential types to required rights |
| EUDI trust‑list resolver | `sdk` or new crate | Resolves EUDI trust lists (XML) into DID‑accreditation proofs |
| On‑chain accreditation pallet (optional) | `pallet-mosaic-did` | Stores accredited issuer DIDs on‑chain for verifiers without off‑chain infrastructure |

### 4.7 Optional — Time‑Bounding Extensions for SD‑JWT / mdoc

Currently the time‑bounding proofs (AfterProof, BeforeProof, SMT) are defined only for
the native proof bundle. For SD‑JWT and mdoc presentations to carry cryptographic time‑bonds:

| Approach | Description |
|----------|-------------|
| **Wrapped native time‑bound** | The holder wraps the SD‑JWT/mdoc presentation inside a `Signed<AfterEnvelope<SmtContent>>` — the native time‑bounding applies to the entire presentation. Most aligned with the plan. |
| **JWT `iat`/`nbf` + external timestamp** | Trust the JWT issuenace time ≤ signing time. Works at `MinimalProof` or `AfterProof` strength only. |
| **mdoc `validityInfo`** | The `validFrom`/`validUntil` in the MSO provides credential‑level time‑bounds, not presentation‑level. Must be combined with device‑engagement timestamp. |

The wrapped‑native approach is recommended because it reuses the plan's time‑bounding
infrastructure without duplicating it per format.

---

## 5. Dependency Summary

### New external dependencies needed

| Dependency | Used by | Purpose |
|------------|---------|---------|
| JOSE / JWS crate | `iop-sd-jwt` | JWS signing and verification, compact serialization |
| CBOR crate | `iop-mdoc` | CBOR decoding for mdoc structures |
| COSE crate | `iop-mdoc` | COSE‑Sign1 verification (or manual implementation) |
| X.509 parser | `iop-mdoc` | Issuer certificate chain validation for mDL |
| `schnorrkel` + `merlin` | `mosaic-keyvault` | Already planned in `keyvault-plan.md` |

### New workspace crates

| Crate | Purpose | Depends on |
|-------|---------|------------|
| `iop-sd-jwt` | SD‑JWT (RFC 9596) encode/decode/verify | `mosaic-keyvault`, new JOSE dep |
| `iop-mdoc` | ISO 18013‑5 mdoc/mDL parser + verifier | `mosaic-keyvault`, CBOR, COSE, X.509 deps |

### Enhanced existing crates

| Crate | Changes |
|-------|---------|
| `mosaic-did-types` | `NormalizedPresentation`, `CredentialFormat`, `CredentialVerifier`, `CredentialTypeRegistry`, `AccreditationVerifier` traits; implement the `off-chain-impersonation-plan.md` types (`DidHistory`, `CommitmentVersion`, etc.) |
| `vault` | `CredentialStore` trait, `SdJwtCredential`, `PresentationBuilder` |
| `sdk` | Re‑export new crates; `AfterProofAttacher` utility |
| `pallet-mosaic-did` | `UpdateCommitment` operation, `previous_version_id` on events, pruning (§4.2 of impersonation plan) |
| `mosaic-keyvault` | sr25519 support per `keyvault-plan.md` (used for SD‑JWT KB‑JWT signing + mdoc DeviceKey) |

---

## 6. Verification Strategy

### Interoperability test vectors

| Vector source | Format | Verified against |
|--------------|--------|-----------------|
| RFC 9596 Appendix B | SD‑JWT | Known Issuer‑signed JWT + disclosures + KB‑JWT |
| EUDI Reference Implementation | SD‑JWT PID | EUDI ARF PID profile with `vct` claim |
| ISO 18013‑5 Annex C | mdoc | Known MSO + value digests |
| ISO 18013‑5 Annex D | mdoc | Device‑engagement test vectors |
| `off-chain-impersonation-plan.md` §8 | Native proof | Cross‑format: wrap SD‑JWT in `AfterEnvelope`, verify time‑bounds apply |

### End‑to‑end scenario tests

1. **EUDI PID presentation (MinimalProof):** Holder SD‑JWT PID → verifier checks `Impersonate` right via commitment document → accepts claims.
2. **EUDI PID presentation (AfterProof):** Holder wraps SD‑JWT in `AfterEnvelope` with blockhash → verifier checks lower time‑bound → accepts.
3. **mDL presentation:** Device‑engagement + DeviceAuthentication → verifier checks mdoc MSO → maps `DeviceKey` → `key_ref` → `Impersonate` right → accepts.
4. **Revoked right (cross‑format):** Post‑revocation SD‑JWT presentation → `has_right_at(key_ref, Impersonate, height)` returns false → rejected.
5. **Unaccredited issuer:** PID from non‑accredited DID → accreditation check fails → rejected.

---

## 7. Relationship to Existing Plan Documents

| Plan document | Role in EUDI flow |
|---------------|-------------------|
| `off-chain-impersonation-plan.md` | **Authorization layer** — must be implemented first. Provides the `has_right_at()` check that all credential formats feed into. |
| `keyvault-plan.md` | **Key signing** — provides sr25519 key types for holder‑binding signatures in SD‑JWT KB‑JWTs and mdoc DeviceAuthentication. Independent of credential formats. |
| `eudi-credential-plan.md` (this document) | **Credential‑format layer** — provides SD‑JWT and mdoc parsing/verification, normalizes them into the authorization pipeline. Depends on both of the above. |

---

## 8. Implementation Order

1. **Implement `off-chain-impersonation-plan.md`** — `DidState` fields, `DidHistory`, `DidHistory::has_right_at()`, `UpdateCommitment` on the pallet, events with `previous_version_id`, pruning, verifier algorithm (§7). **This is the prerequisite.**
2. **Implement `keyvault-plan.md`** — sr25519 cipher suites. Independent but enables SD‑JWT/mdoc holder‑key usage on Substrate chains.
3. **Add `NormalizedPresentation` + `CredentialVerifier` trait** in `mosaic-did-types`. Requires step 1.
4. **Implement `iop-sd-jwt`** crate — SD‑JWT parsing, verification, EUDI PID profile. Requires step 3 for trait impl.
5. **Implement `iop-mdoc`** crate — mdoc/mDL parsing, MSO verification, device engagement. Requires step 3 for trait impl.
6. **Wire credential verifiers into the verifier pipeline** — `verify_presentation()` dispatches to format‑specific verifier, then calls `has_right_at()`.
7. **Wallet credential storage** — `vault` plugin for SD‑JWT and mdoc credentials, selective disclosure UI model.
8. **Trust‑framework adapter** — accreditation checks, credential‑type registry.
9. **End‑to‑end test vectors** — cross‑format verification scenarios.
