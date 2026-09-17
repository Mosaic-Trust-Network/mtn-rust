//! Reachability probe for the evict-then-re-add replay-window reset (#10).
//!
//! The #8 fix made key nonces survive `RevokeKey` so re-registering a
//! `key_ref` cannot reset its replay window — but that guarantee holds
//! only while the nonce map is not full. Under map pressure,
//! `DidState::update_nonce` evicts exactly those surviving removed-key
//! entries, and `AddKey` accepts re-registration of a removed key_ref,
//! after which `validate_nonce`'s `nonce > stored` (absent → 0) accepts
//! replayed pre-revocation operations.
//!
//! This test asserts the full chain against `DidState`, mirroring the
//! pallet's `validation::validate_nonce` semantics. It documents today's
//! reachable gap; the day the gap is closed, the first marked assertion
//! fails and this probe becomes the regression guard. Extend with pallet
//! -level cases (sweep pressure, expired-key eviction) as needed.

use bounded_collections::{BoundedBTreeMap, BoundedVec};
use mosaic_did_types::did::{Did, KeyRef};
use mosaic_did_types::operation::KeyType;
use mosaic_did_types::state::{DidState, MAX_NONCES_PER_DID, VerificationMethod};

fn key_ref(tag: u8) -> KeyRef {
    KeyRef::new(vec![tag]).unwrap()
}

fn method(kr: &KeyRef, did: &Did) -> VerificationMethod {
    VerificationMethod {
        key_ref: kr.clone(),
        key_type: KeyType::Ed25519,
        controller: did.clone(),
        public_key: BoundedVec::try_from(vec![0u8; 32]).unwrap(),
        added_at_height: 1,
        expires_at_height: None,
        revoked_at_height: None,
    }
}

fn stored_nonce(state: &DidState, kr: &KeyRef) -> u64 {
    state.nonces.get(kr).copied().unwrap_or(0)
}

#[test]
fn evict_then_readd_resets_replay_window() {
    let did = Did::from_public_key(&[0u8; 32]).unwrap();
    let mut state = DidState::new(did.clone());

    // Live signer L (stays in keys).
    let l = key_ref(0xFF);
    state.keys.try_push(method(&l, &did)).unwrap();

    // Key K: revoked earlier at nonce 50 — key removed, nonce survives (#8).
    let k = key_ref(0x01); // smallest Ord among dead entries → first eviction victim
    let mut dead_nonces: std::collections::BTreeMap<KeyRef, u64> =
        std::collections::BTreeMap::new();
    dead_nonces.insert(k.clone(), 50);
    for tag in 0x02..0x21u8 {
        // 31 more removed keys with surviving nonces → map at capacity (32).
        dead_nonces.insert(key_ref(tag), 60 + tag as u64);
    }
    assert_eq!(dead_nonces.len(), MAX_NONCES_PER_DID as usize);
    state.nonces = BoundedBTreeMap::try_from(dead_nonces).unwrap();
    assert_eq!(stored_nonce(&state, &k), 50);

    // Map pressure: a live signer's insert evicts the first-ordered dead entry.
    state.update_nonce(&l, 100, 10).unwrap();

    // GAP #10: K's replay window was evicted and reset to 0. When the gap
    // is closed (tombstone high-water marks, re-add rejection, or a much
    // larger MAX_NONCES_PER_DID), this assertion fails — flip it then and
    // keep the test as the regression guard.
    let k_nonce = stored_nonce(&state, &k);
    assert_eq!(
        k_nonce, 0,
        "K's replay window survived eviction — #10 is closed; update this probe"
    );

    // Re-add K: AddKey only rejects keys still present (find_key.is_none()).
    assert!(state.find_key(&k).is_none(), "re-add would be rejected");
    state.keys.try_push(method(&k, &did)).unwrap();
    assert!(state.find_key(&k).is_some());

    // Replay check exactly as pallet validation::validate_nonce does:
    // ensure!(signed_op.nonce > stored_nonce) with stored defaulting to 0.
    let replayed_nonce = 50u64; // pre-revocation signed op
    let accepted = replayed_nonce > stored_nonce(&state, &k);
    assert!(
        accepted,
        "replayed op rejected — replay window not actually reset; #10 is closed, update this probe"
    );
}
