//! Golden tests for the persistence seams' in-memory doubles.
//!
//! These exercise `MemoryIdentityStore` / `MemoryHistoryStore` against the pure
//! `resolve` and `check_against_history` brain functions, the way `tests/image.rs`
//! golden-tests the `Decoder` seam via `FakeDecoder`. They prove the seam
//! *contract* (load -> resolve -> apply -> reload) without any filesystem, so the
//! durable file store in `entangled-client-store` can be tested against the same
//! behavior.

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::types::manifest::OnionAddress;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::canary::RetainedManifestRecord;
use sha3::{Digest, Sha3_256};

use entangled_client::trust::{resolve, PersistenceIntent, TrustState, UserDecision};
use entangled_client::{
    HistoryStore, IdentityStore, MemoryHistoryStore, MemoryIdentityStore, RetainedIdentity,
    RetainedProvenance,
};

fn key(seed: u8) -> PublisherPubkey {
    PublisherSigningKey::from_seed(&[seed; 32]).verifying_key()
}

/// A valid Tor v3 onion address derived from a seed, used as the site key.
fn site(seed: u8) -> OnionAddress {
    let pubkey = [seed; 32];
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(&pubkey);
    payload[32..34].copy_from_slice(&[digest[0], digest[1]]);
    payload[34] = 0x03;
    let s = format!("{}.onion", BASE32.encode(&payload).to_ascii_lowercase());
    OnionAddress::try_from(s.as_str()).expect("onion")
}

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).expect("valid timestamp")
}

fn record(issued_at: &str, runtime_seed: u8, payload_byte: u8) -> RetainedManifestRecord {
    RetainedManifestRecord {
        issued_at: ts(issued_at),
        runtime_pubkey: RuntimeSigningKey::from_seed(&[runtime_seed; 32]).verifying_key(),
        manifest_payload_hash: [payload_byte; 32],
    }
}

// --- IdentityStore: the resolve -> apply -> reload contract ---

#[test]
fn pin_then_reload_resolves_tofu_pinned() {
    let store = MemoryIdentityStore::new();
    let (k, s) = (key(1), site(1));
    // First contact, user pins.
    let r = resolve(&k, None, UserDecision::PinFirstContact);
    assert_eq!(r.intent, PersistenceIntent::PinIdentity { pubkey: k });
    store.apply(&s, &r.intent).unwrap();

    // Next session: load the retained identity for the site, resolve no decision.
    let retained = store.load_identity(&s).unwrap();
    assert_eq!(
        retained,
        Some(RetainedIdentity {
            pubkey: k,
            provenance: RetainedProvenance::Pinned
        })
    );
    let r2 = resolve(&k, retained.as_ref(), UserDecision::None);
    assert_eq!(r2.state, TrustState::TofuPinned);
}

#[test]
fn pip_confirmed_first_contact_reloads_externally_verified() {
    let store = MemoryIdentityStore::new();
    let (k, s) = (key(2), site(2));
    let r = resolve(&k, None, UserDecision::ConfirmPip);
    assert_eq!(
        r.intent,
        PersistenceIntent::MarkExternallyVerified { pubkey: k }
    );
    store.apply(&s, &r.intent).unwrap();

    let retained = store.load_identity(&s).unwrap();
    let r2 = resolve(&k, retained.as_ref(), UserDecision::None);
    assert_eq!(r2.state, TrustState::ExternallyVerified);
}

#[test]
fn tofu_then_pip_elevates_without_clobbering() {
    // Pin first, then confirm the PIP in a later session: the elevation must
    // not reset externally_verified, and a stray re-pin must not demote it.
    let store = MemoryIdentityStore::new();
    let (k, s) = (key(3), site(3));
    store
        .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
        .unwrap();
    store
        .apply(&s, &PersistenceIntent::MarkExternallyVerified { pubkey: k })
        .unwrap();
    // A spurious re-pin afterwards must NOT demote the verified flag.
    store
        .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
        .unwrap();

    let retained = store.load_identity(&s).unwrap().unwrap();
    assert_eq!(
        retained.provenance,
        RetainedProvenance::ExternallyVerified,
        "re-pin must not demote a verified key"
    );
    let r = resolve(&k, Some(&retained), UserDecision::None);
    assert_eq!(r.state, TrustState::ExternallyVerified);
}

#[test]
fn pip_confirmed_replacement_survives_reload() {
    // The durable twin of the trust-test M-2 round-trip: a mismatch (same site,
    // different key) resolved by externally verifying the new PIP must reload as
    // Externally verified, and the prior key must be retained (not lost).
    let store = MemoryIdentityStore::new();
    let (k1, k2, s) = (key(1), key(2), site(1));
    // k1 was previously externally verified for this site.
    store
        .apply(
            &s,
            &PersistenceIntent::MarkExternallyVerified { pubkey: k1 },
        )
        .unwrap();
    // A different key k2 is presented for the SAME site; user confirms via PIP.
    let r = resolve(
        &k2,
        Some(&RetainedIdentity {
            pubkey: k1,
            provenance: RetainedProvenance::ExternallyVerified,
        }),
        UserDecision::ConfirmPip,
    );
    assert_eq!(
        r.intent,
        PersistenceIntent::ReplaceIdentity {
            new_pubkey: k2,
            replaced: k1,
            externally_verified: true,
        }
    );
    store.apply(&s, &r.intent).unwrap();

    // Next session: the site now resolves to k2 as Externally verified.
    let retained = store.load_identity(&s).unwrap();
    assert_eq!(retained.map(|r| r.pubkey), Some(k2));
    let r2 = resolve(&k2, retained.as_ref(), UserDecision::None);
    assert_eq!(r2.state, TrustState::ExternallyVerified);
    // The prior key k1 is retained as a replaced key for the site.
    assert_eq!(store.replaced_keys(&s), vec![k1]);
}

// --- HistoryStore: anti-downgrade / L-1 same-payload re-fetch across reload ---

#[test]
fn history_append_then_reload_holds_anti_downgrade() {
    let store = MemoryHistoryStore::new();
    let p = key(1);
    store
        .append_record(&p, &record("2026-06-05T00:00:00Z", 0xA1, 0x11))
        .unwrap();
    let loaded = store.load_history(&p).unwrap();
    assert_eq!(
        loaded.newest().map(|r| r.issued_at),
        Some(ts("2026-06-05T00:00:00Z"))
    );
    assert!(!loaded.is_empty());
}

#[test]
fn history_reload_round_trips_records() {
    let store = MemoryHistoryStore::new();
    let p = key(7);
    let rec = record("2026-05-07T00:00:00Z", 0xB3, 0x42);
    store.append_record(&p, &rec).unwrap();
    let loaded = store.load_history(&p).unwrap();
    assert_eq!(loaded.records(), &[rec]);
}

#[test]
fn missing_history_is_empty() {
    let store = MemoryHistoryStore::new();
    assert!(store.load_history(&key(9)).unwrap().is_empty());
}

#[test]
fn missing_identity_is_first_contact() {
    let store = MemoryIdentityStore::new();
    let (k, s) = (key(9), site(9));
    assert_eq!(store.load_identity(&s).unwrap(), None);
    assert_eq!(
        resolve(&k, None, UserDecision::None).state,
        TrustState::FirstContact
    );
}

#[test]
fn observation_record_never_overwrites_and_pin_upgrades() {
    // The memory store honors the RecordObservation contract: create only
    // when nothing is retained, never demote, and let a pin upgrade an
    // observed-only record.
    let store = MemoryIdentityStore::new();
    let (k, s) = (key(7), site(7));
    store
        .apply(&s, &PersistenceIntent::RecordObservation { pubkey: k })
        .unwrap();
    assert_eq!(
        store.load_identity(&s).unwrap().unwrap().provenance,
        RetainedProvenance::Observed
    );
    // A second observation (any key) changes nothing.
    let k2 = key(8);
    store
        .apply(&s, &PersistenceIntent::RecordObservation { pubkey: k2 })
        .unwrap();
    let r = store.load_identity(&s).unwrap().unwrap();
    assert_eq!(r.pubkey, k);
    assert_eq!(r.provenance, RetainedProvenance::Observed);
    // An affirmative pin upgrades the observation.
    store
        .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
        .unwrap();
    assert_eq!(
        store.load_identity(&s).unwrap().unwrap().provenance,
        RetainedProvenance::Pinned
    );
    // A later observation cannot demote the pin.
    store
        .apply(&s, &PersistenceIntent::RecordObservation { pubkey: k })
        .unwrap();
    assert_eq!(
        store.load_identity(&s).unwrap().unwrap().provenance,
        RetainedProvenance::Pinned
    );
}
