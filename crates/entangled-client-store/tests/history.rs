//! History store round-trips, and the §08 checks (anti-downgrade, L-1
//! same-payload re-fetch, runtime reuse) holding across a reload from disk.

mod common;
use common::{integrity_root, key, record, ts};

use entangled_client::{check_against_history, HistoryStore};
use entangled_client_store::FileHistoryStore;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{build_manifest, UnsignedManifest};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, Origin};
use entangled_core::types::Manifest;
use entangled_core::validation::DiagnosticCode;

#[test]
fn append_then_reload_round_trips_records() {
    let dir = tempfile::tempdir().unwrap();
    let p = key(7);
    let rec = record("2026-05-07T00:00:00Z", 0xB3, 0x42);
    {
        let store = FileHistoryStore::new(integrity_root(dir.path()));
        store.append_record(&p, &rec).unwrap();
    }
    let store = FileHistoryStore::new(integrity_root(dir.path()));
    let loaded = store.load_history(&p).unwrap();
    // Exact round-trip including the 32-byte hash via hex.
    assert_eq!(loaded.records(), &[rec]);
}

#[test]
fn missing_history_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileHistoryStore::new(integrity_root(dir.path()));
    assert!(store.load_history(&key(9)).unwrap().is_empty());
}

// --- §08 checks against a reloaded history, using a real signed manifest ---

/// Build a signature-valid manifest (mirrors the client history-test helper).
fn manifest(issued_at: &str, next_expected: &str, runtime_seed: u8) -> (Manifest, Vec<u8>) {
    let publisher_key = PublisherSigningKey::from_seed(&[0xB1; 32]);
    let runtime_key = RuntimeSigningKey::from_seed(&[runtime_seed; 32]);
    let origin_pk_bytes = *PublisherSigningKey::from_seed(&[0xB2; 32])
        .verifying_key()
        .as_bytes();
    let onion = entangled_core::types::manifest::OnionAddress::try_from(
        onion_for(&origin_pk_bytes).as_str(),
    )
    .expect("onion");
    let unsigned = UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: publisher_key.verifying_key(),
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion,
            origin_pubkey: OriginPubkey::from_bytes(origin_pk_bytes),
            not_after: None,
        },
        canary: Canary {
            runtime_pubkey: runtime_key.verifying_key(),
            issued_at: ts(issued_at).into(),
            next_expected: ts(next_expected).into(),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts(issued_at),
        migration_pointer: None,
        content_root: None,
    };
    build_manifest(&unsigned, &publisher_key, &ts(issued_at)).expect("build")
}

fn onion_for(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    payload[32..34].copy_from_slice(&[digest[0], digest[1]]);
    payload[34] = 0x03;
    format!(
        "{}.onion",
        data_encoding::BASE32.encode(&payload).to_ascii_lowercase()
    )
}

#[test]
fn anti_downgrade_holds_after_reload() {
    let dir = tempfile::tempdir().unwrap();
    let (m_new, _) = manifest("2026-06-05T00:00:00Z", "2026-07-05T00:00:00Z", 0xA1);
    let p = m_new.publisher_pubkey;
    {
        let store = FileHistoryStore::new(integrity_root(dir.path()));
        store
            .append_record(&p, &entangled_client::record_for(&m_new).unwrap())
            .unwrap();
    }
    let store = FileHistoryStore::new(integrity_root(dir.path()));
    let loaded = store.load_history(&p).unwrap();
    // An older manifest is now a downgrade against the reloaded floor.
    let (m_old, _) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA2);
    let err = check_against_history(&m_old, &loaded).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ECanaryDowngrade);
}

#[test]
fn same_payload_refetch_accepts_after_reload() {
    // L-1 made durable: a byte-identical re-fetch must accept (no spurious
    // RUNTIME_REUSE) after the history is reloaded from disk.
    let dir = tempfile::tempdir().unwrap();
    let (m, _) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA1);
    let p = m.publisher_pubkey;
    {
        let store = FileHistoryStore::new(integrity_root(dir.path()));
        store
            .append_record(&p, &entangled_client::record_for(&m).unwrap())
            .unwrap();
    }
    let store = FileHistoryStore::new(integrity_root(dir.path()));
    let loaded = store.load_history(&p).unwrap();
    // Same manifest re-fetched: must accept.
    assert!(check_against_history(&m, &loaded).is_ok());
}

#[test]
fn runtime_reuse_rejected_after_reload() {
    let dir = tempfile::tempdir().unwrap();
    let (m1, _) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA1);
    let p = m1.publisher_pubkey;
    {
        let store = FileHistoryStore::new(integrity_root(dir.path()));
        store
            .append_record(&p, &entangled_client::record_for(&m1).unwrap())
            .unwrap();
    }
    let store = FileHistoryStore::new(integrity_root(dir.path()));
    let loaded = store.load_history(&p).unwrap();
    // A *new* manifest reusing the same runtime key (different payload) rejects.
    let (m2, _) = manifest("2026-06-05T00:00:00Z", "2026-07-05T00:00:00Z", 0xA1);
    let err = check_against_history(&m2, &loaded).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ECanaryRuntimeReuse);
}
