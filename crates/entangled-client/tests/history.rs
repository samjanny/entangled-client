//! Golden tests for the publisher-history checks (T2): anti-downgrade,
//! equal-`issued_at` conflict, and runtime-key rotation.
//!
//! Each test builds a verifiable manifest with chosen canary timestamps and
//! runtime key, seeds a `PublisherHistory` with a prior record, then drives a
//! new manifest through `verify_manifest` and asserts accept/reject.

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{build_manifest, UnsignedManifest};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::DiagnosticCode;
use sha3::{Digest, Sha3_256};

use entangled_client::{record_for, verify_manifest, FixedClock, Outcome, PublisherHistory};

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).expect("valid timestamp")
}

fn onion_for(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    payload[32..34].copy_from_slice(&[digest[0], digest[1]]);
    payload[34] = 0x03;
    format!("{}.onion", BASE32.encode(&payload).to_ascii_lowercase())
}

/// Build a verifiable manifest at the given canary window and runtime-key seed.
/// The publisher and origin keys are fixed so a series of manifests belongs to
/// the same publisher and binds to the same onion address.
fn manifest(issued_at: &str, next_expected: &str, runtime_seed: u8) -> (Vec<u8>, OnionAddress) {
    let publisher_key = PublisherSigningKey::from_seed(&[0xB1; 32]);
    let runtime_key = RuntimeSigningKey::from_seed(&[runtime_seed; 32]);
    let origin_pk_bytes = *PublisherSigningKey::from_seed(&[0xB2; 32])
        .verifying_key()
        .as_bytes();
    let onion = OnionAddress::try_from(onion_for(&origin_pk_bytes).as_str()).expect("onion");

    let unsigned = UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: publisher_key.verifying_key(),
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion.clone(),
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

    // Sign at the issue time so the manifest's own `updated` skew check passes.
    let (_m, bytes) = build_manifest(&unsigned, &publisher_key, &ts(issued_at)).expect("build");
    (bytes, onion)
}

/// Seed a history with the record of a verified manifest (the prior acceptance).
fn history_with(bytes: &[u8], onion: &OnionAddress, now: &str) -> PublisherHistory {
    let clock = FixedClock(ts(now));
    let prior = match verify_manifest(bytes, onion, None, &clock, &PublisherHistory::new()) {
        Outcome::Accept(v) => v,
        Outcome::Reject(d) => panic!("prior manifest must verify: {d:?}"),
    };
    let mut history = PublisherHistory::new();
    history.push(record_for(&prior.manifest).expect("record"));
    history
}

#[test]
fn newer_manifest_with_rotated_key_accepts() {
    // Prior: issued 2026-05-07, runtime key A. New: issued later, key B.
    let (prior_bytes, onion) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA1);
    let history = history_with(&prior_bytes, &onion, "2026-05-07T00:00:00Z");

    let (new_bytes, _) = manifest("2026-06-05T00:00:00Z", "2026-07-05T00:00:00Z", 0xA2);
    let clock = FixedClock(ts("2026-06-05T00:00:00Z"));
    let outcome = verify_manifest(&new_bytes, &onion, None, &clock, &history);
    assert!(
        outcome.is_accepted(),
        "a newer manifest with a rotated key must accept"
    );
}

#[test]
fn older_issued_at_is_downgrade() {
    // Prior issued 2026-06-05; new issued earlier (2026-05-07): a downgrade.
    let (prior_bytes, onion) = manifest("2026-06-05T00:00:00Z", "2026-07-05T00:00:00Z", 0xA1);
    let history = history_with(&prior_bytes, &onion, "2026-06-05T00:00:00Z");

    let (old_bytes, _) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA2);
    let clock = FixedClock(ts("2026-06-05T00:00:00Z"));
    let outcome = verify_manifest(&old_bytes, &onion, None, &clock, &history);
    assert_eq!(
        outcome.diagnostic().map(|d| d.code),
        Some(DiagnosticCode::ECanaryDowngrade)
    );
}

#[test]
fn equal_issued_at_different_payload_is_conflict() {
    // Same issued_at, different runtime key -> different payload hash: conflict.
    let (prior_bytes, onion) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA1);
    let history = history_with(&prior_bytes, &onion, "2026-05-07T00:00:00Z");

    let (twin_bytes, _) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA2);
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let outcome = verify_manifest(&twin_bytes, &onion, None, &clock, &history);
    assert_eq!(
        outcome.diagnostic().map(|d| d.code),
        Some(DiagnosticCode::ECanaryConflict)
    );
}

#[test]
fn reused_runtime_key_is_rejected() {
    // Newer manifest that reuses the immediately-preceding runtime key.
    let (prior_bytes, onion) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA1);
    let history = history_with(&prior_bytes, &onion, "2026-05-07T00:00:00Z");

    let (reuse_bytes, _) = manifest("2026-06-05T00:00:00Z", "2026-07-05T00:00:00Z", 0xA1);
    let clock = FixedClock(ts("2026-06-05T00:00:00Z"));
    let outcome = verify_manifest(&reuse_bytes, &onion, None, &clock, &history);
    assert_eq!(
        outcome.diagnostic().map(|d| d.code),
        Some(DiagnosticCode::ECanaryRuntimeReuse)
    );
}

#[test]
fn same_payload_refetch_is_accepted() {
    // Re-fetching the byte-identical newest manifest is normal steady-state
    // traffic (§08:242). It carries the same runtime key, but because the
    // payload hash matches the retained record it must NOT trip the
    // runtime-rotation check - unlike a *new* manifest reusing the key
    // (`reused_runtime_key_is_rejected`, which differs in issued_at/payload).
    let (bytes, onion) = manifest("2026-05-07T00:00:00Z", "2026-06-06T00:00:00Z", 0xA1);
    let history = history_with(&bytes, &onion, "2026-05-07T00:00:00Z");

    // Same bytes, re-fetched during the normal interval before the next ceremony.
    let clock = FixedClock(ts("2026-05-20T00:00:00Z"));
    let outcome = verify_manifest(&bytes, &onion, None, &clock, &history);
    assert!(
        outcome.is_accepted(),
        "a byte-identical re-fetch must accept, not report RUNTIME_REUSE: {:?}",
        outcome.diagnostic().map(|d| d.code)
    );
}
