//! Golden tests for the pipeline driver.
//!
//! Build a signed, verifiable manifest (and a content document) with the core's
//! builders, then drive them through the client pipeline and assert the
//! outcome. The onion address is derived from the origin pubkey by the same
//! Tor v3 procedure the core's own tests use, so Stage 9 origin binding passes.

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{build_content, build_manifest, UnsignedContent, UnsignedManifest};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::types::meta::Meta;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::types::{Block, EntangledPath, InlineElement, TextMark};
use entangled_core::validation::canary::CanaryState;
use entangled_core::validation::DiagnosticCode;
use sha3::{Digest, Sha3_256};

use entangled_client::{verify_content, verify_manifest, FixedClock, Outcome, PublisherHistory};

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).expect("valid timestamp")
}

/// Derive the Tor v3 `.onion` address that decodes to `pubkey`, matching the
/// section 06 address-to-key binding.
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

/// Build a verifiable manifest plus the keys/address a client would hold. The
/// canary window is 30 days from `2026-05-07`, so it is Fresh on the issue date.
fn fixture() -> (Vec<u8>, OnionAddress, RuntimeSigningKey) {
    let publisher_key = PublisherSigningKey::from_seed(&[0xB1; 32]);
    let runtime_key = RuntimeSigningKey::from_seed(&[0xB3; 32]);
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
            issued_at: ts("2026-05-07T00:00:00Z").into(),
            next_expected: ts("2026-06-06T00:00:00Z").into(),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
        migration_pointer: None,
        content_root: None,
    };

    let now = ts("2026-05-07T00:00:00Z");
    let (_m, bytes) = build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");
    (bytes, onion, runtime_key)
}

#[test]
fn manifest_accepts_and_is_fresh() {
    let (bytes, onion, _rt) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let outcome = verify_manifest(&bytes, &onion, None, &clock, &PublisherHistory::new());
    match outcome {
        Outcome::Accept(verified) => {
            assert_eq!(verified.canary_state, CanaryState::Fresh);
            assert!(verified.content_index.is_none());
        }
        Outcome::Reject(d) => panic!("expected accept, got {d:?}"),
    }
}

#[test]
fn wrong_origin_address_rejects_at_stage_9() {
    let (bytes, _onion, _rt) = fixture();
    // A syntactically valid but unrelated onion address (derived from a
    // different key): origin binding must fail.
    let other = OnionAddress::try_from(onion_for(&[0x77; 32]).as_str()).expect("onion");
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let outcome = verify_manifest(&bytes, &other, None, &clock, &PublisherHistory::new());
    assert!(
        !outcome.is_accepted(),
        "manifest must be rejected on origin mismatch"
    );
    assert_eq!(
        outcome.diagnostic().unwrap().code,
        DiagnosticCode::EBindOrigin
    );
}

#[test]
fn content_verifies_under_manifest_runtime_key() {
    let (bytes, onion, runtime_key) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let verified = match verify_manifest(&bytes, &onion, None, &clock, &PublisherHistory::new()) {
        Outcome::Accept(v) => v,
        Outcome::Reject(d) => panic!("manifest rejected: {d:?}"),
    };

    // A content document signed by the manifest's authorized runtime key.
    let unsigned = UnsignedContent {
        spec_version: SpecVersion,
        path: EntangledPath::try_from("/hello").expect("path"),
        meta: Meta {
            title: "Hello".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks: vec![Block::Paragraph {
            content: vec![InlineElement::Text {
                value: "hi".to_owned(),
                marks: Vec::<TextMark>::new(),
            }],
        }],
        seq: None,
    };
    let (_c, content_bytes) = build_content(&unsigned, &runtime_key).expect("build_content");

    let outcome = verify_content(&content_bytes, &verified);
    assert!(
        outcome.is_accepted(),
        "content must verify under the runtime key"
    );
}

#[test]
fn content_signed_by_wrong_key_rejects() {
    let (bytes, onion, _rt) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let verified = match verify_manifest(&bytes, &onion, None, &clock, &PublisherHistory::new()) {
        Outcome::Accept(v) => v,
        Outcome::Reject(d) => panic!("manifest rejected: {d:?}"),
    };

    // Sign the content with a runtime key the manifest did NOT authorize.
    let rogue = RuntimeSigningKey::from_seed(&[0x99; 32]);
    let unsigned = UnsignedContent {
        spec_version: SpecVersion,
        path: EntangledPath::try_from("/hello").expect("path"),
        meta: Meta {
            title: "Hello".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks: vec![Block::Paragraph {
            content: vec![InlineElement::Text {
                value: "hi".to_owned(),
                marks: Vec::<TextMark>::new(),
            }],
        }],
        seq: None,
    };
    let (_c, content_bytes) = build_content(&unsigned, &rogue).expect("build_content");

    let outcome = verify_content(&content_bytes, &verified);
    assert!(
        !outcome.is_accepted(),
        "content signed by an unauthorized key must reject"
    );
}
