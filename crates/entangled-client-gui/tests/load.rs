//! Test the pure load path: a verified manifest + content yields a Scene and a
//! First-contact ChromeView. No window is involved.

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
use sha3::{Digest, Sha3_256};

use entangled_client::trust::TrustState;
use entangled_client::FixedClock;
use entangled_client_gui::load;

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

fn fixture() -> (Vec<u8>, Vec<u8>, OnionAddress) {
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
    let (_m, manifest_bytes) =
        build_manifest(&unsigned, &publisher_key, &ts("2026-05-07T00:00:00Z")).expect("manifest");

    let content = UnsignedContent {
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
    let (_c, content_bytes) = build_content(&content, &runtime_key).expect("content");

    (manifest_bytes, content_bytes, onion)
}

#[test]
fn load_yields_scene_and_first_contact_chrome() {
    let (manifest, content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let loaded = load(&manifest, Some(&content), &onion, "abc...xyz.onion", &clock)
        .expect("load must succeed");

    // Chrome: first contact (no retained identity), fresh canary, full PIP.
    assert_eq!(loaded.chrome.trust_state, TrustState::FirstContact);
    assert_eq!(loaded.chrome.canary_state, CanaryState::Fresh);
    assert_eq!(loaded.chrome.pip.split_whitespace().count(), 24);
    assert!(loaded.chrome.warnings.is_empty());

    // Content scene present with the one paragraph.
    let scene = loaded.scene.expect("content scene present");
    assert_eq!(scene.nodes.len(), 1);
}

#[test]
fn manifest_only_load_has_no_scene() {
    let (manifest, _content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let loaded =
        load(&manifest, None, &onion, "abc...xyz.onion", &clock).expect("load must succeed");
    assert!(loaded.scene.is_none());
    assert_eq!(loaded.chrome.trust_state, TrustState::FirstContact);
}

#[test]
fn wrong_onion_fails_to_load() {
    let (manifest, content, _onion) = fixture();
    let other = OnionAddress::try_from(onion_for(&[0x77; 32]).as_str()).expect("onion");
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let result = load(&manifest, Some(&content), &other, "abc...xyz.onion", &clock);
    assert!(result.is_err(), "origin mismatch must fail the load");
}
