//! Test the pure load path: a verified manifest + content yields a Scene and a
//! ChromeView, and the live trust flow (retained identity -> required action,
//! decision -> intent). No window is involved.

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{build_content, build_manifest, UnsignedContent, UnsignedManifest};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::types::meta::Meta;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::types::{Block, EntangledPath, InlineElement, PublisherPubkey, TextMark};
use entangled_core::validation::canary::CanaryState;
use sha3::{Digest, Sha3_256};

use entangled_client::trust::{
    PersistenceIntent, RequiredAction, RetainedIdentity, RetainedProvenance, TrustState,
    UserDecision,
};
use entangled_client::{FixedClock, PublisherHistory};
use entangled_client_gui::load;

/// Convenience: the empty-store first-contact load arguments.
const NO_RETAINED: Option<&RetainedIdentity> = None;

fn empty_history() -> PublisherHistory {
    PublisherHistory::new()
}

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

    let loaded = load(
        &manifest,
        Some(&content),
        &onion,
        "abc...xyz.onion",
        &clock,
        NO_RETAINED,
        &empty_history(),
    )
    .expect("load must succeed");

    // Chrome: first contact (no retained identity), fresh canary, full PIP, and
    // the required action is the pinning prompt.
    assert_eq!(loaded.chrome.trust_state, TrustState::FirstContact);
    assert_eq!(loaded.chrome.canary_state, CanaryState::Fresh);
    assert_eq!(loaded.chrome.pip.split_whitespace().count(), 24);
    assert!(loaded.chrome.warnings.is_empty());
    assert_eq!(loaded.required_action, RequiredAction::PinPrompt);

    // Content scene present with the one paragraph.
    let scene = loaded.scene.expect("content scene present");
    assert_eq!(scene.nodes.len(), 1);
}

#[test]
fn manifest_only_load_has_no_scene() {
    let (manifest, _content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let loaded = load(
        &manifest,
        None,
        &onion,
        "abc...xyz.onion",
        &clock,
        NO_RETAINED,
        &empty_history(),
    )
    .expect("load must succeed");
    assert!(loaded.scene.is_none());
    assert_eq!(loaded.chrome.trust_state, TrustState::FirstContact);
}

#[test]
fn wrong_onion_fails_to_load() {
    let (manifest, content, _onion) = fixture();
    let other = OnionAddress::try_from(onion_for(&[0x77; 32]).as_str()).expect("onion");
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));

    let result = load(
        &manifest,
        Some(&content),
        &other,
        "abc...xyz.onion",
        &clock,
        NO_RETAINED,
        &empty_history(),
    );
    assert!(result.is_err(), "origin mismatch must fail the load");
}

/// The publisher key the `fixture()` manifest is signed by (seed 0xB1).
fn fixture_publisher() -> PublisherPubkey {
    PublisherSigningKey::from_seed(&[0xB1; 32]).verifying_key()
}

#[test]
fn returning_visitor_with_pin_resolves_tofu_pinned() {
    // A retained TOFU pin for the manifest's publisher -> no pin prompt, the
    // chrome shows TOFU pinned, and no decision is required.
    let (manifest, content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let retained = RetainedIdentity {
        pubkey: fixture_publisher(),
        provenance: RetainedProvenance::Pinned,
    };
    let loaded = load(
        &manifest,
        Some(&content),
        &onion,
        "abc...xyz.onion",
        &clock,
        Some(&retained),
        &empty_history(),
    )
    .expect("load must succeed");
    assert_eq!(loaded.chrome.trust_state, TrustState::TofuPinned);
    assert_eq!(loaded.required_action, RequiredAction::None);
}

#[test]
fn returning_visitor_externally_verified_is_not_downgraded() {
    // A retained externally-verified identity must stay externally verified.
    let (manifest, content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let retained = RetainedIdentity {
        pubkey: fixture_publisher(),
        provenance: RetainedProvenance::ExternallyVerified,
    };
    let loaded = load(
        &manifest,
        Some(&content),
        &onion,
        "abc...xyz.onion",
        &clock,
        Some(&retained),
        &empty_history(),
    )
    .expect("load must succeed");
    assert_eq!(loaded.chrome.trust_state, TrustState::ExternallyVerified);
}

#[test]
fn changed_key_yields_mismatch_warning() {
    // A retained identity for a DIFFERENT key than the manifest presents ->
    // Changed/mismatch, and the required action is the mismatch warning.
    let (manifest, content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let other_key = PublisherSigningKey::from_seed(&[0xC1; 32]).verifying_key();
    let retained = RetainedIdentity {
        pubkey: other_key,
        provenance: RetainedProvenance::Pinned,
    };
    let loaded = load(
        &manifest,
        Some(&content),
        &onion,
        "abc...xyz.onion",
        &clock,
        Some(&retained),
        &empty_history(),
    )
    .expect("load must succeed");
    assert_eq!(loaded.chrome.trust_state, TrustState::ChangedMismatch);
    assert_eq!(loaded.required_action, RequiredAction::MismatchWarning);
    // The PIP must be fully shown during mismatch resolution.
    assert_eq!(loaded.chrome.pip.split_whitespace().count(), 24);
}

#[test]
fn pin_decision_yields_pin_intent_and_updates_chrome() {
    // First-contact load, then the user pins: apply_decision re-resolves to
    // TOFU pinned and yields a PinIdentity intent for the shell to persist.
    let (manifest, content, onion) = fixture();
    let clock = FixedClock(ts("2026-05-07T00:00:00Z"));
    let mut loaded = load(
        &manifest,
        Some(&content),
        &onion,
        "abc...xyz.onion",
        &clock,
        NO_RETAINED,
        &empty_history(),
    )
    .expect("load must succeed");
    assert_eq!(loaded.required_action, RequiredAction::PinPrompt);

    let intent = loaded.apply_decision(UserDecision::PinFirstContact);
    assert_eq!(
        intent,
        PersistenceIntent::PinIdentity {
            pubkey: fixture_publisher()
        }
    );
    // Chrome updated in place.
    assert_eq!(loaded.chrome.trust_state, TrustState::TofuPinned);
    assert_eq!(loaded.required_action, RequiredAction::None);
}
