//! Golden tests for the chrome model (T3b).
//!
//! Assert the section 10 chrome MUSTs on data: the always-visible indicators
//! reflect the state, the conditional warnings are present exactly when their
//! condition holds, and the PIP is the full 24 words with a public-identity
//! label that is never a forbidden term.

use entangled_core::crypto::{derive_pip, PublisherSigningKey};
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::canary::CanaryState;

use entangled_client::chrome::{ChromeConditions, ChromeView, Warning, PIP_LABEL};
use entangled_client::trust::TrustState;

fn key(seed: u8) -> PublisherPubkey {
    PublisherSigningKey::from_seed(&[seed; 32]).verifying_key()
}

fn view(trust: TrustState, canary: CanaryState, conditions: ChromeConditions) -> ChromeView {
    ChromeView::build(&key(7), trust, canary, "abcd...wxyz.onion", conditions)
}

#[test]
fn indicators_reflect_state() {
    let v = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions::default(),
    );
    assert_eq!(v.trust_state, TrustState::TofuPinned);
    assert_eq!(v.canary_state, CanaryState::Fresh);
    assert_eq!(v.carrier_address_compact, "abcd...wxyz.onion");
    // No condition holds and the canary is fresh -> no warnings.
    assert!(v.warnings.is_empty());
    assert!(!v.request_state_active);
}

#[test]
fn pip_is_full_24_words_and_label_is_public_identity() {
    let v = view(
        TrustState::FirstContact,
        CanaryState::Fresh,
        ChromeConditions::default(),
    );
    // Exactly the 24-word PIP for the key, never truncated.
    assert_eq!(v.pip, derive_pip(&key(7)));
    assert_eq!(v.pip.split_whitespace().count(), 24);

    // The label conveys public identity and is none of the forbidden terms.
    assert_eq!(v.pip_label, PIP_LABEL);
    let lower = v.pip_label.to_ascii_lowercase();
    for forbidden in [
        "seed phrase",
        "recovery phrase",
        "wallet phrase",
        "secret phrase",
        "private phrase",
    ] {
        assert!(
            !lower.contains(forbidden),
            "label must not say {forbidden:?}"
        );
    }
}

#[test]
fn changed_mismatch_surfaces_a_trust_warning() {
    let v = view(
        TrustState::ChangedMismatch,
        CanaryState::Fresh,
        ChromeConditions::default(),
    );
    assert!(v.warnings.contains(&Warning::TrustMismatch));
}

#[test]
fn pip_must_be_fully_shown_at_first_contact_and_mismatch_only() {
    // Section 10: the full PIP must be shown (not just collapsed) when the user
    // is being asked to verify identity - First contact and Changed/mismatch.
    for state in [TrustState::FirstContact, TrustState::ChangedMismatch] {
        let v = view(state, CanaryState::Fresh, ChromeConditions::default());
        assert!(
            v.pip_must_be_fully_shown,
            "PIP must be fully shown in {state:?}"
        );
    }
    // In the retained states it MAY be collapsed.
    for state in [TrustState::TofuPinned, TrustState::ExternallyVerified] {
        let v = view(state, CanaryState::Fresh, ChromeConditions::default());
        assert!(
            !v.pip_must_be_fully_shown,
            "PIP may be collapsed in {state:?}"
        );
    }
}

#[test]
fn expired_and_invalid_canary_surface_their_warnings() {
    let expired = view(
        TrustState::TofuPinned,
        CanaryState::Expired,
        ChromeConditions::default(),
    );
    assert!(expired.warnings.contains(&Warning::CanaryExpired));
    assert!(!expired.warnings.contains(&Warning::CanaryInvalid));

    let invalid = view(
        TrustState::TofuPinned,
        CanaryState::Invalid,
        ChromeConditions::default(),
    );
    assert!(invalid.warnings.contains(&Warning::CanaryInvalid));
}

#[test]
fn conditional_warnings_present_iff_condition_holds() {
    // Nothing set: no conditional warnings.
    let none = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions::default(),
    );
    assert!(none.warnings.is_empty());

    // Each condition set in turn surfaces exactly its warning.
    let conflict = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions {
            canary_conflict: true,
            ..ChromeConditions::default()
        },
    );
    assert_eq!(conflict.warnings, vec![Warning::CanaryConflict]);

    let gap = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions {
            canary_gap: true,
            ..ChromeConditions::default()
        },
    );
    assert_eq!(gap.warnings, vec![Warning::CanaryGap]);

    let historical = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions {
            historical_content: true,
            ..ChromeConditions::default()
        },
    );
    assert_eq!(historical.warnings, vec![Warning::HistoricalContent]);

    let stale = view(
        TrustState::TofuPinned,
        CanaryState::Unavailable,
        ChromeConditions {
            stale_cached: true,
            ..ChromeConditions::default()
        },
    );
    assert_eq!(stale.warnings, vec![Warning::StaleCachedContent]);
}

#[test]
fn request_state_indicator_reflects_the_flag() {
    let off = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions::default(),
    );
    assert!(!off.request_state_active);

    let on = view(
        TrustState::TofuPinned,
        CanaryState::Fresh,
        ChromeConditions {
            request_state_active: true,
            ..ChromeConditions::default()
        },
    );
    assert!(on.request_state_active);
}

#[test]
fn warnings_order_is_stable_identity_first() {
    // A worst-case stack: mismatch + conflict + expired + gap + historical.
    let v = view(
        TrustState::ChangedMismatch,
        CanaryState::Expired,
        ChromeConditions {
            canary_conflict: true,
            canary_gap: true,
            historical_content: true,
            ..ChromeConditions::default()
        },
    );
    assert_eq!(
        v.warnings,
        vec![
            Warning::TrustMismatch,
            Warning::CanaryConflict,
            Warning::CanaryExpired,
            Warning::CanaryGap,
            Warning::HistoricalContent,
        ]
    );
}
