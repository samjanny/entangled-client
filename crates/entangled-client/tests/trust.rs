//! Golden tests for the Stage 7 trust-state machine.
//!
//! Each test asserts the (state, required action, persistence intent) triple
//! for a transition, with particular attention to the negative MUSTs: no
//! passive pin at first contact, and never silently replacing a retained
//! identity on mismatch.

use entangled_core::crypto::PublisherSigningKey;
use entangled_core::types::PublisherPubkey;

use entangled_client::trust::{
    resolve, PersistenceIntent, RequiredAction, RetainedIdentity, TrustState, UserDecision,
};

fn key(seed: u8) -> PublisherPubkey {
    PublisherSigningKey::from_seed(&[seed; 32]).verifying_key()
}

fn pinned(seed: u8) -> RetainedIdentity {
    RetainedIdentity {
        pubkey: key(seed),
        externally_verified: false,
    }
}

fn verified(seed: u8) -> RetainedIdentity {
    RetainedIdentity {
        pubkey: key(seed),
        externally_verified: true,
    }
}

#[test]
fn first_contact_without_decision_does_not_pin() {
    let r = resolve(&key(1), None, UserDecision::None);
    assert_eq!(r.state, TrustState::FirstContact);
    assert_eq!(r.action, RequiredAction::PinPrompt);
    // The load-bearing MUST: no passive pin -> nothing persisted.
    assert_eq!(r.intent, PersistenceIntent::None);
}

#[test]
fn first_contact_with_affirmative_pin_persists() {
    let r = resolve(&key(1), None, UserDecision::PinFirstContact);
    assert_eq!(r.state, TrustState::TofuPinned);
    assert_eq!(r.action, RequiredAction::None);
    assert_eq!(r.intent, PersistenceIntent::PinIdentity { pubkey: key(1) });
}

#[test]
fn first_contact_with_pip_goes_externally_verified() {
    let r = resolve(&key(1), None, UserDecision::ConfirmPip);
    assert_eq!(r.state, TrustState::ExternallyVerified);
    assert_eq!(
        r.intent,
        PersistenceIntent::MarkExternallyVerified { pubkey: key(1) }
    );
}

#[test]
fn matching_pinned_key_stays_pinned_no_persist() {
    let r = resolve(&key(1), Some(&pinned(1)), UserDecision::None);
    assert_eq!(r.state, TrustState::TofuPinned);
    assert_eq!(r.action, RequiredAction::None);
    assert_eq!(r.intent, PersistenceIntent::None);
}

#[test]
fn matching_verified_key_stays_verified() {
    let r = resolve(&key(1), Some(&verified(1)), UserDecision::None);
    assert_eq!(r.state, TrustState::ExternallyVerified);
    assert_eq!(r.intent, PersistenceIntent::None);
}

#[test]
fn pip_confirmation_elevates_pinned_to_verified() {
    let r = resolve(&key(1), Some(&pinned(1)), UserDecision::ConfirmPip);
    assert_eq!(r.state, TrustState::ExternallyVerified);
    assert_eq!(
        r.intent,
        PersistenceIntent::MarkExternallyVerified { pubkey: key(1) }
    );
}

#[test]
fn different_key_without_confirmation_is_mismatch_and_never_replaces() {
    // Retained key 1, presented key 2, no user confirmation.
    let r = resolve(&key(2), Some(&pinned(1)), UserDecision::None);
    assert_eq!(r.state, TrustState::ChangedMismatch);
    assert_eq!(r.action, RequiredAction::MismatchWarning);
    // The most important MUST: the retained identity is NOT replaced.
    assert_eq!(r.intent, PersistenceIntent::None);
}

#[test]
fn mismatch_against_externally_verified_also_never_replaces() {
    let r = resolve(&key(2), Some(&verified(1)), UserDecision::None);
    assert_eq!(r.state, TrustState::ChangedMismatch);
    assert_eq!(r.intent, PersistenceIntent::None);
}

#[test]
fn confirming_new_identity_replaces_and_preserves_prior() {
    let r = resolve(&key(2), Some(&pinned(1)), UserDecision::ConfirmNewIdentity);
    // The replaced identity becomes a fresh First contact, not auto-verified.
    assert_eq!(r.state, TrustState::FirstContact);
    assert_eq!(
        r.intent,
        PersistenceIntent::ReplaceIdentity {
            new_pubkey: key(2),
            replaced: key(1),
        }
    );
}

#[test]
fn confirming_new_identity_with_pip_replaces_and_verifies() {
    let r = resolve(&key(2), Some(&verified(1)), UserDecision::ConfirmPip);
    assert_eq!(r.state, TrustState::ExternallyVerified);
    assert_eq!(
        r.intent,
        PersistenceIntent::ReplaceIdentity {
            new_pubkey: key(2),
            replaced: key(1),
        }
    );
}
