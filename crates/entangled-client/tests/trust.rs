//! Golden tests for the Stage 7 trust-state machine.
//!
//! Each test asserts the (state, required action, persistence intent) triple
//! for a transition, with particular attention to the negative MUSTs: no
//! passive pin at first contact, and never silently replacing a retained
//! identity on mismatch.

use entangled_core::crypto::PublisherSigningKey;
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::DiagnosticCode;

use entangled_client::trust::{
    resolve, trust_diagnostic, PersistenceIntent, RequiredAction, RetainedIdentity, TrustState,
    UserDecision,
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
    // The replaced identity becomes a fresh First contact, not auto-verified,
    // so the replacement is persisted as a plain (non-externally-verified) pin.
    assert_eq!(r.state, TrustState::FirstContact);
    assert_eq!(
        r.intent,
        PersistenceIntent::ReplaceIdentity {
            new_pubkey: key(2),
            replaced: key(1),
            externally_verified: false,
        }
    );
}

#[test]
fn confirming_new_identity_with_pip_replaces_and_verifies() {
    let r = resolve(&key(2), Some(&verified(1)), UserDecision::ConfirmPip);
    assert_eq!(r.state, TrustState::ExternallyVerified);
    // The PIP-confirmed replacement MUST be persisted as externally verified
    // (§10:349-353), so the next session does not silently downgrade it to a
    // TOFU pin.
    assert_eq!(
        r.intent,
        PersistenceIntent::ReplaceIdentity {
            new_pubkey: key(2),
            replaced: key(1),
            externally_verified: true,
        }
    );
}

#[test]
fn pip_confirmed_replacement_is_not_downgraded_next_session() {
    // §10:349-353: a mismatch the user resolves by externally verifying the new
    // PIP enters Externally verified - and MUST stay there across sessions. We
    // simulate the persistence round-trip the shell performs: take this
    // session's ReplaceIdentity intent, build the retained record it implies,
    // and re-resolve the same key next session. It must resolve as Externally
    // verified, not a plain TOFU pin.
    let first = resolve(&key(2), Some(&verified(1)), UserDecision::ConfirmPip);
    let PersistenceIntent::ReplaceIdentity {
        new_pubkey,
        externally_verified,
        ..
    } = first.intent
    else {
        panic!("ConfirmPip mismatch must yield a ReplaceIdentity intent");
    };
    // The shell persists the replacement with the flag the intent carries.
    let next_session_record = RetainedIdentity {
        pubkey: new_pubkey,
        externally_verified,
    };
    // Next session, the same key is presented with no new decision.
    let second = resolve(&key(2), Some(&next_session_record), UserDecision::None);
    assert_eq!(
        second.state,
        TrustState::ExternallyVerified,
        "a PIP-confirmed replacement must not silently downgrade to TofuPinned"
    );
}

#[test]
fn explicit_rejection_preserves_retained_identity() {
    // The user explicitly rejects the presented identity during mismatch
    // resolution: the retained identity stays untouched, no further prompt is
    // required (the user already acted), and the section 11 outcome is
    // E_TRUST_USER_REJECTED rather than the unresolved-mismatch code.
    let r = resolve(&key(2), Some(&pinned(1)), UserDecision::RejectNewIdentity);
    assert_eq!(r.state, TrustState::ChangedMismatch);
    assert_eq!(r.action, RequiredAction::None);
    assert_eq!(r.intent, PersistenceIntent::None);
    assert_eq!(
        trust_diagnostic(&r, UserDecision::RejectNewIdentity),
        Some(DiagnosticCode::ETrustUserRejected)
    );
}

#[test]
fn trust_diagnostics_map_per_section_11() {
    // Unresolved mismatch -> E_TRUST_MISMATCH.
    let mismatch = resolve(&key(2), Some(&pinned(1)), UserDecision::None);
    assert_eq!(
        trust_diagnostic(&mismatch, UserDecision::None),
        Some(DiagnosticCode::ETrustMismatch)
    );
    // First contact (no decision) -> I_TRUST_FIRST_CONTACT.
    let first = resolve(&key(1), None, UserDecision::None);
    assert_eq!(
        trust_diagnostic(&first, UserDecision::None),
        Some(DiagnosticCode::ITrustFirstContact)
    );
    // Affirmative pin -> I_TRUST_TOFU_PINNED.
    let pin = resolve(&key(1), None, UserDecision::PinFirstContact);
    assert_eq!(
        trust_diagnostic(&pin, UserDecision::PinFirstContact),
        Some(DiagnosticCode::ITrustTofuPinned)
    );
    // PIP confirmation -> I_TRUST_VERIFIED, from first contact and from a pin.
    let pip_first = resolve(&key(1), None, UserDecision::ConfirmPip);
    assert_eq!(
        trust_diagnostic(&pip_first, UserDecision::ConfirmPip),
        Some(DiagnosticCode::ITrustVerified)
    );
    let pip_elevate = resolve(&key(1), Some(&pinned(1)), UserDecision::ConfirmPip);
    assert_eq!(
        trust_diagnostic(&pip_elevate, UserDecision::ConfirmPip),
        Some(DiagnosticCode::ITrustVerified)
    );
    // Steady states surface no event: a matching pin or verified key with no
    // elevating decision.
    let steady_pin = resolve(&key(1), Some(&pinned(1)), UserDecision::None);
    assert_eq!(trust_diagnostic(&steady_pin, UserDecision::None), None);
    let steady_verified = resolve(&key(1), Some(&verified(1)), UserDecision::None);
    assert_eq!(trust_diagnostic(&steady_verified, UserDecision::None), None);
}
