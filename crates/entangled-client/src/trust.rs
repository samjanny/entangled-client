//! The section 10 Stage 7 trust-state machine.
//!
//! This is the security-critical heart of the client. It decides, for a
//! verified manifest's publisher key, which of the four trust states applies,
//! what user action (if any) the chrome must demand, and what the shell should
//! persist - all as a pure function over data. It performs no I/O and writes
//! nothing: persistence is described by a returned [`PersistenceIntent`] that
//! the shell applies via a store trait in a later tranche.
//!
//! The normative MUSTs this encodes (section 10 "Trust state machine"):
//!
//! - a manifest from a publisher with no retained record is **First contact**;
//!   it is never silently pinned. Pinning requires an explicit affirmative user
//!   decision (no passive event pins);
//! - first contact records an automatic **observation** (§10:298): a retained
//!   record with `Observed` provenance that arms Changed/mismatch detection on
//!   later visits without ever becoming a pin by itself. A matching revisit of
//!   an observed-only record stays First contact, prompt included;
//! - a retained identity that matches the presented key stays in its retained
//!   state with no transition;
//! - a retained identity against a *different* presented key is
//!   **Changed/mismatch**: the client MUST NOT silently replace the retained
//!   identity, so [`resolve`] returns the retained state unchanged and an empty
//!   persistence intent unless the user explicitly confirmed the new key;
//! - persistence intent is produced only for a manifest that has already passed
//!   the pipeline (the caller calls this after a verified manifest), honoring
//!   the section 10 persistence-ordering rule.
//!
//! [`resolve`] is given the user's decision as data. The chrome gathers that
//! decision from an affirmative control; this module never assumes it.

use entangled_core::types::PublisherPubkey;
use entangled_core::validation::DiagnosticCode;

/// The four mutually exclusive publisher trust states (section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustState {
    /// No prior retained record and no user-confirmed PIP for this key.
    FirstContact,
    /// The key was previously observed and retained, but not externally
    /// verified against a PIP.
    TofuPinned,
    /// The user confirmed the key against an out-of-band PIP reference.
    ExternallyVerified,
    /// A different key than the retained identity was presented.
    ChangedMismatch,
}

/// How a retained record was established (section 10).
///
/// Section 10 distinguishes the observation record - created automatically at
/// first contact once the pipeline through Stage 9 succeeds, "a retained
/// observation used to detect later changes" (§10:298) - from the records
/// explicit user decisions create: the TOFU pin, which MUST NOT happen without
/// an affirmative response to the pinning prompt (§10:308), and the externally
/// verified record. All three arm Changed/mismatch detection; they differ in
/// the trust state a matching revisit resolves to. An observed-only record
/// keeps the state at First contact (the pin prompt remains), so retention for
/// change detection never silently becomes a pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedProvenance {
    /// Recorded automatically at first contact, with no user decision.
    Observed,
    /// The user explicitly affirmed the pinning prompt.
    Pinned,
    /// The user externally verified the key against its PIP.
    ExternallyVerified,
}

/// What the client has retained for a publisher profile.
///
/// The shell loads this (a later tranche, behind a store trait); here it is the
/// input the machine resolves against. `None` at the call site means first
/// contact with no prior observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedIdentity {
    /// The retained publisher key.
    pub pubkey: PublisherPubkey,
    /// How the record was established: automatic observation, explicit pin, or
    /// external PIP verification.
    pub provenance: RetainedProvenance,
}

/// The user's decision relevant to this resolution, gathered by the chrome from
/// an explicit affirmative control. Absence of a decision is [`UserDecision::None`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UserDecision {
    /// No decision provided this resolution (the default; pinning and
    /// replacement never happen without an explicit decision).
    #[default]
    None,
    /// At first contact, the user affirmatively chose to retain (pin) the
    /// presented identity.
    PinFirstContact,
    /// The user confirmed the presented key against an out-of-band PIP.
    ConfirmPip,
    /// In Changed/mismatch, the user confirmed the new key as legitimate,
    /// replacing the retained identity.
    ConfirmNewIdentity,
    /// In Changed/mismatch, the user explicitly rejected the presented
    /// identity, abandoning the navigation and preserving the retained
    /// identity (section 10 "abandon the site, preserving the existing
    /// retained identity"). Surfaced as `E_TRUST_USER_REJECTED` (section 11).
    RejectNewIdentity,
}

/// The user action the chrome must demand for this state, if any. The chrome
/// turns this into a prompt or warning; the machine never performs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredAction {
    /// Nothing required from the user.
    None,
    /// Present the first-contact pinning prompt (and display the PIP).
    PinPrompt,
    /// Present a prominent, not-easily-dismissible identity-mismatch warning.
    MismatchWarning,
}

/// What the shell should persist as a result of this resolution. The machine
/// returns intent; it never writes. Honors section 10 persistence ordering:
/// these are produced only for a manifest the caller has already verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistenceIntent {
    /// Persist nothing. (A matching revisit that changes nothing; an
    /// unresolved mismatch - the retained identity is left untouched.)
    None,
    /// Record the automatic first-contact observation for `pubkey` (§10:298).
    /// Created with no user decision once the manifest has passed the pipeline
    /// through Stage 9; arms Changed/mismatch detection without pinning. The
    /// store MUST NOT let this overwrite or demote an existing record.
    RecordObservation {
        /// The key observed at first contact.
        pubkey: PublisherPubkey,
    },
    /// Record a new TOFU-pinned observation for `pubkey`.
    PinIdentity {
        /// The key to retain.
        pubkey: PublisherPubkey,
    },
    /// Mark `pubkey` as externally verified (from first contact, TOFU, or a
    /// confirmed replacement).
    MarkExternallyVerified {
        /// The key the user confirmed against a PIP.
        pubkey: PublisherPubkey,
    },
    /// Replace the retained identity with a user-confirmed new key, preserving
    /// the prior key as a replaced-identity history event.
    ReplaceIdentity {
        /// The newly confirmed key.
        new_pubkey: PublisherPubkey,
        /// The prior key being replaced (kept in publisher history).
        replaced: PublisherPubkey,
        /// Whether the user externally verified the new key against its PIP
        /// while resolving the mismatch (§10:349-353). When `true`, the shell
        /// MUST persist the replacement as externally verified so the next
        /// session resolves it as Externally verified, not a plain TOFU pin;
        /// `false` is a plain confirmed replacement that starts as a TOFU pin.
        externally_verified: bool,
    },
}

/// The outcome of resolving trust for a presented publisher key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// The resulting trust state.
    pub state: TrustState,
    /// The user action the chrome must demand, if any.
    pub action: RequiredAction,
    /// What the shell should persist.
    pub intent: PersistenceIntent,
}

/// Resolve the trust state for a verified manifest's `presented` publisher key,
/// given what is `retained` for the publisher profile and the user's `decision`.
///
/// Call this only after the manifest has passed the validation pipeline (the
/// presented key comes from a verified manifest); the returned intent then
/// honors persistence ordering.
pub fn resolve(
    presented: &PublisherPubkey,
    retained: Option<&RetainedIdentity>,
    decision: UserDecision,
) -> Resolution {
    match retained {
        // No retained record: first contact. Never silently pinned.
        None => first_contact(presented, decision),

        // A retained identity exists.
        Some(retained) if &retained.pubkey == presented => {
            // Same key: stay in the retained state. A PIP confirmation may
            // elevate a plain TOFU pin to externally verified.
            matched(presented, retained, decision)
        }
        Some(retained) => {
            // Different key: Changed/mismatch. Never silently replaced.
            mismatch(presented, retained, decision)
        }
    }
}

/// Resolution when no identity is retained for the publisher.
fn first_contact(presented: &PublisherPubkey, decision: UserDecision) -> Resolution {
    match decision {
        // The user externally verified the PIP at first contact: straight to
        // Externally verified.
        UserDecision::ConfirmPip => Resolution {
            state: TrustState::ExternallyVerified,
            action: RequiredAction::None,
            intent: PersistenceIntent::MarkExternallyVerified { pubkey: *presented },
        },
        // The user affirmatively chose to pin.
        UserDecision::PinFirstContact => Resolution {
            state: TrustState::TofuPinned,
            action: RequiredAction::None,
            intent: PersistenceIntent::PinIdentity { pubkey: *presented },
        },
        // No decision (or a decision that does not apply here): remain First
        // contact, show the pinning prompt, and record the automatic
        // observation (§10:298) so a later identity change is detectable. No
        // passive pin: the record's provenance is Observed, not Pinned.
        UserDecision::None | UserDecision::ConfirmNewIdentity | UserDecision::RejectNewIdentity => {
            Resolution {
                state: TrustState::FirstContact,
                action: RequiredAction::PinPrompt,
                intent: PersistenceIntent::RecordObservation { pubkey: *presented },
            }
        }
    }
}

/// Resolution when the retained key matches the presented key.
fn matched(
    presented: &PublisherPubkey,
    retained: &RetainedIdentity,
    decision: UserDecision,
) -> Resolution {
    // A PIP confirmation elevates an observation or a TOFU pin to externally
    // verified.
    if decision == UserDecision::ConfirmPip
        && retained.provenance != RetainedProvenance::ExternallyVerified
    {
        return Resolution {
            state: TrustState::ExternallyVerified,
            action: RequiredAction::None,
            intent: PersistenceIntent::MarkExternallyVerified { pubkey: *presented },
        };
    }
    // An affirmative pin against an observed-only record: the pinning prompt
    // is still showing for this key (§10:308), and the user has now answered
    // it. Upgrade the observation to a pin.
    if decision == UserDecision::PinFirstContact
        && retained.provenance == RetainedProvenance::Observed
    {
        return Resolution {
            state: TrustState::TofuPinned,
            action: RequiredAction::None,
            intent: PersistenceIntent::PinIdentity { pubkey: *presented },
        };
    }
    // Otherwise no transition: stay in the state the provenance implies,
    // persist nothing. An observed-only record keeps the state at First
    // contact with the pinning prompt: retention for change detection never
    // silently becomes a pin (§10:308).
    match retained.provenance {
        RetainedProvenance::Observed => Resolution {
            state: TrustState::FirstContact,
            action: RequiredAction::PinPrompt,
            intent: PersistenceIntent::None,
        },
        RetainedProvenance::Pinned => Resolution {
            state: TrustState::TofuPinned,
            action: RequiredAction::None,
            intent: PersistenceIntent::None,
        },
        RetainedProvenance::ExternallyVerified => Resolution {
            state: TrustState::ExternallyVerified,
            action: RequiredAction::None,
            intent: PersistenceIntent::None,
        },
    }
}

/// Resolution when the retained key differs from the presented key.
fn mismatch(
    presented: &PublisherPubkey,
    retained: &RetainedIdentity,
    decision: UserDecision,
) -> Resolution {
    match decision {
        // The user explicitly confirmed the new key as legitimate: replace,
        // preserving the prior key in history. The new identity becomes a fresh
        // First contact (it is not externally verified by this action alone),
        // so the replacement is persisted as a plain (non-externally-verified)
        // pin.
        UserDecision::ConfirmNewIdentity => Resolution {
            state: TrustState::FirstContact,
            action: RequiredAction::None,
            intent: PersistenceIntent::ReplaceIdentity {
                new_pubkey: *presented,
                replaced: retained.pubkey,
                externally_verified: false,
            },
        },
        // The user also externally verified the new key against its PIP while
        // resolving (§10:349-353): the replacement is persisted as externally
        // verified, so the next session resolves it as Externally verified
        // rather than silently downgrading to a TOFU pin.
        UserDecision::ConfirmPip => Resolution {
            state: TrustState::ExternallyVerified,
            action: RequiredAction::None,
            intent: PersistenceIntent::ReplaceIdentity {
                new_pubkey: *presented,
                replaced: retained.pubkey,
                externally_verified: true,
            },
        },
        // The user explicitly rejected the presented identity: the mismatch is
        // resolved by abandoning the navigation. The retained identity is
        // preserved untouched; no further prompt is required because the user
        // has already acted on the resolution control. The section 11
        // diagnostic for this outcome is E_TRUST_USER_REJECTED (see
        // [`trust_diagnostic`]).
        UserDecision::RejectNewIdentity => Resolution {
            state: TrustState::ChangedMismatch,
            action: RequiredAction::None,
            intent: PersistenceIntent::None,
        },
        // No confirmation: stay Changed/mismatch, warn prominently, and - the
        // load-bearing MUST - never replace the retained identity.
        UserDecision::None | UserDecision::PinFirstContact => Resolution {
            state: TrustState::ChangedMismatch,
            action: RequiredAction::MismatchWarning,
            intent: PersistenceIntent::None,
        },
    }
}

/// Map a [`Resolution`] (and the [`UserDecision`] that produced it) to the
/// section 11 trust diagnostic it surfaces, if any.
///
/// The Stage 6 manifest identity pre-check errors (section 10: detected before
/// signature verification, taking precedence over `E_SIG_VERIFICATION`):
///
/// - an unresolved Changed/mismatch is `E_TRUST_MISMATCH`;
/// - a mismatch the user resolved by explicitly rejecting the presented
///   identity is `E_TRUST_USER_REJECTED`.
///
/// The Stage 7 info codes mark transitions and observations, not steady
/// states:
///
/// - `I_TRUST_FIRST_CONTACT` when a first-contact observation is recorded for
///   a previously unknown publisher identity (§10:298, §11), including the
///   fresh first contact produced by a user-confirmed identity replacement. A
///   matching revisit of an observed-only record stays First contact but
///   records nothing new and surfaces no event;
/// - `I_TRUST_TOFU_PINNED` when an explicit user decision pins the identity;
/// - `I_TRUST_VERIFIED` when the user externally verifies the key against its
///   PIP, whether from first contact, from a TOFU pin, or while resolving a
///   mismatch.
///
/// A resolution that changes nothing - a retained identity matching the
/// presented key with no elevating decision - surfaces no diagnostic.
pub fn trust_diagnostic(resolution: &Resolution, decision: UserDecision) -> Option<DiagnosticCode> {
    match resolution.state {
        TrustState::ChangedMismatch => Some(if decision == UserDecision::RejectNewIdentity {
            DiagnosticCode::ETrustUserRejected
        } else {
            DiagnosticCode::ETrustMismatch
        }),
        TrustState::FirstContact => match resolution.intent {
            PersistenceIntent::RecordObservation { .. }
            | PersistenceIntent::ReplaceIdentity { .. } => Some(DiagnosticCode::ITrustFirstContact),
            _ => None,
        },
        TrustState::TofuPinned => match resolution.intent {
            PersistenceIntent::PinIdentity { .. } => Some(DiagnosticCode::ITrustTofuPinned),
            _ => None,
        },
        TrustState::ExternallyVerified => match resolution.intent {
            PersistenceIntent::MarkExternallyVerified { .. }
            | PersistenceIntent::ReplaceIdentity {
                externally_verified: true,
                ..
            } => Some(DiagnosticCode::ITrustVerified),
            _ => None,
        },
    }
}
