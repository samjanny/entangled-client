//! The chrome model: what the client's always-visible UI must show.
//!
//! Section 10 makes the chrome normative: the client MUST persistently display
//! the publisher trust state, a compact carrier address, and the canary state;
//! MUST surface a fixed set of conditional warnings exactly when their condition
//! holds; and MUST display the full 24-word Publisher Identity Phrase labeled as
//! public identity (never as a "seed phrase"). This module produces a
//! [`ChromeView`]: a pure description of *what* to show. It assigns no colors
//! and uses no toolkit; the shell maps it to widgets. Keeping it pure makes the
//! normative chrome rules golden-testable on data.

use entangled_core::crypto::derive_pip;
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::canary::CanaryState;

use crate::trust::TrustState;

/// The normative label term for the PIP. The spec forbids "seed phrase" and
/// kin; this is the canonical public-identity wording. The shell may localize
/// it but must preserve the public-identity semantics.
pub const PIP_LABEL: &str = "publisher identity phrase";

/// Conditions, supplied by the caller, that drive the conditional warnings.
///
/// Each flag reflects an observed-and-unresolved condition for the current
/// publisher/session (canary conflict seen, a canary gap observed, historical
/// content being rendered, stale cached content shown, request-state active).
/// The caller derives them from canary/state/history; the chrome model only
/// decides which warnings to surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChromeConditions {
    /// `E_CANARY_CONFLICT` observed for the publisher and not yet resolved.
    pub canary_conflict: bool,
    /// A canary gap has been observed and not yet dismissed.
    pub canary_gap: bool,
    /// Historical (non-current) content is being rendered.
    pub historical_content: bool,
    /// Cached content is shown while the live canary state is unavailable.
    pub stale_cached: bool,
    /// The publisher has at least one stored request-state item that will be
    /// transmitted with future submits.
    pub request_state_active: bool,
}

/// A conditional, prominently-displayed warning. Present in [`ChromeView`] only
/// when its condition holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// Changed/mismatch trust state.
    TrustMismatch,
    /// An observed, unresolved canary conflict.
    CanaryConflict,
    /// The canary is expired.
    CanaryExpired,
    /// The canary is structurally invalid.
    CanaryInvalid,
    /// A canary gap was observed and not dismissed.
    CanaryGap,
    /// Historical content is being rendered.
    HistoricalContent,
    /// Stale cached content is shown while the canary state is unavailable.
    StaleCachedContent,
}

/// The pure chrome description for the current publisher/session.
///
/// The always-visible fields are always present; `warnings` holds only the
/// conditional warnings whose condition currently holds; `request_state_active`
/// is the conditional request-state indicator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChromeView {
    /// The publisher trust state to display.
    pub trust_state: TrustState,
    /// A compact representation of the current carrier address.
    pub carrier_address_compact: String,
    /// The canary state to display.
    pub canary_state: CanaryState,
    /// The label to show beside the PIP (public-identity wording, never
    /// "seed phrase").
    pub pip_label: &'static str,
    /// The complete 24-word Publisher Identity Phrase. Never truncated.
    pub pip: String,
    /// The conditional warnings currently in effect, in a stable order.
    pub warnings: Vec<Warning>,
    /// Whether the request-state indicator is shown.
    pub request_state_active: bool,
}

impl ChromeView {
    /// Build the chrome view for a publisher.
    ///
    /// - `publisher`: the verified publisher key; its PIP is derived for display.
    /// - `trust_state`: the resolved Stage 7 state.
    /// - `canary_state`: the computed Stage 8 state.
    /// - `carrier_address_compact`: the abbreviated address the shell shows
    ///   (kept opaque here; the shell decides the abbreviation).
    /// - `conditions`: the observed conditions driving the conditional warnings.
    pub fn build(
        publisher: &PublisherPubkey,
        trust_state: TrustState,
        canary_state: CanaryState,
        carrier_address_compact: impl Into<String>,
        conditions: ChromeConditions,
    ) -> ChromeView {
        let mut warnings = Vec::new();
        // Order is stable and matches the section 10 listing, most identity-
        // critical first.
        if trust_state == TrustState::ChangedMismatch {
            warnings.push(Warning::TrustMismatch);
        }
        if conditions.canary_conflict {
            warnings.push(Warning::CanaryConflict);
        }
        match canary_state {
            CanaryState::Expired => warnings.push(Warning::CanaryExpired),
            CanaryState::Invalid => warnings.push(Warning::CanaryInvalid),
            _ => {}
        }
        if conditions.canary_gap {
            warnings.push(Warning::CanaryGap);
        }
        if conditions.historical_content {
            warnings.push(Warning::HistoricalContent);
        }
        if conditions.stale_cached {
            warnings.push(Warning::StaleCachedContent);
        }

        ChromeView {
            trust_state,
            carrier_address_compact: carrier_address_compact.into(),
            canary_state,
            pip_label: PIP_LABEL,
            pip: derive_pip(publisher),
            warnings,
            request_state_active: conditions.request_state_active,
        }
    }
}
