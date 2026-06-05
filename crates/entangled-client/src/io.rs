//! I/O seams: traits the impure client shell implements so this crate stays
//! pure and testable.
//!
//! The client brain takes facts as data and never performs I/O itself. The one
//! seam it needs in tranche 1 is the clock, because several pipeline checks
//! (canary freshness, `manifest.updated` skew, `origin.not_after`) are relative
//! to the current time, and a pure, testable brain must receive that time
//! rather than read the system clock.
//!
//! Later tranches add more seams here as they gain real semantics:
//! `Transport` (fetch/POST over a carrier), `IdentityStore` / `MigrationHistory`
//! / `AuthorizationHistory` (publisher-history persistence), `Decoder` (image
//! decode), and `SecureRng` (submit `request_id`). They are intentionally not
//! declared yet: an empty trait fixes nothing, and each is best shaped together
//! with the tranche that uses it.

use entangled_core::types::EntangledTimestamp;

/// Source of the current time.
///
/// The shell implements this over the system clock; tests implement it with a
/// fixed instant so time-relative pipeline checks are deterministic. The spec's
/// clock-skew tolerances and canary-state thresholds are evaluated against the
/// value this returns.
pub trait Clock {
    /// The current wall-clock time, as an Entangled timestamp.
    fn now(&self) -> EntangledTimestamp;
}

/// A [`Clock`] pinned to a fixed instant. Useful for tests and for any caller
/// that has already established a verified-time reference and wants to drive the
/// pipeline against it.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub EntangledTimestamp);

impl Clock for FixedClock {
    fn now(&self) -> EntangledTimestamp {
        self.0
    }
}
