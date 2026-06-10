//! I/O seams: traits the impure client shell implements so this crate stays
//! pure and testable.
//!
//! The client brain takes facts as data and never performs I/O itself. The one
//! seam it needed in tranche 1 is the clock, because several pipeline checks
//! (canary freshness, `manifest.updated` skew, `origin.not_after`) are relative
//! to the current time, and a pure, testable brain must receive that time
//! rather than read the system clock.
//!
//! This tranche adds the persistence seams: [`IdentityStore`] (the retained
//! publisher identity for Stage 7 trust resolution) and [`HistoryStore`] (the
//! accepted-manifest history the §08 anti-downgrade / canary-conflict /
//! runtime-rotation checks run against). Both follow the [`Clock`] shape - a
//! trait the impure shell implements, consumed here as `&impl Trait`, with an
//! in-memory double ([`MemoryIdentityStore`] / [`MemoryHistoryStore`]) for
//! tests. The durable, filesystem-backed implementations live in a separate
//! crate so this one stays pure and dependency-light.
//!
//! Later tranches add more seams here as they gain real semantics: `Transport`
//! (fetch/POST over a carrier), `MigrationHistory` / `AuthorizationHistory` (the
//! cross-session migration recall window and runtime-authorization history),
//! `Decoder` (image decode), and `SecureRng` (submit `request_id`). They are
//! intentionally not declared yet: an empty trait fixes nothing, and each is
//! best shaped together with the tranche that uses it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use entangled_core::types::{EntangledTimestamp, OnionAddress, PublisherPubkey};
use entangled_core::validation::canary::RetainedManifestRecord;

use crate::history::PublisherHistory;
use crate::trust::{PersistenceIntent, RetainedIdentity, RetainedProvenance};

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

/// An error from a persistence seam.
///
/// Opaque to the brain: the brain never branches on the cause, it only
/// distinguishes "the store says nothing is retained" (`Ok(None)` /
/// `Ok(empty)`) from "the store failed or is untrustworthy" (`Err`). The shell
/// maps real I/O, decode, and integrity (MAC/AEAD) failures into this. The
/// brain treats `Err` as fail-closed: a corrupt or tampered trust store MUST
/// NOT be silently read as "no retained identity" (which would downgrade a
/// pinned publisher to first contact), per the §10:571 corruption-rejection
/// precedent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// Result alias for the persistence seams.
pub type StoreResult<T> = Result<T, StoreError>;

/// Persistence of the retained publisher identity for Stage 7 trust resolution.
///
/// Keyed by **site** (the carrier [`OnionAddress`]), not by publisher key, per
/// §10:187-189: the retained identity is "for the site or publisher profile",
/// and a Changed/mismatch is precisely the case where the manifest's
/// `publisher_pubkey` *differs* from the retained one. Keying by the presented
/// publisher key would never find the retained record on a key change, so every
/// rotation would read as first contact instead of the mismatch §10:338
/// requires.
///
/// The shell calls [`load_identity`](IdentityStore::load_identity) for the site
/// before [`crate::trust::resolve`] to obtain the `Option<RetainedIdentity>`
/// that function takes, and [`apply`](IdentityStore::apply) afterwards to commit
/// the [`PersistenceIntent`] the resolution produced. The seam honors §10:215
/// persistence ordering by contract: the caller only ever calls `apply` after a
/// manifest has passed every stage including Stage 9 origin binding.
///
/// `&self` (not `&mut self`): the durable map is the filesystem, and the
/// in-memory double uses interior mutability, so one store can be shared as
/// `&impl IdentityStore` exactly like `&impl Clock`.
pub trait IdentityStore {
    /// Load the retained identity for `site`, or `None` if none is retained
    /// (first contact). A missing store is `Ok(None)`. A corrupt, unreadable, or
    /// integrity-failed store is `Err` (fail-closed - see [`StoreError`]).
    fn load_identity(&self, site: &OnionAddress) -> StoreResult<Option<RetainedIdentity>>;

    /// Apply a trust resolution's persistence intent for `site`.
    ///
    /// [`PersistenceIntent::None`] is a no-op that returns `Ok(())`. The intent
    /// carries the publisher keys; `site` is the record key. For
    /// [`PersistenceIntent::ReplaceIdentity`] the replaced key MUST be retained
    /// (not lost), so a later tranche can surface the replacement history.
    fn apply(&self, site: &OnionAddress, intent: &PersistenceIntent) -> StoreResult<()>;
}

/// Persistence of the accepted-manifest history for a publisher.
///
/// Feeds the §08 anti-downgrade, canary-conflict, and runtime-rotation checks
/// ([`crate::history::check_against_history`]). The shell calls
/// [`load_history`](HistoryStore::load_history) before verifying (so the checks
/// run against retained records) and [`append_record`](HistoryStore::append_record)
/// after a manifest is accepted (§10:215 ordering).
pub trait HistoryStore {
    /// Load the full retained history for `publisher`, newest-first, ready to
    /// hand to [`crate::history::check_against_history`]. A missing store is
    /// `Ok(PublisherHistory::new())` (empty == first contact). A corrupt store
    /// is `Err` (fail-closed: a silently-emptied history would re-open the
    /// anti-downgrade and runtime-reuse holes).
    fn load_history(&self, publisher: &PublisherPubkey) -> StoreResult<PublisherHistory>;

    /// Append a newly accepted record as the newest entry for `publisher`.
    /// Called only after the manifest passed all stages (§10:215). The record is
    /// [`crate::history::record_for`] of the verified manifest.
    fn append_record(
        &self,
        publisher: &PublisherPubkey,
        record: &RetainedManifestRecord,
    ) -> StoreResult<()>;
}

/// An in-memory [`IdentityStore`] for golden tests and any caller that wants a
/// non-durable store. Mirrors [`FixedClock`]'s role. Interior mutability lets it
/// be shared as `&impl IdentityStore` while `apply` mutates. Keyed by site.
#[derive(Default)]
pub struct MemoryIdentityStore {
    map: RefCell<HashMap<OnionAddress, RetainedIdentity>>,
    /// Replaced keys preserved per site (newest-first) so a replacement never
    /// loses the prior key, mirroring the file store's `replaced_pubkeys`.
    replaced: RefCell<HashMap<OnionAddress, Vec<PublisherPubkey>>>,
}

impl MemoryIdentityStore {
    /// A fresh, empty store.
    pub fn new() -> MemoryIdentityStore {
        MemoryIdentityStore::default()
    }

    /// Test helper: seed a retained identity for `site` directly (bypassing `apply`).
    pub fn seed(&self, site: OnionAddress, identity: RetainedIdentity) {
        self.map.borrow_mut().insert(site, identity);
    }

    /// Test helper: the replaced keys retained for `site`, newest-first.
    pub fn replaced_keys(&self, site: &OnionAddress) -> Vec<PublisherPubkey> {
        self.replaced
            .borrow()
            .get(site)
            .cloned()
            .unwrap_or_default()
    }
}

impl IdentityStore for MemoryIdentityStore {
    fn load_identity(&self, site: &OnionAddress) -> StoreResult<Option<RetainedIdentity>> {
        Ok(self.map.borrow().get(site).copied())
    }

    fn apply(&self, site: &OnionAddress, intent: &PersistenceIntent) -> StoreResult<()> {
        match intent {
            PersistenceIntent::None => {}
            PersistenceIntent::RecordObservation { pubkey } => {
                // The automatic first-contact observation (§10:298): created
                // only when nothing is retained. Never overwrites or demotes an
                // existing record of any provenance.
                self.map
                    .borrow_mut()
                    .entry(site.clone())
                    .or_insert(RetainedIdentity {
                        pubkey: *pubkey,
                        provenance: RetainedProvenance::Observed,
                    });
            }
            PersistenceIntent::PinIdentity { pubkey } => {
                // Non-destructive: a pin upgrades an observed-only record but
                // never demotes an already-verified site back to a plain pin.
                self.map
                    .borrow_mut()
                    .entry(site.clone())
                    .and_modify(|r| {
                        if r.provenance == RetainedProvenance::Observed {
                            r.pubkey = *pubkey;
                            r.provenance = RetainedProvenance::Pinned;
                        }
                    })
                    .or_insert(RetainedIdentity {
                        pubkey: *pubkey,
                        provenance: RetainedProvenance::Pinned,
                    });
            }
            PersistenceIntent::MarkExternallyVerified { pubkey } => {
                // Covers first-contact-PIP (insert) and observed/TOFU->verified
                // elevation without ever clobbering the provenance back down.
                self.map
                    .borrow_mut()
                    .entry(site.clone())
                    .and_modify(|r| {
                        r.pubkey = *pubkey;
                        r.provenance = RetainedProvenance::ExternallyVerified;
                    })
                    .or_insert(RetainedIdentity {
                        pubkey: *pubkey,
                        provenance: RetainedProvenance::ExternallyVerified,
                    });
            }
            PersistenceIntent::ReplaceIdentity {
                new_pubkey,
                replaced,
                externally_verified,
            } => {
                self.replaced
                    .borrow_mut()
                    .entry(site.clone())
                    .or_default()
                    .insert(0, *replaced);
                // The replaced key is no longer the site's active identity; it is
                // preserved in `replaced`. The site slot now holds the new key. A
                // confirmed replacement is an explicit decision, so the record is
                // a pin (or a verification when the user confirmed the PIP too).
                self.map.borrow_mut().insert(
                    site.clone(),
                    RetainedIdentity {
                        pubkey: *new_pubkey,
                        provenance: if *externally_verified {
                            RetainedProvenance::ExternallyVerified
                        } else {
                            RetainedProvenance::Pinned
                        },
                    },
                );
            }
        }
        Ok(())
    }
}

/// An in-memory [`HistoryStore`] for golden tests. Mirrors [`FixedClock`]'s role.
#[derive(Default)]
pub struct MemoryHistoryStore {
    map: RefCell<HashMap<PublisherPubkey, Vec<RetainedManifestRecord>>>,
}

impl MemoryHistoryStore {
    /// A fresh, empty store.
    pub fn new() -> MemoryHistoryStore {
        MemoryHistoryStore::default()
    }
}

impl HistoryStore for MemoryHistoryStore {
    fn load_history(&self, publisher: &PublisherPubkey) -> StoreResult<PublisherHistory> {
        let records = self
            .map
            .borrow()
            .get(publisher)
            .cloned()
            .unwrap_or_default();
        Ok(PublisherHistory::from_records_newest_first(records))
    }

    fn append_record(
        &self,
        publisher: &PublisherPubkey,
        record: &RetainedManifestRecord,
    ) -> StoreResult<()> {
        self.map
            .borrow_mut()
            .entry(*publisher)
            .or_default()
            .insert(0, record.clone());
        Ok(())
    }
}
