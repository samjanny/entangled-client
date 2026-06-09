//! Publisher history: the anti-downgrade, canary-conflict, and runtime-rotation
//! checks a client applies against what it has already accepted for a publisher.
//!
//! Section 08 / section 10 require a client to reject a manifest whose canary
//! `issued_at` regresses (anti-downgrade), to flag an equal-`issued_at` manifest
//! that differs from the retained one (canary conflict), and to enforce that the
//! runtime key rotates (no reuse of the immediately-preceding key, and SHOULD
//! not reuse an earlier one). `entangled-core` provides the primitive checks
//! ([`check_anti_downgrade`], [`check_canary_conflict`],
//! [`check_runtime_pubkey_rotation`]) and the [`RetainedManifestRecord`] type;
//! this module holds the per-publisher history those checks run against and
//! drives them as one step.
//!
//! It is pure: the history is data the caller supplies (the shell will load and
//! persist it behind a trait in a later tranche), and these functions return a
//! decision without performing any I/O.

use entangled_core::types::Manifest;
use entangled_core::validation::canary::{
    check_anti_downgrade, check_canary_conflict, check_runtime_pubkey_rotation,
    RetainedManifestRecord,
};
use entangled_core::validation::Diagnostic;

/// What a client has previously accepted for a single publisher, newest first.
///
/// The anti-downgrade and conflict checks compare a new manifest against the
/// newest retained record; the runtime-rotation check additionally consults the
/// older entries (the "extended history"). The caller is responsible for
/// keeping this keyed per `K_publisher.pub` and persisting it (a later tranche
/// does that behind a trait); here it is a plain, ordered list.
#[derive(Clone, Debug, Default)]
pub struct PublisherHistory {
    /// Accepted manifest records, newest first.
    records: Vec<RetainedManifestRecord>,
}

impl PublisherHistory {
    /// An empty history (first contact: no prior records).
    pub fn new() -> PublisherHistory {
        PublisherHistory {
            records: Vec::new(),
        }
    }

    /// Build a history from records already ordered newest-first - for example,
    /// loaded from a persistence store. The caller guarantees the ordering; this
    /// does not re-sort. Pairs with [`records`](Self::records) for round-tripping
    /// the history through a [`HistoryStore`](crate::io::HistoryStore).
    pub fn from_records_newest_first(records: Vec<RetainedManifestRecord>) -> PublisherHistory {
        PublisherHistory { records }
    }

    /// All retained records, newest-first, for persistence or inspection.
    pub fn records(&self) -> &[RetainedManifestRecord] {
        &self.records
    }

    /// Whether any record has been retained.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The most recently accepted record, if any.
    pub fn newest(&self) -> Option<&RetainedManifestRecord> {
        self.records.first()
    }

    /// Push a newly accepted record as the newest entry.
    ///
    /// The caller pushes only after a manifest has fully passed verification,
    /// honoring the section 10 persistence-ordering rule (no record is retained
    /// for a manifest that failed any stage).
    pub fn push(&mut self, record: RetainedManifestRecord) {
        self.records.insert(0, record);
    }

    /// The records older than the newest, in newest-first order, for the
    /// runtime-rotation extended-history (SHOULD) check.
    fn extended(&self) -> &[RetainedManifestRecord] {
        self.records.get(1..).unwrap_or(&[])
    }
}

/// Derive the retained record for a verified manifest: its canary `issued_at`,
/// `runtime_pubkey`, and canonical payload hash.
///
/// Returns `None` only if the canary `issued_at` does not validate as a strict
/// timestamp - which cannot happen for a manifest that has passed Stage 8, so
/// callers driving the pipeline can treat a verified manifest as always
/// producing a record.
pub fn record_for(manifest: &Manifest) -> Option<RetainedManifestRecord> {
    let issued_at = manifest.canary.issued_at.validate().ok()?;
    Some(RetainedManifestRecord {
        issued_at,
        runtime_pubkey: manifest.canary.runtime_pubkey,
        manifest_payload_hash: manifest.canonical_payload_hash(),
    })
}

/// Run the section 08 history checks for `manifest` against `history`:
/// anti-downgrade, equal-`issued_at` conflict, and runtime-key rotation.
///
/// Returns the first failing check's [`Diagnostic`] (the codes are
/// `E_CANARY_DOWNGRADE`, `E_CANARY_CONFLICT`, `E_CANARY_RUNTIME_REUSE`), or
/// `Ok(())` when the manifest is acceptable against the history. A `manifest`
/// whose `issued_at` does not validate is out of scope here (Stage 8 would have
/// rejected it); such a manifest passes these checks vacuously.
pub fn check_against_history(
    manifest: &Manifest,
    history: &PublisherHistory,
) -> Result<(), Diagnostic> {
    let Some(record) = record_for(manifest) else {
        return Ok(());
    };
    let newest = history.newest();

    check_anti_downgrade(&record.issued_at, newest.map(|r| &r.issued_at))?;
    check_canary_conflict(
        &record.issued_at,
        &record.runtime_pubkey,
        &record.manifest_payload_hash,
        newest,
    )?;
    // A byte-identical re-fetch of the newest retained manifest is normal
    // steady-state traffic the protocol explicitly blesses (§08:242: "this rule
    // does not affect refetching the same manifest"). The runtime-rotation MUST
    // is scoped to a *new* manifest with a *fresh* canary; a same-payload
    // re-fetch carries the same issued_at and makes no rotation claim. The
    // anti-downgrade (strict `<`) and conflict (payload-hash carve-out) checks
    // already pass such a re-fetch; the rotation check is the lone one lacking
    // the symmetric exemption, so skip it on a payload-hash match to avoid a
    // spurious E_CANARY_RUNTIME_REUSE. (A different payload re-using the runtime
    // key still trips the check, since its hash differs.)
    let is_same_payload_refetch =
        newest.is_some_and(|n| n.manifest_payload_hash == record.manifest_payload_hash);
    if !is_same_payload_refetch {
        check_runtime_pubkey_rotation(
            &record.runtime_pubkey,
            &record.issued_at,
            newest,
            history.extended(),
        )?;
    }
    Ok(())
}
