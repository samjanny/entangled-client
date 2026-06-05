//! The validation-pipeline driver.
//!
//! This sequences `entangled-core`'s manifest type-state chain in section 10
//! stage order and reports a single structured [`Outcome`]. The core enforces
//! section 11 error precedence internally: each stage returns the first
//! [`Diagnostic`] it finds and the chain stops there, so the `Outcome` carries
//! the first-failing-stage diagnostic, as the spec requires.
//!
//! The driver does not fetch anything. It is given the already-fetched bytes,
//! the carrier address the manifest was fetched from, the current time (via a
//! [`Clock`]), and - when the manifest declares `content_root` - the
//! `/content_index.json` bytes. Stage 1 (transport) and Stage 7 (trust state)
//! are not part of this tranche: transport is the shell's job behind a future
//! `Transport` trait, and the trust-state machine is a later tranche.

use entangled_core::document::{parse_and_verify_content, parse_and_verify_manifest};
use entangled_core::types::{ContentDocument, Manifest, OnionAddress, RuntimePubkey};
use entangled_core::validation::canary::CanaryState;
use entangled_core::validation::{ContentIndex, Diagnostic};

use crate::history::{check_against_history, PublisherHistory};
use crate::io::Clock;

/// The result of driving a document through the pipeline.
///
/// `Accept` carries the verified product; `Reject` carries the first-failing
/// stage's diagnostic under section 11 error precedence.
#[derive(Debug)]
pub enum Outcome<T> {
    /// The document passed every applicable stage.
    Accept(T),
    /// The document failed; the diagnostic is the first-failing-stage one.
    Reject(Diagnostic),
}

impl<T> Outcome<T> {
    /// Whether the document was accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Outcome::Accept(_))
    }

    /// The rejection diagnostic, if this is a `Reject`.
    pub fn diagnostic(&self) -> Option<&Diagnostic> {
        match self {
            Outcome::Reject(d) => Some(d),
            Outcome::Accept(_) => None,
        }
    }
}

/// A manifest that has passed the manifest stages of the pipeline.
///
/// Carries the verified [`Manifest`], its computed [`CanaryState`] (the spec's
/// five-state value; `Fresh`/`NearExpiration`/`Expired` here, with `Invalid`
/// surfaced as a rejection and `Unavailable` a transport-layer condition the
/// shell determines), and the validated content index when the manifest
/// declared a `content_root`.
#[derive(Debug)]
pub struct VerifiedManifest {
    /// The verified manifest.
    pub manifest: Manifest,
    /// The canary state computed against the clock.
    pub canary_state: CanaryState,
    /// The validated content index, when the manifest committed to one.
    pub content_index: Option<ContentIndex>,
}

impl VerifiedManifest {
    /// The runtime public key this manifest authorizes for content and
    /// transaction documents (`canary.runtime_pubkey`).
    pub fn runtime_pubkey(&self) -> &RuntimePubkey {
        &self.manifest.canary.runtime_pubkey
    }
}

/// Drive a manifest through the pipeline: signature (Stage 6), canary
/// (Stage 8) including the anti-downgrade / conflict / runtime-rotation checks
/// against publisher history, origin binding (Stage 9), and the content-index
/// sub-step (Stage 9b) when `content_root` is present.
///
/// - `manifest_bytes`: the exact wire bytes fetched for `/manifest.json`.
/// - `fetched_address`: the carrier address the manifest was fetched from, for
///   origin binding.
/// - `content_index_bytes`: the exact `/content_index.json` bytes when the
///   manifest declares `content_root`, else `None` (a `None` against a declared
///   `content_root` is the section 09 hard-fail, surfaced as a rejection).
/// - `clock`: the current-time source for canary and `not_after` checks.
/// - `history`: what the client has already accepted for this publisher; pass
///   an empty [`PublisherHistory`] on first contact. The anti-downgrade,
///   equal-`issued_at` conflict, and runtime-rotation checks run against it.
///
/// Stage 1 (transport) and Stage 7 (trust state) are out of this tranche.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    fetched_address: &OnionAddress,
    content_index_bytes: Option<&[u8]>,
    clock: &impl Clock,
    history: &PublisherHistory,
) -> Outcome<VerifiedManifest> {
    let now = clock.now();
    let result = parse_and_verify_manifest(manifest_bytes, &now)
        .and_then(|sig_verified| sig_verified.verify_canary(&now))
        .and_then(|canary_checked| canary_checked.verify_origin(fetched_address, &now))
        .and_then(|origin_bound| origin_bound.verify_content_index(content_index_bytes));
    let verified = match result {
        Ok(verified) => verified,
        Err(diagnostic) => return Outcome::Reject(diagnostic),
    };
    let (manifest, canary_state, content_index) = verified.into_parts();

    // Stage 8 history checks: anti-downgrade, equal-issued_at conflict, and
    // runtime-key rotation against what was previously accepted.
    if let Err(diagnostic) = check_against_history(&manifest, history) {
        return Outcome::Reject(diagnostic);
    }

    Outcome::Accept(VerifiedManifest {
        manifest,
        canary_state,
        content_index,
    })
}

/// Drive a content document through verification under a verified manifest's
/// authorized runtime key (Stage 6 signature verification).
///
/// Stage 9 path binding (matching `content.path` against the fetched path) and
/// the Stage 9b per-document `seq`/hash check against a cached content index
/// are the caller's responsibility once it knows the fetched path; this tranche
/// covers the signature step that requires the manifest's runtime key.
pub fn verify_content(
    content_bytes: &[u8],
    manifest: &VerifiedManifest,
) -> Outcome<ContentDocument> {
    match parse_and_verify_content(content_bytes, manifest.runtime_pubkey()) {
        Ok(doc) => Outcome::Accept(doc),
        Err(diagnostic) => Outcome::Reject(diagnostic),
    }
}
