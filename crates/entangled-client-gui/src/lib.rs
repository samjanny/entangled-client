//! Pure load path for the egui client shell.
//!
//! Given the bytes a client would have fetched (a manifest, a content document,
//! the carrier address) plus the retained identity and history the binary read
//! from the store, this verifies them through `entangled-client`'s pipeline and
//! produces what the window draws: the content [`Scene`] and the [`ChromeView`].
//! It performs no I/O of its own (the binary reads files, the store, and the
//! clock); keeping it pure lets the verify-and-resolve step be tested without a
//! window.
//!
//! Trust is now *live*: the binary loads the retained identity and history for
//! the publisher and passes them in. The first [`load`] resolves with
//! [`UserDecision::None`] - rendering the current trust state and selecting the
//! prompt the shell should show ([`Loaded::required_action`]). The user's actual
//! decision arrives from a dialog on a later frame and is fed back through
//! [`Loaded::apply_decision`], which re-resolves and yields the
//! [`PersistenceIntent`] the binary applies to the store.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

use entangled_client::chrome::{ChromeConditions, ChromeView};
use entangled_client::history::record_for;
use entangled_client::pipeline::{verify_content, verify_manifest, Outcome};
use entangled_client::trust::{
    resolve, PersistenceIntent, RequiredAction, RetainedIdentity, UserDecision,
};
use entangled_client::{Clock, PublisherHistory};
use entangled_core::types::OnionAddress;
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::canary::{CanaryState, RetainedManifestRecord};
use entangled_engine::Scene;

/// What the window needs to draw a loaded document and drive the trust flow.
pub struct Loaded {
    /// The chrome to show (trust state, canary state, PIP, warnings).
    pub chrome: ChromeView,
    /// The content scene to render, when a content document was supplied and
    /// verified. `None` for a manifest-only load.
    pub scene: Option<Scene>,
    /// The verified presented publisher key - the re-resolve input and the
    /// history store key.
    pub publisher: PublisherPubkey,
    /// The carrier site the manifest was fetched from - the identity store key
    /// (§10:187: identity is retained per site, not per publisher key).
    pub site: OnionAddress,
    /// What was retained for this site at load (re-resolve input). `None` means
    /// first contact.
    pub retained: Option<RetainedIdentity>,
    /// Which prompt the shell must drive this load.
    pub required_action: RequiredAction,
    /// The load-time persistence intent. On a fresh first contact this is the
    /// automatic observation record of section 10:298 (created with no user
    /// decision once the manifest passed the pipeline); the shell MUST apply
    /// it via its identity store right after a successful load, or a later
    /// identity change at this site would go undetected. Decisions the user
    /// takes afterwards flow through [`Loaded::apply_decision`].
    pub initial_intent: PersistenceIntent,
    /// The accepted manifest's record, for the binary to append to the history
    /// store after the user pins/confirms (persistence ordering: the manifest
    /// already verified). `None` only if the record could not be derived.
    pub record: Option<RetainedManifestRecord>,
    /// The computed canary state, kept so `apply_decision` can rebuild chrome.
    canary_state: CanaryState,
    /// The compact carrier address, kept for chrome rebuilds.
    compact_address: String,
}

impl Loaded {
    /// Re-resolve trust with the user's `decision` and rebuild the chrome so the
    /// new trust state shows immediately. Returns the [`PersistenceIntent`] the
    /// caller must apply to the store. This is the pure half of the
    /// decision->persist flow; only the store write itself is left to the shell.
    pub fn apply_decision(&mut self, decision: UserDecision) -> PersistenceIntent {
        let resolution = resolve(&self.publisher, self.retained.as_ref(), decision);
        self.chrome = ChromeView::build(
            &self.publisher,
            resolution.state,
            self.canary_state,
            self.compact_address.clone(),
            ChromeConditions::default(),
        );
        self.required_action = resolution.action;
        resolution.intent
    }
}

/// A load error: which step failed and a human-readable message.
#[derive(Debug)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

/// Verify `manifest_bytes` (and `content_bytes`, if present) against the
/// retained `history`, resolve trust against the `retained` identity, and build
/// the content scene and chrome view.
///
/// `fetched_address` is the carrier address the manifest was treated as fetched
/// from (origin binding); `compact_address` is the abbreviated form to show in
/// chrome; `clock` supplies the current time. `retained` and `history` are the
/// store state the binary loaded for this publisher (`None` / empty == first
/// contact). The resolution uses [`UserDecision::None`]: the returned
/// [`Loaded::required_action`] tells the shell which prompt to open, and the
/// user's decision is applied later via [`Loaded::apply_decision`].
#[allow(clippy::too_many_arguments)]
pub fn load(
    manifest_bytes: &[u8],
    content_bytes: Option<&[u8]>,
    fetched_address: &OnionAddress,
    compact_address: impl Into<String>,
    clock: &impl Clock,
    retained: Option<&RetainedIdentity>,
    history: &PublisherHistory,
) -> Result<Loaded, LoadError> {
    let verified = match verify_manifest(manifest_bytes, fetched_address, None, clock, history) {
        Outcome::Accept(v) => v,
        Outcome::Reject(d) => return Err(LoadError(format!("manifest rejected: {d:?}"))),
    };

    // Trust: resolve against the retained identity. Decision None on first load
    // -> renders the state and selects the prompt; the real decision arrives via
    // apply_decision.
    let publisher = verified.manifest.publisher_pubkey;
    let resolution = resolve(&publisher, retained, UserDecision::None);

    let compact_address = compact_address.into();
    let chrome = ChromeView::build(
        &publisher,
        resolution.state,
        verified.canary_state,
        compact_address.clone(),
        ChromeConditions::default(),
    );

    // Content, when supplied, verified under the manifest's runtime key.
    let scene = match content_bytes {
        Some(bytes) => match verify_content(bytes, &verified) {
            Outcome::Accept(doc) => Some(Scene::from_content(&doc)),
            Outcome::Reject(d) => return Err(LoadError(format!("content rejected: {d:?}"))),
        },
        None => None,
    };

    let record = record_for(&verified.manifest);

    Ok(Loaded {
        chrome,
        scene,
        publisher,
        site: fetched_address.clone(),
        retained: retained.copied(),
        required_action: resolution.action,
        initial_intent: resolution.intent,
        record,
        canary_state: verified.canary_state,
        compact_address,
    })
}
