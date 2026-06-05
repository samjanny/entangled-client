//! Pure load path for the egui client shell.
//!
//! Given the bytes a client would have fetched (a manifest, a content document,
//! the carrier address), this verifies them through `entangled-client`'s
//! pipeline and produces what the window draws: the content [`Scene`] and the
//! [`ChromeView`]. It performs no I/O of its own (the binary reads the files and
//! supplies the clock); keeping it pure lets the verify-and-build step be tested
//! without a window.
//!
//! This tranche is **read-only**: there is no retained identity yet, so the
//! trust state is always First contact, and nothing is pinned or persisted. The
//! pinning prompt, the `IdentityStore` persistence, and the user-decision flow
//! arrive in a later tranche.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

use entangled_client::chrome::{ChromeConditions, ChromeView};
use entangled_client::pipeline::{verify_content, verify_manifest, Outcome};
use entangled_client::trust::{resolve, TrustState, UserDecision};
use entangled_client::Clock;
use entangled_core::types::OnionAddress;
use entangled_engine::Scene;

/// What the window needs to draw a loaded document.
pub struct Loaded {
    /// The chrome to show (trust state, canary state, PIP, warnings).
    pub chrome: ChromeView,
    /// The content scene to render, when a content document was supplied and
    /// verified. `None` for a manifest-only load.
    pub scene: Option<Scene>,
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

/// Verify `manifest_bytes` (and `content_bytes`, if present) and build the
/// content scene and chrome view.
///
/// `fetched_address` is the carrier address the manifest was treated as fetched
/// from (origin binding); `compact_address` is the abbreviated form to show in
/// chrome; `clock` supplies the current time. With no retained identity, the
/// trust state is First contact.
pub fn load(
    manifest_bytes: &[u8],
    content_bytes: Option<&[u8]>,
    fetched_address: &OnionAddress,
    compact_address: impl Into<String>,
    clock: &impl Clock,
) -> Result<Loaded, LoadError> {
    // No publisher history retained in this read-only tranche: first contact.
    let verified = match verify_manifest(
        manifest_bytes,
        fetched_address,
        None,
        clock,
        &entangled_client::PublisherHistory::new(),
    ) {
        Outcome::Accept(v) => v,
        Outcome::Reject(d) => return Err(LoadError(format!("manifest rejected: {d:?}"))),
    };

    // Trust: no retained identity -> First contact (no user decision, no pin).
    let publisher = verified.manifest.publisher_pubkey;
    let resolution = resolve(&publisher, None, UserDecision::None);
    debug_assert_eq!(resolution.state, TrustState::FirstContact);

    let chrome = ChromeView::build(
        &publisher,
        resolution.state,
        verified.canary_state,
        compact_address,
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

    Ok(Loaded { chrome, scene })
}
