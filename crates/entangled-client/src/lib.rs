//! Conforming-client orchestration for the Entangled v1.0 protocol.
//!
//! `entangled-core` provides the verification primitives (the manifest
//! type-state chain, canary-state computation, PIP derivation, origin binding,
//! the state store, anti-downgrade checks). It deliberately stops at pure
//! per-document verification and leaves the *client* concerns to an embedding
//! layer: the section 10 validation-pipeline ordering, the Stage 7 trust-state
//! machine, publisher-history persistence, consent, transport, and image
//! fetch/decode.
//!
//! This crate is that client layer - or rather its brain. It is **pure**: it
//! takes already-fetched bytes plus facts (the current time, retained records)
//! as data and returns decisions; it performs no I/O and pulls in no UI
//! toolkit. The impure parts (transport, persistence, decoding, the clock) are
//! [`io`] traits a shell implements. This keeps the security-critical logic
//! golden-testable, exactly like the rest of the Entangled crate family, and
//! lets a GUI, a TUI, or a headless harness reuse the same brain.
//!
//! The long-term goal is a fully conforming Entangled v1.0 client (section 10),
//! built in tranches. Tranche 1 (this revision) is the validation-pipeline
//! driver: it sequences the core's verification chain in section 10 order and
//! reports a structured outcome under the section 11 error-precedence rule. The
//! Stage 7 trust-state machine, canary anti-downgrade history, transport, and
//! images arrive in later tranches.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]

pub mod chrome;
pub mod history;
pub mod image;
pub mod io;
pub mod pipeline;
pub mod trust;

pub use chrome::{ChromeConditions, ChromeView, Warning, PIP_LABEL};
pub use history::{check_against_history, record_for, PublisherHistory};
pub use image::{
    verify_image, DecodeError, Decoded, Decoder, ImageBudget, ImageOutcome, NoRetrySet,
};
pub use io::{
    Clock, FixedClock, HistoryStore, IdentityStore, MemoryHistoryStore, MemoryIdentityStore,
    StoreError, StoreResult,
};
pub use pipeline::{verify_content, verify_manifest, Outcome, VerifiedManifest};
pub use trust::{
    resolve, PersistenceIntent, RequiredAction, Resolution, RetainedIdentity, TrustState,
    UserDecision,
};
