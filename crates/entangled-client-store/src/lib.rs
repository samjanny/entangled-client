//! Filesystem-backed persistence for the Entangled v1.0 client.
//!
//! This crate provides durable implementations of the `entangled-client`
//! persistence seams - [`FileIdentityStore`] (`IdentityStore`) and
//! [`FileHistoryStore`] (`HistoryStore`) - so a GUI, TUI, or headless shell can
//! remember pinned publisher identities and the accepted-manifest history across
//! sessions. The pure brain crate stays I/O- and serde-free; this crate owns the
//! filesystem, serialization, and at-rest protection.
//!
//! # Layout
//!
//! One JSON file per publisher, keyed by the publisher key's base64url string
//! (filesystem-safe), under a [`StoreRoot`]:
//!
//! ```text
//! <root>/store-meta.json              protection mode (+ salt for Encrypted)
//! <root>/store-key                    Integrity mode only: HMAC key, 0600
//! <root>/identities/<pubkey>.json     the RetainedIdentity
//! <root>/history/<pubkey>.json        the accepted-manifest history
//! ```
//!
//! # Protection
//!
//! The store holds only public data, so the threat is tampering, not disclosure.
//! [`Protection::Integrity`] (default) authenticates every file with HMAC-SHA256;
//! [`Protection::Encrypted`] (the `encrypted` feature) seals files with a
//! passphrase-derived AEAD. In both modes a failed integrity check is a hard
//! error, never a silent fallback (the §10:571 corruption-rejection posture).
//!
//! # Example
//!
//! ```no_run
//! use std::path::PathBuf;
//! use std::sync::Arc;
//! use entangled_client_store::{FileIdentityStore, FileHistoryStore, Protection, StoreRoot};
//!
//! let root = Arc::new(StoreRoot::open(
//!     PathBuf::from("/path/to/store"),
//!     &Protection::Integrity,
//!     None,
//! )?);
//! let identities = FileIdentityStore::new(root.clone());
//! let history = FileHistoryStore::new(root);
//! # Ok::<(), entangled_client::StoreError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]

mod dto;
mod history;
mod identity;
mod protect;
mod root;

pub use history::FileHistoryStore;
pub use identity::FileIdentityStore;
pub use protect::Protection;
pub use root::StoreRoot;

// Re-export the seam traits + error so downstream code can use the file stores
// through them without depending on `entangled-client` directly for the traits.
pub use entangled_client::{HistoryStore, IdentityStore, StoreError, StoreResult};
