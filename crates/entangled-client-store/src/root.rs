//! The store root: directory layout, atomic writes, and protection keying.
//!
//! A [`StoreRoot`] resolves the base directory, builds per-publisher paths,
//! writes files atomically (tmp + rename) with `0600` permissions on Unix, and
//! holds the resolved [`Protector`] (the HMAC key for Integrity mode, or the
//! AEAD key for Encrypted mode) so the identity/history stores can seal/open
//! payloads without re-resolving keying per call.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use entangled_client::StoreError;
use entangled_core::types::manifest::OnionAddress;
use entangled_core::types::PublisherPubkey;

use crate::protect::{Protection, ProtectionTag, Protector};

/// Per-store metadata, written once to `store-meta.json`, so a reload knows
/// which protection scheme to apply.
#[derive(Serialize, Deserialize)]
struct StoreMeta {
    v: u32,
    protection: ProtectionTag,
    /// Per-store salt for Encrypted mode (base64url); absent for Integrity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    salt_b64: Option<String>,
}

const META_V: u32 = 1;

/// A resolved store root: paths + the protector for sealing/opening payloads.
pub struct StoreRoot {
    base: PathBuf,
    protector: Protector,
}

impl StoreRoot {
    /// Open (or initialize) a store rooted at `base` with [`Protection::Integrity`].
    ///
    /// On first use the base dir, an `identities/` and `history/` subdir, the
    /// `store-meta.json`, and a random `store-key` (`0600`) are created. On a
    /// later open the existing key is loaded and the recorded protection mode is
    /// checked to match.
    pub fn open_integrity(base: impl Into<PathBuf>) -> Result<StoreRoot, StoreError> {
        let base = base.into();
        ensure_dirs(&base)?;
        let key = match read_file_opt(&base.join("store-key"))? {
            Some(bytes) => bytes,
            None => {
                // First use: generate and persist the HMAC key (0600).
                let key = crate::protect::generate_integrity_key()?;
                write_atomic(&base.join("store-key"), &key)?;
                write_meta(
                    &base,
                    &StoreMeta {
                        v: META_V,
                        protection: ProtectionTag::Integrity,
                        salt_b64: None,
                    },
                )?;
                key
            }
        };
        check_mode(&base, ProtectionTag::Integrity)?;
        Ok(StoreRoot {
            base,
            protector: Protector::Integrity { key },
        })
    }

    /// Open (or initialize) a store rooted at `base` with [`Protection::Encrypted`],
    /// deriving the AEAD key from `passphrase` and a per-store salt (generated on
    /// first use, recorded in `store-meta.json`).
    #[cfg(feature = "encrypted")]
    pub fn open_encrypted(
        base: impl Into<PathBuf>,
        passphrase: &str,
    ) -> Result<StoreRoot, StoreError> {
        let base = base.into();
        ensure_dirs(&base)?;
        let salt = match read_meta(&base)? {
            Some(meta) => {
                if meta.protection != ProtectionTag::Encrypted {
                    return Err(StoreError(
                        "store was initialized in a different protection mode".to_owned(),
                    ));
                }
                let s = meta
                    .salt_b64
                    .ok_or_else(|| StoreError("encrypted store missing salt".to_owned()))?;
                data_encoding::BASE64URL_NOPAD
                    .decode(s.as_bytes())
                    .map_err(|e| StoreError(format!("salt base64: {e}")))?
            }
            None => {
                // First use: fresh 16-byte salt.
                let mut salt = vec![0u8; 16];
                getrandom::getrandom(&mut salt).map_err(|e| StoreError(format!("rng: {e}")))?;
                write_meta(
                    &base,
                    &StoreMeta {
                        v: META_V,
                        protection: ProtectionTag::Encrypted,
                        salt_b64: Some(data_encoding::BASE64URL_NOPAD.encode(&salt)),
                    },
                )?;
                salt
            }
        };
        let key = crate::protect::derive_key(passphrase, &salt)?;
        Ok(StoreRoot {
            base,
            protector: Protector::Encrypted { key },
        })
    }

    /// Open with the given [`Protection`], dispatching to the right constructor.
    /// `passphrase` is required for [`Protection::Encrypted`].
    pub fn open(
        base: impl Into<PathBuf>,
        protection: &Protection,
        passphrase: Option<&str>,
    ) -> Result<StoreRoot, StoreError> {
        match protection {
            Protection::Integrity => StoreRoot::open_integrity(base),
            #[cfg(feature = "encrypted")]
            Protection::Encrypted => {
                let pass = passphrase.ok_or_else(|| {
                    StoreError("encrypted store requires a passphrase".to_owned())
                })?;
                StoreRoot::open_encrypted(base, pass)
            }
            #[cfg(not(feature = "encrypted"))]
            Protection::Encrypted => {
                let _ = passphrase;
                Err(StoreError(
                    "encrypted store mode requires the `encrypted` feature".to_owned(),
                ))
            }
        }
    }

    /// Path of the identity file for `site` (the carrier onion address). The
    /// onion string is filesystem-safe (56 lowercase base32 chars + `.onion`).
    pub fn identity_path(&self, site: &OnionAddress) -> PathBuf {
        self.base.join("identities").join(format!("{site}.json"))
    }

    /// Path of the history file for `publisher`.
    pub fn history_path(&self, publisher: &PublisherPubkey) -> PathBuf {
        self.base.join("history").join(format!("{publisher}.json"))
    }

    /// Seal `payload` and write it atomically to `path`.
    pub fn write_protected(&self, path: &Path, payload: &[u8]) -> Result<(), StoreError> {
        let sealed = self.protector.seal(payload)?;
        write_atomic(path, &sealed)
    }

    /// Read and open `path`, returning the plaintext payload, or `None` if the
    /// file is missing. A present-but-unverifiable file is an error (fail-closed).
    pub fn read_protected(&self, path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
        match read_file_opt(path)? {
            None => Ok(None),
            Some(on_disk) => self.protector.open(&on_disk).map(Some),
        }
    }

    /// Remove the file at `path` if present (used by identity replacement).
    pub fn remove_if_present(&self, path: &Path) -> Result<(), StoreError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError(format!("remove {}: {e}", path.display()))),
        }
    }
}

fn ensure_dirs(base: &Path) -> Result<(), StoreError> {
    for sub in ["", "identities", "history"] {
        let dir = if sub.is_empty() {
            base.to_path_buf()
        } else {
            base.join(sub)
        };
        fs::create_dir_all(&dir)
            .map_err(|e| StoreError(format!("create {}: {e}", dir.display())))?;
    }
    Ok(())
}

fn meta_path(base: &Path) -> PathBuf {
    base.join("store-meta.json")
}

fn write_meta(base: &Path, meta: &StoreMeta) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(meta).map_err(|e| StoreError(format!("encode meta: {e}")))?;
    write_atomic(&meta_path(base), &bytes)
}

fn read_meta(base: &Path) -> Result<Option<StoreMeta>, StoreError> {
    match read_file_opt(&meta_path(base))? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StoreError(format!("decode meta: {e}"))),
    }
}

fn check_mode(base: &Path, expected: ProtectionTag) -> Result<(), StoreError> {
    if let Some(meta) = read_meta(base)? {
        if meta.protection != expected {
            return Err(StoreError(
                "store was initialized in a different protection mode".to_owned(),
            ));
        }
    }
    Ok(())
}

fn read_file_opt(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError(format!("read {}: {e}", path.display()))),
    }
}

/// Write `bytes` to `path` atomically: a unique temp file in the same directory,
/// fsync, then rename. On Unix the file is created `0600`. A reader therefore
/// never sees a half-written file - only the old complete one or the new one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path
        .parent()
        .ok_or_else(|| StoreError(format!("path has no parent: {}", path.display())))?;
    fs::create_dir_all(dir).map_err(|e| StoreError(format!("create {}: {e}", dir.display())))?;

    // Unique temp name in the same directory (same filesystem => atomic rename).
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|e| StoreError(format!("rng: {e}")))?;
    let tmp = path.with_extension(format!("tmp-{}", data_encoding::HEXLOWER.encode(&nonce)));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<(), StoreError> {
        let mut f = opts
            .open(&tmp)
            .map_err(|e| StoreError(format!("create temp {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| StoreError(format!("write temp: {e}")))?;
        f.sync_all()
            .map_err(|e| StoreError(format!("sync temp: {e}")))?;
        fs::rename(&tmp, path)
            .map_err(|e| StoreError(format!("rename into {}: {e}", path.display())))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
