//! On-disk payload protection.
//!
//! The store holds only *public* data (publisher pubkeys, an
//! externally-verified flag, public-manifest timestamps/runtime-keys/hashes).
//! The threat is therefore **tampering**, not disclosure: an attacker who can
//! edit the store could delete a pin (silently downgrading a publisher to first
//! contact) or lower the anti-downgrade floor. The base protection level is thus
//! *authenticated integrity*, and confidentiality is an opt-in.
//!
//! Two modes, selected per store:
//!
//! * [`Protection::Integrity`] (default) - each file is wrapped with an
//!   HMAC-SHA256 over the payload, keyed by a random key generated on first use
//!   and stored `0600` alongside the data. A failed MAC is a hard error.
//! * [`Protection::Encrypted`] (opt-in, `encrypted` feature) - the payload is
//!   sealed with XChaCha20-Poly1305 under a key derived from a user passphrase
//!   via Argon2id. The AEAD tag *is* the integrity check; no separate key file.
//!
//! In both modes a verification failure is surfaced as an error, never a silent
//! fallback - the §10:571 corruption-rejection posture.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use entangled_client::StoreError;

type HmacSha256 = Hmac<Sha256>;

/// How the store protects its on-disk payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Authenticated integrity via HMAC-SHA256 keyed by a local `0600` key file.
    /// The default: defends against tampering with no user friction.
    Integrity,
    /// Passphrase-derived AEAD (XChaCha20-Poly1305 + Argon2id). Confidentiality
    /// and integrity together; requires the `encrypted` feature and a passphrase.
    Encrypted,
}

/// The serialized tag identifying a store's protection mode, written to
/// `store-meta.json` so a reload applies the right scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTag {
    /// [`Protection::Integrity`].
    Integrity,
    /// [`Protection::Encrypted`].
    Encrypted,
}

impl Protection {
    /// The persisted tag for this mode.
    pub fn tag(&self) -> ProtectionTag {
        match self {
            Protection::Integrity => ProtectionTag::Integrity,
            Protection::Encrypted => ProtectionTag::Encrypted,
        }
    }
}

/// The on-disk envelope for [`Protection::Integrity`]: the plaintext payload
/// plus its HMAC. The payload is kept as raw bytes (base64url) so the MAC covers
/// exactly what was written.
#[derive(Serialize, Deserialize)]
struct IntegrityEnvelope {
    /// Schema version of the envelope.
    v: u32,
    /// The payload bytes, base64url (no padding).
    payload_b64: String,
    /// HMAC-SHA256(key, payload_bytes), base64url (no padding).
    mac_b64: String,
}

const ENVELOPE_V: u32 = 1;

fn b64() -> data_encoding::Encoding {
    data_encoding::BASE64URL_NOPAD
}

/// The material a [`Protector`] needs: the mode plus its keying.
pub enum Protector {
    /// Integrity mode with the resolved HMAC key.
    Integrity { key: Vec<u8> },
    /// Encrypted mode with the resolved AEAD key (derived from the passphrase).
    #[cfg(feature = "encrypted")]
    Encrypted { key: [u8; 32] },
}

impl Protector {
    /// Seal `payload` into the bytes to write to disk.
    pub fn seal(&self, payload: &[u8]) -> StoreResultBytes {
        match self {
            Protector::Integrity { key } => {
                let mut mac = HmacSha256::new_from_slice(key)
                    .map_err(|e| StoreError(format!("hmac key: {e}")))?;
                mac.update(payload);
                let tag = mac.finalize().into_bytes();
                let env = IntegrityEnvelope {
                    v: ENVELOPE_V,
                    payload_b64: b64().encode(payload),
                    mac_b64: b64().encode(&tag),
                };
                serde_json::to_vec(&env).map_err(|e| StoreError(format!("encode envelope: {e}")))
            }
            #[cfg(feature = "encrypted")]
            Protector::Encrypted { key } => encrypted::seal(key, payload),
        }
    }

    /// Open the bytes read from disk back into the plaintext payload, verifying
    /// integrity. A failed MAC / AEAD tag is an error (fail-closed).
    pub fn open(&self, on_disk: &[u8]) -> StoreResultBytes {
        match self {
            Protector::Integrity { key } => {
                let env: IntegrityEnvelope = serde_json::from_slice(on_disk)
                    .map_err(|e| StoreError(format!("decode envelope: {e}")))?;
                if env.v != ENVELOPE_V {
                    return Err(StoreError(format!(
                        "unsupported integrity envelope version {}",
                        env.v
                    )));
                }
                let payload = b64()
                    .decode(env.payload_b64.as_bytes())
                    .map_err(|e| StoreError(format!("payload base64: {e}")))?;
                let tag = b64()
                    .decode(env.mac_b64.as_bytes())
                    .map_err(|e| StoreError(format!("mac base64: {e}")))?;
                let mut mac = HmacSha256::new_from_slice(key)
                    .map_err(|e| StoreError(format!("hmac key: {e}")))?;
                mac.update(&payload);
                // Constant-time verify; failure => tampering => fail-closed.
                mac.verify_slice(&tag)
                    .map_err(|_| StoreError("integrity check failed (store tampered?)".to_owned()))?;
                Ok(payload)
            }
            #[cfg(feature = "encrypted")]
            Protector::Encrypted { key } => encrypted::open(key, on_disk),
        }
    }
}

/// Result of a seal/open: the bytes, or a [`StoreError`].
pub type StoreResultBytes = Result<Vec<u8>, StoreError>;

#[cfg(feature = "encrypted")]
mod encrypted {
    use super::{b64, StoreError, StoreResultBytes};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct AeadEnvelope {
        v: u32,
        nonce_b64: String,
        ct_b64: String,
    }
    const AEAD_V: u32 = 1;

    pub(super) fn seal(key: &[u8; 32], payload: &[u8]) -> StoreResultBytes {
        let cipher = XChaCha20Poly1305::new(key.into());
        // 24-byte random nonce.
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|e| StoreError(format!("rng: {e}")))?;
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| StoreError("encrypt failed".to_owned()))?;
        let env = AeadEnvelope {
            v: AEAD_V,
            nonce_b64: b64().encode(&nonce),
            ct_b64: b64().encode(&ct),
        };
        serde_json::to_vec(&env).map_err(|e| StoreError(format!("encode aead envelope: {e}")))
    }

    pub(super) fn open(key: &[u8; 32], on_disk: &[u8]) -> StoreResultBytes {
        let env: AeadEnvelope = serde_json::from_slice(on_disk)
            .map_err(|e| StoreError(format!("decode aead envelope: {e}")))?;
        if env.v != AEAD_V {
            return Err(StoreError(format!("unsupported aead envelope version {}", env.v)));
        }
        let nonce = b64()
            .decode(env.nonce_b64.as_bytes())
            .map_err(|e| StoreError(format!("nonce base64: {e}")))?;
        let ct = b64()
            .decode(env.ct_b64.as_bytes())
            .map_err(|e| StoreError(format!("ciphertext base64: {e}")))?;
        let cipher = XChaCha20Poly1305::new(key.into());
        // Wrong passphrase (wrong key) or tampered ciphertext => AEAD tag fails.
        cipher
            .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
            .map_err(|_| StoreError("decrypt failed (wrong passphrase or store tampered?)".to_owned()))
    }
}

/// Derive a 32-byte AEAD key from a passphrase and a per-store salt via Argon2id.
#[cfg(feature = "encrypted")]
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], StoreError> {
    use argon2::{Argon2, Algorithm, Params, Version};
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| StoreError(format!("argon2: {e}")))?;
    Ok(key)
}

/// Generate a fresh random HMAC key (32 bytes) for the Integrity mode.
pub fn generate_integrity_key() -> Result<Vec<u8>, StoreError> {
    let mut key = vec![0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| StoreError(format!("rng: {e}")))?;
    Ok(key)
}
