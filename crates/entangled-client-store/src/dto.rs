//! On-disk serializable mirrors of the brain's types.
//!
//! The pure `entangled-client` crate is serde-free and `RetainedManifestRecord`
//! (in core) does not derive serde, so this crate owns thin DTOs that map
//! to/from those types. The publisher/runtime keys and timestamps already
//! serialize as strings via their core impls; only the `[u8; 32]` payload hash
//! needs an explicit text encoding (lowercase hex), so the on-disk JSON stays
//! compact and grep-able rather than a 64-element number array.

use serde::{Deserialize, Serialize};

use entangled_client::trust::RetainedIdentity;
use entangled_client::StoreError;
use entangled_core::types::{EntangledTimestamp, PublisherPubkey, RuntimePubkey};
use entangled_core::validation::canary::RetainedManifestRecord;

/// On-disk identity record (one per publisher).
#[derive(Serialize, Deserialize)]
pub struct IdentityDto {
    /// Schema version; bumped if the shape changes. Unknown => corruption.
    pub v: u32,
    /// The retained publisher key (serde -> base64url string).
    pub pubkey: PublisherPubkey,
    /// Whether the user externally verified it against a PIP.
    pub externally_verified: bool,
    /// Prior keys replaced into this identity, newest-first. Never lost, so a
    /// later tranche can surface the replacement history. Defaults to empty.
    #[serde(default)]
    pub replaced_pubkeys: Vec<PublisherPubkey>,
}

/// The current `IdentityDto` schema version.
pub const IDENTITY_V: u32 = 1;

impl IdentityDto {
    /// Build from a retained identity plus its retained replaced keys.
    pub fn new(identity: &RetainedIdentity, replaced_pubkeys: Vec<PublisherPubkey>) -> IdentityDto {
        IdentityDto {
            v: IDENTITY_V,
            pubkey: identity.pubkey,
            externally_verified: identity.externally_verified,
            replaced_pubkeys,
        }
    }

    /// The `RetainedIdentity` this record represents.
    pub fn to_identity(&self) -> RetainedIdentity {
        RetainedIdentity {
            pubkey: self.pubkey,
            externally_verified: self.externally_verified,
        }
    }

    /// Validate the schema version after deserialization. Unknown => corruption.
    pub fn check_version(&self) -> Result<(), StoreError> {
        if self.v != IDENTITY_V {
            return Err(StoreError(format!(
                "unsupported identity record version {}",
                self.v
            )));
        }
        Ok(())
    }
}

/// On-disk manifest record (one history entry).
#[derive(Serialize, Deserialize)]
pub struct ManifestRecordDto {
    /// `canary.issued_at` (serde -> "YYYY-MM-DDTHH:MM:SSZ").
    pub issued_at: EntangledTimestamp,
    /// `canary.runtime_pubkey` (serde -> base64url).
    pub runtime_pubkey: RuntimePubkey,
    /// SHA-256 payload hash as 64 lowercase hex chars.
    pub payload_hash_hex: String,
}

impl ManifestRecordDto {
    /// Build from a core record (hash -> lowercase hex).
    pub fn from_record(record: &RetainedManifestRecord) -> ManifestRecordDto {
        ManifestRecordDto {
            issued_at: record.issued_at,
            runtime_pubkey: record.runtime_pubkey,
            payload_hash_hex: data_encoding::HEXLOWER.encode(&record.manifest_payload_hash),
        }
    }

    /// Convert back to a core record. A `payload_hash_hex` that is not exactly
    /// 32 bytes of hex is a corruption signal (`Err`).
    pub fn into_record(self) -> Result<RetainedManifestRecord, StoreError> {
        let bytes = data_encoding::HEXLOWER
            .decode(self.payload_hash_hex.as_bytes())
            .map_err(|e| StoreError(format!("payload_hash_hex not hex: {e}")))?;
        let hash: [u8; 32] = bytes
            .try_into()
            .map_err(|_| StoreError("payload_hash_hex is not 32 bytes".to_owned()))?;
        Ok(RetainedManifestRecord {
            issued_at: self.issued_at,
            runtime_pubkey: self.runtime_pubkey,
            manifest_payload_hash: hash,
        })
    }
}

/// On-disk history file (one per publisher).
#[derive(Serialize, Deserialize)]
pub struct HistoryDto {
    /// Schema version. Unknown => corruption.
    pub v: u32,
    /// History entries, newest-first.
    pub records: Vec<ManifestRecordDto>,
}

/// The current `HistoryDto` schema version.
pub const HISTORY_V: u32 = 1;

impl HistoryDto {
    /// Validate the schema version after deserialization.
    pub fn check_version(&self) -> Result<(), StoreError> {
        if self.v != HISTORY_V {
            return Err(StoreError(format!(
                "unsupported history version {}",
                self.v
            )));
        }
        Ok(())
    }
}
