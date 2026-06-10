//! On-disk serializable mirrors of the brain's types.
//!
//! The pure `entangled-client` crate is serde-free and `RetainedManifestRecord`
//! (in core) does not derive serde, so this crate owns thin DTOs that map
//! to/from those types. The publisher/runtime keys and timestamps already
//! serialize as strings via their core impls; only the `[u8; 32]` payload hash
//! needs an explicit text encoding (lowercase hex), so the on-disk JSON stays
//! compact and grep-able rather than a 64-element number array.

use serde::{Deserialize, Serialize};

use entangled_client::trust::{RetainedIdentity, RetainedProvenance};
use entangled_client::StoreError;
use entangled_core::types::{EntangledTimestamp, PublisherPubkey, RuntimePubkey};
use entangled_core::validation::canary::RetainedManifestRecord;

/// On-disk identity record (one per publisher).
///
/// Version 2 records carry `provenance` ("observed" | "pinned" | "verified",
/// the section 10 three-flavor retention model). Version 1 records predate
/// the observed flavor and carry `externally_verified` instead; they are
/// readable (the mapping is lossless: v1 records were pins or verifications)
/// and are rewritten as v2 on the next write.
#[derive(Serialize, Deserialize)]
pub struct IdentityDto {
    /// Schema version; bumped if the shape changes. Unknown => corruption.
    pub v: u32,
    /// The retained publisher key (serde -> base64url string).
    pub pubkey: PublisherPubkey,
    /// v2: how the record was established ("observed" | "pinned" | "verified").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// v1 legacy field: whether the user externally verified against a PIP.
    /// Read-only compatibility; never written by v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub externally_verified: Option<bool>,
    /// Prior keys replaced into this identity, newest-first. Never lost, so a
    /// later tranche can surface the replacement history. Defaults to empty.
    #[serde(default)]
    pub replaced_pubkeys: Vec<PublisherPubkey>,
}

/// The current `IdentityDto` schema version.
pub const IDENTITY_V: u32 = 2;

/// The legacy pre-provenance schema version, still readable.
pub const IDENTITY_V1: u32 = 1;

fn provenance_str(p: RetainedProvenance) -> &'static str {
    match p {
        RetainedProvenance::Observed => "observed",
        RetainedProvenance::Pinned => "pinned",
        RetainedProvenance::ExternallyVerified => "verified",
    }
}

impl IdentityDto {
    /// Build from a retained identity plus its retained replaced keys.
    pub fn new(identity: &RetainedIdentity, replaced_pubkeys: Vec<PublisherPubkey>) -> IdentityDto {
        IdentityDto {
            v: IDENTITY_V,
            pubkey: identity.pubkey,
            provenance: Some(provenance_str(identity.provenance).to_owned()),
            externally_verified: None,
            replaced_pubkeys,
        }
    }

    /// The `RetainedIdentity` this record represents. A v2 record maps its
    /// `provenance`; a v1 record maps its legacy flag (v1 had no observed
    /// flavor). An invalid combination is a corruption signal (`Err`).
    pub fn to_identity(&self) -> Result<RetainedIdentity, StoreError> {
        let provenance = match (self.v, self.provenance.as_deref(), self.externally_verified) {
            (IDENTITY_V, Some("observed"), None) => RetainedProvenance::Observed,
            (IDENTITY_V, Some("pinned"), None) => RetainedProvenance::Pinned,
            (IDENTITY_V, Some("verified"), None) => RetainedProvenance::ExternallyVerified,
            (IDENTITY_V1, None, Some(false)) => RetainedProvenance::Pinned,
            (IDENTITY_V1, None, Some(true)) => RetainedProvenance::ExternallyVerified,
            _ => {
                return Err(StoreError(format!(
                    "identity record v{} carries an invalid provenance shape",
                    self.v
                )))
            }
        };
        Ok(RetainedIdentity {
            pubkey: self.pubkey,
            provenance,
        })
    }

    /// Validate the schema version after deserialization. Unknown => corruption.
    pub fn check_version(&self) -> Result<(), StoreError> {
        if self.v != IDENTITY_V && self.v != IDENTITY_V1 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use entangled_core::crypto::PublisherSigningKey;

    fn key() -> PublisherPubkey {
        PublisherSigningKey::from_seed(&[7; 32]).verifying_key()
    }

    #[test]
    fn v2_roundtrips_every_provenance() {
        for provenance in [
            RetainedProvenance::Observed,
            RetainedProvenance::Pinned,
            RetainedProvenance::ExternallyVerified,
        ] {
            let id = RetainedIdentity {
                pubkey: key(),
                provenance,
            };
            let dto = IdentityDto::new(&id, Vec::new());
            assert_eq!(dto.v, IDENTITY_V);
            dto.check_version().unwrap();
            assert_eq!(dto.to_identity().unwrap(), id);
        }
    }

    #[test]
    fn legacy_v1_records_map_losslessly() {
        // v1 predates the observed flavor: its records were pins or
        // verifications, and remain readable as such.
        for (flag, want) in [
            (false, RetainedProvenance::Pinned),
            (true, RetainedProvenance::ExternallyVerified),
        ] {
            let raw = format!(
                "{{\"v\":1,\"pubkey\":\"{}\",\"externally_verified\":{}}}",
                serde_json::to_value(key()).unwrap().as_str().unwrap(),
                flag
            );
            let dto: IdentityDto = serde_json::from_str(&raw).unwrap();
            dto.check_version().unwrap();
            assert_eq!(dto.to_identity().unwrap().provenance, want);
        }
    }

    #[test]
    fn invalid_provenance_shapes_fail_closed() {
        // A v2 record without provenance, or with an unknown provenance
        // string, is corruption, not a default.
        let pk = serde_json::to_value(key()).unwrap();
        let pk = pk.as_str().unwrap();
        for raw in [
            format!("{{\"v\":2,\"pubkey\":\"{pk}\"}}"),
            format!("{{\"v\":2,\"pubkey\":\"{pk}\",\"provenance\":\"trusted\"}}"),
            format!("{{\"v\":2,\"pubkey\":\"{pk}\",\"externally_verified\":true}}"),
        ] {
            let dto: IdentityDto = serde_json::from_str(&raw).unwrap();
            dto.check_version().unwrap();
            assert!(dto.to_identity().is_err(), "must fail closed: {raw}");
        }
    }

    #[test]
    fn unknown_version_fails_closed() {
        let pk = serde_json::to_value(key()).unwrap();
        let raw = format!("{{\"v\":3,\"pubkey\":{},\"provenance\":\"pinned\"}}", pk);
        let dto: IdentityDto = serde_json::from_str(&raw).unwrap();
        assert!(dto.check_version().is_err());
    }
}
