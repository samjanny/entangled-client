//! `FileIdentityStore`: a durable [`IdentityStore`] backed by one JSON file per
//! publisher under `<root>/identities/`.

use std::sync::Arc;

use entangled_client::trust::{PersistenceIntent, RetainedIdentity, RetainedProvenance};
use entangled_client::{IdentityStore, StoreError, StoreResult};
use entangled_core::types::manifest::OnionAddress;

use crate::dto::IdentityDto;
use crate::root::StoreRoot;

/// Filesystem-backed identity store, keyed by **site** (the carrier onion),
/// per §10:187. Reads/writes the site's identity file per call (the durable map
/// is the disk), so it is shared as `&self`.
#[derive(Clone)]
pub struct FileIdentityStore {
    root: Arc<StoreRoot>,
}

impl FileIdentityStore {
    /// Build over a shared [`StoreRoot`].
    pub fn new(root: Arc<StoreRoot>) -> FileIdentityStore {
        FileIdentityStore { root }
    }

    /// Load the raw DTO for a site, or `None` if absent. Corrupt/tampered =>
    /// `Err` (fail-closed).
    fn load_dto(&self, site: &OnionAddress) -> StoreResult<Option<IdentityDto>> {
        let path = self.root.identity_path(site);
        let Some(bytes) = self.root.read_protected(&path)? else {
            return Ok(None);
        };
        let dto: IdentityDto = serde_json::from_slice(&bytes)
            .map_err(|e| StoreError(format!("decode identity: {e}")))?;
        dto.check_version()?;
        Ok(Some(dto))
    }

    fn write_dto(&self, site: &OnionAddress, dto: &IdentityDto) -> StoreResult<()> {
        let path = self.root.identity_path(site);
        let bytes =
            serde_json::to_vec(dto).map_err(|e| StoreError(format!("encode identity: {e}")))?;
        self.root.write_protected(&path, &bytes)
    }
}

impl IdentityStore for FileIdentityStore {
    fn load_identity(&self, site: &OnionAddress) -> StoreResult<Option<RetainedIdentity>> {
        self.load_dto(site)?.map(|d| d.to_identity()).transpose()
    }

    fn apply(&self, site: &OnionAddress, intent: &PersistenceIntent) -> StoreResult<()> {
        match intent {
            PersistenceIntent::None => Ok(()),
            PersistenceIntent::RecordObservation { pubkey } => {
                // The automatic first-contact observation (section 10:298):
                // created only when nothing is retained for the site. Never
                // overwrites or demotes an existing record of any provenance.
                if self.load_dto(site)?.is_none() {
                    let id = RetainedIdentity {
                        pubkey: *pubkey,
                        provenance: RetainedProvenance::Observed,
                    };
                    self.write_dto(site, &IdentityDto::new(&id, Vec::new()))?;
                }
                Ok(())
            }
            PersistenceIntent::PinIdentity { pubkey } => {
                // Non-destructive: a pin creates the record, or upgrades an
                // observed-only record to a pin. It never demotes an existing
                // pinned or verified record.
                match self.load_dto(site)? {
                    None => {
                        let id = RetainedIdentity {
                            pubkey: *pubkey,
                            provenance: RetainedProvenance::Pinned,
                        };
                        self.write_dto(site, &IdentityDto::new(&id, Vec::new()))
                    }
                    Some(dto) => {
                        let existing = dto.to_identity()?;
                        if existing.provenance == RetainedProvenance::Observed {
                            let id = RetainedIdentity {
                                pubkey: *pubkey,
                                provenance: RetainedProvenance::Pinned,
                            };
                            self.write_dto(site, &IdentityDto::new(&id, dto.replaced_pubkeys))?;
                        }
                        Ok(())
                    }
                }
            }
            PersistenceIntent::MarkExternallyVerified { pubkey } => {
                // Read-modify-write: keep replaced_pubkeys, raise the provenance.
                // Covers first-contact-PIP (create) and observed/TOFU->verified.
                let replaced = self
                    .load_dto(site)?
                    .map(|d| d.replaced_pubkeys)
                    .unwrap_or_default();
                let id = RetainedIdentity {
                    pubkey: *pubkey,
                    provenance: RetainedProvenance::ExternallyVerified,
                };
                self.write_dto(site, &IdentityDto::new(&id, replaced))
            }
            PersistenceIntent::ReplaceIdentity {
                new_pubkey,
                replaced,
                externally_verified,
            } => {
                // Same site, new key: carry forward any prior replaced keys with
                // the just-replaced key newest-first (never lost), and write the
                // new active identity into the SAME site file. A confirmed
                // replacement is an explicit decision: a pin, or a verification
                // when the user confirmed the PIP while resolving.
                let mut replaced_pubkeys = self
                    .load_dto(site)?
                    .map(|d| d.replaced_pubkeys)
                    .unwrap_or_default();
                replaced_pubkeys.insert(0, *replaced);
                let id = RetainedIdentity {
                    pubkey: *new_pubkey,
                    provenance: if *externally_verified {
                        RetainedProvenance::ExternallyVerified
                    } else {
                        RetainedProvenance::Pinned
                    },
                };
                self.write_dto(site, &IdentityDto::new(&id, replaced_pubkeys))
            }
        }
    }
}
