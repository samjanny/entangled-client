//! `FileHistoryStore`: a durable [`HistoryStore`] backed by one JSON file per
//! publisher under `<root>/history/`.

use std::sync::Arc;

use entangled_client::{HistoryStore, PublisherHistory, StoreError, StoreResult};
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::canary::RetainedManifestRecord;

use crate::dto::{HistoryDto, ManifestRecordDto, HISTORY_V};
use crate::root::StoreRoot;

/// Filesystem-backed history store. Read-modify-writes the publisher's history
/// file per append (the durable list is the disk), so it is shared as `&self`.
#[derive(Clone)]
pub struct FileHistoryStore {
    root: Arc<StoreRoot>,
}

impl FileHistoryStore {
    /// Build over a shared [`StoreRoot`].
    pub fn new(root: Arc<StoreRoot>) -> FileHistoryStore {
        FileHistoryStore { root }
    }

    fn load_dto(&self, publisher: &PublisherPubkey) -> StoreResult<Option<HistoryDto>> {
        let path = self.root.history_path(publisher);
        let Some(bytes) = self.root.read_protected(&path)? else {
            return Ok(None);
        };
        let dto: HistoryDto = serde_json::from_slice(&bytes)
            .map_err(|e| StoreError(format!("decode history: {e}")))?;
        dto.check_version()?;
        Ok(Some(dto))
    }
}

impl HistoryStore for FileHistoryStore {
    fn load_history(&self, publisher: &PublisherPubkey) -> StoreResult<PublisherHistory> {
        let Some(dto) = self.load_dto(publisher)? else {
            return Ok(PublisherHistory::new());
        };
        let mut records = Vec::with_capacity(dto.records.len());
        for r in dto.records {
            records.push(r.into_record()?); // 32-byte hex check; corrupt => Err
        }
        Ok(PublisherHistory::from_records_newest_first(records))
    }

    fn append_record(
        &self,
        publisher: &PublisherPubkey,
        record: &RetainedManifestRecord,
    ) -> StoreResult<()> {
        // Read existing (newest-first), prepend the new record, write back.
        let mut records: Vec<ManifestRecordDto> = self
            .load_dto(publisher)?
            .map(|d| d.records)
            .unwrap_or_default();
        records.insert(0, ManifestRecordDto::from_record(record));
        let dto = HistoryDto {
            v: HISTORY_V,
            records,
        };
        let path = self.root.history_path(publisher);
        let bytes =
            serde_json::to_vec(&dto).map_err(|e| StoreError(format!("encode history: {e}")))?;
        self.root.write_protected(&path, &bytes)
    }
}
