//! Shared test helpers (key/record/record construction + a temp store root).
//!
//! Included by multiple test binaries; not every binary uses every helper, so
//! per-binary dead-code warnings are expected and suppressed.
#![allow(dead_code)]

use std::sync::Arc;

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::types::manifest::OnionAddress;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::types::PublisherPubkey;
use entangled_core::validation::canary::RetainedManifestRecord;
use sha3::{Digest, Sha3_256};

use entangled_client_store::{Protection, StoreRoot};

pub fn key(seed: u8) -> PublisherPubkey {
    PublisherSigningKey::from_seed(&[seed; 32]).verifying_key()
}

/// A valid Tor v3 onion address derived from a seed, used as the site key.
pub fn site(seed: u8) -> OnionAddress {
    let pubkey = [seed; 32];
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(&pubkey);
    payload[32..34].copy_from_slice(&[digest[0], digest[1]]);
    payload[34] = 0x03;
    let s = format!("{}.onion", BASE32.encode(&payload).to_ascii_lowercase());
    OnionAddress::try_from(s.as_str()).expect("onion")
}

pub fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).expect("valid timestamp")
}

pub fn record(issued_at: &str, runtime_seed: u8, payload_byte: u8) -> RetainedManifestRecord {
    RetainedManifestRecord {
        issued_at: ts(issued_at),
        runtime_pubkey: RuntimeSigningKey::from_seed(&[runtime_seed; 32]).verifying_key(),
        manifest_payload_hash: [payload_byte; 32],
    }
}

/// An Integrity-mode store root over a fresh temp dir.
pub fn integrity_root(dir: &std::path::Path) -> Arc<StoreRoot> {
    Arc::new(StoreRoot::open(dir, &Protection::Integrity, None).expect("open integrity store"))
}
