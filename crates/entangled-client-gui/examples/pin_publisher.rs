//! Test helper: pin the fixture publisher (for the fixture site) into a store,
//! exercising the exact persistence path the GUI's "Pin this identity" button
//! uses. Lets the returning-visitor scenario be verified end-to-end without
//! simulating a click.
//!
//! Usage: pin_publisher <store-dir> <onion-address> [verified]
//!   - default: PinIdentity (TOFU pin)
//!   - "verified": MarkExternallyVerified

use std::sync::Arc;

use entangled_client::trust::PersistenceIntent;
use entangled_client::IdentityStore;
use entangled_client_store::{FileIdentityStore, Protection, StoreRoot};
use entangled_core::crypto::PublisherSigningKey;
use entangled_core::types::manifest::OnionAddress;

fn main() {
    let mut args = std::env::args().skip(1);
    let store_dir = args
        .next()
        .expect("usage: pin_publisher <store-dir> <onion-address> [verified]");
    let onion = args
        .next()
        .expect("usage: pin_publisher <store-dir> <onion-address> [verified]");
    let verified = args.next().as_deref() == Some("verified");

    // The fixture's publisher key (seed 0xB1) for the fixture site.
    let publisher = PublisherSigningKey::from_seed(&[0xB1; 32]).verifying_key();
    let site = OnionAddress::try_from(onion.as_str()).expect("valid onion");

    let root = Arc::new(
        StoreRoot::open(
            std::path::PathBuf::from(store_dir),
            &Protection::Integrity,
            None,
        )
        .expect("open store"),
    );
    let store = FileIdentityStore::new(root);

    let intent = if verified {
        PersistenceIntent::MarkExternallyVerified { pubkey: publisher }
    } else {
        PersistenceIntent::PinIdentity { pubkey: publisher }
    };
    store.apply(&site, &intent).expect("apply pin");
    eprintln!(
        "pinned publisher {} for site {} ({})",
        publisher,
        site.as_str(),
        if verified {
            "externally verified"
        } else {
            "TOFU"
        }
    );
}
