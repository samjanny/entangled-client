//! Protection-mode behavior at the public store boundary.
//!
//! Integrity-mode tampering detection is covered in `corruption.rs`. This file
//! covers the Encrypted mode (feature `encrypted`): a passphrase round-trip, a
//! wrong-passphrase failure, and tampered-ciphertext detection. All assert
//! fail-closed (`Err`), never a silent `Ok`.

#![cfg(feature = "encrypted")]

mod common;
use common::{key, site};

use std::sync::Arc;

use entangled_client::trust::PersistenceIntent;
use entangled_client::IdentityStore;
use entangled_client_store::{FileIdentityStore, Protection, StoreRoot};

fn encrypted_store(dir: &std::path::Path, pass: &str) -> FileIdentityStore {
    let root = Arc::new(
        StoreRoot::open(dir, &Protection::Encrypted, Some(pass)).expect("open encrypted store"),
    );
    FileIdentityStore::new(root)
}

#[test]
fn encrypted_round_trip_with_correct_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(1), site(1));
    {
        let store = encrypted_store(dir.path(), "correct horse battery staple");
        store
            .apply(&s, &PersistenceIntent::MarkExternallyVerified { pubkey: k })
            .unwrap();
    }
    // Reopen with the same passphrase -> loads, externally_verified preserved.
    let store = encrypted_store(dir.path(), "correct horse battery staple");
    let id = store.load_identity(&s).unwrap().unwrap();
    assert!(id.externally_verified);
}

#[test]
fn encrypted_wrong_passphrase_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(1), site(1));
    {
        let store = encrypted_store(dir.path(), "right-passphrase");
        store
            .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
            .unwrap();
    }
    // Wrong passphrase -> AEAD tag fails -> Err, never a silent first-contact.
    let store = encrypted_store(dir.path(), "WRONG-passphrase");
    assert!(
        store.load_identity(&s).is_err(),
        "a wrong passphrase MUST be an error, not Ok(None)"
    );
}

#[test]
fn encrypted_tampered_ciphertext_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(2), site(2));
    let pass = "passphrase";
    let store = encrypted_store(dir.path(), pass);
    store
        .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
        .unwrap();

    // Tamper the encrypted identity file.
    let root = Arc::new(StoreRoot::open(dir.path(), &Protection::Encrypted, Some(pass)).unwrap());
    let path = root.identity_path(&s);
    let mut bytes = std::fs::read(&path).unwrap();
    let i = bytes.len() - 6;
    bytes[i] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let store2 = encrypted_store(dir.path(), pass);
    assert!(store2.load_identity(&s).is_err());
}
