//! Fail-closed behavior: missing store == first contact; corrupt/tampered store
//! == hard error (NOT a silent first-contact fallback). This is the §10:571
//! corruption-rejection posture that prevents an attacker who can edit the store
//! from silently downgrading a pinned identity.

mod common;
use common::{integrity_root, key, site};

use entangled_client::trust::{resolve, PersistenceIntent, TrustState, UserDecision};
use entangled_client::{HistoryStore, IdentityStore};
use entangled_client_store::{FileHistoryStore, FileIdentityStore};

#[test]
fn missing_identity_is_first_contact() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileIdentityStore::new(integrity_root(dir.path()));
    let (k, s) = (key(9), site(9));
    assert_eq!(store.load_identity(&s).unwrap(), None);
    assert_eq!(resolve(&k, None, UserDecision::None).state, TrustState::FirstContact);
}

#[test]
fn corrupt_identity_is_error_not_first_contact() {
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(1), site(1));
    let root = integrity_root(dir.path());
    let store = FileIdentityStore::new(root.clone());
    // Establish a valid pin first so the file exists and is well-formed.
    store
        .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
        .unwrap();

    // Now tamper with the on-disk file (flip bytes) -> integrity check must fail.
    let path = root.identity_path(&s);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 5;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let err = store.load_identity(&s);
    assert!(
        err.is_err(),
        "a tampered identity store MUST be an error, not Ok(None) first-contact"
    );
}

#[test]
fn garbage_identity_file_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let s = site(2);
    let root = integrity_root(dir.path());
    let store = FileIdentityStore::new(root.clone());
    // Write raw garbage where an identity file would be.
    let path = root.identity_path(&s);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not json at all").unwrap();
    assert!(store.load_identity(&s).is_err());
}

#[test]
fn corrupt_history_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = key(3);
    let root = integrity_root(dir.path());
    let store = FileHistoryStore::new(root.clone());
    store
        .append_record(&p, &common::record("2026-06-05T00:00:00Z", 0xA1, 0x11))
        .unwrap();
    let path = root.history_path(&p);
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    assert!(store.load_history(&p).is_err());
}

#[test]
fn no_temp_files_left_after_apply() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileIdentityStore::new(integrity_root(dir.path()));
    store
        .apply(&site(4), &PersistenceIntent::PinIdentity { pubkey: key(4) })
        .unwrap();
    // Walk the identities dir; assert no leftover *.tmp-* files.
    let idents = dir.path().join("identities");
    for entry in std::fs::read_dir(&idents).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(!name.contains("tmp-"), "leftover temp file: {name}");
    }
}
