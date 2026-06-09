//! Identity store round-trips: pin/verify/replace survive a reload from disk.
//! These are the durable twins of the pure trust golden tests (esp. the M-2
//! non-downgrade round-trip), proving the behavior across an actual write+read.

mod common;
use common::{integrity_root, key, site};

use entangled_client::trust::{resolve, PersistenceIntent, TrustState, UserDecision};
use entangled_client::{IdentityStore, RetainedIdentity};
use entangled_client_store::FileIdentityStore;

#[test]
fn pin_then_reload_is_tofu_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(1), site(1));
    {
        let store = FileIdentityStore::new(integrity_root(dir.path()));
        store
            .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
            .unwrap();
    }
    // Fresh store over the same dir == a new session.
    let store = FileIdentityStore::new(integrity_root(dir.path()));
    let retained = store.load_identity(&s).unwrap();
    assert_eq!(
        retained,
        Some(RetainedIdentity {
            pubkey: k,
            externally_verified: false
        })
    );
    assert_eq!(
        resolve(&k, retained.as_ref(), UserDecision::None).state,
        TrustState::TofuPinned
    );
}

#[test]
fn externally_verified_survives_reload() {
    // M-2 made durable: a PIP-confirmed identity must reload as Externally
    // verified, not silently downgraded to a TOFU pin.
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(2), site(2));
    {
        let store = FileIdentityStore::new(integrity_root(dir.path()));
        store
            .apply(&s, &PersistenceIntent::MarkExternallyVerified { pubkey: k })
            .unwrap();
    }
    let store = FileIdentityStore::new(integrity_root(dir.path()));
    let retained = store.load_identity(&s).unwrap().unwrap();
    assert!(retained.externally_verified);
    assert_eq!(
        resolve(&k, Some(&retained), UserDecision::None).state,
        TrustState::ExternallyVerified
    );
}

#[test]
fn replace_preserves_prior_key_and_verified_flag() {
    // Same site, key rotation confirmed via PIP.
    let dir = tempfile::tempdir().unwrap();
    let (k1, k2, s) = (key(1), key(2), site(1));
    {
        let store = FileIdentityStore::new(integrity_root(dir.path()));
        store
            .apply(
                &s,
                &PersistenceIntent::MarkExternallyVerified { pubkey: k1 },
            )
            .unwrap();
        store
            .apply(
                &s,
                &PersistenceIntent::ReplaceIdentity {
                    new_pubkey: k2,
                    replaced: k1,
                    externally_verified: true,
                },
            )
            .unwrap();
    }
    let store = FileIdentityStore::new(integrity_root(dir.path()));
    // The site now resolves to k2 as the active, externally-verified identity.
    let r2 = store.load_identity(&s).unwrap().unwrap();
    assert_eq!(r2.pubkey, k2);
    assert!(r2.externally_verified);
    assert_eq!(
        resolve(&k2, Some(&r2), UserDecision::None).state,
        TrustState::ExternallyVerified
    );
}

#[test]
fn repin_does_not_demote_verified() {
    let dir = tempfile::tempdir().unwrap();
    let (k, s) = (key(5), site(5));
    let store = FileIdentityStore::new(integrity_root(dir.path()));
    store
        .apply(&s, &PersistenceIntent::MarkExternallyVerified { pubkey: k })
        .unwrap();
    // A stray re-pin must not demote.
    store
        .apply(&s, &PersistenceIntent::PinIdentity { pubkey: k })
        .unwrap();
    assert!(
        store
            .load_identity(&s)
            .unwrap()
            .unwrap()
            .externally_verified
    );
}
