//! Corpus-driven conformance for the section 10 trust machinery.
//!
//! Runs every corpus vector whose expected diagnostic is in the trust family
//! (`E_TRUST_*` / `I_TRUST_*`, vectors 210-214) through this crate's Stage 6
//! manifest identity pre-check and Stage 7 trust-state machine. These are the
//! vectors both verifier libraries (entangled-api, entangled-api-java) skip as
//! out of scope: the trust machinery belongs to the client, so the client is
//! where they are driven.
//!
//! The drive order is the section 10 one. Stages 2 through 5 parse and
//! schema-validate the manifest, which yields the presented `publisher_pubkey`
//! without verifying the signature. The Stage 6 identity pre-check then
//! resolves the presented key against the retained identity the vector seeds:
//! a Changed/mismatch outcome surfaces its `E_TRUST_*` diagnostic *before*
//! signature verification, taking precedence over `E_SIG_VERIFICATION` even
//! though the vector manifests are correctly signed under the presented key.
//! Only a non-mismatch resolution proceeds through the full pipeline (Stages 6
//! through 9), after which the Stage 7 transition surfaces its `I_TRUST_*`
//! info code.
//!
//! The corpus is located exactly as in the image harness: the
//! `ENTANGLED_CORPUS_PATH` environment variable, or the workspace-sibling
//! `docs-spec/corpus/` layout used by CI; absent both, the test skips with a
//! notice.

use std::fs;
use std::path::{Path, PathBuf};

use entangled_client::trust::{
    resolve, trust_diagnostic, PersistenceIntent, RetainedIdentity, RetainedProvenance, TrustState,
    UserDecision,
};
use entangled_client::{verify_manifest, FixedClock, PublisherHistory};
use entangled_core::types::manifest::OnionAddress;
use entangled_core::types::{EntangledTimestamp, PublisherPubkey};
use entangled_core::validation::parse_and_validate_manifest;

/// Locate the corpus: `ENTANGLED_CORPUS_PATH`, or the workspace-sibling
/// `docs-spec/corpus/` directory that CI checks out.
fn corpus_root() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ENTANGLED_CORPUS_PATH") {
        let p = PathBuf::from(p);
        return p.join("corpus.json").exists().then_some(p);
    }
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let p = crate_dir
        .parent()?
        .parent()?
        .parent()?
        .join("docs-spec")
        .join("corpus");
    p.join("corpus.json").exists().then_some(p)
}

/// Map the corpus `context.user_decision` string onto the machine's
/// [`UserDecision`]. Absent means no decision.
fn map_decision(raw: Option<&str>) -> UserDecision {
    match raw {
        None => UserDecision::None,
        Some("pin_identity") => UserDecision::PinFirstContact,
        Some("verify_pip") => UserDecision::ConfirmPip,
        Some("reject_new_identity") => UserDecision::RejectNewIdentity,
        Some("accept_new_identity") => UserDecision::ConfirmNewIdentity,
        Some(other) => panic!("unknown corpus user_decision: {other}"),
    }
}

#[test]
fn corpus_trust_vectors_match_spec() {
    let Some(root) = corpus_root() else {
        eprintln!(
            "conformance corpus not found at docs-spec/corpus/ \
             (set ENTANGLED_CORPUS_PATH to override); skipping."
        );
        return;
    };
    let corpus: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("corpus.json")).expect("read corpus.json"))
            .expect("parse corpus.json");

    // Lockstep guard, as in the image harness: the corpus revision must match
    // the spec revision the verifier dependency was read against.
    let rc_target = corpus["rc_target"].as_str().expect("rc_target");
    assert_eq!(
        rc_target,
        entangled_core::SPEC_REVISION,
        "corpus rc_target {} drifted from entangled-core SPEC_REVISION {}; bump \
         the CI corpus pin (.github/workflows/ci.yml) and the entangled-api \
         SPEC_REVISION in lockstep",
        rc_target,
        entangled_core::SPEC_REVISION,
    );
    let now = EntangledTimestamp::try_from(corpus["clock_now"].as_str().expect("clock_now"))
        .expect("clock_now timestamp");

    let mut driven = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for vector in corpus["vectors"].as_array().expect("vectors array") {
        let Some(expected_code) = vector["expected"]["diagnostic"].as_str() else {
            continue;
        };
        if !(expected_code.starts_with("E_TRUST") || expected_code.starts_with("I_TRUST")) {
            continue;
        }
        let id = vector["id"].as_str().expect("id");
        let ctx = &vector["context"];
        let expected_verdict = vector["expected"]["verdict"].as_str().expect("verdict");

        let raw = fs::read(root.join(vector["input"].as_str().expect("input")))
            .expect("read vector input");

        // Stages 2-5: parse and schema-validate; the presented publisher key
        // is readable without signature verification.
        let manifest = match parse_and_validate_manifest(&raw, &now) {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!("[{id}] stages 2-5 rejected the manifest: {e:?}"));
                continue;
            }
        };
        let presented = manifest.publisher_pubkey;

        // Seed what the vector says the client retained for this site, and the
        // user's decision. context.retained_provenance selects the section 10
        // retention flavor; absent means a plain TOFU pin (the 210/211 shape,
        // "the same site was earlier pinned", corpus README).
        let provenance = match ctx["retained_provenance"].as_str() {
            None | Some("pinned") => RetainedProvenance::Pinned,
            Some("observed") => RetainedProvenance::Observed,
            Some("verified") => RetainedProvenance::ExternallyVerified,
            Some(other) => panic!("unknown corpus retained_provenance: {other}"),
        };
        let retained = ctx["retained_publisher_pubkey"]
            .as_str()
            .map(|s| RetainedIdentity {
                pubkey: PublisherPubkey::try_from(s).expect("retained_publisher_pubkey"),
                provenance,
            });
        let decision = map_decision(ctx["user_decision"].as_str());

        // Stage 6 identity pre-check: resolved before signature verification,
        // taking precedence over E_SIG_VERIFICATION (section 10).
        let resolution = resolve(&presented, retained.as_ref(), decision);
        if resolution.state == TrustState::ChangedMismatch {
            // The load-bearing MUST: a mismatch never replaces the retained
            // identity, whatever the decision was.
            if resolution.intent != PersistenceIntent::None {
                failures.push(format!(
                    "[{id}] mismatch resolution produced a persistence intent: {:?}",
                    resolution.intent
                ));
            }
            if expected_verdict != "reject" {
                failures.push(format!("[{id}] mismatch on an accept vector"));
                continue;
            }
            let got = trust_diagnostic(&resolution, decision)
                .map(|code| {
                    serde_json::to_value(code)
                        .expect("serialize diagnostic code")
                        .as_str()
                        .expect("diagnostic code string")
                        .to_owned()
                })
                .unwrap_or_else(|| "accept".to_owned());
            if got != expected_code {
                failures.push(format!("[{id}] expected {expected_code}, got {got}"));
            }
            driven += 1;
            continue;
        }

        // Not a mismatch: the manifest must pass the full pipeline before any
        // Stage 7 transition persists (section 10 persistence ordering).
        if expected_verdict != "accept" {
            failures.push(format!(
                "[{id}] non-mismatch resolution on a reject vector (state {:?})",
                resolution.state
            ));
            continue;
        }
        let fetched = OnionAddress::try_from(
            ctx["fetched_origin_address"]
                .as_str()
                .expect("fetched_origin_address"),
        )
        .expect("fetched origin address");
        let outcome = verify_manifest(
            &raw,
            &fetched,
            None,
            &FixedClock(now),
            &PublisherHistory::new(),
        );
        if let Some(diagnostic) = outcome.diagnostic() {
            failures.push(format!(
                "[{id}] pipeline rejected the manifest: {diagnostic:?}"
            ));
            continue;
        }
        let got = trust_diagnostic(&resolution, decision)
            .map(|code| {
                serde_json::to_value(code)
                    .expect("serialize diagnostic code")
                    .as_str()
                    .expect("diagnostic code string")
                    .to_owned()
            })
            .unwrap_or_else(|| "accept".to_owned());
        if got != expected_code {
            failures.push(format!("[{id}] expected {expected_code}, got {got}"));
        }
        driven += 1;
    }

    assert!(
        driven >= 5,
        "expected at least the five trust vectors (210-214); drove {driven}"
    );
    assert!(
        failures.is_empty(),
        "{} trust-vector failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("{driven} trust vectors driven, all outcomes match");
}
