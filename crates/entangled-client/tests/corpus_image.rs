//! Corpus-driven conformance for the section 03 image resource layer.
//!
//! Runs every corpus vector carrying `expected.image_outcomes` (the image
//! tranche, 240-245) through this crate's `verify_image` pipeline and asserts
//! the per-image outcome against the recorded expectation. This is the
//! client-side counterpart of the verifier conformance suites in
//! entangled-api and entangled-api-java, which skip these vectors as out of
//! scope: the image layer belongs to the client, so the client is where the
//! vectors are driven.
//!
//! The decoder used here is a header-level PNG reader: it validates the PNG
//! signature and chunk framing, takes the geometry from IHDR, and reports
//! animation from an acTL chunk preceding the first IDAT - exactly the
//! pre-decode information the section 03 resource-exhaustion gate reads. It
//! does not inflate pixel data; pixel-level decoding belongs to the shell's
//! real decoder, and the §03 policy under test is independent of it.
//!
//! The corpus is located through the `ENTANGLED_CORPUS_PATH` environment
//! variable, or at the workspace-sibling `docs-spec/corpus/` layout used by
//! CI. When neither is present the test skips with a notice, mirroring the
//! entangled-api conformance harness.

use std::fs;
use std::path::{Path, PathBuf};

use entangled_client::image::{
    verify_image, DecodeError, Decoded, Decoder, ImageBudget, NoRetrySet,
};
use entangled_core::document::parser::parse_and_verify_content;
use entangled_core::types::{ImageMediaType, RuntimePubkey};
use entangled_engine::{ImageRef, Scene, SceneNode};

/// Header-level PNG reader implementing the test [`Decoder`].
struct PngHeaderDecoder;

impl Decoder for PngHeaderDecoder {
    fn decode(&self, bytes: &[u8], media_type: ImageMediaType) -> Result<Decoded, DecodeError> {
        // The current image tranche carries only image/png resources. A real
        // shell decoder selects a decoder per declared media_type; rejecting
        // the others here is the conservative §03 fallback (an implementation
        // that cannot inspect a format reliably must not render it).
        if media_type != ImageMediaType::Png {
            return Err(DecodeError);
        }
        parse_png_header(bytes).ok_or(DecodeError)
    }
}

/// Parse a PNG at the chunk-structure level: signature, IHDR-first framing,
/// IDAT and IEND presence, IHDR geometry, and acTL-before-IDAT animation
/// detection (§03: an APNG is identified by an acTL chunk preceding the
/// first IDAT). Returns `None` for anything that is not a well-formed PNG
/// chunk stream.
fn parse_png_header(b: &[u8]) -> Option<Decoded> {
    const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if b.len() < SIG.len() || &b[..SIG.len()] != SIG {
        return None;
    }
    let mut i = SIG.len();
    let mut dims: Option<(u32, u32)> = None;
    let mut animated = false;
    let mut seen_idat = false;
    let mut seen_iend = false;
    let mut first = true;
    while i + 12 <= b.len() {
        let len = u32::from_be_bytes(b[i..i + 4].try_into().ok()?) as usize;
        let ctype: [u8; 4] = b[i + 4..i + 8].try_into().ok()?;
        let data_start = i + 8;
        let data_end = data_start.checked_add(len)?;
        if data_end + 4 > b.len() {
            return None;
        }
        if first {
            if &ctype != b"IHDR" || len != 13 {
                return None;
            }
            let w = u32::from_be_bytes(b[data_start..data_start + 4].try_into().ok()?);
            let h = u32::from_be_bytes(b[data_start + 4..data_start + 8].try_into().ok()?);
            if w == 0 || h == 0 {
                return None;
            }
            dims = Some((w, h));
            first = false;
        } else {
            match &ctype {
                b"acTL" if !seen_idat => animated = true,
                b"IDAT" => seen_idat = true,
                b"IEND" => {
                    seen_iend = true;
                    break;
                }
                _ => {}
            }
        }
        i = data_end + 4;
    }
    let (width, height) = dims?;
    if !(seen_idat && seen_iend) {
        return None;
    }
    Some(Decoded {
        width,
        height,
        animated,
    })
}

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

#[test]
fn corpus_image_vectors_match_spec() {
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

    // Lockstep: the corpus revision must match the spec revision the verifier
    // dependency was read against, so a corpus bump and a code bump cannot
    // drift apart silently. The client has no SPEC_REVISION of its own; the
    // entangled-core constant is the anchor for the whole dependency chain.
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

    let mut driven = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for vector in corpus["vectors"].as_array().expect("vectors array") {
        let Some(outcomes) = vector["expected"]["image_outcomes"].as_array() else {
            continue;
        };
        let id = vector["id"].as_str().expect("id");
        let ctx = &vector["context"];

        // The containing content document must itself verify before any image
        // is fetched (§03, §10): drive it through the core pipeline under the
        // runtime key the corpus supplies, then apply the byte-exact Stage 9
        // path binding.
        let raw = fs::read(root.join(vector["input"].as_str().expect("input")))
            .expect("read vector input");
        let runtime = RuntimePubkey::try_from(
            ctx["expected_runtime_pubkey"]
                .as_str()
                .expect("expected_runtime_pubkey"),
        )
        .expect("runtime pubkey");
        let doc = match parse_and_verify_content(&raw, &runtime) {
            Ok(doc) => doc,
            Err(e) => {
                failures.push(format!("[{id}] containing document rejected: {e:?}"));
                continue;
            }
        };
        let fetched_path = ctx["fetched_path"].as_str().expect("fetched_path");
        if doc.path.as_str() != fetched_path {
            failures.push(format!(
                "[{id}] path binding failed: document path {} vs fetched {}",
                doc.path.as_str(),
                fetched_path
            ));
            continue;
        }

        // Image blocks in document order, via the engine IR the client brain
        // actually consumes.
        let scene = Scene::from_content(&doc);
        let images: Vec<&ImageRef> = scene
            .nodes
            .iter()
            .filter_map(|node| match node {
                SceneNode::Image { image, .. } => Some(image),
                _ => None,
            })
            .collect();
        let responses = ctx["image_responses"].as_array().expect("image_responses");
        assert_eq!(
            images.len(),
            responses.len(),
            "[{id}] image block count vs image_responses length"
        );
        assert_eq!(
            outcomes.len(),
            responses.len(),
            "[{id}] image_outcomes vs image_responses length"
        );

        // Drive the §03 pipeline per image, sharing the document-wide pixel
        // budget and no-retry set as a rendering session would.
        let mut budget = ImageBudget::new();
        let mut no_retry = NoRetrySet::new();
        for (i, ((image, response), want)) in images
            .iter()
            .zip(responses.iter())
            .zip(outcomes.iter())
            .enumerate()
        {
            let body = fs::read(root.join(response["file"].as_str().expect("file")))
                .expect("read image response body");
            let content_type = response["content_type"].as_str().expect("content_type");
            let outcome = verify_image(
                image,
                &body,
                content_type,
                &PngHeaderDecoder,
                &mut budget,
                &mut no_retry,
            );
            let got = match outcome.diagnostic() {
                None => "accept".to_owned(),
                Some(code) => serde_json::to_value(code)
                    .expect("serialize diagnostic code")
                    .as_str()
                    .expect("diagnostic code string")
                    .to_owned(),
            };
            let want = want.as_str().expect("image outcome string");
            if got != want {
                failures.push(format!("[{id}] image {i}: expected {want}, got {got}"));
            }
        }
        driven += 1;
    }

    assert!(
        driven >= 6,
        "expected at least the six rc.52 image vectors; drove {driven}"
    );
    assert!(
        failures.is_empty(),
        "{} image-vector failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("{driven} image vectors driven, all outcomes match");
}
