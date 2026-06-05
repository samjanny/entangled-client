//! Golden tests for the section 03 image-verification policy.
//!
//! A fake Decoder reports chosen dimensions/animation, so every branch is
//! exercised on data without a real image decoder: accept, each W_IMAGE_*
//! rejection, the no-retry rule, and the cumulative pixel budget.

use entangled_core::crypto::sha256_image;
use entangled_core::types::{EntangledPath, ImageMediaType};
use entangled_core::validation::DiagnosticCode;
use entangled_engine::ImageRef;

use entangled_client::image::{
    verify_image, DecodeError, Decoded, Decoder, ImageBudget, NoRetrySet,
};

/// A decoder that returns a fixed result, for testing the policy around it.
struct FakeDecoder {
    result: Result<Decoded, DecodeError>,
}

impl Decoder for FakeDecoder {
    fn decode(&self, _bytes: &[u8], _media_type: ImageMediaType) -> Result<Decoded, DecodeError> {
        self.result
    }
}

fn ok_decoder(width: u32, height: u32) -> FakeDecoder {
    FakeDecoder {
        result: Ok(Decoded {
            width,
            height,
            animated: false,
        }),
    }
}

/// An ImageRef whose declared sha256 matches `body`, declared as png WxH.
fn image_for(body: &[u8], width: u32, height: u32) -> ImageRef {
    ImageRef {
        src: EntangledPath::try_from("/img/a.png").expect("path"),
        sha256: sha256_image(body),
        media_type: ImageMediaType::Png,
        width,
        height,
        alt: "alt".to_owned(),
        caption: None,
    }
}

#[test]
fn accepts_a_well_formed_image() {
    let body = b"the image bytes";
    let image = image_for(body, 800, 600);
    let mut budget = ImageBudget::new();
    let mut no_retry = NoRetrySet::new();

    let outcome = verify_image(
        &image,
        body,
        "image/png",
        &ok_decoder(800, 600),
        &mut budget,
        &mut no_retry,
    );
    assert_eq!(
        outcome,
        entangled_client::image::ImageOutcome::Accept(Decoded {
            width: 800,
            height: 600,
            animated: false,
        })
    );
    assert_eq!(budget.used(), 800 * 600);
}

#[test]
fn content_type_mismatch_rejected() {
    let body = b"x";
    let image = image_for(body, 1, 1);
    let outcome = verify_image(
        &image,
        body,
        "image/jpeg", // declared png; header says jpeg
        &ok_decoder(1, 1),
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert_eq!(
        outcome.diagnostic(),
        Some(DiagnosticCode::WImageContentType)
    );
}

#[test]
fn content_type_with_parameters_still_matches() {
    let body = b"x";
    let image = image_for(body, 1, 1);
    let outcome = verify_image(
        &image,
        body,
        "image/png; charset=binary",
        &ok_decoder(1, 1),
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert!(outcome.is_accepted());
}

#[test]
fn oversize_body_rejected() {
    let body = vec![0u8; 2 * 1024 * 1024 + 1];
    let image = image_for(&body, 1, 1);
    let outcome = verify_image(
        &image,
        &body,
        "image/png",
        &ok_decoder(1, 1),
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert_eq!(outcome.diagnostic(), Some(DiagnosticCode::WImageOversize));
}

#[test]
fn hash_mismatch_rejected() {
    let body = b"the image bytes";
    let mut image = image_for(body, 1, 1);
    // Declare a different hash than the body's.
    image.sha256 = sha256_image(b"different bytes");
    let outcome = verify_image(
        &image,
        body,
        "image/png",
        &ok_decoder(1, 1),
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert_eq!(
        outcome.diagnostic(),
        Some(DiagnosticCode::WImageHashMismatch)
    );
}

#[test]
fn decode_failure_rejected() {
    let body = b"x";
    let image = image_for(body, 1, 1);
    let decoder = FakeDecoder {
        result: Err(DecodeError),
    };
    let outcome = verify_image(
        &image,
        body,
        "image/png",
        &decoder,
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert_eq!(
        outcome.diagnostic(),
        Some(DiagnosticCode::WImageDecodeFailed)
    );
}

#[test]
fn animated_webp_rejected() {
    let body = b"webp bytes";
    let mut image = image_for(body, 2, 2);
    image.media_type = ImageMediaType::Webp;
    let decoder = FakeDecoder {
        result: Ok(Decoded {
            width: 2,
            height: 2,
            animated: true,
        }),
    };
    let outcome = verify_image(
        &image,
        body,
        "image/webp",
        &decoder,
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert_eq!(
        outcome.diagnostic(),
        Some(DiagnosticCode::WImageDecodeFailed)
    );
}

#[test]
fn dimension_mismatch_rejected() {
    let body = b"x";
    let image = image_for(body, 100, 100);
    // Decoder reports different real dimensions than declared.
    let outcome = verify_image(
        &image,
        body,
        "image/png",
        &ok_decoder(120, 100),
        &mut ImageBudget::new(),
        &mut NoRetrySet::new(),
    );
    assert_eq!(outcome.diagnostic(), Some(DiagnosticCode::WImageDimensions));
}

#[test]
fn budget_is_cumulative_and_blocks_once_exceeded() {
    let mut budget = ImageBudget::new();
    let mut no_retry = NoRetrySet::new();

    // First image: 4096x4096 = 16,777,216 px = exactly the budget. Accepts.
    let b1 = b"first";
    let i1 = image_for(b1, 4096, 4096);
    let o1 = verify_image(
        &i1,
        b1,
        "image/png",
        &ok_decoder(4096, 4096),
        &mut budget,
        &mut no_retry,
    );
    assert!(o1.is_accepted());
    assert_eq!(budget.used(), 16_777_216);

    // Second image: any pixels now exceed the 16 MP budget -> refused.
    let b2 = b"second";
    let i2 = image_for(b2, 1, 1);
    let o2 = verify_image(
        &i2,
        b2,
        "image/png",
        &ok_decoder(1, 1),
        &mut budget,
        &mut no_retry,
    );
    assert_eq!(o2.diagnostic(), Some(DiagnosticCode::WImageBudget));
}

#[test]
fn failed_triple_is_not_retried() {
    let body = b"x";
    let mut image = image_for(body, 1, 1);
    image.sha256 = sha256_image(b"wrong"); // will fail hash
    let mut no_retry = NoRetrySet::new();

    // First attempt fails with the real diagnostic and records the triple.
    let first = verify_image(
        &image,
        body,
        "image/png",
        &ok_decoder(1, 1),
        &mut ImageBudget::new(),
        &mut no_retry,
    );
    assert_eq!(first.diagnostic(), Some(DiagnosticCode::WImageHashMismatch));
    assert!(no_retry.contains(&image));

    // Second attempt for the same triple is short-circuited (no re-verify).
    let second = verify_image(
        &image,
        body,
        "image/png",
        &ok_decoder(1, 1),
        &mut ImageBudget::new(),
        &mut no_retry,
    );
    assert!(!second.is_accepted());
}
