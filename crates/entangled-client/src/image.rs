//! Image-resource verification policy (section 03).
//!
//! Section 03 defines a strict, ordered pipeline for an `image` block's
//! resource: the bytes are authenticated by hash before decoding, the declared
//! `media_type` (png/jpeg/webp only - no SVG, no animated images: WebP or APNG) is authoritative
//! for the decoder, decoded dimensions must match the declared ones, and a
//! document-wide 16-megapixel budget bounds total decoded pixels. A failure at
//! any step rejects only the image (never the containing document), and the
//! same `(src, sha256, media_type)` triple must not be retried within a
//! rendering session.
//!
//! This module is the pure policy: given the fetched response bytes, the
//! response `Content-Type`, the declared block ([`entangled_engine::ImageRef`]),
//! the running budget, and the no-retry set, it runs steps 3 through 9 and
//! returns accept or the section 11 `W_IMAGE_*` diagnostic. The one impure step
//! (decoding) is a [`Decoder`] trait the caller (the shell) implements; the
//! crate stays pure and golden-testable, and the unsafe-adjacent decode lives in
//! the shell where it can be sandboxed (see the crate's sandbox note).
//!
//! Steps 1 (the containing document is verified) and 2 (fetch) are the caller's
//! responsibility - the pipeline driver verifies the document, and transport is
//! a later tranche; this module is handed the already-fetched bytes. Step 10
//! (render) is the shell's.

use std::collections::BTreeSet;

use entangled_core::crypto::sha256_image;
use entangled_core::types::ImageMediaType;
use entangled_core::validation::DiagnosticCode;
use entangled_engine::ImageRef;

/// The 2 MiB cap on an image response body (section 03 / section 02).
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// The document-wide decoded pixel budget: 16 megapixels (section 03).
pub const MAX_DECODED_PIXELS: u64 = 16_777_216;

/// The result of decoding image bytes, as the shell's decoder reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// Decoded width in pixels.
    pub width: u32,
    /// Decoded height in pixels.
    pub height: u32,
    /// Whether the resource is animated. Animation is forbidden for every
    /// permitted `media_type`: an animated WebP or an animated PNG (APNG) is
    /// rejected as `W_IMAGE_DECODE_FAILED`. The shell's decoder MUST set this
    /// for an APNG (`acTL` chunk) under `image/png`, not only for WebP.
    pub animated: bool,
}

/// A decode failure reported by the shell's [`Decoder`]. The policy turns any
/// decode error into `W_IMAGE_DECODE_FAILED`; the specific cause is the shell's
/// detail and not distinguished here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

/// The impure decode step, implemented by the shell.
///
/// The implementation MUST select the decoder from the declared `media_type`
/// (not the transport `Content-Type`) and report the true decoded dimensions.
/// It MUST report `animated = true` for any animated resource under its declared
/// `media_type` - an animated WebP or an animated PNG (APNG, signalled by an
/// `acTL` chunk) - so the policy can reject it; animation detection is not
/// WebP-only. To bound resource use (section 03 "Resource-exhaustion gate"), the
/// implementation MUST read the pixel geometry from the container header and
/// refuse to allocate a full surface beyond the section 03 limits (4096 by 4096,
/// and the document pixel budget) before decoding, rather than allocating first
/// and checking after. A decode failure - including bytes that are valid for a
/// different format than declared - is [`DecodeError`], which the policy turns
/// into `W_IMAGE_DECODE_FAILED`. Decoding is unsafe-adjacent (hostile bytes can
/// target decoder bugs and decompression bombs); the implementation SHOULD use a
/// memory-safe or sandboxed decoder (section 03 "Decoder safety").
pub trait Decoder {
    /// Decode `bytes` as `media_type`, reporting dimensions and animation.
    fn decode(&self, bytes: &[u8], media_type: ImageMediaType) -> Result<Decoded, DecodeError>;
}

/// The document-wide decoded-pixel budget accumulator (section 03).
///
/// Pixels are counted only for images that passed hash verification and were
/// decoded. Once an image would push the total past 16 MP, it and every
/// subsequent image in the document is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageBudget {
    used: u64,
}

impl ImageBudget {
    /// A fresh budget for a document (zero pixels used).
    pub fn new() -> ImageBudget {
        ImageBudget { used: 0 }
    }

    /// Pixels consumed so far.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Try to charge `width * height` pixels. On success the budget is advanced
    /// and `true` is returned; if it would exceed [`MAX_DECODED_PIXELS`], the
    /// budget is left unchanged and `false` is returned (the image is refused).
    fn try_charge(&mut self, width: u32, height: u32) -> bool {
        let pixels = u64::from(width) * u64::from(height);
        match self.used.checked_add(pixels) {
            Some(total) if total <= MAX_DECODED_PIXELS => {
                self.used = total;
                true
            }
            _ => false,
        }
    }
}

/// The set of `(src, sha256, media_type)` triples that already failed in this
/// rendering session, so the same image is not retried (section 03 no-retry).
#[derive(Clone, Debug, Default)]
pub struct NoRetrySet {
    failed: BTreeSet<String>,
}

impl NoRetrySet {
    /// An empty set (a fresh rendering session).
    pub fn new() -> NoRetrySet {
        NoRetrySet::default()
    }

    /// The stable key for an image's bound triple.
    fn key(image: &ImageRef) -> String {
        // src and sha256 have restricted, unambiguous string forms; join with a
        // separator that cannot appear in either.
        format!(
            "{}\u{0}{}\u{0}{}",
            image.src.as_str(),
            image.sha256,
            media_type_str(image.media_type),
        )
    }

    /// Whether this image's triple already failed and must not be retried.
    pub fn contains(&self, image: &ImageRef) -> bool {
        self.failed.contains(&Self::key(image))
    }

    /// Record that this image's triple failed.
    fn record(&mut self, image: &ImageRef) {
        self.failed.insert(Self::key(image));
    }
}

/// Whether an image resource was accepted, or which `W_IMAGE_*` it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageOutcome {
    /// The image passed every check and may be rendered at these decoded
    /// dimensions.
    Accept(Decoded),
    /// The image was rejected; the code is the section 11 `W_IMAGE_*`.
    Reject(DiagnosticCode),
}

impl ImageOutcome {
    /// Whether the image was accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, ImageOutcome::Accept(_))
    }

    /// The rejection code, if any.
    pub fn diagnostic(&self) -> Option<DiagnosticCode> {
        match self {
            ImageOutcome::Reject(c) => Some(*c),
            ImageOutcome::Accept(_) => None,
        }
    }
}

/// Verify a fetched image resource against its block (section 03 steps 3-9).
///
/// - `image`: the declared `image` block (src, sha256, media_type, width,
///   height).
/// - `body`: the exact fetched response body bytes.
/// - `content_type`: the response `Content-Type` header value (the wire type),
///   compared against the declared `media_type` for header consistency.
/// - `decoder`: the shell's decoder (the only impure step).
/// - `budget`: the document-wide decoded-pixel budget, charged on success.
/// - `no_retry`: the session's failed-triple set; consulted first and updated
///   on failure.
///
/// Steps 1 (document verified) and 2 (fetch) are the caller's; a transport
/// failure is `W_IMAGE_FETCH_FAILED`, reported by the caller before calling
/// this. On any rejection here the triple is recorded in `no_retry`.
pub fn verify_image(
    image: &ImageRef,
    body: &[u8],
    content_type: &str,
    decoder: &impl Decoder,
    budget: &mut ImageBudget,
    no_retry: &mut NoRetrySet,
) -> ImageOutcome {
    // No-retry: a triple that already failed this session is not retried.
    if no_retry.contains(image) {
        // Report the generic decode-failed marker; the original failure was
        // already surfaced. (The caller may also choose to render a placeholder
        // without re-reporting.)
        return ImageOutcome::Reject(DiagnosticCode::WImageDecodeFailed);
    }

    let outcome = run_checks(image, body, content_type, decoder, budget);
    if !outcome.is_accepted() {
        no_retry.record(image);
    }
    outcome
}

fn run_checks(
    image: &ImageRef,
    body: &[u8],
    content_type: &str,
    decoder: &impl Decoder,
    budget: &mut ImageBudget,
) -> ImageOutcome {
    // Step 3: Content-Type vs declared media_type (header consistency).
    if !content_type_matches(content_type, image.media_type) {
        return ImageOutcome::Reject(DiagnosticCode::WImageContentType);
    }
    // Step 4: 2 MiB body cap, before any decoding.
    if body.len() > MAX_IMAGE_BYTES {
        return ImageOutcome::Reject(DiagnosticCode::WImageOversize);
    }
    // Step 5: SHA-256 of the exact bytes vs the block's sha256, before decode.
    if sha256_image(body) != image.sha256 {
        return ImageOutcome::Reject(DiagnosticCode::WImageHashMismatch);
    }
    // Step 6: decode under the declared media_type (the impure step).
    let decoded = match decoder.decode(body, image.media_type) {
        Ok(d) => d,
        Err(DecodeError) => return ImageOutcome::Reject(DiagnosticCode::WImageDecodeFailed),
    };
    // Step 7: an animated resource (animated WebP or APNG) is a decode failure.
    if decoded.animated {
        return ImageOutcome::Reject(DiagnosticCode::WImageDecodeFailed);
    }
    // Step 8: decoded dimensions vs declared.
    if decoded.width != image.width || decoded.height != image.height {
        return ImageOutcome::Reject(DiagnosticCode::WImageDimensions);
    }
    // Step 9: document-wide 16 MP budget (charged only on full success).
    if !budget.try_charge(decoded.width, decoded.height) {
        return ImageOutcome::Reject(DiagnosticCode::WImageBudget);
    }
    ImageOutcome::Accept(decoded)
}

/// The canonical `Content-Type` for a declared media type.
fn media_type_str(media_type: ImageMediaType) -> &'static str {
    match media_type {
        ImageMediaType::Png => "image/png",
        ImageMediaType::Jpeg => "image/jpeg",
        ImageMediaType::Webp => "image/webp",
    }
}

/// Whether the response `Content-Type` is consistent with the declared media
/// type. The header may carry parameters (e.g. `image/png; charset=...`); the
/// media type is the part before any `;`, compared case-insensitively.
fn content_type_matches(content_type: &str, declared: ImageMediaType) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == media_type_str(declared)
}
