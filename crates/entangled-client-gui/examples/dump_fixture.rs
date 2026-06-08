//! Dump a verified manifest + content + onion to files, for driving the GUI
//! shell with real, signature-valid input.
//!
//! Writes `/tmp/ent-manifest.json`, `/tmp/ent-content.json`, and prints the
//! onion address to stdout. The content block list is deliberately varied
//! (headings, bold/italic/code runs, a list, a quote, a code block) so the
//! shell exercises inline styling and block layout, not just a single
//! paragraph.

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{build_content, build_manifest, UnsignedContent, UnsignedManifest};
use entangled_core::types::blocks::HeadingLevel;
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::types::meta::Meta;
use entangled_core::types::slug::Slug;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::types::{Block, EntangledPath, InlineElement, NoteVariant, TextMark};

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).expect("valid timestamp")
}

fn onion_for(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    payload[32..34].copy_from_slice(&[digest[0], digest[1]]);
    payload[34] = 0x03;
    format!("{}.onion", BASE32.encode(&payload).to_ascii_lowercase())
}

fn text(value: &str, marks: Vec<TextMark>) -> InlineElement {
    InlineElement::Text {
        value: value.to_owned(),
        marks,
    }
}

fn main() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xB1; 32]);
    let runtime_key = RuntimeSigningKey::from_seed(&[0xB3; 32]);
    let origin_pk_bytes = *PublisherSigningKey::from_seed(&[0xB2; 32])
        .verifying_key()
        .as_bytes();
    let onion = OnionAddress::try_from(onion_for(&origin_pk_bytes).as_str()).expect("onion");

    let unsigned = UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: publisher_key.verifying_key(),
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion.clone(),
            origin_pubkey: OriginPubkey::from_bytes(origin_pk_bytes),
            not_after: None,
        },
        canary: Canary {
            runtime_pubkey: runtime_key.verifying_key(),
            issued_at: ts("2026-05-07T00:00:00Z").into(),
            next_expected: ts("2026-06-06T00:00:00Z").into(),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
        migration_pointer: None,
        content_root: None,
    };
    let (_m, manifest_bytes) =
        build_manifest(&unsigned, &publisher_key, &ts("2026-05-07T00:00:00Z")).expect("manifest");

    let content = UnsignedContent {
        spec_version: SpecVersion,
        path: EntangledPath::try_from("/hello").expect("path"),
        meta: Meta {
            title: "Hello".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks: vec![
            Block::Heading {
                level: HeadingLevel::try_from(1u8).expect("level"),
                content: vec![text("Entangled chrome restyle", vec![])],
            },
            Block::Paragraph {
                content: vec![
                    text("This paragraph mixes ", vec![]),
                    text("bold", vec![TextMark::Bold]),
                    text(", ", vec![]),
                    text("italic", vec![TextMark::Italic]),
                    text(", and ", vec![]),
                    text("inline code", vec![TextMark::Code]),
                    text(" in one wrapping line.", vec![]),
                ],
            },
            Block::List {
                ordered: false,
                items: vec![
                    vec![text("first bullet", vec![])],
                    vec![
                        text("second bullet, ", vec![]),
                        text("emphasized", vec![TextMark::Italic]),
                    ],
                ],
            },
            Block::Quote {
                content: vec![text("A quoted line, shown italic by the shell.", vec![])],
                attribution: Some(vec![text("Someone", vec![])]),
            },
            Block::CodeBlock {
                language: Slug::try_from("text").expect("slug"),
                content: "fn main() {\n    // a fenced code block\n}".to_owned(),
            },
            Block::Note {
                variant: NoteVariant::Info,
                title: Some("A note".to_owned()),
                content: vec![text(
                    "A boxed callout, stretched to the full content column.",
                    vec![],
                )],
            },
        ],
        seq: None,
    };
    let (_c, content_bytes) = build_content(&content, &runtime_key).expect("content");

    std::fs::write("/tmp/ent-manifest.json", &manifest_bytes).expect("write manifest");
    std::fs::write("/tmp/ent-content.json", &content_bytes).expect("write content");

    eprintln!("wrote /tmp/ent-manifest.json and /tmp/ent-content.json");
    println!("{}", onion_for(&origin_pk_bytes));
}
