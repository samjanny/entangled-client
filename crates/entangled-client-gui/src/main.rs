//! `entangled-client-gui` binary: the thin eframe/egui shell.
//!
//! Loads a manifest (and optionally a content document) from files, verifies
//! them through `entangled-client`, and draws the chrome and content in a
//! window. All verification and the chrome model live in the pure crates; this
//! file only reads files and maps the result to egui widgets.
//!
//! Read-only tranche: there is no retained identity, persistence, or pinning
//! prompt yet. The window is honest that it is a viewer, not a conforming
//! client.

use std::path::PathBuf;
use std::process::ExitCode;

use eframe::egui;
use entangled_client::chrome::{ChromeView, Warning};
use entangled_client::trust::TrustState;
use entangled_client::FixedClock;
use entangled_client_gui::{load, Loaded};
use entangled_core::types::{EntangledTimestamp, OnionAddress};
use entangled_core::validation::canary::CanaryState;
use entangled_engine::{InlineRun, Scene, SceneNode};

const NOT_A_CLIENT: &str =
    "entangled-client-gui - read-only viewer (no persistence/pinning yet; NOT a conforming client)";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(manifest), onion_arg) = (args.next(), args.next()) else {
        eprintln!("usage: entangled-client-gui <manifest.json> <onion-address> [content.json]");
        eprintln!("  loads and verifies a manifest (and optional content) and shows it.");
        return ExitCode::from(2);
    };
    let Some(onion_arg) = onion_arg else {
        eprintln!("error: missing <onion-address> (the address the manifest was fetched from)");
        return ExitCode::from(2);
    };
    let content_arg = args.next();

    let loaded = match build(
        &PathBuf::from(manifest),
        &onion_arg.to_string_lossy(),
        content_arg.as_ref().map(PathBuf::from).as_deref(),
    ) {
        Ok(l) => l,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let options = eframe::NativeOptions::default();
    match eframe::run_native(
        "entangled-client",
        options,
        Box::new(|_cc| Ok(Box::new(App { loaded }))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read the files and run the pure `load`. Errors are strings for the CLI.
fn build(
    manifest_path: &std::path::Path,
    onion: &str,
    content_path: Option<&std::path::Path>,
) -> Result<Loaded, String> {
    let manifest_bytes =
        std::fs::read(manifest_path).map_err(|e| format!("reading manifest: {e}"))?;
    let content_bytes = match content_path {
        Some(p) => Some(std::fs::read(p).map_err(|e| format!("reading content: {e}"))?),
        None => None,
    };
    let address =
        OnionAddress::try_from(onion).map_err(|e| format!("invalid onion address: {e:?}"))?;
    let compact = compact_onion(onion);
    // A real client supplies wall-clock time; this viewer uses a fixed instant
    // so the load is deterministic. (A later tranche wires a real clock.)
    let clock = FixedClock(
        EntangledTimestamp::try_from("2026-06-05T00:00:00Z").expect("valid fixed timestamp"),
    );
    load(
        &manifest_bytes,
        content_bytes.as_deref(),
        &address,
        compact,
        &clock,
    )
    .map_err(|e| e.to_string())
}

/// A short, distinguishable form of an onion address for the chrome indicator.
fn compact_onion(onion: &str) -> String {
    let stem = onion.strip_suffix(".onion").unwrap_or(onion);
    if stem.len() > 12 {
        format!("{}...{}.onion", &stem[..6], &stem[stem.len() - 6..])
    } else {
        onion.to_owned()
    }
}

struct App {
    loaded: Loaded,
}

/// Background for the chrome panel: a distinct, slightly tinted dark fill with
/// a separating bottom stroke, so the client-controlled chrome is visibly
/// separate from the publisher content (section 10 chrome separation).
fn chrome_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(0x1c, 0x22, 0x2c))
        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgb(0x3a, 0x44, 0x52),
        ))
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Chrome: a client-controlled top panel, structurally separate from the
        // content area below. Its distinct frame makes the boundary visible.
        // Publisher content never draws here.
        egui::TopBottomPanel::top("chrome")
            .frame(chrome_frame())
            .show(ctx, |ui| {
                draw_chrome(ui, &self.loaded.chrome);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Constrain content to a readable column rather than the full
                // window width, and give it breathing room.
                ui.add_space(8.0);
                let max_width = 720.0_f32.min(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add_space(((ui.available_width() - max_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_max_width(max_width);
                        match &self.loaded.scene {
                            Some(scene) => draw_scene(ui, scene),
                            None => {
                                ui.label("(manifest only - no content document loaded)");
                            }
                        }
                    });
                });
            });
        });
    }
}

/// Draw the always-visible chrome indicators and any conditional warnings.
fn draw_chrome(ui: &mut egui::Ui, chrome: &ChromeView) {
    // Honest banner: this is a viewer, not a conforming client (yet).
    ui.label(
        egui::RichText::new(NOT_A_CLIENT)
            .small()
            .color(egui::Color32::from_rgb(0xC0, 0x80, 0x00)),
    );
    ui.add_space(4.0);

    // Always-visible compact indicators (section 10), with semantic color.
    ui.horizontal_wrapped(|ui| {
        let (label, color) = trust_label(chrome.trust_state);
        ui.label(egui::RichText::new(label).strong().color(color));
        ui.separator();
        ui.label(egui::RichText::new(&chrome.carrier_address_compact).monospace());
        ui.separator();
        let (clabel, ccolor) = canary_label(chrome.canary_state);
        ui.label(egui::RichText::new(clabel).color(ccolor));
    });

    // PIP, labeled as public identity (never "seed phrase"). Section 10 (304,
    // 687): at First contact and Changed/mismatch the user is being asked to
    // verify identity, so the full 24-word PIP MUST be shown, not only
    // collapsed. In the other states it may stay behind an expand control.
    ui.add_space(2.0);
    if chrome.pip_must_be_fully_shown {
        ui.label(egui::RichText::new(chrome.pip_label).small());
        ui.monospace(&chrome.pip);
    } else {
        ui.collapsing(chrome.pip_label, |ui| {
            ui.monospace(&chrome.pip);
        });
    }

    for warning in &chrome.warnings {
        ui.label(
            egui::RichText::new(warning_label(*warning))
                .strong()
                .color(egui::Color32::from_rgb(0xE0, 0x50, 0x50)),
        );
    }
    if chrome.request_state_active {
        ui.label(
            egui::RichText::new("request state active")
                .color(egui::Color32::from_rgb(0xC0, 0x80, 0x00)),
        );
    }
}

fn trust_label(state: TrustState) -> (&'static str, egui::Color32) {
    let green = egui::Color32::from_rgb(0x4c, 0xc0, 0x6a);
    let yellow = egui::Color32::from_rgb(0xd0, 0xa0, 0x30);
    let red = egui::Color32::from_rgb(0xe0, 0x50, 0x50);
    match state {
        TrustState::ExternallyVerified => ("trust: externally verified", green),
        TrustState::TofuPinned => ("trust: TOFU pinned", green),
        TrustState::FirstContact => ("trust: first contact", yellow),
        TrustState::ChangedMismatch => ("trust: CHANGED / MISMATCH", red),
    }
}

fn canary_label(state: CanaryState) -> (&'static str, egui::Color32) {
    let green = egui::Color32::from_rgb(0x4c, 0xc0, 0x6a);
    let yellow = egui::Color32::from_rgb(0xd0, 0xa0, 0x30);
    let red = egui::Color32::from_rgb(0xe0, 0x50, 0x50);
    let gray = egui::Color32::from_rgb(0x90, 0x98, 0xa4);
    match state {
        CanaryState::Fresh => ("canary: fresh", green),
        CanaryState::NearExpiration => ("canary: near expiration", yellow),
        CanaryState::Expired => ("canary: expired", red),
        CanaryState::Invalid => ("canary: invalid", red),
        CanaryState::Unavailable => ("canary: unavailable", gray),
    }
}

fn warning_label(warning: Warning) -> &'static str {
    match warning {
        Warning::TrustMismatch => "WARNING: publisher identity changed / mismatch",
        Warning::CanaryConflict => "WARNING: canary conflict",
        Warning::CanaryExpired => "WARNING: canary expired",
        Warning::CanaryInvalid => "WARNING: canary invalid",
        Warning::CanaryGap => "WARNING: canary gap observed",
        Warning::HistoricalContent => "historical content",
        Warning::StaleCachedContent => "stale cached content",
    }
}

/// Draw a content scene: one egui element per node. egui handles pixel
/// wrapping, so the engine Scene is rendered directly without column layout.
fn draw_scene(ui: &mut egui::Ui, scene: &Scene) {
    for node in &scene.nodes {
        draw_node(ui, node);
    }
}

fn draw_node(ui: &mut egui::Ui, node: &SceneNode) {
    match node {
        SceneNode::Paragraph { runs } => {
            ui.label(runs_text(runs));
            ui.add_space(4.0);
        }
        SceneNode::Heading { level, runs } => {
            let size = match level {
                1 => 22.0,
                2 => 19.0,
                3 => 17.0,
                _ => 15.0,
            };
            ui.label(egui::RichText::new(runs_text(runs)).size(size).strong());
            ui.add_space(4.0);
        }
        SceneNode::CodeBlock { language: _, text } => {
            ui.add(egui::Label::new(egui::RichText::new(text).monospace()).wrap());
            ui.add_space(4.0);
        }
        SceneNode::Quote { runs, attribution } => {
            ui.label(egui::RichText::new(format!("\"{}\"", runs_text(runs))).italics());
            if let Some(attr) = attribution {
                ui.label(egui::RichText::new(format!("  -- {}", runs_text(attr))).small());
            }
            ui.add_space(4.0);
        }
        SceneNode::List { ordered, items } => {
            for (i, item) in items.iter().enumerate() {
                let bullet = if *ordered {
                    format!("{}. ", i + 1)
                } else {
                    "- ".to_owned()
                };
                ui.label(format!("{bullet}{}", runs_text(item)));
            }
            ui.add_space(4.0);
        }
        SceneNode::Divider => {
            ui.separator();
        }
        SceneNode::Image { image } => {
            // Images are not fetched in this tranche; show a placeholder.
            let alt = if image.alt.is_empty() {
                "image".to_owned()
            } else {
                image.alt.clone()
            };
            ui.label(egui::RichText::new(format!("[image: {alt}]")).weak());
            if let Some(caption) = &image.caption {
                ui.label(egui::RichText::new(caption).small());
            }
            ui.add_space(4.0);
        }
        SceneNode::Link { label, link: _ } => {
            ui.label(egui::RichText::new(runs_text(label)).underline());
            ui.add_space(4.0);
        }
        SceneNode::SubmitForm {
            label,
            submit_to: _,
            fields,
            submit_label,
        } => {
            ui.label(egui::RichText::new(runs_text(label)).strong());
            for field in fields {
                ui.label(format!("  {}", field_label(field)));
            }
            ui.label(format!("[{submit_label}]"));
            ui.add_space(4.0);
        }
        SceneNode::Feedback { variant: _, runs } => {
            ui.label(runs_text(runs));
            ui.add_space(4.0);
        }
        SceneNode::Note {
            variant: _,
            title,
            runs,
        } => {
            if let Some(t) = title {
                ui.label(egui::RichText::new(t).strong());
            }
            ui.label(runs_text(runs));
            ui.add_space(4.0);
        }
    }
}

/// Flatten inline runs to plain text. Inline styling/marks are not applied in
/// this first shell; a later tranche maps marks to egui text styling.
fn runs_text(runs: &[InlineRun]) -> String {
    let mut s = String::new();
    for run in runs {
        match run {
            InlineRun::Text { text, .. } => s.push_str(text),
            InlineRun::Link { text, .. } => s.push_str(text),
        }
    }
    s
}

fn field_label(field: &entangled_engine::FormFieldView) -> String {
    use entangled_engine::FormFieldView as F;
    let (kind, label) = match field {
        F::Text { label, .. } => ("text", label),
        F::Textarea { label, .. } => ("textarea", label),
        F::Select { label, .. } => ("select", label),
        F::Checkbox { label, .. } => ("checkbox", label),
    };
    format!("[{kind}] {label}")
}
