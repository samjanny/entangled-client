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
        Box::new(|_cc| Ok(Box::new(App::new(loaded)))),
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
    /// When set, the external-link handoff dialog is open for this URL.
    handoff: Option<String>,
}

impl App {
    fn new(loaded: Loaded) -> App {
        App {
            loaded,
            handoff: None,
        }
    }
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
        // egui's default text is small on modern displays; scale everything up
        // a touch for comfortable reading. Set once per frame (idempotent).
        ctx.set_zoom_factor(1.1);

        // Chrome: a client-controlled top panel, structurally separate from the
        // content area below. Its distinct frame makes the boundary visible.
        // Publisher content never draws here.
        egui::TopBottomPanel::top("chrome")
            .frame(chrome_frame())
            .show(ctx, |ui| {
                draw_chrome(ui, &self.loaded.chrome);
            });

        // A click on an external link this frame requests the handoff dialog.
        let mut requested: Option<String> = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Constrain content to a readable column rather than the full
                // window width, and give it breathing room.
                ui.add_space(16.0);
                let max_width = 720.0_f32.min(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add_space(((ui.available_width() - max_width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_max_width(max_width);
                        match &self.loaded.scene {
                            Some(scene) => draw_scene(ui, scene, &mut requested),
                            None => {
                                ui.label("(manifest only - no content document loaded)");
                            }
                        }
                    });
                });
            });
        });
        if let Some(url) = requested {
            self.handoff = Some(url);
        }

        self.show_handoff(ctx);
    }
}

impl App {
    /// The external-link handoff dialog (section 03): the client must not
    /// navigate automatically to a citation/carrier URL. When the user clicks
    /// such a link, show the full URL and the trust-boundary notice, and offer
    /// only an explicit copy-to-clipboard (this viewer never opens a browser).
    fn show_handoff(&mut self, ctx: &egui::Context) {
        let Some(url) = self.handoff.clone() else {
            return;
        };
        let mut open = true;
        let mut close = false;
        egui::Window::new("Open external link?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(
                    egui::RichText::new(
                        "This link leaves Entangled for the clearnet. Opening or copying it \
                         transmits the URL outside the carrier; the destination and any in-path \
                         observer may learn it was reached from here.",
                    )
                    .color(egui::Color32::from_rgb(0xD0, 0xA0, 0x30)),
                );
                ui.add_space(8.0);
                ui.label(egui::RichText::new(&url).monospace());
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Copy URL").clicked() {
                        ui.ctx().copy_text(url.clone());
                        close = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if close || !open {
            self.handoff = None;
        }
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
    ui.add_space(10.0);

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
/// A click on an external (citation/carrier) link sets `handoff` to its URL.
fn draw_scene(ui: &mut egui::Ui, scene: &Scene, handoff: &mut Option<String>) {
    for node in &scene.nodes {
        draw_node(ui, node, handoff);
    }
}

fn draw_node(ui: &mut egui::Ui, node: &SceneNode, handoff: &mut Option<String>) {
    // Comfortable typographic constants for the content column.
    const BODY: f32 = 15.0;
    let body_color = egui::Color32::from_rgb(0xCC, 0xD2, 0xDA);
    let muted = egui::Color32::from_rgb(0x90, 0x98, 0xA4);

    match node {
        SceneNode::Paragraph { runs } => {
            ui.label(runs_job(runs, BODY, body_color));
            ui.add_space(12.0);
        }
        SceneNode::Heading { level, runs } => {
            // Extra space above a heading to separate it from the prior block.
            ui.add_space(10.0);
            let size = match level {
                1 => 26.0,
                2 => 21.0,
                3 => 18.0,
                _ => 16.0,
            };
            let heading_color = egui::Color32::from_rgb(0xF0, 0xF2, 0xF5);
            ui.label(runs_job(runs, size, heading_color));
            ui.add_space(8.0);
        }
        SceneNode::CodeBlock { language: _, text } => {
            // A subtly boxed monospace block.
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(0x16, 0x1a, 0x20))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(text)
                                .monospace()
                                .size(BODY - 1.0)
                                .color(body_color),
                        )
                        .wrap(),
                    );
                });
            ui.add_space(12.0);
        }
        SceneNode::Quote { runs, attribution } => {
            // Italic quote with a muted left context.
            let mut job = runs_job(runs, BODY, muted);
            // Mark the whole quote italic by re-rendering: simplest is to set
            // italics per section, which runs_job already does for marks; here
            // we add the surrounding quotation marks via plain runs.
            job.sections
                .iter_mut()
                .for_each(|s| s.format.italics = true);
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(job);
            });
            if let Some(attr) = attribution {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(format!("-- {}", runs_text(attr)))
                            .size(BODY - 2.0)
                            .color(muted),
                    );
                });
            }
            ui.add_space(12.0);
        }
        SceneNode::List { ordered, items } => {
            for (i, item) in items.iter().enumerate() {
                let bullet = if *ordered {
                    format!("{}.", i + 1)
                } else {
                    "\u{2022}".to_owned()
                };
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(bullet).size(BODY).color(muted));
                    ui.label(runs_job(item, BODY, body_color));
                });
                ui.add_space(4.0);
            }
            ui.add_space(10.0);
        }
        SceneNode::Divider => {
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(8.0);
        }
        SceneNode::Image { image } => {
            // Images are not fetched in this tranche; show a placeholder.
            let alt = if image.alt.is_empty() {
                "image".to_owned()
            } else {
                image.alt.clone()
            };
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(0x16, 0x1a, 0x20))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(format!("[image: {alt}]")).color(muted));
                    if let Some(caption) = &image.caption {
                        ui.label(egui::RichText::new(caption).size(BODY - 2.0).color(muted));
                    }
                });
            ui.add_space(12.0);
        }
        SceneNode::Link { label, link } => {
            let mut job = runs_job(label, BODY, egui::Color32::from_rgb(0x6c, 0xa8, 0xff));
            job.sections
                .iter_mut()
                .for_each(|s| s.format.underline = egui::Stroke::new(1.0, s.format.color));
            match external_url(link) {
                // Citation/carrier links are clickable but never auto-navigate:
                // a click requests the handoff dialog (section 03).
                Some(url) => {
                    if ui
                        .add(egui::Label::new(job).sense(egui::Sense::click()))
                        .clicked()
                    {
                        *handoff = Some(url);
                    }
                }
                // Same-site / entangled links are internal navigation, out of
                // scope for this read-only tranche: shown inert.
                None => {
                    ui.label(job);
                }
            }
            ui.add_space(12.0);
        }
        SceneNode::SubmitForm {
            label,
            submit_to: _,
            fields,
            submit_label,
        } => {
            ui.label(runs_job(
                label,
                BODY + 1.0,
                egui::Color32::from_rgb(0xF0, 0xF2, 0xF5),
            ));
            ui.add_space(4.0);
            for field in fields {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(field_label(field))
                            .size(BODY)
                            .color(muted),
                    );
                });
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("[ {submit_label} ]"))
                    .size(BODY)
                    .color(body_color),
            );
            ui.add_space(12.0);
        }
        SceneNode::Feedback { variant: _, runs } => {
            ui.label(runs_job(runs, BODY, body_color));
            ui.add_space(12.0);
        }
        SceneNode::Note {
            variant: _,
            title,
            runs,
        } => {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(0x18, 0x20, 0x18))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    if let Some(t) = title {
                        ui.label(
                            egui::RichText::new(t)
                                .size(BODY)
                                .strong()
                                .color(egui::Color32::from_rgb(0xF0, 0xF2, 0xF5)),
                        );
                    }
                    ui.label(runs_job(runs, BODY, body_color));
                });
            ui.add_space(12.0);
        }
    }
}

/// Build a styled `LayoutJob` from inline runs: each run's marks become real
/// egui text formatting (italics, monospace for code, strikethrough), bold is
/// rendered as a brighter color since egui has no built-in bold weight without
/// a bold font. Links carry a distinct color. `base_size`/`base_color` are the
/// defaults for unmarked text.
fn runs_job(
    runs: &[InlineRun],
    base_size: f32,
    base_color: egui::Color32,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    for run in runs {
        let (text, style, is_link) = match run {
            InlineRun::Text { text, style } => (text, style, false),
            InlineRun::Link { text, style, .. } => (text, style, true),
        };
        let family = if style.code {
            egui::FontFamily::Monospace
        } else {
            egui::FontFamily::Proportional
        };
        let mut color = if is_link {
            egui::Color32::from_rgb(0x6c, 0xa8, 0xff)
        } else {
            base_color
        };
        // egui has no bold weight without a bold font; approximate with a
        // brighter color so bold runs are visibly distinct.
        if style.bold {
            color = egui::Color32::from_rgb(0xFF, 0xFF, 0xFF);
        }
        let mut fmt = egui::TextFormat {
            font_id: egui::FontId::new(base_size, family),
            color,
            italics: style.italic,
            line_height: Some(base_size * 1.4),
            ..Default::default()
        };
        if style.strikethrough {
            fmt.strikethrough = egui::Stroke::new(1.0, color);
        }
        if is_link {
            fmt.underline = egui::Stroke::new(1.0, color);
        }
        job.append(text, 0.0, fmt);
    }
    job
}

/// Flatten inline runs to plain text (used where styling is not needed, e.g.
/// the quote attribution line).
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

/// The clearnet/carrier URL of an external link, or `None` for an internal
/// (same-site / entangled) target. Only external targets get the handoff
/// dialog; internal navigation is out of scope for this read-only tranche.
fn external_url(link: &entangled_engine::LinkRef) -> Option<String> {
    use entangled_engine::LinkRef as L;
    match link {
        L::Citation { url } | L::Carrier { url, .. } => Some(url.clone()),
        L::SameSite { .. } | L::Entangled { .. } => None,
    }
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
