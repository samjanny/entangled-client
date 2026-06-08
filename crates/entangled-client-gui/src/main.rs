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

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 680.0]),
        ..Default::default()
    };
    match eframe::run_native(
        "entangled-client",
        options,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            install_theme(&cc.egui_ctx);
            Ok(Box::new(App::new(loaded)))
        }),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A named font family for bold runs (egui's built-in families are only
/// Proportional and Monospace; we register a third for the bold weight).
fn bold_family() -> egui::FontFamily {
    egui::FontFamily::Name("bold".into())
}

/// Install the embedded DejaVu fonts: DejaVu Sans as the proportional default,
/// DejaVu Sans Mono as the monospace family, and DejaVu Sans Bold under a named
/// "bold" family so bold runs render with a real bold weight.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "dejavu".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/DejaVuSans.ttf")),
    );
    fonts.font_data.insert(
        "dejavu-bold".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/DejaVuSans-Bold.ttf")),
    );
    fonts.font_data.insert(
        "dejavu-mono".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/DejaVuSansMono.ttf")),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "dejavu".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "dejavu-mono".to_owned());
    fonts
        .families
        .insert(bold_family(), vec!["dejavu-bold".to_owned()]);
    ctx.set_fonts(fonts);
}

/// Tune egui visuals: a coherent dark palette, comfortable text sizes, and
/// rounded widgets, so the shell reads as an intentional app rather than the
/// default debug-UI look.
fn install_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    use egui::{FontFamily, FontId, TextStyle};
    style.text_styles = [
        (
            TextStyle::Heading,
            FontId::new(22.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
        (
            TextStyle::Monospace,
            FontId::new(14.0, FontFamily::Monospace),
        ),
        (
            TextStyle::Button,
            FontId::new(15.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
    ]
    .into();

    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(0x12, 0x15, 0x1a);
    v.widgets.noninteractive.rounding = 6.0.into();
    v.widgets.inactive.rounding = 6.0.into();
    v.widgets.hovered.rounding = 6.0.into();
    v.widgets.active.rounding = 6.0.into();
    v.window_rounding = 8.0.into();
    v.hyperlink_color = egui::Color32::from_rgb(0x6c, 0xa8, 0xff);
    v.selection.bg_fill = egui::Color32::from_rgb(0x2a, 0x40, 0x60);
    style.visuals = v;

    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);

    ctx.set_style(style);
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
    // A real client supplies wall-clock time; this viewer uses a fixed instant
    // so the load is deterministic. (A later tranche wires a real clock.)
    let clock = FixedClock(
        EntangledTimestamp::try_from("2026-06-05T00:00:00Z").expect("valid fixed timestamp"),
    );
    // Show the full onion address in chrome (there is room horizontally).
    load(
        &manifest_bytes,
        content_bytes.as_deref(),
        &address,
        onion.to_owned(),
        &clock,
    )
    .map_err(|e| e.to_string())
}

/// Which external link kind a handoff is for. The two carry different
/// trust-boundary semantics (section 03), so the handoff dialog must not show
/// the same notice for both: a `carrier` destination is outside Entangled but
/// still reached over the carrier (Tor), while a `citation` destination is on
/// the clearnet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HandoffKind {
    /// A `carrier` target: reached over the carrier, not the clearnet (§03:593).
    Carrier,
    /// A `citation` target: a clearnet reference (§03:621).
    Citation,
}

/// A pending external-link handoff: the destination URL and which kind of
/// external target it is.
#[derive(Clone)]
struct Handoff {
    url: String,
    kind: HandoffKind,
}

struct App {
    loaded: Loaded,
    /// When set, the external-link handoff dialog is open for this target.
    handoff: Option<Handoff>,
    /// Per-session override of the Expired-canary render-block (§08:185). Starts
    /// `false`; set only by an affirmative user click. It applies for the rest
    /// of this session for this site, does not persist, does not modify the
    /// canary state, and does not suppress the chrome warning.
    canary_override: bool,
}

impl App {
    fn new(loaded: Loaded) -> App {
        App {
            loaded,
            handoff: None,
            canary_override: false,
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
        // Chrome: a client-controlled top panel, structurally separate from the
        // content area below. Its distinct frame makes the boundary visible.
        // Publisher content never draws here.
        egui::TopBottomPanel::top("chrome")
            .frame(chrome_frame())
            .show(ctx, |ui| {
                draw_chrome(ui, &self.loaded.chrome);
            });

        // A click on an external link this frame requests the handoff dialog.
        let mut requested: Option<Handoff> = None;
        // An Expired canary blocks rendering of publisher content by default
        // (§08:185 / §10:211): the content area must be blank or a client-
        // generated placeholder until the user invokes the per-session
        // override. A click on the override control this frame is recorded.
        let canary_expired = self.loaded.chrome.canary_state == CanaryState::Expired;
        let render_blocked = render_block_active(canary_expired, self.canary_override);
        let mut override_clicked = false;
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
                        if render_blocked {
                            // Client-generated placeholder in place of the
                            // publisher scene; publisher content MUST NOT appear.
                            override_clicked = draw_canary_block(ui);
                        } else {
                            // When rendering under an active override, a
                            // persistent notice sits above the content (the
                            // override does not suppress the warning, §08:185).
                            if canary_expired && self.canary_override {
                                draw_override_active_notice(ui);
                            }
                            match &self.loaded.scene {
                                Some(scene) => draw_scene(ui, scene, &mut requested),
                                None => {
                                    ui.label("(manifest only - no content document loaded)");
                                }
                            }
                        }
                    });
                });
            });
        });
        if override_clicked {
            self.canary_override = true;
        }
        if let Some(target) = requested {
            self.handoff = Some(target);
        }

        self.show_handoff(ctx);
    }
}

impl App {
    /// The external-link handoff dialog (section 03): the client must not
    /// navigate automatically to a citation/carrier URL. When the user clicks
    /// such a link, show the full URL and the trust-boundary notice, and offer
    /// only an explicit copy-to-clipboard (this viewer never opens a browser).
    ///
    /// Carrier and citation are NOT the same boundary (§03:593 vs §03:621): a
    /// `carrier` destination is outside Entangled but still reached over the
    /// carrier (Tor) - it is not exposed to the clearnet - whereas a `citation`
    /// is a clearnet reference. The notice text branches on the kind so the
    /// dialog never tells the user a carrier-onion link "leaves for the
    /// clearnet."
    fn show_handoff(&mut self, ctx: &egui::Context) {
        let Some(target) = self.handoff.clone() else {
            return;
        };
        let url = target.url;
        let (title, notice) = match target.kind {
            HandoffKind::Carrier => (
                "Open carrier link?",
                "This link points outside Entangled to a service reachable over the carrier \
                 (Tor), not the clearnet. It is not auto-opened: copying it lets you open it in \
                 a carrier-aware browser (such as Tor Browser). Do not open it in a browser that \
                 would resolve the host over public DNS or the clearnet, which would leak the \
                 request and defeat the carrier's confidentiality.",
            ),
            HandoffKind::Citation => (
                "Open clearnet link?",
                "This link leaves Entangled for the clearnet. Opening or copying it transmits the \
                 URL outside the carrier; the destination and any in-path observer on the clearnet \
                 may learn it was reached from here.",
            ),
        };
        let mut open = true;
        let mut close = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                // Caution glyph + the trust-boundary notice, in the chrome's
                // caution tone so the warning reads consistently with the bar.
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.label(
                        egui::RichText::new("\u{26A0}")
                            .size(16.0)
                            .color(Severity::Caution.accent()),
                    );
                    ui.label(
                        egui::RichText::new(notice)
                            .color(egui::Color32::from_rgb(0xE6, 0xCF, 0x9a)),
                    );
                });
                ui.add_space(10.0);
                // The URL in a bordered monospace chip, matching the address
                // chip in the chrome so it reads as the same kind of element.
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x15, 0x1a, 0x22))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(10.0, 7.0))
                    .stroke(egui::Stroke::new(
                        1.0,
                        egui::Color32::from_rgb(0x2c, 0x34, 0x42),
                    ))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(&url)
                                .monospace()
                                .color(egui::Color32::from_rgb(0x9a, 0xB0, 0xC8)),
                        );
                    });
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().button_padding = egui::vec2(12.0, 6.0);
                    if ui
                        .button(egui::RichText::new("Copy URL").strong())
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        ui.ctx().copy_text(url.clone());
                        close = true;
                    }
                    if ui
                        .button("Cancel")
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        close = true;
                    }
                });
            });
        if close || !open {
            self.handoff = None;
        }
    }
}

/// A semantic severity, driving badge colors consistently across the chrome.
#[derive(Clone, Copy)]
enum Severity {
    Good,
    Caution,
    Alert,
    Neutral,
}

impl Severity {
    /// (foreground text, background fill) for a filled pill at this severity.
    fn pill_colors(self) -> (egui::Color32, egui::Color32) {
        match self {
            // Bright, legible text over a deep tint of the same hue.
            Severity::Good => (
                egui::Color32::from_rgb(0xB6, 0xF0, 0xC4),
                egui::Color32::from_rgb(0x1c, 0x3a, 0x28),
            ),
            Severity::Caution => (
                egui::Color32::from_rgb(0xF2, 0xDC, 0xA0),
                egui::Color32::from_rgb(0x3c, 0x30, 0x12),
            ),
            Severity::Alert => (
                egui::Color32::from_rgb(0xF6, 0xC0, 0xC0),
                egui::Color32::from_rgb(0x40, 0x1c, 0x1c),
            ),
            Severity::Neutral => (
                egui::Color32::from_rgb(0xC4, 0xCC, 0xD6),
                egui::Color32::from_rgb(0x24, 0x2b, 0x36),
            ),
        }
    }

    /// The accent (border / dot) color at this severity.
    fn accent(self) -> egui::Color32 {
        match self {
            Severity::Good => egui::Color32::from_rgb(0x4c, 0xc0, 0x6a),
            Severity::Caution => egui::Color32::from_rgb(0xd0, 0xa0, 0x30),
            Severity::Alert => egui::Color32::from_rgb(0xe0, 0x50, 0x50),
            Severity::Neutral => egui::Color32::from_rgb(0x90, 0x98, 0xa4),
        }
    }
}

/// Draw a filled status pill: a colored dot, a small uppercase category label,
/// and the value, all on a rounded tinted background. Returns the response so
/// callers can lay several out in a row.
fn status_pill(
    ui: &mut egui::Ui,
    category: &str,
    value: &str,
    severity: Severity,
) -> egui::Response {
    let (fg, bg) = severity.pill_colors();
    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(999.0)) // fully rounded -> pill
        .inner_margin(egui::Margin::symmetric(10.0, 5.0))
        .stroke(egui::Stroke::new(1.0, severity.accent().gamma_multiply(0.5)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                // Status dot.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(
                    rect.center(),
                    4.0,
                    severity.accent(),
                );
                ui.label(
                    egui::RichText::new(category.to_ascii_uppercase())
                        .size(10.5)
                        .strong()
                        .color(fg.gamma_multiply(0.8)),
                );
                ui.label(egui::RichText::new(value).size(13.0).strong().color(fg));
            });
        })
        .response
}

/// Draw the always-visible chrome indicators and any conditional warnings: an
/// honesty strip, a row of status pills (trust, canary, and request state),
/// a monospace address chip, the PIP identity section, and warning banners.
/// Publisher content never draws here (section 10 chrome separation).
fn draw_chrome(ui: &mut egui::Ui, chrome: &ChromeView) {
    // Honesty strip: still present, but smaller and muted - it's a disclaimer,
    // not the headline.
    ui.label(
        egui::RichText::new(NOT_A_CLIENT)
            .size(11.0)
            .color(egui::Color32::from_rgb(0x8a, 0x7a, 0x40)),
    );
    ui.add_space(8.0);

    // Status row: trust and canary as filled pills, address as a mono chip,
    // request-state as a trailing pill when active. Wraps on narrow windows.
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);

        let (tlabel, tsev) = trust_badge(chrome.trust_state);
        status_pill(ui, "trust", tlabel, tsev);

        let (clabel, csev) = canary_badge(chrome.canary_state);
        status_pill(ui, "canary", clabel, csev);

        // Address chip: monospace, in its own subtly bordered rounded box.
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(0x15, 0x1a, 0x22))
            .rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::symmetric(10.0, 5.0))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(0x2c, 0x34, 0x42),
            ))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(&chrome.carrier_address_compact)
                        .monospace()
                        .size(12.5)
                        .color(egui::Color32::from_rgb(0x9a, 0xB0, 0xC8)),
                );
            });

        if chrome.request_state_active {
            status_pill(ui, "request", "active", Severity::Caution);
        }
    });

    ui.add_space(10.0);

    // PIP card: the identity anchor, always in a prominent bordered card with a
    // left accent bar. When it must be fully shown, the words are visible; when
    // it may be collapsed, a disclosure toggles them - but the card framing is
    // the same so the identity always reads as a first-class element.
    draw_pip_card(ui, chrome);

    // Warning banners: each warning as a full-width tinted banner with an icon
    // glyph, far more legible than a red text line.
    if !chrome.warnings.is_empty() {
        ui.add_space(10.0);
    }
    for warning in &chrome.warnings {
        draw_warning_banner(ui, *warning);
        ui.add_space(6.0);
    }
}

/// The PIP identity section. Rather than a floating rounded card (which reads
/// as a widget nested inside the chrome bar), this is a flush section of the
/// chrome itself: separated by a top divider line, with a short accent tick at
/// the left to anchor it as the identity element. No perimeter box, so it sits
/// as part of the bar, not on top of it.
fn draw_pip_card(ui: &mut egui::Ui, chrome: &ChromeView) {
    let pip_label = format!("{} (PIP)", chrome.pip_label);
    let accent = egui::Color32::from_rgb(0x6c, 0xa8, 0xff);

    // Top separator: a full-width hairline marking where the status row ends
    // and the identity section begins.
    let sep_y = ui.cursor().top();
    let (left, right) = (ui.max_rect().left(), ui.max_rect().right());
    ui.painter().line_segment(
        [egui::pos2(left, sep_y), egui::pos2(right, sep_y)],
        egui::Stroke::new(1.0, egui::Color32::from_rgb(0x2c, 0x34, 0x42)),
    );
    ui.add_space(8.0);

    // Label row, prefixed by a short accent tick (a 3px bar the height of the
    // label) so the identity reads as a first-class, client-owned element.
    ui.horizontal(|ui| {
        let (tick, _) = ui.allocate_exact_size(egui::vec2(3.0, 14.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(tick, egui::Rounding::same(1.5), accent);
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(&pip_label)
                .size(11.0)
                .strong()
                .color(egui::Color32::from_rgb(0x9a, 0xB6, 0xD8)),
        );
        ui.label(
            egui::RichText::new("- compare these words out of band")
                .size(11.0)
                .italics()
                .color(egui::Color32::from_rgb(0x6c, 0x78, 0x88)),
        );
    });
    ui.add_space(6.0);

    let pip_text = || {
        egui::RichText::new(&chrome.pip)
            .monospace()
            .size(15.0)
            .color(egui::Color32::from_rgb(0xE8, 0xEC, 0xF2))
    };
    if chrome.pip_must_be_fully_shown {
        ui.label(pip_text());
    } else {
        ui.collapsing("show identity phrase", |ui| {
            ui.label(pip_text());
        });
    }
}

/// A full-width warning banner: an alert-tinted rounded bar with a glyph and
/// the warning text. Historical/stale notes use the gentler caution tone.
fn draw_warning_banner(ui: &mut egui::Ui, warning: Warning) {
    let (glyph, text, severity) = match warning {
        Warning::TrustMismatch => (
            "\u{26A0}",
            "Publisher identity changed / mismatch",
            Severity::Alert,
        ),
        Warning::CanaryConflict => ("\u{26A0}", "Canary conflict", Severity::Alert),
        Warning::CanaryExpired => ("\u{26A0}", "Canary expired", Severity::Alert),
        Warning::CanaryInvalid => ("\u{26A0}", "Canary invalid", Severity::Alert),
        Warning::CanaryGap => ("\u{26A0}", "Canary gap observed", Severity::Caution),
        Warning::HistoricalContent => ("\u{1F552}", "Historical content", Severity::Caution),
        Warning::StaleCachedContent => ("\u{1F552}", "Stale cached content", Severity::Caution),
    };
    let (fg, bg) = severity.pill_colors();
    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(10.0, 7.0))
        .stroke(egui::Stroke::new(1.0, severity.accent().gamma_multiply(0.6)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(egui::RichText::new(glyph).size(14.0).color(severity.accent()));
                ui.label(egui::RichText::new(text).size(13.0).strong().color(fg));
            });
        });
}

/// Trust state as a short pill value and severity (parallels `trust_label`).
fn trust_badge(state: TrustState) -> (&'static str, Severity) {
    match state {
        TrustState::ExternallyVerified => ("externally verified", Severity::Good),
        TrustState::TofuPinned => ("TOFU pinned", Severity::Good),
        TrustState::FirstContact => ("first contact", Severity::Caution),
        TrustState::ChangedMismatch => ("CHANGED / MISMATCH", Severity::Alert),
    }
}

/// Canary state as a short pill value and severity (parallels `canary_label`).
fn canary_badge(state: CanaryState) -> (&'static str, Severity) {
    match state {
        CanaryState::Fresh => ("fresh", Severity::Good),
        CanaryState::NearExpiration => ("near expiration", Severity::Caution),
        CanaryState::Expired => ("expired", Severity::Alert),
        CanaryState::Invalid => ("invalid", Severity::Alert),
        CanaryState::Unavailable => ("unavailable", Severity::Neutral),
    }
}

/// Whether the publisher content area must be blocked this frame: true exactly
/// when the canary is Expired and the user has not invoked the per-session
/// override (§08:185 / §10:211). Pure, so the gating is unit-testable without a
/// window.
fn render_block_active(canary_expired: bool, override_active: bool) -> bool {
    canary_expired && !override_active
}

/// The Expired-canary render-block placeholder shown in place of publisher
/// content (§08:185 / §10:211). Publisher content MUST NOT appear here. Renders
/// a client-generated explanation and an affirmative per-session override
/// control; returns `true` on the frame the user clicks the override (a passive
/// event never counts as acceptance - only this button click does).
fn draw_canary_block(ui: &mut egui::Ui) -> bool {
    ui.add_space(24.0);
    let mut clicked = false;
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(0x20, 0x18, 0x14))
        .rounding(egui::Rounding::same(8.0))
        .stroke(egui::Stroke::new(1.0, Severity::Alert.accent().gamma_multiply(0.6)))
        .inner_margin(egui::Margin::same(16.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(
                    egui::RichText::new("\u{26A0}")
                        .size(18.0)
                        .color(Severity::Alert.accent()),
                );
                ui.label(
                    egui::RichText::new("Content blocked: the publisher's canary has expired")
                        .size(16.0)
                        .strong()
                        .color(egui::Color32::from_rgb(0xF0, 0xE0, 0xD8)),
                );
            });
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "The publisher missed a committed canary refresh. The content is not shown as \
                     current because an expired canary can signal an operational pause or a \
                     compromise. You may proceed for this session only.",
                )
                .color(egui::Color32::from_rgb(0xD0, 0xC0, 0xB8)),
            );
            ui.add_space(12.0);
            if ui
                .button(
                    egui::RichText::new("Show content for this session")
                        .strong()
                        .color(egui::Color32::from_rgb(0xF0, 0xE0, 0xD8)),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                clicked = true;
            }
        });
    clicked
}

/// The persistent, not-easily-dismissible notice shown above content while the
/// Expired-canary render-block is active by user override (§08:185). The
/// override does not suppress this warning.
fn draw_override_active_notice(ui: &mut egui::Ui) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(0x3c, 0x30, 0x12))
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(10.0, 7.0))
        .stroke(egui::Stroke::new(1.0, Severity::Caution.accent().gamma_multiply(0.6)))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(
                    egui::RichText::new("\u{26A0}")
                        .size(14.0)
                        .color(Severity::Caution.accent()),
                );
                ui.label(
                    egui::RichText::new(
                        "Expired-canary content is shown by your override for this session.",
                    )
                    .size(13.0)
                    .strong()
                    .color(egui::Color32::from_rgb(0xF2, 0xDC, 0xA0)),
                );
            });
        });
    ui.add_space(12.0);
}

/// Draw a content scene: one egui element per node. egui handles pixel
/// wrapping, so the engine Scene is rendered directly without column layout.
/// A click on an external (citation/carrier) link sets `handoff` to its target.
fn draw_scene(ui: &mut egui::Ui, scene: &Scene, handoff: &mut Option<Handoff>) {
    for node in &scene.nodes {
        draw_node(ui, node, handoff);
    }
}

fn draw_node(ui: &mut egui::Ui, node: &SceneNode, handoff: &mut Option<Handoff>) {
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
            // A subtly boxed monospace block, stretched to the full content
            // column width (left/right edges aligned with paragraphs) rather
            // than shrink-wrapped to the longest line.
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(0x16, 0x1a, 0x20))
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    // Force the inner ui to occupy the whole available width so
                    // the frame spans the column.
                    ui.set_min_width(ui.available_width());
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
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    // Span the full content column, like the code block.
                    ui.set_min_width(ui.available_width());
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
            match external_handoff(link) {
                // Citation/carrier links are clickable but never auto-navigate:
                // a click requests the handoff dialog (section 03). Carrier and
                // citation are displayed distinctly (§03:593, §03:621) via a
                // trailing class tag, so the user can tell a carrier-reachable
                // destination from a clearnet one before opening the handoff.
                Some(target) => {
                    let tag = match target.kind {
                        HandoffKind::Carrier => " [carrier \u{2197}]",
                        HandoffKind::Citation => " [clearnet \u{2197}]",
                    };
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let clicked = ui
                            .add(egui::Label::new(job).sense(egui::Sense::click()))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked();
                        let tag_clicked = ui
                            .add(
                                egui::Label::new(
                                    egui::RichText::new(tag)
                                        .size(BODY - 2.0)
                                        .color(muted),
                                )
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked();
                        if clicked || tag_clicked {
                            *handoff = Some(target);
                        }
                    });
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
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    // Span the full content column, like the code block.
                    ui.set_min_width(ui.available_width());
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
        // Code is monospace; bold (when not code) uses the real bold family;
        // everything else is the proportional default. The run keeps its real
        // color in every case.
        let family = if style.code {
            egui::FontFamily::Monospace
        } else if style.bold {
            bold_family()
        } else {
            egui::FontFamily::Proportional
        };
        let color = if is_link {
            egui::Color32::from_rgb(0x6c, 0xa8, 0xff)
        } else {
            base_color
        };
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

/// The external-handoff target of a link, or `None` for an internal (same-site
/// / entangled) target. Carrier and citation are kept distinct so the renderer
/// and the handoff dialog can present their different trust boundaries (§03:593
/// vs §03:621); only external targets get the handoff dialog, since internal
/// navigation is out of scope for this read-only tranche.
fn external_handoff(link: &entangled_engine::LinkRef) -> Option<Handoff> {
    use entangled_engine::LinkRef as L;
    match link {
        L::Carrier { url, .. } => Some(Handoff {
            url: url.clone(),
            kind: HandoffKind::Carrier,
        }),
        L::Citation { url } => Some(Handoff {
            url: url.clone(),
            kind: HandoffKind::Citation,
        }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use entangled_engine::LinkRef;

    // --- H-1: Expired-canary render-block gating (§08:185 / §10:211) ---

    #[test]
    fn non_expired_canary_never_blocks() {
        // Whatever the override flag, a non-Expired canary renders content.
        assert!(!render_block_active(false, false));
        assert!(!render_block_active(false, true));
    }

    #[test]
    fn expired_canary_blocks_until_override() {
        // Expired blocks by default...
        assert!(render_block_active(true, false));
        // ...and only an active per-session override unblocks it.
        assert!(!render_block_active(true, true));
    }

    // --- M-3: carrier vs citation handoff classification (§03:593 / §03:621) ---

    #[test]
    fn carrier_link_is_a_carrier_handoff() {
        let link = LinkRef::Carrier {
            carrier: entangled_core::types::Carrier::TorV3,
            url: "http://example.onion/x".to_owned(),
        };
        let h = external_handoff(&link).expect("carrier is an external handoff");
        assert_eq!(h.kind, HandoffKind::Carrier);
        assert_eq!(h.url, "http://example.onion/x");
    }

    #[test]
    fn citation_link_is_a_citation_handoff() {
        let link = LinkRef::Citation {
            url: "https://example.org/ref".to_owned(),
        };
        let h = external_handoff(&link).expect("citation is an external handoff");
        assert_eq!(h.kind, HandoffKind::Citation);
    }

    #[test]
    fn internal_links_have_no_handoff() {
        // Same-site is internal navigation, never an external handoff.
        let link = LinkRef::SameSite {
            path: entangled_core::types::EntangledPath::try_from("/x").expect("path"),
        };
        assert!(external_handoff(&link).is_none());
    }
}
