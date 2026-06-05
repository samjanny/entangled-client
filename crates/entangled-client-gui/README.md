# entangled-client-gui

The egui shell for the Entangled v1.0 client. It loads a verified manifest (and
optional content document) and draws the content (the engine `Scene`) and the
chrome (`ChromeView`: trust state, canary state, the PIP, warnings) in a window.

This is a **read-only viewer** for now: there is no retained identity,
persistence, or pinning prompt yet, so the trust state is always First contact.
It is honest in chrome that it is a viewer, not yet a conforming client.

All verification and the chrome model live in the pure `entangled-client` and
`entangled-engine` crates; this crate is the thin eframe/egui shell over them
(the pure `load` in the lib, the window in the binary).

See the [workspace README](../../README.md) for the full picture and roadmap.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.
