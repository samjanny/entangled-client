# entangled-client

[![CI](https://github.com/samjanny/entangled-client/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/entangled-client/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-orange.svg)](#building)

A conforming-client implementation for the Entangled v1.0 protocol, built toward
a full section 10 client with an eventual egui GUI.

The protocol specification lives at [github.com/samjanny/entangled](https://github.com/samjanny/entangled).

## Why this exists

[`entangled-core`](https://github.com/samjanny/entangled-api) is a verifier: it
covers per-document validation and signature verification and deliberately stops
there. The section 10 *client* concerns - the validation-pipeline ordering, the
Stage 7 trust-state machine (TOFU pinning, externally-verified identity,
Changed/mismatch detection), publisher-history persistence, consent, transport
over a carrier such as Tor, and image fetch/decode - are left to an embedding
client. This repository is that client.

## Architecture

The repository is a cargo workspace. The discipline mirrors the rest of the
Entangled crate family: a **pure, golden-testable brain** plus a **thin I/O /
toolkit shell**, so the security-critical logic is verified on data, not pixels.

```
entangled-core      entangled-engine        entangled-client (this repo)
verifier primitives  Scene IR + lowering  -> pure brain + (later) egui shell
```

- `crates/entangled-client` - the pure brain. The section 10 validation-pipeline
  driver and the I/O seams (traits) a shell implements. No I/O, no toolkit,
  `#![forbid(unsafe_code)]`.
- `crates/entangled-client-gui` *(later tranche)* - the eframe/egui shell that
  implements the traits and renders the chrome and content.
- `crates/entangled-transport-tor` *(later tranche)* - the Tor transport behind
  the client's `Transport` trait.

## Roadmap

Built in tranches, each a shippable increment toward full section 10 conformance:

1. **Pipeline driver** (this tranche): sequence the core's verification chain in
   section 10 order; report a structured outcome under section 11 error
   precedence. Pure, no I/O.
2. Anti-downgrade / canary-conflict / runtime-rotation history.
3. Stage 7 trust-state machine + PIP + chrome model; the egui shell.
4. Images (hash-verify-before-decode, media-type allowlist, pixel budget).
5. Transport (Tor) behind the `Transport` trait.
6. Forms and submit.
7. State and consent (section 07).
8. Historical content, origin migration, reduced modes; full section 10 audit.

Transport (Tor), filesystem persistence, and image decode all sit behind traits,
so the brain stays testable without any of them.

## Security posture

A goal of this client is to be **OS-sandboxable** (seccomp-bpf, namespaces,
`bubblewrap`/`firejail`, platform sandboxes) as defence in depth: it processes
authenticated-but-potentially-hostile publisher content over a hostile network.
The architecture is built to make that practical - the pure brain performs no
I/O and touches no syscalls, and every resource access (clock, transport,
persistence, image decode) goes through a trait whose implementation lives in
the shell. The syscall surface to confine is therefore exactly the shell's trait
impls. A CI guard rejects `std::net` / `std::fs` / `SystemTime` / toolkit imports
in the brain crate so this property cannot erode.

The spec does not mandate a process sandbox; section 03 separately recommends
isolating the image decoder (hash verification authenticates bytes but does not
make decoding safe). A concrete seccomp/bubblewrap profile and decoder isolation
are documented as the shell and image tranches land.

## Building

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Requires the sibling repo `entangled-api` checked out alongside this one (the
path dependency in `Cargo.toml` assumes that layout). `entangled-engine` joins
as a sibling once the GUI member consumes the Scene IR.

## License

Dual-licensed under either of:

- MIT License
- Apache License, Version 2.0

at your option.
