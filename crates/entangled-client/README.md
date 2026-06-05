# entangled-client

The conforming-client brain for the Entangled v1.0 protocol: a **pure**,
golden-testable orchestration layer over [`entangled-core`](https://github.com/samjanny/entangled-api).
It performs no I/O and pulls in no UI toolkit; the impure parts (transport,
persistence, decoding, the clock) are traits a shell implements.

See the [workspace README](../../README.md) for the full picture and roadmap.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.
