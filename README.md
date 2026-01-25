# darkforest

[![CI](https://github.com/zond/darkforest/actions/workflows/ci.yml/badge.svg)](https://github.com/zond/darkforest/actions/workflows/ci.yml)

A spanning tree protocol for decentralized mesh networks, designed for bandwidth-constrained environments like LoRa.

## Crates

- **darktree** - Core protocol implementation (no_std compatible)
- **darksim** - Discrete event simulator for testing and validation

## Building

```bash
cargo build --all
```

## Testing

Run all tests:
```bash
cargo test --all
```

Run slow/ignored tests (e.g., 100-node convergence):
```bash
cargo test --all -- --ignored
```

Check formatting and lints:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
```

## Documentation

- [Design Document](docs/design.md) - Protocol specification and architecture
- [Test Scenarios](docs/test-scenarios.md) - Comprehensive test case definitions
- [Transport Notes](docs/transport-notes.md) - UDP peer bridging for internet links

## License

MIT
