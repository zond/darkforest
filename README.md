# darkforest

[![CI](https://github.com/zond/darkforest/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zond/darkforest/actions/workflows/ci.yml)

A spanning tree protocol for decentralized mesh networks, designed for bandwidth-constrained environments like LoRa.

## Crates

- **darktree** - Core protocol implementation (no_std compatible)
- **darksim** - Discrete event simulator for testing and validation

## Hardware Requirements

The protocol is designed for embedded devices with limited resources:

| Configuration | Target RAM | Node State Memory |
|--------------|------------|-------------------|
| DefaultConfig | 256KB+ | ~130 KB |
| SmallConfig | 64KB+ | ~24 KB |

See the Memory Analysis section in the [Design Document](docs/design.md) for detailed breakdown.

## Building

```bash
cargo build --all
```

## Testing

```bash
cargo test
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
