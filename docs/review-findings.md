# Codebase Review Findings

Open issues from protocol-security-architect, embedded-rust-engineer, and code-simplifier reviews.

## Critical Issues

*None remaining.*

## Completed

### Const generics for memory bounds
**Source:** Embedded reviewer (2026-01-24)
**Completed:** 2026-01-24

Implemented `NodeConfig` trait with `DefaultConfig` (256KB+ RAM) and `SmallConfig` (64KB RAM).

### Config tests incomplete
**Source:** Code simplifier (2026-01-24)
**Completed:** 2026-01-24

Expanded tests to verify all 12 config values for both DefaultConfig and SmallConfig.

### Missing MCU selection guidance
**Source:** Code simplifier (2026-01-24)
**Completed:** 2026-01-24

Added memory footprint table, MCU recommendations, and memory formulas to config.rs docs.

### pending_data lacks bounded insertion helper
**Source:** Embedded reviewer (2026-01-24)
**Completed:** 2026-01-24

Documented the implicit bound: pending_data is bounded by MAX_PENDING_LOOKUPS since entries
are only added when a lookup starts and removed when it completes or times out.

### No SmallConfig test coverage
**Source:** Code simplifier (2026-01-24)
**Completed:** 2026-01-24

Added test_small_config_eviction to verify bounded collections work correctly with SmallConfig.

### MAX_UNIQUE_PUBLISHERS not configurable
**Source:** Embedded reviewer (2026-01-24)
**Completed:** 2026-01-24

Replaced HashSet-based publisher tracking with HyperLogLog in design doc. Now uses fixed 256 bytes
regardless of network size (supports 100k+ nodes). See docs/design.md "HyperLogLog Cardinality Estimation".

### u64 division in hot paths
**Source:** Embedded reviewer (2026-01-24)
**Completed:** 2026-01-24

- Tau calculation: cached at node initialization (zero runtime divisions)
- Keyspace division: uses `FastDivisor` with reciprocal multiplication (~100-150 cycles vs ~800-1200 cycles)

## Low Priority / Future Work

*None remaining.*
