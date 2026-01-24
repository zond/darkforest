# Codebase Review Findings

Open issues from protocol-security-architect, embedded-rust-engineer, and code-simplifier reviews.

## Critical Issues

*None remaining.*

## Completed

### Const generics for memory bounds
**Source:** Embedded reviewer (2026-01-24)
**Completed:** 2026-01-24

Implemented `NodeConfig` trait with `DefaultConfig` (256KB+ RAM) and `SmallConfig` (64KB RAM).

## Low Priority / Future Work

### u64 division in hot paths
**Source:** Embedded reviewer (2026-01-24)
**Location:** `tree.rs:269,275,548,556`, `node.rs:360,470`

Keyspace calculation and tau calculation use u64 division. On 32-bit MCUs this is ~100-1000 cycles per operation.

**Impact:** Minor performance concern. Called during pulse processing (~every 20s for LoRa), not truly hot.

### pending_data lacks bounded insertion helper
**Source:** Embedded reviewer (2026-01-24)
**Location:** `node.rs`

The `pending_data` HashMap has no `insert_pending_data()` bounded helper like other collections. Currently implicitly bounded by `MAX_PENDING_LOOKUPS` since you can only have pending data for nodes being looked up.

**Recommendation:** Add explicit bounds checking or document the implicit bound.

### MAX_UNIQUE_PUBLISHERS not configurable
**Source:** Embedded reviewer (2026-01-24)
**Location:** `fraud.rs:15`

Hardcoded to 512. On 64KB devices using `SmallConfig`, tracking 512 publishers (512 × 16 bytes = 8KB) may be excessive.

**Recommendation:** Consider adding to `NodeConfig` or document why it's intentionally fixed.

### No SmallConfig test coverage
**Source:** Code simplifier (2026-01-24)

Tests only use `DefaultConfig`. No tests verify `SmallConfig` behavior when hitting smaller bounds.

**Recommendation:** Add at least one test using `SmallConfig` to verify eviction works correctly at smaller capacities.

### Config tests incomplete
**Source:** Code simplifier (2026-01-24)
**Location:** `config.rs` tests

Tests only verify 3 of 12 config values per config type.

**Recommendation:** Either test all values or document why only a subset is tested.

### Missing MCU selection guidance
**Source:** Code simplifier (2026-01-24)
**Location:** `config.rs` docs

No guidance on how to choose between configs for specific MCUs, or how to calculate actual memory footprint.

**Recommendation:** Add documentation with memory formulas and example MCU recommendations.
