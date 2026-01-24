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

## Low Priority / Future Work

### u64 division in hot paths
**Source:** Embedded reviewer (2026-01-24)
**Location:** `tree.rs:269,275,548,556`, `node.rs:360,470`

Keyspace calculation and tau calculation use u64 division. On 32-bit MCUs this is ~100-1000 cycles per operation.

**Impact:** Minor performance concern. Called during pulse processing (~every 20s for LoRa), not truly hot.

### MAX_UNIQUE_PUBLISHERS not configurable
**Source:** Embedded reviewer (2026-01-24)
**Location:** `fraud.rs:15`

Hardcoded to 512. On 64KB devices using `SmallConfig`, tracking 512 publishers (512 × 16 bytes = 8KB) may be excessive.

**Recommendation:** Consider adding to `NodeConfig` or document why it's intentionally fixed.

### No SmallConfig test coverage
**Source:** Code simplifier (2026-01-24)

Tests only use `DefaultConfig`. No tests verify `SmallConfig` behavior when hitting smaller bounds.

**Recommendation:** Add at least one test using `SmallConfig` to verify eviction works correctly at smaller capacities.
