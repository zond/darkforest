# Design vs Implementation Review Findings

Findings from protocol-security-architect and embedded-rust-engineer reviews comparing docs/design.md against the implementation.

## High Priority

### Fraud detection uses HashSet instead of HyperLogLog
**Source:** Both reviewers (2026-01-24)
**Location:** `fraud.rs`

Design doc specifies HyperLogLog with 256 bytes fixed memory, but implementation uses `HashSet<NodeId>` with `MAX_UNIQUE_PUBLISHERS = 512`.

**Impact:**
- Memory: ~8KB vs 256 bytes (32x more)
- Scalability: Stops counting at 512 publishers; HLL supports unlimited
- Missing: SipHash keyed hashing, combined variance in Z-score

**Fix:** Implement HyperLogLog as specified in design doc lines 576-758.

## Medium Priority

*None remaining.*

## Low Priority

### DATA message retries not implemented
**Source:** Embedded reviewer (2026-01-24)

Design doc shows request/response retry pattern for DATA messages, but only LOOKUP has retries.

**Impact:** DATA messages can be lost without notification to application.

### Sequence number persistence not implemented
**Source:** Embedded reviewer (2026-01-24)

Design doc lists three options for seq recovery after reboot. Implementation doesn't persist.

**Impact:** 12-hour delay after reboot before PUBLISH works (acceptable per design doc).