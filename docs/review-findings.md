# Codebase Review Findings

Open issues from protocol-security-architect and embedded-rust-engineer review (2026-01-24).

## Critical Issues

*None remaining.*

## Low Priority / Future Work

### Const generics for memory bounds
**Source:** Embedded reviewer

Allow compile-time tuning of MAX_NEIGHBORS, MAX_PUBKEY_CACHE, etc. for different MCU memory sizes.

### u64 division in hot paths
**Source:** Embedded reviewer
**Location:** `tree.rs:269,275,548,556`, `node.rs:360,470`

Keyspace calculation and tau calculation use u64 division. On 32-bit MCUs this is ~100-1000 cycles per operation.

**Impact:** Minor performance concern. Called during pulse processing (~every 20s for LoRa), not truly hot.
