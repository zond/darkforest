# Codebase Review Findings

Open issues from protocol-security-architect and embedded-rust-engineer review (2026-01-24).

## Critical Issues

### Link-layer reliability not implemented
**Source:** Both reviewers
**Design doc:** Part 5 (lines 1428-1563)

The entire link-layer reliability system is missing:
- No implicit ACK via overhearing
- No `pending_acks` tracking
- No `recently_forwarded` duplicate detection
- No exponential backoff retransmission
- Missing constants: MAX_PENDING_ACKS, MAX_RECENTLY_FORWARDED, ACK_HASH_SIZE

**Impact:** Without hop-by-hop reliability, multi-hop message delivery degrades severely. With 50% loss per hop and 6 hops, only ~1.5% of messages arrive.

---

## Medium Priority Issues

### Bandwidth budget not explicitly tracked
**Source:** Embedded reviewer
**Location:** `node.rs:461-483`

Design doc says proactive pulses should count toward bandwidth budget and be delayed if budget exhausted. Implementation only uses pulse interval calculation, no explicit budget tracking.

**Impact:** Under rapid state changes, multiple proactive pulses could be scheduled in quick succession, exceeding bandwidth budget.

---

## Low Priority / Future Work

### Unbounded Vec allocations
**Source:** Embedded reviewer

`ChildrenList`, `Payload` use `Vec<u8>`. While validated at decode time, consider `heapless::Vec` for compile-time bounds on memory-constrained targets.

### Const generics for memory bounds
**Source:** Embedded reviewer

Allow compile-time tuning of MAX_NEIGHBORS, MAX_PUBKEY_CACHE, etc. for different MCU memory sizes.

### u64 division in hot paths
**Source:** Embedded reviewer
**Location:** `tree.rs:269,275,548,556`, `node.rs:360,470`

Keyspace calculation and tau calculation use u64 division. On 32-bit MCUs this is ~100-1000 cycles per operation.

**Impact:** Minor performance concern. Called during pulse processing (~every 20s for LoRa), not truly hot.
