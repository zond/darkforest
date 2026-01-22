# Codebase Review Findings

Comprehensive review by protocol-security-architect and embedded-rust-engineer agents (2026-01-22).

## Critical Issues

### Link-layer reliability not implemented
**Source:** Both reviewers
**Design doc:** Part 5 (lines 1310-1446)

The entire link-layer reliability system is missing:
- No `MSG_ACK = 4` message type
- No implicit ACK via overhearing
- No `pending_acks` tracking
- No `recently_forwarded` duplicate detection
- No exponential backoff retransmission

**Impact:** Without hop-by-hop reliability, multi-hop message delivery degrades severely. With 50% loss per hop and 6 hops, only ~1.5% of messages arrive.

### No-std incompatible
**Source:** Embedded reviewer
**Location:** `node.rs:26`

```rust
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
```

Cannot compile for `#![no_std]` targets (Cortex-M, etc.).

**Fix:** Use `hashbrown::HashMap` or `heapless` collections, change to `alloc::collections` for BTreeMap/BTreeSet.

### Keyspace calculation broken outside subtree
**Source:** Protocol reviewer
**Location:** `routing.rs:195-263`

`addr_for_key()` only computes addresses within the node's subtree. This breaks DHT routing for keys outside the subtree.

**Impact:** PUBLISH/LOOKUP messages may be misrouted. The `owns_replica_key()` check is also broken due to this.

**Note:** May need architectural discussion - each node only knows its children, not the full tree.

---

## High Priority Issues

### Routed signatures not verified by forwarders
**Source:** Protocol reviewer
**Location:** `routing.rs:25-55`

Signature verification only happens at final destination. Forwarders relay messages without verification, allowing forged messages to waste bandwidth.

**Trade-off:** Verification at each hop costs CPU cycles and latency. Design doc doesn't explicitly require it.

### Memory pressure from pending_pubkey
**Source:** Embedded reviewer
**Location:** `node.rs`

Stores full `Routed` messages (up to 255 bytes each) for nodes awaiting pubkey. Worst case: 32 nodes * 16 messages = ~130KB.

**Fix:** Consider storing only essential fields, or reducing limits for memory-constrained targets.

---

## Medium Priority Issues

### Parent rejection tracking logic confusing
**Source:** Protocol reviewer
**Location:** `tree.rs:145-192`

The `pending_parent` field is used both for:
- Tracking nodes we're trying to join (its intended purpose)
- Tracking rejection by our current parent

This overloading is confusing and may cause edge case bugs.

### u128 division in keyspace calculation
**Source:** Embedded reviewer
**Location:** `routing.rs:237`

```rust
let child_range = ((range_size as u128) * (*child_subtree as u128)
    / (total_subtree as u128)) as u64;
```

u128 division is emulated on 32-bit MCUs (hundreds of cycles). Consider alternative algorithms if this is hot path.

### Missing radio power control in Transport trait
**Source:** Embedded reviewer
**Location:** `traits.rs`

No methods for radio sleep/wake control. Important for battery-powered LoRa devices with duty cycling.

**Suggestion:** Add `enable_rx()`, `disable_rx()`, `radio_state()` to Transport trait.

---

## Low Priority / Future Work

### Unbounded Vec allocations
**Source:** Embedded reviewer

`TreeAddr`, `ChildPrefix`, `Payload` use `Vec<u8>`. While validated at decode time, consider `heapless::Vec` for compile-time bounds on memory-constrained targets.

### Sort allocation in find_ordinal_in_children
**Source:** Embedded reviewer
**Location:** `tree.rs:331-349`

Allocates and sorts a Vec on every pulse from parent. With MAX_CHILDREN=16, this is bounded but could be avoided with cached ordering.

### Const generics for memory bounds
**Source:** Embedded reviewer

Allow compile-time tuning of MAX_NEIGHBORS, MAX_PUBKEY_CACHE, etc. for different MCU memory sizes.

### MAX_RETRIES mismatch
**Source:** Protocol reviewer

Design doc: `MAX_RETRIES = 8`, Implementation: `MAX_RETRIES = 3`. Not currently used since link-layer reliability isn't implemented.

---

## Verified Working Correctly

- Saturating arithmetic in all time operations
- Varint canonical encoding with rejection of non-minimal
- Collection bounds via bounded insertion helpers
- Zero unsafe code in production
- Tau timing model with bandwidth scaling
- Domain separation prefixes (PULSE:, ROUTE:, LOC:)
- Wire format encoding/decoding
- Tree merge decision (size then root_id tie-break)
- Empty tree address handling for root nodes
- MAX_CHILDREN overflow protection
- Timestamp overflow/underflow protection
- Varint overflow attack protection
- Children count validation in decoder
- Fraud detection wired up and tested
- RSSI-based parent selection with discovery phase
- Shortcut routing optimization
