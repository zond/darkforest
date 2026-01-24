# Codebase Review Findings

Comprehensive review by protocol-security-architect and embedded-rust-engineer agents (2026-01-24).

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

### Missing radio power control in Transport trait
**Source:** Embedded reviewer
**Location:** `traits.rs`

No methods for radio sleep/wake control. Important for battery-powered LoRa devices with duty cycling.

**Suggestion:** Add `enable_rx()`, `disable_rx()`, `radio_state()` to Transport trait.

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

---

## Test Coverage Gaps

### tree.rs has no tests
**Location:** `tree.rs`

The entire tree.rs module (tree operations, pulse handling, parent selection, merge logic) has zero tests. This is a critical gap.

**Straightforward tests to add:**
1. `handle_neighbor_timeouts()` - parent timeout → become root, child timeout → removal
2. `handle_location_expiry()` - entries older than LOCATION_TTL are removed
3. `compute_child_keyspace()` - keyspace division algorithm
4. `select_best_parent()` - candidate filtering, RSSI selection
5. `consider_merge()` - merge decision (larger tree wins, root_hash tiebreak)

### dht.rs has minimal tests
**Location:** `dht.rs`

Only 1 test (`test_publish_stores_locally_when_owner`).

**Tests to add:**
1. `rebalance_keyspace()` - entries forwarded when keyspace changes
2. `handle_lookup_msg()` - lookup returns correct entry
3. `handle_found()` - validates and caches location

### routing.rs missing routing tests
**Location:** `routing.rs`

Basic tests exist but routing logic is untested.

**Tests to add:**
1. `best_next_hop()` - selects tightest range, uses shortcuts
2. `forward_routed()` - TTL decrement, signature verification

---

## Verified Working Correctly

### Protocol Implementation
- All message formats (Pulse, Routed, PUBLISH/LOOKUP/FOUND payloads)
- Wire encoding/decoding with varint canonical enforcement
- Domain separation prefixes (PULSE:, ROUTE:, LOC:)
- Keyspace division algorithm
- Routing algorithm (tightest range, shortcuts, upward fallback)
- Tree merge decision (larger tree_size wins, root_hash tiebreak)
- Tree inversion during merge
- Discovery phase (3τ) with RSSI-based parent selection
- Proactive pulse sending on state change / unknown neighbor / pubkey request
- Implicit parent rejection (3 pulses not in children list)
- Rebalancing when keyspace changes

### Security Verification (All Critical Paths Implemented)
- **Signature verification by forwarders** - routing.rs:51-55 verifies before forwarding
- Pulse signature verification before tree operations
- Pubkey binding verification (hash(pubkey)[..16] == node_id)
- LOC: signature verification for PUBLISH and FOUND
- Routed signature verification before message handling
- Sequence number replay protection for PUBLISH
- dest_hash verification for DATA/FOUND recipients
- TTL decrement with saturating_sub

### Fraud Detection
- Z-score calculation for PUBLISH rate anomaly detection
- Unique publisher tracking (prevents spoofing via repeated PUBLISH)
- Distrust mechanism with TTL and bounded storage
- JoinContext tracking for fraud attribution

### Memory Safety
- Saturating arithmetic in all time operations
- Collection bounds via bounded insertion helpers (LRU/oldest eviction)
- MAX_CHILDREN overflow protection
- Timestamp overflow/underflow protection
- Varint overflow attack protection
- Children count validation in decoder
- Zero unsafe code in production

### Strict Message Parsing (Defense in Depth)
- Wire type validation (0x01 Pulse, 0x02 Routed only)
- Non-canonical varint rejection
- Signature algorithm validation (0x01 Ed25519 only)
- Reserved bit 7 in Routed flags must be 0
- Message type bounds (0-4 only)
- Replica index bounds (< K_REPLICAS)
- Children sorted order validation
- Pulse sanity: subtree_size >= 1, tree_size >= subtree_size, keyspace_lo <= keyspace_hi
- Trailing bytes rejection

**TODO:** Have embedded-rust-engineer agent verify strict parsing implementation for correctness and efficiency on constrained devices.

### Embedded Compatibility
- no_std compatible (uses alloc, hashbrown for HashMap)
- No recursion (all iterative algorithms)
- No large stack allocations (uses heap)
- No u128 operations
- Tau timing model with bandwidth scaling

---

## Constants Verification

| Constant | Design Doc | Implementation | Status |
|----------|-----------|----------------|--------|
| K_REPLICAS | 3 | 3 | Match |
| DEFAULT_TTL | 255 | 255 | Match |
| MAX_CHILDREN | 12 | 12 | Match |
| MAX_TREE_DEPTH | 127 | 127 | Match |
| MAX_NEIGHBORS | 128 | 128 | Match |
| MAX_PUBKEY_CACHE | 128 | 128 | Match |
| MAX_LOCATION_STORE | 256 | 256 | Match |
| MAX_LOCATION_CACHE | 64 | 64 | Match |
| MAX_PENDING_LOOKUPS | 16 | 16 | Match |
| MAX_DISTRUSTED | 64 | 64 | Match |
| MIN_TAU_MS | 100 | 100 | Match |
| MIN_PULSE_INTERVAL | 10s | 10s | Match |
| MISSED_PULSES_TIMEOUT | 8 | 8 | Match |
| LOCATION_TTL | 12h | 12h | Match |
| LOCATION_REFRESH | 8h | 8h | Match |
| DISTRUST_TTL | 24h | 24h | Match |
| FRAUD_Z_THRESHOLD | 2.33 | 2.33 | Match |
| MIN_EXPECTED | 5.0 | 5.0 | Match |
| LOOKUP_TIMEOUT | 32τ | 32τ | Match |
| PULSE_BW_DIVISOR | 5 | 5 | Match |
| MAX_RETRIES | 8 | 8 | Match |
| MSG_ACK | 4 | 4 | Match |
| MAX_PENDING_ACKS | 32 | N/A | Not implemented |
| MAX_RECENTLY_FORWARDED | 256 | N/A | Not implemented |
