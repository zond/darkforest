# Tree-Based DHT for LoRa Mesh Networks

A protocol for building mesh networks over LoRa radios with O(log N) routing.

**Key properties:**
- Nodes form a spanning tree via periodic broadcasts
- Keyspace addresses enable efficient routing without flooding
- A distributed hash table maps node IDs to keyspace addresses
- Ed25519 signatures prevent impersonation
- No clock synchronization required

---

## Nodes

Each node has a permanent 16-byte ID derived from its Ed25519 public key:

```rust
type NodeId = [u8; 16];
type PublicKey = [u8; 32];

struct Signature {
    algorithm: u8,      // 0x01 = Ed25519 (reserved for future algorithms)
    sig: [u8; 64],      // algorithm-specific signature data
}

fn hash(data: &[u8]) -> [u8; 32] {
    sha256(data)  // SHA-256 per FIPS 180-4
}

fn generate_identity() -> (NodeId, PublicKey, SecretKey) {
    let (pubkey, secret) = ed25519_keygen();
    let node_id = hash(&pubkey)[..16].try_into().unwrap();
    (node_id, pubkey, secret)
}
```

The `algorithm` byte is reserved for future cryptographic agility. Currently only Ed25519 (0x01) is defined. If Ed25519 is compromised, new algorithms can be added without protocol redesign.

**Properties:**
- **Cryptographically bound:** node_id is derived from pubkey, so ownership is provable
- **Collision resistant:** 128-bit hash provides ~2^64 collision resistance
- **Preimage resistant:** ~2^128 work to find a pubkey matching a target node_id

The keypair is generated once at first boot and stored in flash. The node_id never changes.

---

## Constants and Limits

These constants define protocol limits and memory bounds. Implementations MUST respect these values.

### Protocol Limits

| Constant | Value | Rationale |
|----------|-------|-----------|
| MAX_CHILDREN | 12 | Ensures worst-case Pulse fits in 252 bytes |
| K_REPLICAS | 3 | Location directory replication factor |
| MISSED_PULSES_TIMEOUT | 8 | Pulses before declaring neighbor dead |

**Tree depth:** There is no protocol limit on tree depth. In practice, depth is bounded by:
- Fan-out: With MAX_CHILDREN=12, depth ≈ log₁₂(N) for network size N
- TTL: Messages cannot complete round-trip if depth > TTL/2
- Latency: Each hop adds ~τ delay; deep trees have high latency

**TTL calculation:** When creating Routed messages, TTL is computed as `max(255, max_depth * 3)`. This ensures messages can traverse the tree and return, with a floor of 255 to handle tree formation when max_depth is not yet known.

### Timing Constants

| Constant | Value | Rationale |
|----------|-------|-----------|
| MIN_TAU_MS | 100 | Floor for unlimited-bandwidth links |
| RECENTLY_FORWARDED_TTL | 320τ | Must exceed worst-case retry (~280τ) |
| LOOKUP_TIMEOUT | 3τ + 3τ × max_depth | Per-replica; scales with observed tree depth |
| DISTRUST_TTL | 24 hours | How long to avoid fraudulent nodes |

### Memory Bounds

| Constant | DefaultConfig | SmallConfig | Purpose |
|----------|---------------|-------------|---------|
| MAX_NEIGHBORS | 128 | 16 | Neighbor tracking |
| MAX_PUBKEY_CACHE | 64 | 16 | LRU pubkey cache |
| MAX_LOCATION_STORE | 256 | 32 | Primary DHT entries |
| MAX_BACKUP_STORE | 256 | 64 | Backup DHT entries (2× location store) |
| MAX_BACKUPS_PER_NEIGHBOR | 64 | 16 | Per-neighbor backup limit |
| MAX_PENDING_ACKS | 32 | 8 | Messages awaiting ACK |
| MAX_RECENTLY_FORWARDED | 512 | 128 | Duplicate detection (reclaimable) |
| MAX_DELAYED_FORWARDS | 256 | 64 | Bounce-back dampening (reclaimable) |
| MAX_PENDING_ROUTED | 512 | 128 | Messages awaiting route (reclaimable) |
| MAX_PENDING_LOOKUPS | 16 | 4 | Concurrent DHT lookups |
| MAX_DISTRUSTED | 64 | 8 | Fraud detection blacklist |
| HLL_REGISTERS | 256 | 256 | HyperLogLog registers (hardcoded) |

**Reclaimable queues:** Collections marked "reclaimable" use shrinking data structures that automatically reclaim memory after sustained inactivity. This allows generous limits during network churn without permanent memory cost.

---

## Timing Model

All protocol timeouts scale with transport bandwidth to work correctly across vastly different link speeds (LoRa at ~38 bytes/sec vs UDP at effectively unlimited).

### τ (tau) — the bandwidth time unit

```rust
const MIN_TAU_MS: u64 = 100;  // floor for unlimited-bandwidth links

fn tau(&self) -> Duration {
    match self.transport().bw() {
        Some(bw) if bw > 0 => {
            // τ = MTU / effective_bandwidth
            let ms = (self.transport().mtu() as u64 * 1000) / bw as u64;
            Duration::from_millis(ms.max(MIN_TAU_MS))
        }
        _ => Duration::from_millis(MIN_TAU_MS),
    }
}
```

### Example values

| Transport | MTU | Effective BW | τ |
|-----------|-----|--------------|---|
| LoRa SF8, 10% duty | 255 | 38 bytes/sec | 6.7s |
| LoRa SF8, 1% duty | 255 | 3.8 bytes/sec | 67s |
| BLE extended | 252 | ~1000 bytes/sec | 252ms |
| UDP | 512 | unlimited | 100ms (floor) |

**Why τ = MTU / bw?** This represents the worst-case time to "afford" one maximum-size transmission under duty cycle constraints. For LoRa with 10% duty cycle, even though actual transmission of 255 bytes takes ~670ms, you can only transmit 10% of the time, so the effective cost is ~6.7 seconds of "budget."

All protocol timeouts are expressed as multiples of τ, ensuring they scale appropriately for both slow constrained links and fast unconstrained ones.

**Time source requirement:** Implementations MUST use a monotonic clock (not wall-clock time) for all timeout calculations. Monotonic time ensures timeouts work correctly even if the system clock is adjusted. The clock need not be synchronized across nodes.

### Transport Requirements

**Bandwidth allocation:**

| Budget | Max Share | Message Types |
|--------|-----------|---------------|
| Protocol | 1/5 | Pulse, ACK, Broadcast(!DATA), Routed(!DATA) |
| Application | 4/5 | Broadcast(DATA), Routed(DATA) |

Protocol messages are bounded to 1/5 of bandwidth, ensuring infrastructure never starves application traffic. Application messages get the remaining 4/5.

**Priority order (highest to lowest):**

| Priority | Message Type | Budget | Rationale |
|----------|--------------|--------|-----------|
| 1 | Pulse | Protocol | Tree maintenance; single-timer, not queued |
| 2 | ACK | Protocol | Reliability; enables retransmission |
| 3 | Broadcast(!DATA) | Protocol | DHT backup protocol |
| 4 | Routed(PUBLISH) | Protocol | Location directory registration |
| 5 | Routed(FOUND) | Protocol | Location directory response |
| 6 | Routed(LOOKUP) | Protocol | Location directory query |
| 7 | Broadcast(DATA) | Application | Application broadcast |
| 8 | Routed(DATA) | Application | Application unicast |

**DHT message priority rationale (PUBLISH > FOUND > LOOKUP):**
- PUBLISH ensures nodes are findable (write operations to location directory)
- FOUND completes pending lookups (response to earlier query)
- LOOKUP initiates new queries (can wait longer)

Within each budget (Protocol/Application), higher-priority messages are sent first. The Protocol budget (priorities 1-6) is capped at 1/5 of bandwidth; the Application budget (priorities 7-8) gets the remaining 4/5. Pulse is generated on-demand when its timer fires (not queued); other messages are queued and sent in priority order as bandwidth permits.

**Drop policy:** When queues are full, messages are dropped rather than blocking. This is acceptable because:
- **Pulse loss is tolerable:** Neighbors timeout after 8 missed Pulses. With 50% packet loss, P(miss 8) = 0.4%.
- **ACK loss triggers retry:** Sender will retransmit after timeout.
- **PUBLISH has redundancy:** Published to k=3 replicas and refreshed every 8 hours.
- **LOOKUP has retries:** Tries each replica sequentially; one drop just advances to the next.
- **FOUND is idempotent:** Lost responses cause timeout and retry.
- **DATA is application's responsibility:** Applications needing reliability implement their own acks.

**Link quality filtering:**

Transports MAY implement RSSI-based filtering to avoid selecting parents with unreliable links. The threshold is transport-specific because different physical layers have vastly different signal characteristics:

| Transport | Typical Threshold | Rationale |
|-----------|-------------------|-----------|
| LoRa | -110 dBm | Conservative margin above -120 dBm noise floor |
| WiFi | -80 dBm | Weak signal, high packet loss |
| Bluetooth | -90 dBm | Near receiver sensitivity limit |
| UDP/TCP | N/A | No RSSI concept |

The Transport trait provides `is_acceptable_rssi(rssi: Option<i16>) -> bool` for this purpose. Default returns `true` (no filtering). Transports without RSSI semantics (e.g., UDP) should use the default.

This is a **link reliability optimization**, not a security control. See "Security note on RSSI" in the Parent Selection section.

---

## Pulse

Nodes broadcast periodic **Pulse** messages to maintain the tree.

### Message Structure

```rust
struct Pulse {
    node_id: NodeId,                    // 16 bytes
    flags: u8,                          // 1 byte (see layout below)
    parent_hash: Option<[u8; 4]>,       // 0 or 4 bytes (truncated hash of parent node_id)
    root_hash: [u8; 4],                 // 4 bytes (truncated hash of root node_id)
    depth: varint,                      // 1-5 bytes (distance from root, 0 = root)
    max_depth: varint,                  // 1-5 bytes (max depth in subtree below)
    subtree_size: varint,               // 1-3 bytes
    tree_size: varint,                  // 1-3 bytes
    keyspace_lo: u32,                   // 4 bytes (start of owned keyspace range)
    keyspace_hi: u32,                   // 4 bytes (end of owned keyspace range, exclusive)
    pubkey: Option<PublicKey>,          // 0 or 32 bytes (if has_pubkey flag set)
    children: ChildList,                // N × (4 + varint) bytes (see encoding below)
    signature: Signature,               // 65 bytes (1 algorithm + 64 sig)
}
```

### Flags Byte Layout

```
- bit 0: has_parent (if set, parent_hash is present)
- bit 1: need_pubkey (requesting pubkeys from neighbors)
- bit 2: has_pubkey (if set, pubkey field is present)
- bit 3: unstable (node is in transition, don't join as child)
- bits 4-7: child_count (0-15 encodable, but values > 12 MUST be rejected)

Example: 5 children, has parent, includes pubkey → 0b0101_0_101 = 0x55
```

**Note:** While bits 4-7 can encode values 0-15, only 0-12 are valid. Messages with child_count > MAX_CHILDREN (12) MUST be rejected during parsing.

### Keyspace Range

The keyspace range `[keyspace_lo, keyspace_hi)` is the portion of 32-bit keyspace this node owns. The range is half-open: `keyspace_lo` is inclusive, `keyspace_hi` is exclusive.

**Root's range:** Root owns the entire keyspace with `keyspace_lo = 0` and `keyspace_hi = u32::MAX`. This represents the range `[0, u32::MAX)` containing u32::MAX valid addresses (0 through u32::MAX-1). The value u32::MAX itself is not a valid address—it serves only as the exclusive upper bound.

**Notation:** This document uses "2³²" as shorthand for the full 32-bit address space. Since 2³² exceeds u32, root actually stores `keyspace_hi = u32::MAX`, and the keyspace contains u32::MAX (not 2³²) addresses.

Children compute their range from parent's Pulse (see Tree Structure section).

A node's "address" for routing is the center of its range: `keyspace_lo + (keyspace_hi - keyspace_lo) / 2`. This formula avoids overflow.

### Signature

Signature covers ALL fields (domain-separated):
```
"PULSE:" || node_id || flags || parent_hash || root_hash || depth || max_depth ||
            subtree_size || tree_size || keyspace_lo || keyspace_hi || pubkey || children
```

### Children Encoding (ChildList)

Each child is identified by a 4-byte truncated hash of its node_id:
```rust
fn child_hash(node_id: &NodeId) -> [u8; 4] {
    hash(node_id)[..4].try_into().unwrap()
}
```

**Format:** For each child (count from flags bits 4-7):
```
[hash: [u8; 4]] [subtree_size: varint]
```

**Ordering:** Children MUST be sorted by their 4-byte hash in lexicographic (big-endian) order. This ordering:
- Determines keyspace division order (first child by hash gets first slice)
- Determines key range responsibility
- Enables binary search for child lookup
- Provides deterministic ordering across all nodes

**Example:** 3 children with hashes:
- Child A: hash `0xAB123456`
- Child B: hash `0xCD789012`
- Child C: hash `0xEF345678`

Wire encoding (sorted by hash):
```
[0xAB123456] [size_A]   // Child A (ordinal 0)
[0xCD789012] [size_B]   // Child B (ordinal 1)
[0xEF345678] [size_C]   // Child C (ordinal 2)
```

A child finds its ordinal by computing `hash(own_node_id)[..4]` and counting how many children have lexicographically smaller hashes.

### Hash Collision Handling

With 4-byte hashes, the probability of two children having the same hash is 1 in 2³² (~2.3 × 10⁻¹⁰). Even with 12 children (66 pairs), collision probability is ~1.5 × 10⁻⁸.

To prevent collisions:
- **Parents** MUST NOT accept a child whose hash matches an existing child's hash
- **Children** SHOULD NOT attempt to join a parent that already has a child with their hash

**Known limitation:** If two nodes with the same 4-byte hash race to join the same parent simultaneously, one will be silently rejected. The rejected node sees its hash in the parent's child list and believes it was accepted, but messages routed to that keyspace range will be delivered to the other node. This doesn't self-correct—it persists until one node leaves. Given the ~10⁻¹⁰ probability per join attempt, this is an acceptable trade-off for simpler encoding.

### Pulse Purposes

A Pulse serves multiple purposes:
- **Liveness signal** for parent and children
- **Tree state** for merge decisions (root_hash, tree_size)
- **Children list** for keyspace range computation
- **Pubkey exchange** for signature verification

### Replay Consideration

Pulses have no sequence number. This is a deliberate tradeoff:

- **Attack:** Replaying an old Pulse causes ~25s confusion until the legitimate node's next Pulse corrects it. Extending the attack requires jamming the legitimate Pulses.
- **Why no seq:** Adding seq (4 bytes) would require recovery after reboot. Since neighbors track `last_seen_seq`, a rebooted node's Pulses would be rejected until neighbors timeout (~75-90s). This recovery delay costs more than the 25s confusion it prevents.
- **Conclusion:** Pulses are frequent and self-correcting. The brief confusion window is acceptable given the recovery complexity seq would introduce.

### Typical Sizes

| Scenario | Size |
|----------|------|
| Root (no parent, no children, no pubkey) | ~96 bytes |
| Leaf (no pubkey) | ~100 bytes |
| Leaf (with pubkey) | ~132 bytes |
| 8 children + pubkey | ~177 bytes |
| 12 children + pubkey | ~207 bytes |
| 12 children + pubkey (worst) | ~250 bytes |

**Size formula:** `96 + has_parent×4 + has_pubkey×32 + children×(4+varint) + varint_overhead`

Base: 16 (node_id) + 1 (flags) + 4 (root_hash) + 1-5 (depth varint) + 1-5 (max_depth varint) + 1-5 (subtree_size varint) + 1-5 (tree_size varint) + 4 (keyspace_lo) + 4 (keyspace_hi) + 65 (signature) ≈ 96-108 bytes minimum. Typical shallow trees use 1 byte each for depth/max_depth.

**MTU constraints:** MAX_CHILDREN is set to 12 to guarantee worst-case Pulse (with pubkey and maximum varints) fits within 252 bytes, leaving headroom for any transport framing.

### Proactive Pulse Sending

In addition to periodic Pulses, nodes send **proactive Pulses** to accelerate state propagation. This reduces join/merge latency from 25-75 seconds to just a few seconds while keeping the protocol simple (one message type).

**Triggers for proactive Pulse:**

1. **State change** — When your tree state changes (parent, children, root, tree_size, subtree_size, keyspace range)
2. **Unknown neighbor** — When you receive a Pulse from an unrecognized node_id
3. **Pubkey request** — When you see `need_pubkey=true` in a neighbor's Pulse and they need yours

**Batching:** To avoid message storms during rapid changes, proactive Pulses are batched with jitter. The delay spreads concurrent senders over ~2τ to reduce collisions:

```rust
// Proactive Pulse delay: 1.5τ ± 0.5τ (range: 1τ to 2τ)
// For LoRa (τ=6.7s): 6.7s to 13.4s
// For UDP (τ=0.1s): 100ms to 200ms

impl Node {
    fn schedule_proactive_pulse(&mut self) {
        // If already scheduled, don't reschedule (coalesce triggers)
        if self.proactive_pulse_pending.is_none() {
            let tau = self.tau();
            let base = tau + tau / 2;  // 1.5τ
            let jitter_range = tau.as_millis() as u64;  // 1τ range
            let jitter = self.random.gen_range(0, jitter_range);
            let delay = base - tau / 2 + Duration::from_millis(jitter);  // 1τ to 2τ
            self.proactive_pulse_pending = Some(now() + delay);
        }
    }

    fn on_state_changed(&mut self) {
        self.schedule_proactive_pulse();
    }

    fn on_unknown_neighbor_pulse(&mut self, pulse: &Pulse) {
        self.schedule_proactive_pulse();
    }

    fn on_neighbor_needs_pubkey(&mut self, pulse: &Pulse) {
        if self.should_respond_with_pubkey(pulse) {
            self.schedule_proactive_pulse();
            self.include_pubkey_in_next_pulse = true;
        }
    }
}
```

**Bandwidth budget:** Pulses consume from the protocol bandwidth budget (1/5 of available bandwidth, shared with ACK and DHT messages). Pulse timing uses a token bucket model:

```
PULSE_BW_DIVISOR = 5
budget_rate = effective_bandwidth / PULSE_BW_DIVISOR  // bytes per second
max_budget = 2 × typical_pulse_size                   // ~300 bytes

// On sending a Pulse of `size` bytes:
budget -= size
next_available_budget_slot = now + size / budget_rate

// Budget recovers continuously:
budget += elapsed_time × budget_rate  (capped at max_budget)
```

If budget is exhausted, the next Pulse is delayed until budget recovers. This prevents proactive sending from starving other traffic while allowing brief bursts (e.g., two quick Pulses during rapid state changes).

**Pulse scheduling:**

Nodes maintain a single timer for the next Pulse—no queue. When the timer fires, the node sends its current state. All state changes are automatically coalesced into whichever Pulse fires next.

```
// After sending a Pulse:
next_pulse = min(now + 3τ, next_available_budget_slot)

// On proactive trigger (if next_pulse > now + 2τ):
next_pulse = now + 1.5τ ± 0.5τ  (range: 1τ to 2τ)
```

- **Regular interval**: ~3τ based on bandwidth budget (1/5 of available bandwidth)
- **Proactive rescheduling**: Moves timer earlier when triggered (state change, unknown neighbor, pubkey request). Jitter spreads concurrent senders to reduce collisions. Only reschedules if current timer is >2τ away.

The effective Pulse interval is approximately 3τ under normal conditions (based on ~150-byte pulse, PULSE_BW_DIVISOR=5, and τ = MTU/bw). During active state changes, proactive rescheduling reduces this to 1-2τ.

**Latency improvement:**

| Scenario | Periodic only | With proactive |
|----------|---------------|----------------|
| Join (get keyspace range) | 6-9τ | 2-4τ |
| Merge detection | 0-3τ | 1-2τ |
| Shopping | 3τ | 3τ |
| State propagation | 0-3τ | 1-2τ |
| Pubkey exchange | 3-6τ | 2-4τ |

For LoRa (τ=6.7s): periodic join takes ~40-60s, proactive takes ~13-27s.
For UDP (τ=0.1s): periodic join takes ~0.6-0.9s, proactive takes ~0.2-0.4s.

**Why this works:** The single-timer model automatically coalesces all state changes and triggers into the next Pulse. Multiple events (e.g., receiving several unknown Pulses at once) result in one outgoing Pulse, not many. The bandwidth budget prevents runaway sending during network churn.

**During shopping (unstable=true):** Proactive pulses are still sent when shopping. The `unstable` flag warns neighbors that the node may change parent, but state changes (new children, keyspace updates) still need to propagate. Not pulsing during shopping would delay tree convergence.

### Pubkey Exchange

Nodes cache pubkeys for signature verification. When a node receives a Pulse from an unknown node_id:

1. Set `need_pubkey = true` and schedule proactive Pulse
2. Neighbors see the request and send proactive Pulse with `pubkey` included
3. **Verify binding:** `hash(pubkey)[..16] == node_id` (MUST check!)
4. Receiver caches: `node_id → pubkey`
5. Future signatures can be verified

With proactive sending, pubkey exchange typically completes in ~5 seconds instead of 25-50 seconds.

```rust
fn handle_pubkey(&mut self, claimed_node_id: NodeId, pubkey: PublicKey) {
    // CRITICAL: Verify cryptographic binding
    if hash(&pubkey)[..16] != claimed_node_id {
        // Attacker trying to substitute their own pubkey
        return;
    }
    self.pubkey_cache.insert(claimed_node_id, pubkey);
}
```

This verification is essential — without it, an attacker could respond to pubkey requests with their own pubkey, enabling impersonation.

---

## Tree Structure

This section describes the static properties of the tree: how keyspace is partitioned and how tree metadata is computed.

### Keyspace Ranges

The keyspace is `[0, u32::MAX)`. Since `keyspace_hi` is stored as `u32`, the keyspace contains exactly `u32::MAX` valid addresses (0 through u32::MAX-1). The value `u32::MAX` itself is not a valid address — it serves as the exclusive upper bound.

Each node owns a range proportional to its subtree_size. The root owns the entire keyspace and divides it among itself and its children.

**Keyspace division algorithm:**

A node with range `[lo, hi)` and `subtree_size = S` divides its range:
1. **Parent's own slice** (at the beginning): `[lo, lo + (hi-lo)/S)` — weight 1 for itself
2. **Children's slices** (sorted by hash): each child gets `(hi-lo) × child_subtree_size / S`

```
Root has range [0, 2³²), subtree_size = 201 (1 + 100 + 50 + 50)
Children (sorted by hash): A (100), B (50), C (50)

Division:
  Root itself: [0, ~21M)                    // 1/201 of range
  A: [~21M, ~2.1B)                          // 100/201 of range
  B: [~2.1B, ~3.2B)                         // 50/201 of range
  C: [~3.2B, 2³²)                           // 50/201 of range
```

**Child computes its range from parent's Pulse:**

```rust
impl Node {
    /// Called when receiving parent's Pulse to compute own keyspace range
    fn compute_my_range(&self, parent_pulse: &Pulse) -> (u32, u32) {
        let parent_lo = parent_pulse.keyspace_lo as u64;
        let parent_hi = parent_pulse.keyspace_hi as u64;
        let parent_range = parent_hi - parent_lo;
        let parent_subtree = parent_pulse.subtree_size as u64;

        // Parent keeps first slice for itself (weight 1)
        let parent_slice = parent_range / parent_subtree;
        let mut cursor = parent_lo + parent_slice;

        // Children sorted by hash get consecutive slices
        for (child_hash, child_subtree) in &parent_pulse.children {
            let child_range = (parent_range * *child_subtree as u64) / parent_subtree;
            if *child_hash == hash(&self.node_id)[..4] {
                return (cursor as u32, (cursor + child_range) as u32);
            }
            cursor += child_range;
        }
        // Not found in parent's children - shouldn't happen
        (0, 0)
    }
}
```

**A node's "address"** is the center of its *owned slice*, not the full keyspace range:
```rust
fn my_address(&self) -> u32 {
    let range = self.keyspace_hi - self.keyspace_lo;
    let own_slice_size = range / self.subtree_size;
    self.keyspace_lo + own_slice_size / 2
}
```

The owned slice is 1/subtree_size of the total range, starting at keyspace_lo. Using the center of this slice (rather than the full range) ensures the address falls within keyspace the node actually owns. This is critical for LOOKUP responses - if a node published an address in keyspace delegated to children, FOUND messages would route to the wrong node.

This address is what gets published to the location directory and used in `src_addr` for routing replies.

### Metadata

**tree_size:** The total number of nodes in the entire tree. Propagated from root through Pulses.

**subtree_size:** The number of nodes in a node's subtree (including itself). Computed as:
```rust
subtree_size = 1 + sum(child.subtree_size for each child)
```

These values enable:
- Merge decisions (larger tree_size wins)
- Keyspace division (proportional to subtree_size)
- Fraud detection (PUBLISH traffic should match expectations)

### Child Ordering

Children are sorted by their 4-byte hash (lexicographic, big-endian). This provides:
- **Deterministic keyspace division:** All nodes agree on which child gets which slice
- **Efficient lookup:** Binary search for child by hash
- **Consistent ordering:** No ambiguity in range computation

---

## Tree Dynamics

This section describes how the tree changes over time: bootstrapping, joining, merging, partitioning, and liveness detection.

### Bootstrap (Alone)

When a node N boots and finds no neighbors:

```
N generates keypair: (pubkey_N, secret_N)
N.node_id = hash(pubkey_N)[0:16]

N → Pulse{
  node_id: N,
  parent_hash: None,
  root_hash: hash(N)[..4],
  depth: 0,
  max_depth: 0,
  subtree_size: 1,
  tree_size: 1,
  keyspace_lo: 0,
  keyspace_hi: 2³²,
  children: []
}

N state:
  parent = None
  root = N
  depth = 0
  max_depth = 0
  tree_size = 1
  keyspace = [0, 2³²)
```

N is root of its own single-node tree (depth=0, max_depth=0).

### Parent Selection

Nodes always boot as root of a single-node tree (see Bootstrap). Parent selection happens through **shopping** — a mechanism that collects neighbor Pulses before choosing a parent.

#### Shopping Triggers

Three events trigger shopping:

- **First boot** — node starts as a 1-node tree root, immediately shops for a parent
- **Dominating tree seen** — neighbor's tree is larger (or equal size with lower root_hash)
- **Parent lost** — 8 missed Pulses or explicit rejection (child not in parent's children list after 3 Pulses)

#### Shopping Procedure

When shopping is triggered:

1. **Remember `old_parent` and `old_tree`** (current root_hash, may be None for first boot)
2. **Set `unstable = true`** — signals to neighbors not to join this node during shopping
3. **Start shopping timer** for `3τ`
4. **Collect Pulses from ALL neighbors** — the trigger started shopping, but we might find an even better option during the window
5. **When timer fires, select parent using preference order:**
   a. If candidates exist in a dominating tree → pick best, switch to that tree
   b. Else if `old_parent` is valid (responding, not full) → stay with them
   c. Else if candidates exist in current tree (`old_tree`) → pick best
   d. Else → become root (or stay root for first boot)
6. **Clear `unstable`** after shopping completes

The 3τ duration allows time to collect neighbor Pulses before deciding.

**Why this preference order works:**

- *First boot with no neighbors* → step 5d, stays as root
- *First boot with neighbors* → step 5a or 5c, joins best tree
- *Dominating tree seen, valid parent there* → step 5a, switches trees (merge)
- *Dominating tree seen, no valid parent there* → step 5b, stays with old parent
- *Parent lost, new candidate found* → step 5a or 5c, switches to new parent
- *Parent lost, old parent reappears* → step 5b, stays with old parent
- *Parent lost, no candidates* → step 5d, becomes root

**Retry after becoming root:** Step 5d is not permanent. If a node becomes root due to no valid candidates, the next dominating Pulse it receives will trigger shopping again. This allows recovery when the network topology changes.

#### The Unstable Flag

A node sets `unstable = true` whenever it is shopping for a parent. This signals to neighbors: "don't join me as a child right now — my position in the tree might change."

**A node is stable (unstable = false) when:**
- It is root (no claimed parent) AND not currently shopping, OR
- It has a claimed parent AND is receiving Pulses from that parent (within 8-Pulse timeout) AND not currently shopping

**A node becomes unstable when:**
- It starts shopping (any trigger: first boot, dominating tree, or parent loss)
- Its claimed parent stops responding (8 missed Pulses) — this triggers shopping

**Why this matters:** During shopping, a node's depth and tree membership might change. If another node joins it as a child based on stale information, this could create inconsistencies or cycles. The unstable flag prevents this.

#### Selecting Best Candidate

During shopping, candidates are evaluated as follows:

1. **Pick the best tree** — if multiple trees visible, choose largest tree_size (tie-break: lowest root_hash). This becomes the "target tree."
2. **Filter by minimum signal quality** — remove candidates where `transport.is_acceptable_rssi(rssi)` returns false. This is an absolute threshold filter that rejects links likely to be unreliable. Transports define their own thresholds based on physical layer characteristics (see Transport Requirements). If no RSSI data is available (rssi = None), the candidate is not filtered.
3. **Pick shallowest** — from remaining candidates, choose the one with smallest depth (tie-break: best RSSI, or arbitrary if no RSSI). This keeps trees wide and shallow. The `depth` field in Pulses is the authoritative measure of tree position.

This algorithm is used in step 5a/5c of the Shopping Procedure. The preference order in that step handles fallback when no valid candidates exist.

**Security note on RSSI:** RSSI filtering is a soft defense for link reliability, not a security guarantee. An adversary with physical-layer capabilities (high-power transmitter, directional antenna) can manipulate apparent signal strength. The protocol's security properties rely on cryptographic identity verification (Ed25519 signatures binding node_id to pubkey), not radio signal characteristics. RSSI filtering reduces churn from flaky links; it does not defend against active attackers with radio capabilities.

#### Candidate Filtering

A neighbor is **skipped** during candidate evaluation if:
- It has `children.len() >= MAX_CHILDREN` (parent is full)
- It is in the distrusted set
- It has `unstable = true` in its Pulse flags — **except `old_parent`**, since we're already their child
- **Same tree AND depth >= our depth** (would create cycle — see below)

**Racing shopping:** If `old_parent` is also shopping when we choose to stay with them (step 5b), they might switch trees before we finish. This is safe: if `old_parent` switches trees, they won't include us in their children list (wrong root_hash), triggering implicit rejection and new shopping.

**Why depth check prevents cycles:** In the same tree, a node can only join a shallower node (smaller depth). This forms a DAG that converges to a tree. Joining a node at equal or greater depth could create a cycle where A→B→...→A.

**Mutual parent detection:** If a node claims a parent but sees that parent also claiming it as parent (via parent_hash), one of them is in an invalid state. The node from the dominated tree (smaller tree_size, or equal size with higher root_hash) should back off and retry shopping.

#### After Joining

Once a node has a parent, it only switches parent when:
- **Dominating tree** — node sees a better tree (triggers shopping)
- **Parent timeout** — after 8 missed Pulses (triggers shopping)

This mechanism ensures nodes find optimal shallow positions. Without shopping, a node might join the first neighbor it sees even when a much shallower position is reachable.

**Implicit rejection:** When a node claims a parent (by setting `parent_hash` in its Pulse), the parent decides whether to accept by including the child in its `children` list. A parent silently ignores a child if it already has `MAX_CHILDREN` children.

If a joining node doesn't see itself in the parent's `children` list after 3 Pulses, it assumes rejection and tries another neighbor.

**Join sequence example:**

```
t=0: N → Pulse{node_id: N, parent_hash: None, root_hash: hash(N), tree_size: 1, depth: 0, ...}

t=0: P receives N's Pulse:
  - Unknown node_id → schedule proactive Pulse, need_pubkey=true

t≈1.5τ: P → proactive Pulse{node_id: P, parent_hash: hash(G), root_hash: hash(R), tree_size: 500,
            keyspace_lo: X, keyspace_hi: Y, depth: 2, need_pubkey: true, ...}

t≈1.5τ: N receives P's Pulse:
  - Different root_hash
  - N.tree_size(1) < P.tree_size(500) → N starts shopping (dominating tree trigger)
  - Target tree: hash(R)

t≈3τ: N evaluates candidates, picks P (shallowest from target tree)
  - N.parent = P, N.root = R, N.depth = 3
  - State changed → schedule proactive Pulse with pubkey

t≈4.5τ: N → proactive Pulse{node_id: N, parent_hash: hash(P), root_hash: hash(R), tree_size: 500,
          keyspace_lo: 0, keyspace_hi: 0, depth: 3,  // doesn't know range yet
          pubkey: pubkey_N, ...}

t≈4.5τ: P receives N's Pulse:
  - N.pubkey present → cache it
  - N claims parent_hash = hash(P) → P.children.insert(N)
  - P.subtree_size += 1
  - State changed → schedule proactive Pulse

t≈6τ: P → proactive Pulse{..., children: [(hash(N), 1), ...], ...}

t≈6τ: N receives P's Pulse:
  - N finds itself in P.children (by hash) → computes keyspace range from P's range
```

**Total join time: ~6τ** (for LoRa with τ≈6.7s, this is ~40 seconds)

### Merging

When two nodes from different trees come into radio range:

```
Tree A (900 nodes)              Tree B (100 nodes)
      Ra                              Rb
     /  \                             |
    .    X  ←— discover —→  Y         Py
```

**Merge decision:** Larger tree_size wins. If equal, lower root_hash wins.

```
X: root_hash=hash(Ra), tree_size=900
Y: root_hash=hash(Rb), tree_size=100

t=0: X and Y exchange Pulses (or X's periodic Pulse reaches Y)

t=0: Y receives X's Pulse:
  - Unknown node → schedule proactive Pulse
  - Y.tree_size(100) < X.tree_size(900) → Y dominated
  - Y.parent = X, Y.root = Ra
  - State changed → schedule proactive Pulse

t≈1.5τ: Y → proactive Pulse (claiming parent=X, root_hash=hash(Ra))

t≈1.5τ: Py receives Y's Pulse:
  - Py.tree_size < Y's tree_size → Py dominated
  - INVERSION: Py.parent = Y (former child becomes parent!)
  - Py.root = Ra
  - State changed → schedule proactive Pulse

t≈3τ: Py → proactive Pulse (inversion propagates up tree B)

(proactive Pulses propagate inversion to Rb in ~1.5τ per hop)
```

**Merge time:** With proactive Pulses, the entire tree B inverts in ~1.5τ per hop. A 10-hop deep tree merges in ~15τ (for LoRa: ~15 seconds) instead of 4-8 minutes.

**Visual sequence:**

```
Step 1 (t=0): Initial state - X and Y discover each other
═════════════════════════════════════════════════════════

Tree A (900 nodes)              Tree B (100 nodes)
     Ra                              Rb
    /  \                             |
   .    X  · · · · · · · · · ·  Y ← Py
                                    / \


Step 2 (t≈1.5τ): Y switches parent to X
═══════════════════════════════════════

     Ra                              Rb
    /  \                             |
   .    X─────────────────────Y     Py (orphaned)


Step 3 (t≈3τ): Py inverts, claims Y as parent
═════════════════════════════════════════════

     Ra
    /  \
   .    X────────────────────Y
                             |
                             Py
                            / \


Step 4 (t≈4.5τ): Inversion propagates to Rb
═══════════════════════════════════════════

           Ra (root, 1000 nodes)
          /  \
         .    X
             /|
            / Y
              |
              Py
             /|\
            . Rb .
```

### Partition and Reconnection

**Network partition:**

```
Before:
      R (tree_size=100, depth=0)
     / \
    A   B
   /
  C (subtree_size=30, depth=2, max_depth=5)

Link A-C breaks. After 8 missed Pulses:

C (no Pulse from parent A):
  - C starts shopping (parent lost trigger, see Parent Selection)
  - C sets unstable=true in Pulse flags
  - Shopping duration: 3τ

During C's shopping period:
  - C's children see unstable=true, don't try to switch parents
  - Other nodes won't try to join C as children

After C's shopping timer (3τ):
  - If A's Pulse received: C stays with A, clears unstable
  - If no valid parent: C becomes root, C.tree_size = 30, clears unstable

A (no Pulse from child C):
  A.children.remove(C)
  A.subtree_size -= 30

Two separate trees: R (70 nodes), C (30 nodes)
```

**Partition heals:**

```
A and C back in radio range.

C receives A's Pulse:
  - C.tree_size(30) < A.tree_size(70) → C starts shopping (dominating tree trigger)
  - Target tree: hash(R)

After shopping:
  - C.parent = A
  - C.root_id = R

Tree reunified: R.tree_size = 100
```

### Liveness Detection

Nodes track Pulse timestamps for all neighbors. After 8 missed Pulses, a neighbor is presumed dead.

**Why 8 Pulses?** With 50% packet loss per Pulse:
- P(miss 3 in a row) = 12.5% — too high, causes spurious timeouts
- P(miss 8 in a row) = 0.4% — rare enough to be acceptable

At ~3τ Pulse intervals (20 seconds for LoRa), 8 missed Pulses = ~24τ (~160 seconds for LoRa) before declaring a neighbor dead.

Since Pulse intervals vary by node, we track the observed interval:

```rust
const MIN_PULSE_INTERVAL: Duration = self.tau() * 2;  // rate limit floor (scales with bandwidth)
const MISSED_PULSES_TIMEOUT: u32 = 8;  // pulses before declaring neighbor dead

impl Node {
    fn on_pulse_received(&mut self, pulse: &Pulse) {
        let neighbor = &pulse.node_id;

        // After signature verification...

        // ALWAYS update timestamps first (prevents spurious timeouts)
        let prev = self.neighbor_times.get(neighbor).map(|(last, _)| *last);
        self.neighbor_times.insert(*neighbor, (now(), prev));

        // Rate limiting: skip tree operations if Pulses arrive too fast.
        // Timing is already updated, so this only affects tree processing.
        if let Some(prev_seen) = prev {
            if now() - prev_seen < MIN_PULSE_INTERVAL {
                return;  // Too soon for tree ops, but timing is updated
            }
        }

        // Process tree state...
    }

    fn is_timed_out(&self, neighbor: &NodeId) -> bool {
        // Timeout uses fixed 3τ interval, not observed pulse rate.
        // This prevents spurious timeouts when neighbors pulse faster than normal
        // (e.g., due to proactive pulses during tree changes).
        let expected_interval = self.tau() * 3;
        match self.neighbor_times.get(neighbor) {
            Some((last_seen, _)) => {
                now() > *last_seen + MISSED_PULSES_TIMEOUT * expected_interval
            }
            None => false,
        }
    }
}
```

| Relationship | Timeout | Effect |
|--------------|---------|--------|
| Parent | ~24τ (8 × ~3τ interval) | Start shopping (parent lost) |
| Child | ~24τ (8 × ~3τ interval) | Remove from children |
| Shortcut | ~24τ (8 × ~3τ interval) | Remove from shortcuts |

### Depth Propagation

The `depth` and `max_depth` fields enable cycle prevention.

**Depth computation:**
- Root has `depth = 0`
- Child has `depth = parent_depth + 1` (saturating at 255)
- Learned from parent's Pulse (a joining node sets `depth = parent.depth + 1`)

**Max depth computation:**
- Leaf has `max_depth = depth` (no children below)
- Non-leaf has `max_depth = max(child.max_depth for all children)`
- Propagated up from children via their Pulses

**Example:**

```
        R (depth=0, max_depth=3)
       / \
      A   B (depth=1, max_depth=1)
     /
    C (depth=2, max_depth=3)
   /
  D (depth=3, max_depth=3)  ← leaf
```

When D joins as C's child:
1. D sets `depth = C.depth + 1 = 3`
2. D sets `max_depth = 3` (leaf)
3. C sees D's max_depth=3, updates `max_depth = max(3) = 3`
4. A sees C's max_depth=3, updates `max_depth = max(3) = 3`
5. R sees A's max_depth=3, updates `max_depth = max(3, 1) = 3`

**Why depth matters for cycle prevention:** When switching parents within the same tree, a node can only join a node with smaller depth. This ensures the parent relationship forms a DAG that converges to a tree. Without depth checking, two nodes could potentially claim each other as parent.

### Tree Size Verification

A node's `tree_size` is self-reported and could be inflated by a malicious node to win merge decisions. This section describes how to detect such fraud.

#### The Problem

When two trees meet, the smaller tree joins the larger (based on `tree_size`). An attacker can claim an inflated `tree_size` to "steal" nodes from honest trees.

**Why naive verification fails:** We cannot verify `tree_size` by checking our neighbor's `subtree_size` against their observable children. An attacker can honestly report a small `subtree_size` while claiming a huge `tree_size` — they simply claim the inflation is elsewhere in the tree, beyond our observation.

#### The Insight: PUBLISH Traffic Reveals True Tree Size

Every node publishes its location to `K_REPLICAS=3` keyspace positions every 8 hours. My keyspace fraction equals `my_subtree_size / tree_size`. Therefore:

```
Expected PUBLISH per 8 hours = tree_size × 3 × (my_subtree_size / tree_size)
                             = 3 × my_subtree_size
```

**The tree_size cancels out.** I should always receive `3S` PUBLISH messages per 8 hours, where `S` is my subtree size. If I receive significantly fewer, the tree is smaller than claimed.

#### Statistical Model

PUBLISH arrivals follow a Poisson distribution with expected value `λ`:

```
λ = 3 × S × (T / 8h)
```

Where `S` = my subtree size, `T` = observation time.

If the tree is fraudulent (actual size < claimed), I receive fewer PUBLISH than expected. We measure how unlikely the observed count is under an honest tree:

```
Z = (λ - P) / √λ
```

Where `P` = observed PUBLISH count. The Z-score tells us how many standard deviations below expected we are.

| Z-score | Confidence that tree is fraudulent |
|---------|-----------------------------------|
| 1.65 | 95% |
| 2.33 | 99% |
| 3.00 | 99.9% |

#### Example

My subtree size `S = 10`. After 8 hours, I expect `λ = 3 × 10 = 30` PUBLISH messages.

| Scenario | Actual nodes | PUBLISH received | Z-score | Confidence |
|----------|--------------|------------------|---------|------------|
| Honest (1000 nodes) | 1000 | ~30 | ~0 | — |
| 10× fraud (claim 1000, have 100) | 100 | ~3 | 4.9 | >99.99% |
| 100× fraud (claim 10000, have 100) | 100 | ~0.3 | 5.4 | >99.99% |

Large fraud is detectable within one refresh period (8 hours). For faster detection with smaller `S`, wait longer to accumulate samples.

#### Scalability Challenge

A naive implementation using `HashSet<NodeId>` to track unique publishers doesn't scale:
- 1,000 nodes × 16 bytes = 16 KB
- 100,000 nodes × 16 bytes = 1.6 MB — far too much for embedded devices

We need bounded memory regardless of network size.

#### Solution: HyperLogLog Cardinality Estimation

HyperLogLog (HLL) is a probabilistic algorithm that estimates the cardinality (unique count) of a set using fixed memory. It's used by Redis, PostgreSQL, and other systems for COUNT DISTINCT operations.

**Properties:**
- **Fixed memory:** ~1.5 KB for 2% accuracy, regardless of set size
- **Supports billions of items** with the same memory footprint
- **Simple operations:** add(item), estimate() → count
- **Mergeable:** Two HLL sketches can be combined (useful for distributed counting)

**How it works:**
1. Hash each item to a uniform random value
2. Count leading zeros in the hash (geometric distribution)
3. Track maximum leading zeros seen across many "buckets"
4. Estimate cardinality from the harmonic mean of bucket values

**Memory vs Accuracy trade-off:**

| Registers | Memory | Std Error |
|-----------|--------|-----------|
| 64 | 64 B | 13% |
| 256 | 256 B | 6.5% |
| 1024 | 1 KB | 3.25% |
| 2048 | 2 KB | 2.3% |

For fraud detection, 6.5% error (256 bytes) is acceptable — we're detecting 2× or larger fraud, not subtle differences.

#### Implementation

```rust
const FRAUD_CONFIDENCE: f64 = 0.99;  // 99% confidence before acting
const FRAUD_Z_THRESHOLD: f64 = 2.33; // Z-score for 99% confidence
const MIN_EXPECTED: f64 = 5.0;       // need λ ≥ 5 for valid Poisson approximation
const DISTRUST_TTL: Duration = Duration::from_secs(24 * 3600);
const MAX_DISTRUSTED: usize = 64;

// HyperLogLog parameters (configurable via NodeConfig)
const HLL_REGISTERS: usize = 256;    // 256 bytes, ~6.5% std error

struct Node {
    join_context: Option<JoinContext>,
    distrusted: HashMap<NodeId, Instant>,
    fraud_detection: FraudDetection,
    hll_secret_key: [u8; 16],  // Random key for SipHash (prevents adversarial bucket attacks)
    last_fraud_reset: Instant, // Rate-limit reset attempts
    // ...
}

struct JoinContext {
    parent_at_join: NodeId,
    join_time: Instant,
}

struct FraudDetection {
    // HyperLogLog sketch for cardinality estimation
    // Each register stores max leading zeros (0-64), fits in u8
    hll_registers: [u8; HLL_REGISTERS],
    count_start: Instant,
    subtree_size_at_start: u32,
}

impl FraudDetection {
    fn new(subtree_size: u32) -> Self {
        Self {
            hll_registers: [0; HLL_REGISTERS],
            count_start: Instant::now(),
            subtree_size_at_start: subtree_size,
        }
    }

    fn add_publisher(&mut self, node_id: &NodeId, secret_key: &[u8]) {
        // Use keyed hash (SipHash) to prevent adversarial bucket manipulation.
        // Without keyed hash, attacker could craft NodeIds targeting specific buckets.
        let hash = siphash64(secret_key, node_id);

        // Use lower bits for bucket index
        let bucket = (hash as usize) & (HLL_REGISTERS - 1);

        // Count leading zeros in upper 56 bits, +1 for rank (so rank is always >= 1)
        // For 56-bit value in u64: subtract 8 from leading_zeros() result
        let leading_zeros = (hash >> 8).leading_zeros() as u8 - 8 + 1;

        // Update register if this is a new maximum
        if leading_zeros > self.hll_registers[bucket] {
            self.hll_registers[bucket] = leading_zeros;
        }
    }

    fn estimate_cardinality(&self) -> f64 {
        // HyperLogLog estimation formula
        let m = HLL_REGISTERS as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);  // bias correction

        let sum: f64 = self.hll_registers.iter()
            .map(|&r| 2.0_f64.powi(-(r as i32)))
            .sum();

        let estimate = alpha * m * m / sum;

        // Small range correction (linear counting)
        let zeros = self.hll_registers.iter().filter(|&&r| r == 0).count();
        if estimate < 2.5 * m && zeros > 0 {
            return m * (m / zeros as f64).ln();
        }

        estimate
    }
}

fn on_publish_received(&mut self, msg: &Routed) {
    if self.is_storage_node_for(msg) {
        // Add to HyperLogLog sketch (O(1) time and space)
        self.fraud_detection.add_publisher(&msg.src_node_id, &self.hll_secret_key);
    }
}

fn on_subtree_size_changed(&mut self, now: Instant) {
    // Reset fraud detection if subtree_size changed significantly (2x either way)
    let old = self.fraud_detection.subtree_size_at_start;
    let new = self.subtree_size;
    if new > old * 2 || new < old / 2 {
        // Rate-limit resets to prevent attacker from manipulating subtree_size
        // to repeatedly reset our fraud detection window
        const MIN_RESET_INTERVAL: Duration = Duration::from_secs(3600);  // 1 hour
        if now.duration_since(self.last_fraud_reset) >= MIN_RESET_INTERVAL {
            self.fraud_detection = FraudDetection::new(new);
            self.last_fraud_reset = now;
        }
    }
}

fn check_tree_size_fraud(&mut self) {
    let ctx = match &self.join_context {
        Some(c) => c,
        None => return,
    };

    let fd = &self.fraud_detection;
    let t_hours = fd.count_start.elapsed().as_secs_f64() / 3600.0;
    let expected = 3.0 * fd.subtree_size_at_start as f64 * t_hours / 8.0;

    // Wait until we have enough expected samples for valid statistics
    if expected < MIN_EXPECTED {
        return;
    }

    // Use HyperLogLog estimate instead of exact count
    let observed = fd.estimate_cardinality();

    // Combined variance accounts for both:
    // 1. Poisson variance of expected arrivals: Var(Poisson) = λ = expected
    // 2. HLL estimation error: ~6.5% std error for 256 registers
    let poisson_variance = expected;
    let hll_std_error = 0.065;  // 1.04 / sqrt(256) ≈ 0.065
    let hll_variance = (hll_std_error * observed).powi(2);
    let combined_std = (poisson_variance + hll_variance).sqrt();

    let z = (expected - observed) / combined_std;

    if z > FRAUD_Z_THRESHOLD {
        // We received significantly fewer PUBLISH than expected.
        // With 99% confidence, the tree is smaller than claimed.
        self.add_distrust(ctx.parent_at_join);
        self.leave_and_rejoin();
    }
}

fn leave_and_rejoin(&mut self) {
    self.join_context = None;
    self.fraud_detection = FraudDetection::new(self.subtree_size);
    self.parent = None;
    self.root_id = self.node_id;
    self.tree_size = self.subtree_size;
}
```

#### Memory Budget

With HyperLogLog, fraud detection uses **fixed memory regardless of network size**:

| Config | HLL Registers | Memory | Std Error | Max Network |
|--------|--------------|--------|-----------|-------------|
| SmallConfig | 64 | 64 B | 13% | Unlimited |
| DefaultConfig | 256 | 256 B | 6.5% | Unlimited |

Compare to the previous HashSet approach:
- 1,000 nodes: 16 KB → 256 B (64× reduction)
- 100,000 nodes: 1.6 MB → 256 B (6,400× reduction)

#### Distrust Management

```rust
fn add_distrust(&mut self, node: NodeId) {
    while self.distrusted.len() >= MAX_DISTRUSTED {
        if let Some(oldest) = self.distrusted.iter()
            .min_by_key(|(_, time)| *time)
            .map(|(id, _)| *id)
        {
            self.distrusted.remove(&oldest);
        } else {
            break;
        }
    }
    self.distrusted.insert(node, Instant::now());
}

fn is_distrusted(&self, node: &NodeId) -> bool {
    match self.distrusted.get(node) {
        Some(when) => when.elapsed() < DISTRUST_TTL,
        None => false,
    }
}

fn on_pulse_from_potential_parent(&mut self, pulse: &Pulse) {
    if self.is_distrusted(&pulse.node_id) {
        return;
    }
    // ... proceed with merge decision
}
```

#### Limitations

**Detection limits:**
- **Small subtrees need more time:** A leaf node (`S=1`) needs ~14 hours to reach `λ=5` for reliable statistics.
- **Slow ramp attack:** An attacker claiming ~1.3× actual size stays below detection threshold indefinitely. Only large fraud (>2×) is reliably detected.
- **Subtree size resets:** When subtree_size changes significantly (2× either way), counters reset, delaying detection.

**Sybil attacks:**
- **PUBLISH spoofing:** Attacker can generate fake PUBLISH by grinding keypairs until `hash(node_id || replica)` lands in victim's keyspace. Cost: ~`tree_size/(3×S)` keypairs per fake message. For S=10 in 1000-node tree: ~33 keypairs per fake PUBLISH. Since we count *unique* node_ids (not total messages), each fake PUBLISH requires a fresh keypair. Sustaining fraud indefinitely requires ongoing computation proportional to network size.
- **Identity rotation:** After being distrusted, attacker generates new keypair and rejoins. The distrust mechanism provides temporary relief only. Possible mitigation: progressive backoff (after N frauds in time T, become more conservative about joining any tree).

**Controlled merge attack:**
- An attacker operates a small "tree" (possibly just themselves) claiming an inflated `tree_size`
- When a legitimate node comes in radio range, it sees the attacker's larger claimed size and joins
- The attacker now controls routing for the victim's subtree until fraud detection triggers
- **Temporary win:** The attacker intercepts traffic for several hours before detection
- **Mitigation:** Fraud detection limits the attack duration. For high-security deployments, consider requiring multiple consistent Pulses before merge (merge hysteresis), though this slows legitimate merges.

**Fundamental limits:**
- **Distrust is local:** Each node detects fraud independently. No gossip (to avoid false-accusation amplification attacks).
- **Timer required:** Needs monotonic timer. Distrust state is lost on reboot.
- **No prevention, only detection:** We cannot prevent fraud, only detect it after joining. The attacker "wins" temporarily until detected.

---

## Broadcast

**Broadcast** is a single-hop message type for local radio communication, complementing multi-hop Routed messages. Like Routed, Broadcast is signed and acknowledged.

### Message Structure

```rust
// Top-level message type: wire_type = 0x04
struct Broadcast {
    src_node_id: NodeId,           // Sender's identity (16 bytes)
    destinations: Vec<ChildHash>,  // Designated recipients (varint + 4n bytes)
    payload: Vec<u8>,              // Application-specific payload
    signature: Signature,          // Signs: "BCAST:" || src_node_id || destinations || payload
}
```

### Key Properties

- **Never forwarded**: Broadcast is strictly local (single radio hop)
- **Signed**: Signature proves sender identity, enables verification
- **Acknowledged**: Recipients send explicit ACKs (same mechanism as Routed)
- **Multiple destinations**: One transmission, multiple designated recipients

### Comparison with Routed

| Property | Routed | Broadcast |
|----------|--------|-----------|
| Hops | Multi-hop (TTL-limited) | Single hop only |
| Implicit ACK | Yes (overhear forward) | No (never forwarded) |
| Explicit ACK | Yes (on duplicate) | Yes (always) |
| Addressing | Keyspace address | Explicit ChildHash list |
| Retry on timeout | Re-route | Payload-specific |

### Broadcast Payloads

Broadcast can carry different payload types, identified by the first byte:

| Payload Type | Value | Description |
|--------------|-------|-------------|
| DATA | 0x00 | Generic application data |
| BACKUP_PUBLISH | 0x01 | Location entry for backup storage |

**Retry behavior differs by payload:**
- **DATA**: Retry to the same destination
- **BACKUP_PUBLISH**: Pick a new random neighbor (any backup holder works)

---

## Routed

Unicast messages route through the tree using keyspace addresses.

### Message Structure

```rust
struct Routed {
    flags_and_type: u8,             // combined flags + message type (see below)
    next_hop: [u8; 4],              // truncated hash of intended forwarder (see below)
    dest_addr: u32,                 // keyspace location to route toward
    dest_hash: Option<[u8; 4]>,     // truncated hash(node_id) for recipient verification
    src_addr: Option<u32>,          // sender's keyspace address for replies
    src_node_id: NodeId,            // sender identity
    src_pubkey: Option<PublicKey>,  // sender's public key (optional, for signature verification)
    ttl: varint,                    // hop limit (computed from max(255, max_depth * 3))
    hops: varint,                   // actual hop count, always increments (for duplicate detection)
    payload: Vec<u8>,               // type-specific content
    signature: Signature,           // Ed25519 signature (see below)
}
```

### Flags and Type Byte Layout

```
- bits 0-3: msg_type (0-15)
- bit 4: has_dest_hash (1 = dest_hash present for recipient verification)
- bit 5: has_src_addr (1 = src_addr present for replies)
- bit 6: has_src_pubkey (1 = src_pubkey present for signature verification)
- bit 7: reserved (must be 0)
```

### Field Descriptions

**next_hop** identifies which node should forward this message:
- Computed as `hash(next_hop_node_id)[..4]` (same format as dest_hash, child hashes)
- Each forwarder sets next_hop to the hash of the next node in the route
- Nodes that receive a message but don't match next_hop ignore it (don't forward)
- This prevents message amplification in dense networks where broadcasts reach many nodes
- The destination node (who owns dest_addr) always handles the message regardless of next_hop

**msg_type values:** 0=PUBLISH, 1=LOOKUP, 2=FOUND, 3=DATA
Messages with undefined msg_type MUST be dropped silently (future extensions).
Note: ACK is a separate top-level message type (0x03), not a Routed subtype.

**dest_addr** is a keyspace location (u32). All messages route uniformly toward dest_addr:
- PUBLISH/LOOKUP: dest_addr = hash(node_id || replica_index) (the key)
- DATA/FOUND: dest_addr = target node's published keyspace address

**dest_hash** verifies the intended recipient or identifies the lookup target:
- DATA/FOUND: identifies the *recipient* of the message. Recipient verifies: `hash(my_node_id)[..4] == dest_hash`
- LOOKUP: identifies the *node being looked up* (non-standard usage—see LOOKUP section). Storage node searches for matching entry.
- PUBLISH: absent (routes to keyspace, any owner handles)

Collision probability ~2.3×10⁻¹⁰ per message (negligible).

**src_addr** is the sender's keyspace address (center of their range) for replies.

**src_pubkey** enables signature verification for messages from far-away nodes whose pubkey isn't cached from Pulses. Receivers MUST verify: `src_node_id == hash(src_pubkey)[..16]`

Include src_pubkey when: LOOKUP (so storage node can verify and respond).
Omit src_pubkey when: PUBLISH/FOUND (LOC: signature in payload has pubkey), DATA (receiver has cached pubkey).
If receiver lacks pubkey and message has none, drop message (sender retries with pubkey).

**ttl** is the hop limit, decremented at each forward. Computed as `max(255, max_depth * 3)` when creating messages—the floor of 255 ensures messages can route during tree formation when max_depth may not yet be known. On bounce-back, TTL is restored to the value when first forwarded (not reset), because bounce-backs are retransmission attempts, not forward progress.

**hops** counts actual forwards (see "Duplicate Detection and Bounce-Back" in Message Reliability section):
- Originator sends with `hops=0`
- Each forwarder increments hops before transmitting
- Retransmissions do NOT increment hops (same value as original send)
- Saturates at maximum varint value (no wrap-around)

**TTL and hops:** Both TTL and hops use varint encoding (u32 internally). TTL decrements at each hop; hops increments. Messages expire when TTL reaches 0.

### Typical Flag Combinations

- PUBLISH: has_dest_hash=0, has_src_addr=0, has_src_pubkey=0
- LOOKUP: has_dest_hash=1, has_src_addr=1, has_src_pubkey=1
- FOUND: has_dest_hash=1, has_src_addr=0, has_src_pubkey=0
- DATA: has_dest_hash=1, has_src_addr=0/1, has_src_pubkey=0/1

**Signature verification by message type:**

| Message | ROUTE: sig verified? | Why |
|---------|---------------------|-----|
| PUBLISH | No | LOC: signature in payload authenticates the location claim. Payload contains pubkey. |
| LOOKUP | Yes | Prevents amplification attacks (attacker spoofing src_addr to flood victim with FOUND). |
| FOUND | No | LOC: signature in payload authenticates the location entry. Integrity protected by LOC:. |
| DATA | Yes | Application data requires sender authentication. |

For PUBLISH and FOUND, forwarders MAY skip ROUTE: signature verification since the critical protection is the LOC: signature. Recipients MUST verify the LOC: signature in the payload before processing.

### Signature

Signature covers all fields EXCEPT ttl, hops, and next_hop (forwarders must modify these):
```
"ROUTE:" || flags_and_type || dest_addr || dest_hash || src_addr || src_node_id || payload
```
Note: src_pubkey not signed (bound to src_node_id via hash)

```rust
fn routed_sign_data(msg: &Routed) -> Vec<u8> {
    encode(b"ROUTE:", msg.flags_and_type, msg.dest_addr, &msg.dest_hash,
           &msg.src_addr, &msg.src_node_id, &msg.payload)
}
```

The signature covers all fields except `ttl`, `hops`, and `next_hop` to prevent:
- Routing manipulation (changing dest_addr)
- Reply redirection (changing src_addr)
- Type confusion (changing msg_type)
- Payload tampering

The `ttl` field is not signed because forwarders decrement it and bounce-back resets it. An attacker could reset TTL to extend message lifetime, but cannot forge the message itself.

The `hops` field is not signed because forwarders increment it. An attacker could manipulate hops to affect duplicate detection:
- Setting hops artificially high triggers bounce-back handling instead of retransmit handling, causing unnecessary delays (up to 128τ per bounce)
- Setting hops artificially low could bypass bounce-back dampening, causing extra forwarding attempts
- Maximum damage is bounded: messages still expire at TTL=0, and bounce-back gives up after MAX_RETRIES (8). The attacker can waste bandwidth and delay delivery, but cannot prevent delivery of messages that would otherwise succeed.

The `next_hop` field is not signed because forwarders must update it at each hop to specify the next forwarder. An attacker could change `next_hop` to route through a different path, but cannot change the destination (`dest_addr` is signed) or impersonate the sender.

The `dest_hash` field indicates recipient verification:
- `None` — message is for whoever owns the keyspace location (PUBLISH)
- `Some(hash)` — message is for a specific node/entry matching the hash (LOOKUP/DATA/FOUND)

---

## Routing

This section describes how messages are forwarded through the tree.

### Forward Up, Down, or Handle

Messages route toward `dest_addr` using keyspace ranges. Each hop forwards to the neighbor with the tightest range containing the destination, or upward to parent. The `next_hop` field ensures only the intended forwarder processes each hop, preventing message amplification in dense networks.

```rust
impl Node {
    // TTL computed as max(255, max_depth * 3) when creating messages
    fn route(&mut self, mut msg: Routed) {
        // TTL check - prevent routing loops
        if msg.ttl == 0 {
            return;  // drop message
        }
        msg.ttl -= 1;

        let dest = msg.dest_addr;

        // Do I own this keyspace location?
        if self.owns_key(dest) {
            let msg_type = msg.flags_and_type & 0x0F;

            // For DATA/FOUND: dest_hash must match my node_id (I'm the recipient)
            // For PUBLISH/LOOKUP: always handle if I own the keyspace
            if msg_type == DATA || msg_type == FOUND {
                if let Some(h) = msg.dest_hash {
                    if h != hash(&self.node_id)[..4] {
                        // Stale address - intended recipient no longer owns this keyspace
                        return;
                    }
                }
            }
            self.handle_locally(msg);
            return;
        }

        // Am I the intended forwarder? If not, ignore (don't forward).
        // This prevents message amplification when broadcasts reach multiple nodes.
        let my_hash = hash(&self.node_id)[..4];
        if msg.next_hop != my_hash {
            return;
        }

        // Find best next hop among children and shortcuts whose range contains dest
        if let Some(next) = self.best_downward_hop(dest) {
            msg.next_hop = hash(&next)[..4];
            self.send_to(next, msg);
        } else if let Some(parent) = self.parent {
            // No child/shortcut contains dest → route up
            msg.next_hop = hash(&parent)[..4];
            self.send_to(parent, msg);
        }
        // else: see "Queueing When No Route Available" below
    }

    fn owns_key(&self, key: u32) -> bool {
        key >= self.keyspace_lo && key < self.keyspace_hi
    }

    fn best_downward_hop(&self, dest: u32) -> Option<NodeId> {
        // Collect children and shortcuts whose range contains dest
        let mut candidates: Vec<(NodeId, u32)> = Vec::new();  // (id, range_size)

        for (child_id, (lo, hi)) in &self.child_ranges {
            if dest >= *lo && dest < *hi {
                candidates.push((*child_id, hi - lo));
            }
        }

        for (shortcut_id, (lo, hi)) in &self.shortcuts {
            if dest >= *lo && dest < *hi {
                candidates.push((*shortcut_id, hi - lo));
            }
        }

        // Pick tightest range (smallest range_size)
        candidates.into_iter()
            .min_by_key(|(_, size)| *size)
            .map(|(id, _)| id)
    }
}
```

**Routing example:**

```
Root (subtree_size=201) owns [0, 2³²):
  Root's slice: [0, ~21M)        weight 1 (itself)
  A: [~21M, ~2.1B)               subtree_size=100
  B: [~2.1B, ~3.2B)              subtree_size=50
  C: [~3.2B, 2³²)                subtree_size=50

Node X in A's subtree sends to dest_addr = 0xC0000000 (in C's range):
  X sends with next_hop=hash(A)     A is X's parent
  A receives, matches next_hop      A forwards with next_hop=hash(Root)
  Root receives, matches next_hop   Root forwards with next_hop=hash(C)
  C receives, owns dest_addr        C handles locally

All nodes in radio range hear each broadcast, but only the node matching
next_hop forwards. Others may use the overheard message for implicit ACKs.
```

### Opportunistic Receipt (PUBLISH and LOOKUP Only)

For PUBLISH and LOOKUP messages, nodes SHOULD check if they are the intended recipient even when `next_hop` doesn't match. During tree restructuring, routing paths may become stale, but the broadcast nature of radio means the correct recipient may still overhear the message.

```rust
fn handle_routed(&mut self, msg: Routed, from: NodeId) {
    let ack_hash = compute_ack_hash(&msg);
    let my_hash = hash(&self.node_id)[..4];
    let is_for_me = msg.next_hop == my_hash;

    // For PUBLISH/LOOKUP: check if we're the destination even if not next_hop
    let msg_type = msg.flags_and_type & 0x0F;
    let is_keyspace_targeted = msg_type == PUBLISH || msg_type == LOOKUP;

    if is_keyspace_targeted && !is_for_me && self.owns_key(msg.dest_addr) {
        // Opportunistic: we overheard a message destined for our keyspace
        // Add to recently_forwarded to prevent duplicate processing when
        // the message arrives via the designated forwarding path
        if self.recently_forwarded.contains(&ack_hash) {
            return;  // Already handled
        }
        self.recently_forwarded.insert(ack_hash, msg.hops, 1);
        self.handle_locally(msg);
        return;
    }

    if !is_for_me {
        return;  // Not for us, don't forward
    }

    // Normal forwarding logic...
}
```

**Why PUBLISH and LOOKUP:** These messages target keyspace locations, not specific nodes. Any node owning the destination keyspace can handle them.

**Why not FOUND or DATA:** These messages have `dest_hash` identifying a specific recipient node. A node owning the keyspace might not be the intended recipient (keyspace may have changed since the address was cached). Only the node matching `dest_hash` should process these.

**Why not forward:** The designated forwarder (`next_hop`) will also receive the broadcast and forward. If we forwarded too, we'd create duplicates. We only *handle* opportunistically, never *forward*.

**Why add to recently_forwarded:** Without this, the same message could be processed twice—once opportunistically and again when it arrives via the designated forwarding path moments later.

**Single-threaded assumption:** The check-then-insert pattern assumes message processing is single-threaded. On systems with interrupt-driven radio reception, ensure messages are queued and processed sequentially from the main loop, not handled directly in interrupt context.

### Queueing When No Route Available

When a parent node cannot route a message because:
1. `dest_addr` is within the parent's managed keyspace range, AND
2. No child has pulsed acknowledgement of owning that keyspace portion

The parent SHOULD queue the message rather than bouncing it up (or dropping if root).

**Why this happens:** After a child joins, the parent immediately knows the child's keyspace range (from the join request). However, routing is based on `neighbor_times`, which only updates when the child actually Pulses with its new keyspace. Until that first Pulse, the parent has no routing entry for the child's keyspace.

```rust
fn route(&mut self, mut msg: Routed) {
    // ... TTL check, local delivery check (owns_key returned false) ...

    let dest = msg.dest_addr;

    // Find best next hop among children and shortcuts
    if let Some(next) = self.best_downward_hop(dest) {
        msg.next_hop = hash(&next)[..4];
        self.send_to(next, msg);
    } else if self.is_in_managed_keyspace(dest) {
        // Dest is within our keyspace but we don't own it (child does)
        // and no child has pulsed with that range yet → queue
        self.queue_pending_routed(msg);
    } else if let Some(parent) = self.parent {
        // Dest is outside our keyspace → route up
        msg.next_hop = hash(&parent)[..4];
        self.send_to(parent, msg);
    } else {
        // Root: dest is outside our managed keyspace. This can happen during
        // tree churn when keyspace assignments are in flux. Queue and retry
        // when routing options change.
        self.queue_pending_routed(msg);
    }
}

fn is_in_managed_keyspace(&self, dest: u32) -> bool {
    // We've already checked owns_key (local slice), so if dest is
    // still within [keyspace_lo, keyspace_hi), it's in a child's portion
    dest >= self.keyspace_lo && dest < self.keyspace_hi
}
```

**Queue processing:** When ANY neighbor Pulses (updating `neighbor_times`), the node schedules a retry after τ delay (allowing routing info to propagate). To avoid overwhelming the outgoing queue when many messages are waiting, retries are performed incrementally:

**Incremental Retry Algorithm:**
1. Find ONE pending message from the queue (FIFO order)
2. Attempt to route it:
   - If we now own the destination, deliver locally
   - If a route exists, forward via normal routing
   - If still no route, put it back at the end of the queue
3. If more pending messages exist, schedule next retry after 2τ
4. Repeat until queue is empty or all messages have been re-checked

**Scheduling delays:**
- **On neighbor pulse:** τ delay before retry (routing info may have changed)
- **Between retries:** 2τ delay (spread traffic, avoid collisions)

**Rationale:**
- **Traffic spreading:** The delays between retries reduce collision probability on shared radio channels
- **Graceful degradation:** If the node is busy with higher-priority traffic, pending retries naturally yield
- **Consistent pattern:** Matches the incremental rebalancing approach (see "Incremental Rebalancing" in PUBLISH section)

**Bounded memory:** The queue is bounded by `MAX_PENDING_ROUTED` (512 in DefaultConfig, 128 in SmallConfig), separate from the bounce-back dampening queue (`MAX_DELAYED_FORWARDS`). Oldest entries are evicted when full. Entries expire after 320τ if no route becomes available (matching `RECENTLY_FORWARDED_TTL` to survive tree restructuring). Applications relying on delivery must implement end-to-end acknowledgment.

### Originating a Routed Message

When a node originates a message (rather than forwarding), it must compute the initial `next_hop`:

```rust
impl Node {
    fn send_routed(&mut self, dest_addr: u32, dest_hash: Option<[u8; 4]>,
                   src_addr: Option<u32>, msg_type: u8, payload: Vec<u8>) {
        // Handle locally if we own the destination
        if self.owns_key(dest_addr) {
            self.handle_locally_originated(dest_addr, dest_hash, msg_type, payload);
            return;
        }

        // Determine first hop
        let first_hop = if let Some(next) = self.best_downward_hop(dest_addr) {
            next
        } else if let Some(parent) = self.parent {
            parent
        } else {
            return;  // Isolated node, cannot send
        };

        let msg = Routed {
            flags_and_type: msg_type | compute_flags(dest_hash, src_addr, ...),
            next_hop: hash(&first_hop)[..4],
            dest_addr,
            dest_hash,
            src_addr,
            src_node_id: self.node_id,
            src_pubkey: ...,  // include if needed
            ttl: max(255, self.max_depth * 3),  // dynamic TTL
            payload,
            signature: self.sign(&routed_sign_data(...)),
        };

        self.send_to(first_hop, msg);
        self.track_pending_ack(msg, first_hop);  // for implicit ACK
    }
}
```

**Note on implicit ACKs at final hop:** When the next hop is the final destination (owns `dest_addr`), that node handles the message locally and doesn't forward. The sender won't receive an implicit ACK from overhearing a forward. In this case:
- The sender times out and may retransmit
- The destination can send an explicit ACK if it detects a duplicate
- For end-to-end reliability, applications should implement acknowledgment at the DATA message level

### Routing via Neighbor Timing

Routing uses the `neighbor_times` map (which stores pulse-reported keyspace ranges and root hashes for all neighbors) to find the best next hop. This eliminates the need for a separate "shortcuts" data structure.

**How it works:**
1. Every neighbor's `NeighborTiming` stores their pulse-reported `keyspace_range` and `root_hash`
2. When routing, we check all same-tree neighbors (matching `root_hash`) whose range contains the destination
3. We pick the neighbor with the tightest range (smallest `hi - lo`)
4. Parent is excluded from this check (it's used as fallback only)
5. Neighbors expire after 8 missed Pulses (24τ timeout)

**Routing optimization:** Non-tree neighbors enable faster routing by skipping tree hops. Since Pulses are broadcast (heard by all nodes in radio range), every node learns about all neighbors' keyspace ranges passively with no additional bandwidth cost.

**Example:**
```
         Root [0, 4B)
           │ slice: [0, 40M)
        ┌──┴──┐
    L [40M, 2B)      R [2B, 4B)
        │                │
  LL [60M, 1B)    RR [2.5B, 3.5B)
       A                 B
```
(Numbers abbreviated: M=million, B=billion, 4B ≈ 2³²)

A owns range [60M, 1B) and has R in its neighbor_times (heard R's Pulse).
A sends to dest_addr = 3B (in B's range):

- Normal route: A → L → Root → R → B = **4 hops**
- Via neighbor R: A → R → B = **2 hops**

R's range [2B, 4B) contains dest=3B, and is tighter than any other candidate, so we route through R.

---

## Message Reliability

This section describes how nodes handle packet loss on half-duplex radio links.

### The Problem

LoRa radios are half-duplex: a node cannot receive while transmitting. When node A sends to node B:
- B may be transmitting simultaneously (can't hear A)
- Radio interference may corrupt the packet
- B's receive buffer may be full

Without acknowledgment, A doesn't know if B received the message. For multi-hop Routed messages, each hop has independent loss probability. With 50% loss per hop and 64 hops, delivery probability approaches zero.

### ACK Message

```rust
// Top-level message type: wire_type = 0x03
struct Ack {
    hash: [u8; 4],          // truncated ack_hash that sender is waiting for
    sender_hash: ChildHash, // truncated hash of ACK sender (4 bytes)
}

// Wire format: 1 + 4 + 4 = 9 bytes
```

**Why ACK is a top-level message type:** ACK is intentionally minimal (9 bytes) rather than a Routed message subtype. On half-duplex radios, the original sender may have missed the forward because it was transmitting a retry. A smaller ACK has shorter time-on-air, reducing the chance of another collision. ACK needs no routing (strictly local within radio range), no signature (the hash itself proves knowledge of the forwarded message), and no complex addressing (broadcast to all neighbors).

**Why sender_hash:** For Broadcast messages with multiple destinations, the sender needs to know *which* neighbors acknowledged—not just how many ACKs arrived. Without sender identification, two ACKs from the same neighbor (due to duplicate reception) would incorrectly appear as two confirmations.

**Why 4-byte hash is sufficient:** With slow message flow on LoRa networks, collision probability within the ACK timeout window is negligible. The hash only needs to be unique among messages a node is currently waiting on (typically <10).

### Implicit ACK (Routed Only)

Since all transmissions are broadcasts, A can overhear when B forwards A's message. This serves as an implicit acknowledgment.

**Hash function:** A single `ack_hash(msg)` is used for both ACK matching and duplicate detection. It is computed **excluding TTL and next_hop**. This hash identifies the "logical message" regardless of which hop it's on or which path it takes.

**Why exclude TTL:** The same message at hop 1 (TTL=50) and hop 2 (TTL=49) is the same logical message. By excluding TTL, A can recognize B's forward even though TTL was decremented.

**Why exclude next_hop:** A cannot predict which neighbor B will choose as the next hop (B might use a shortcut A doesn't know about). By excluding next_hop, A can recognize B's forward regardless of B's routing decision.

**Sender (A) behavior:**
1. A sends `Routed` with TTL=X, next_hop=hash(B) to B
2. A stores `(ack_hash(msg), TTL=X)` in pending_acks
3. A starts exponential backoff timer
4. If A hears a message where `ack_hash` matches AND `overheard_TTL == X-1`: this is B's forward. Implicit ACK, done.
5. If timeout without ACK: A resends original (TTL=X), up to 8 retries

**Why check TTL on overhear:** If A only checked the hash, a message from further down the chain (e.g., TTL=45) that loops back could be mistaken for B's forward. By verifying `overheard_TTL == sent_TTL - 1`, A confirms this is the immediate next hop's forward.

### Duplicate Detection and Bounce-Back

When a forwarder receives a message it has seen before (same `ack_hash`), it must distinguish between:
- **Retransmission**: Upstream didn't hear our forward, wants us to ACK
- **Bounce-back**: Message traveled further, then returned due to tree restructuring

The `hops` field enables this distinction.

#### The hops Field

- Originator sends with `hops=0`
- Each forwarder increments hops before transmitting
- Retransmissions do NOT increment hops
- When first forwarding, store `(ack_hash, received_hops)` in `recently_forwarded` (hops value before incrementing)

#### Detection Algorithm

On receiving a message with `ack_hash` already in `recently_forwarded`:

| Condition | Meaning | Action |
|-----------|---------|--------|
| `received_hops == stored_hops` | Retransmission (upstream retry) | Send explicit ACK |
| `received_hops > stored_hops` | Bounce-back (message returned) | Apply dampening |
| `received_hops < stored_hops` | Anomaly (shouldn't happen) | Treat as retransmission |

**Forwarder (B) full behavior:**
1. B receives `Routed` with hops=X, next_hop=hash(B) from A
2. B verifies next_hop matches hash(B.node_id) — if not, ignore (not the intended forwarder)
3. B computes `ack_hash(msg)` and checks recently_forwarded set:
   - If hash NOT in set → new message: store (hash, received_hops=X, seen_count=1), forward with hops=X+1
   - If hash in set AND hops == stored_hops → retransmission: send ACK(ack_hash)
   - If hash in set AND hops > stored_hops → bounce-back: apply dampening (see below)
   - If hash in set AND hops < stored_hops → anomaly: treat as retransmission

**Why store hops alongside hash:** The hash identifies the "logical message" (excludes hops/TTL). But we need hops to distinguish retransmits from bounce-backs.

#### Handling Retransmissions

When `received_hops == stored_hops`, the upstream node didn't hear our forward. Instead of re-forwarding (creating duplicates), send an explicit ACK:

```rust
if received_hops == stored_hops {
    self.send_ack(ack_hash);
    return;  // Don't forward again
}
```

#### Handling Bounce-Backs

When `received_hops > stored_hops`, the message bounced back through the tree (e.g., child's keyspace changed). Apply exponential backoff dampening:

1. **ACK upstream** so they don't waste retries while we delay
2. **Clear own pending_ack** (the bounce proves downstream heard us)
3. **Increment seen_count** and refresh the `recently_forwarded` entry
4. **Schedule delayed forward** with exponential backoff

```rust
fn handle_bounce_back(&mut self, msg: Routed, ack_hash: [u8; 4]) {
    // Always ACK upstream so they don't retry while we delay (or drop)
    self.send_ack(ack_hash);

    // TTL=1 would become TTL=0 (expired) on forward - just drop it
    if msg.ttl <= 1 {
        return;
    }

    // Clear our own pending_ack if present (bounce proves downstream heard us)
    self.pending_acks.remove(&ack_hash);

    // Update recently_forwarded entry
    let entry = self.recently_forwarded.get_mut(&ack_hash).unwrap();
    entry.seen_count += 1;
    entry.expires_at = now() + self.recently_forwarded_ttl();  // Refresh expiration

    // Schedule delayed forward with exponential backoff
    // Backoff: 1τ, 2τ, 4τ, 8τ, ..., capped at 128τ
    let delay = self.tau() * (1 << min(entry.seen_count - 1, 7));
    self.schedule_delayed_forward(msg, ack_hash, entry.seen_count, delay);
}
```

**Why this helps:**
- ACK prevents upstream retry storms during long delays
- Gives the tree time to stabilize during churn
- Prevents bandwidth waste from rapid bouncing
- Message eventually delivers once tree settles

**TTL handling:** Delayed forwards restore TTL to the value when first forwarded (stored in the `recently_forwarded` entry alongside the ack_hash and seen_count), rather than decrementing. Bounce-backs are retransmission attempts, not forward progress—TTL only decrements for actual routing advancement. This prevents TTL exhaustion during tree churn.

**Entry refresh:** The `recently_forwarded` entry's expiration is reset to `now() + 320τ` on each bounce. This ensures the entry (and its `seen_count`) survives until the delayed forward fires, even for long delays like 128τ.

**Retry limit:** After `MAX_RETRIES` (8) bounces, drop the message. The sender will retry via normal ACK timeout.

#### Delayed Forward Queue

- Bounded by `MAX_DELAYED_FORWARDS` (256 in DefaultConfig, 64 in SmallConfig)
- Each entry stores: message, ack_hash, seen_count, scheduled time
- **seen_count storage:** The entry stores its own `seen_count` so backoff state survives even if the `recently_forwarded` entry is evicted under LRU pressure
- **Deduplication:** At most one delayed forward per `ack_hash`. If a new bounce arrives for a hash already in the queue, double the remaining delay
- **Eviction:** When full, drop the entry with the longest remaining delay (most likely to exceed TTL anyway)
- When the delay fires, forward with restored TTL and recompute `next_hop` based on current routing table

#### TTL=1 Behavior

When a message arrives with TTL=1, the forwarder cannot continue routing (TTL=0 means expired). If `dest_addr` is within the forwarder's keyspace, the message is delivered locally. Otherwise, the message expires silently — the sender will retry and eventually give up. The dynamic TTL calculation (`max(255, max_depth * 3)`) provides ample headroom for most networks.

#### Example Flows

**Success (no duplicates):**
```
A sends:     hops=0, TTL=255, next_hop=hash(B)
B receives:  hops=0, stores (ack_hash, hops=0)
B forwards:  hops=1, TTL=254, next_hop=hash(C)
A hears:     hops=1 == 0+1 → implicit ACK
```

**Loss + explicit ACK:**
```
A sends:     hops=0, TTL=255
B receives:  stores (ack_hash, hops=0), forwards hops=1
A misses B's forward, retransmits: hops=0
B receives:  hops=0 == stored_hops → retransmission, sends ACK
A receives:  ACK matches → done
```

**Bounce-back:**
```
A sends:     hops=0 to B
B forwards:  hops=1 to C
C forwards:  hops=2 to D
D's keyspace changed, routes back up
...bounces back to B...
B receives:  hops=5 > stored_hops=0 → bounce-back
B: ACKs upstream, schedules delayed forward with 1τ delay
```

### Retransmission Strategy

All retransmission timeouts use τ (see Timing Model) to scale with bandwidth:

```rust
const MAX_RETRIES: u8 = 8;

// Base backoffs: 1τ, 2τ, 4τ, 8τ, 16τ, 32τ, 64τ, 128τ (with ±10% jitter)
// Total worst-case: ~280τ (255τ base + jitter margin)
// For LoRa (τ=6.7s): ~31 minutes
// For UDP (τ=0.1s): ~28 seconds

struct PendingAck {
    expected_hash: [u8; 4],  // truncated ack_hash (excludes TTL and next_hop)
    sent_ttl: u8,            // TTL we sent, expect to hear TTL-1
    original_msg: Vec<u8>,   // for retransmission
    retries: u8,
    next_retry: Instant,
}

fn retry_backoff(&self, retries: u8) -> Duration {
    let base = self.tau() << retries;  // 1τ, 2τ, 4τ, ...
    let jitter_range = base.as_millis() as u64 / 5;  // ±10% jitter
    let jitter = self.random.gen_range(0, jitter_range * 2) as i64 - jitter_range as i64;
    base + Duration::from_millis(jitter.unsigned_abs())
}
```

**Memory bounds:**

```rust
const MAX_PENDING_ACKS: usize = 32;          // messages awaiting ACK
const MAX_RECENTLY_FORWARDED: usize = 512;   // for duplicate detection (DefaultConfig, reclaimable)
const ACK_HASH_SIZE: usize = 4;              // truncated hash bytes

// RECENTLY_FORWARDED_TTL = 320τ (must exceed worst-case retry sequence of ~280τ with jitter)
// For LoRa (τ=6.7s): ~36 minutes
// For UDP (τ=0.1s): ~32 seconds
fn recently_forwarded_ttl(&self) -> Duration {
    self.tau() * 320
}
```

**Memory usage (DefaultConfig):**
- `pending_acks`: 32 entries × ~16 bytes (hash + metadata) = ~512 bytes
  - Plus original messages for retransmission (bounded by MTU × 32 ≈ 8KB worst case)
- `recently_forwarded`: 512 entries × ~20 bytes (hash + timestamp + hops + seen_count) = ~10KB (reclaimable)
- `delayed_forwards`: 256 entries × ~280 bytes (hash + message + metadata) = ~70KB (reclaimable)
- `pending_routed`: 512 entries × ~280 bytes (message + timestamp) = ~140KB (reclaimable)
- Total metadata: ~10KB, message storage: ~210KB peak (reclaimable when idle)

**Why these values:**
- `RECENTLY_FORWARDED_TTL = 320τ`: Must exceed worst-case retry sequence (~280τ with jitter). Provides ~14% margin.
- `MAX_RECENTLY_FORWARDED = 512` (DefaultConfig) / `128` (SmallConfig): Forwarding rate scales inversely with τ (slow links forward slowly), so the product (TTL × rate) stays roughly constant. Generous limit is acceptable because these are reclaimable.
- `MAX_PENDING_ACKS = 32`: Limits concurrent outbound messages awaiting ACK. With worst-case ~280τ per message, throughput floor is ~32/280τ messages per τ under heavy loss.
- `MAX_DELAYED_FORWARDS = 256` (DefaultConfig) / `64` (SmallConfig): Sized to handle burst bounce-backs during tree restructuring. Reclaimable, so generous limit is acceptable.
- `MAX_PENDING_ROUTED = 512` (DefaultConfig) / `128` (SmallConfig): Messages queued when no route available. Reclaimable.

When collections are full, entries are evicted:
- Evicted pending_ack (LRU): give up on that message (application can retry)
- Evicted recently_forwarded (LRU): may forward a duplicate (harmless, just wasteful)
- Evicted delayed_forward (longest delay): drop message most likely to exceed TTL anyway

### Hash Collision Tolerance

The 4-byte (32-bit) `ack_hash` provides acceptable collision resistance for the expected message rates:

- **Birthday bound:** Collisions become likely after ~2^16 (~65k) messages.
- **Per-entry collision probability:** With 32 `pending_acks` entries, probability of a collision is ~32/2^32 ≈ 1 in 134 million.
- **Practical impact:** For LoRa networks with ~0.05 msg/s throughput, 65k messages would take ~15 days—well beyond any single pending ACK lifetime.

If a collision does occur:
- A message might be incorrectly identified as a duplicate and not forwarded.
- Or an ACK might satisfy the wrong pending message.

Both cases result in a single message loss, which is acceptable given the design's explicit non-goal of exactly-once delivery. The hash only needs to be unique among the small set of messages a node is concurrently waiting on (typically <10).

### Timing Considerations

**Time-on-air at SF8 @ 125kHz:**
- Symbol time ≈ 2ms
- ~3-5ms per payload byte
- 150-byte Pulse ≈ 500-750ms airtime
- 100-byte Routed ≈ 300-500ms airtime

**Minimum time for forwarder to respond:**
1. Receive full packet (~500ms)
2. Process and decide to forward (~10ms)
3. Possible duty cycle delay (0 to many τ under congestion)
4. Transmit forwarded packet (~500ms)

Under normal conditions: ~0.1τ. Under duty cycle pressure: could be several τ.

### Stale Route Recovery

When retransmissions fail repeatedly (e.g., MAX_RETRIES reached), the sender should invalidate the route:

1. **Shortcut used:** Remove the shortcut from the routing table. The shortcut target may have left the network or moved out of range.
2. **Parent used:** This indicates potential partition. The node should start monitoring parent liveness more aggressively.

After invalidation, the next send attempt will recompute the route using remaining valid neighbors.

### What This Doesn't Provide

- **End-to-end reliability:** Only hop-by-hop. Multi-hop messages may still fail if every hop loses 50%.
- **Ordering guarantees:** Messages may arrive out of order
- **Exactly-once delivery:** Receivers must handle duplicates (same signature = same message)

Applications needing stronger guarantees should implement their own ack/retry at the DATA message level.

---

## DATA

DATA is a Routed message subtype (msg_type=3) for application payload delivery.

### Sending Data

```rust
impl Node {
    fn send_data(&self, target_id: NodeId, target_addr: u32, data: Vec<u8>) {
        self.send_routed(Routed {
            flags_and_type: DATA | HAS_DEST_HASH | HAS_SRC_ADDR,
            dest_addr: target_addr,
            dest_hash: Some(hash(&target_id)[..4]),
            src_addr: Some(self.my_address()),
            payload: data,
            ...
        });
    }
}
```

### Stale Address Handling

During tree reshuffles, cached keyspace addresses may become stale.

**For request-response patterns:** Timeout triggers re-lookup and retry:

```rust
impl Node {
    fn send_request(&mut self, target_id: NodeId, data: Vec<u8>) {
        if let Some(addr) = self.location_cache.get(&target_id) {
            self.send_data(target_id, *addr, data.clone());
            self.pending_requests.insert(target_id, PendingRequest {
                data,
                sent_at: now(),
                retries: 0,
            });
        } else {
            self.pending_data.insert(target_id, data);
            self.lookup_node(target_id);
        }
    }

    fn check_request_timeouts(&mut self) {
        for (target_id, req) in self.pending_requests.iter_mut() {
            if now() - req.sent_at > REQUEST_TIMEOUT {
                if req.retries < MAX_RETRIES {
                    self.location_cache.remove(target_id);
                    self.lookup_node(*target_id);
                    req.retries += 1;
                } else {
                    self.on_request_failed(*target_id);
                }
            }
        }
    }
}
```

**For fire-and-forget:** Accept possible loss during reshuffles (rare events).

---

## Location Directory

The location directory is a distributed hash table (DHT) that maps node IDs to their current keyspace addresses. This enables any node to find and message any other node by ID.

### Replicas

Each location is published to k=3 independent storage nodes:

```rust
const K_REPLICAS: usize = 3;

fn replica_addr(node_id: &NodeId, replica_index: u8) -> u32 {
    hash_to_u32(&[&node_id[..], &[replica_index]].concat())
}
```

```
replica_0_key = hash(node_id || 0x00)
replica_1_key = hash(node_id || 0x01)
replica_2_key = hash(node_id || 0x02)
```

Replicas are distributed across different parts of the tree, increasing the chance that at least one replica survives link failures or subtree partitions.

### PUBLISH

A node publishes its location to announce where it can be reached.

#### Location Entry Structure

```rust
struct LocationEntry {
    node_id: NodeId,            // owner's identity
    pubkey: PublicKey,          // owner's public key
    keyspace_addr: u32,         // center of owner's keyspace range
    seq: u32,                   // sequence number for replay protection
    replica_index: u8,          // 0, 1, or 2 (for rebalancing)
    signature: Signature,       // location signature (LOC: prefix)
    received_at: Instant,       // local-only, set on receipt (not transmitted)
    hops: u32,                  // hops when received (for rebalance, not transmitted)
}

// Location signature covers:
// "LOC:" || node_id || keyspace_addr || seq
fn location_sign_data(node_id: &NodeId, keyspace_addr: u32, seq: u32) -> Vec<u8> {
    encode(b"LOC:", node_id, keyspace_addr, seq)
}
```

The location signature uses a separate "LOC:" domain prefix, allowing storage nodes to forward entries during rebalancing without re-signing. The signature proves the owner's claim to the keyspace address.

**Varint encoding:** All varint fields (seq, subtree_size, tree_size) use LEB128 encoding. Implementations MUST use canonical (minimal) encoding: the shortest byte sequence that represents the value. Non-minimal encodings (e.g., `0x80 0x00` for 0 instead of `0x00`) MUST be rejected during decoding to prevent signature ambiguity attacks. Standard libraries like `integer-encoding` or `postcard` handle this correctly.

The LOC: signature in the PUBLISH payload authenticates the location claim. The ROUTE: signature on the outer Routed message is defense-in-depth (PUBLISH omits src_pubkey since the payload already contains the pubkey). Storage nodes reject entries with `seq <= current_seq` for the same node_id.

**Sequence number recovery after reboot:**

If a node loses its `location_seq` state, all its PUBLISH messages will be rejected until `seq` exceeds the value stored at replicas. Options:

1. **Accept delay (recommended)** — Do nothing special. Old entries expire after 12 hours, then new publishes succeed. Simplest, and state loss is rare enough that 12-hour delay is acceptable.

2. **Persist reliably** — Write `location_seq` to flash before each publish. Faster recovery but causes flash wear on embedded devices.

3. **Epoch-based sequence** — Use `seq = (coarse_time << 24) | counter` where `coarse_time` is hours since some epoch. Requires rough time source.

Implementers may choose based on their hardware constraints and recovery time requirements.

#### Publishing Process

```rust
// Jitter for republish: 0 to 1τ (prevents storms during tree reshuffles)

struct Node {
    location_seq: u32,  // persisted, incremented on each publish (varint 1-5 bytes on wire)
    // ...
}

impl Node {
    fn publish_location(&mut self) {
        self.location_seq += 1;
        let my_addr = self.my_address();

        // Sign the location claim
        let loc_sig = sign(b"LOC:", &self.node_id, my_addr, self.location_seq);

        for replica in 0..K_REPLICAS {
            let key = hash_to_u32(&[&self.node_id[..], &[replica as u8]].concat());
            let payload = encode(&self.node_id, &self.pubkey, my_addr,
                                 self.location_seq, replica as u8, &loc_sig);
            self.send_routed(Routed {
                flags_and_type: PUBLISH | HAS_SRC_ADDR | HAS_SRC_PUBKEY,
                dest_addr: key,
                dest_hash: None,
                src_addr: Some(my_addr),
                payload,
                ...
            });
        }
    }

    fn on_keyspace_changed(&mut self) {
        // Jitter prevents publish storms during tree reshuffles
        let jitter_ms = self.random.gen_range(0, self.tau().as_millis() as u64);
        self.schedule_publish_after(Duration::from_millis(jitter_ms));
    }
}
```

**PUBLISH payload:** `node_id (16) || pubkey (32) || keyspace_addr (4) || seq (varint) || replica_index (1) || location_signature (65)`

Typical size: 119-123 bytes. The payload is self-contained—storage nodes can verify and forward it without accessing the Routed header.

**Rebalancing:** When keyspace ownership changes (e.g., a new child joins), the storage node forwards stored entries to new owners. The location signature remains valid because it doesn't depend on routing path.

##### Incremental Rebalancing

When keyspace ownership changes (e.g., a child joins/leaves), the storage node must forward entries it no longer owns to their new owners. To avoid overwhelming the outgoing queue during large keyspace shifts, rebalancing is performed incrementally:

**Algorithm:**
1. Find ONE entry where `!owns_key(replica_addr(entry))`
2. Remove it from local storage
3. Re-publish to the correct owner via normal PUBLISH routing, using `hops = entry.hops + 1`
4. If more unowned entries exist, schedule next rebalance after 2τ
5. Repeat until no unowned entries remain

**Hops increment:** The republished message uses `hops = entry.hops.saturating_add(1)` rather than `hops = 0`. This prevents intermediate nodes (which may still have `recently_forwarded` entries from the original delivery) from misdetecting the republish as a retransmission. The goal is to avoid hitting `received_hops == stored_hops` (exact equality), which would trigger retransmission detection and cause the message to be dropped. Since `entry.hops` reflects the hops at storage time, and intermediate nodes stored lower values (they're closer to the origin), the rebalanced message with `hops = entry.hops + 1 + routing_hops` will always exceed any intermediate node's `stored_hops`, triggering bounce-back handling which correctly forwards with dampening.

**Hops saturation:** If `entry.hops == u32::MAX`, the saturating add produces `u32::MAX`. When the message is forwarded and hops is incremented again, it remains at `u32::MAX`, eventually causing the message to be dropped when TTL expires. This is acceptable—an entry that has been rebalanced billions of times without a fresh PUBLISH from the owner is stale anyway.

**Fresh TTL:** Rebalancing creates a new Routed message with fresh TTL (not a modified version of the original). This is correct because rebalancing is a new routing cycle, not a continuation of the original delivery.

**Rationale:**
- **Bounded work per tick:** Processing one entry at a time keeps CPU and queue usage predictable
- **Traffic spreading:** The 2τ delay between entries reduces collision probability on shared radio channels
- **Graceful degradation:** If the node is busy, rebalancing naturally yields to higher-priority work

**Memory:** No additional allocation—uses the existing location_store iteration.

#### Storing Published Data

**PUBLISH verification order** (storage node receiving a PUBLISH):
1. Verify Routed signature (defense-in-depth; LOC: signature is critical protection)
2. Parse PUBLISH payload: `node_id`, `pubkey`, `keyspace_addr`, `seq`, `replica_index`, `location_signature`
3. Verify keyspace ownership: we own a replica key for `payload.node_id`
4. Verify `payload.pubkey` binds to `payload.node_id`: `hash(pubkey)[..16] == node_id`
5. Verify LOC: signature: `verify(pubkey, "LOC:" || node_id || keyspace_addr || seq, signature)`
6. Verify `seq > existing_seq` for this `node_id` (replay protection)
7. Store entry with current timestamp for expiry tracking, and set `entry.hops` from the received message's hops value

**Hops on store:** The `entry.hops` field is set on every store operation, whether from a fresh PUBLISH by the owner or a rebalance republish. When the owner sends a fresh PUBLISH (with incremented `seq`), the entry arrives with low hops (reflecting the new routing path), effectively resetting accumulated hops from previous rebalance cycles.

Note: The Routed `src_node_id` may differ from `payload.node_id` during rebalancing (storage nodes forward entries they no longer own). The LOC: signature is the authoritative proof of the location claim.

### BACKUP_PUBLISH

While replication spreads entries across the tree, node churn can cause data loss when storage nodes die. **Broadcast backup** provides redundancy by having storage nodes notify neighbors to hold backup copies.

#### Sending Backups

When a storage node stores a location entry, it sends a BACKUP_PUBLISH via Broadcast to create backups:

```rust
struct BackupPublish {
    payload_type: u8,       // 0x01 = BACKUP_PUBLISH
    publish: LocationEntry, // The entry to back up
}

impl Node {
    fn on_location_stored(&mut self, entry: &LocationEntry) {
        // Skip if we already have confirmed backups for this (node_id, replica_index, seq)
        if self.has_confirmed_backups(entry) {
            return;
        }

        // Select up to 2 random neighbors as backup holders
        let destinations = self.select_random_neighbors(2);
        if destinations.is_empty() {
            return; // No neighbors, cannot create backup
        }

        // Send signed broadcast with BACKUP_PUBLISH payload
        let payload = encode_backup_publish(entry);
        self.send_broadcast(Broadcast {
            src_node_id: self.node_id,
            destinations,
            payload,
            signature: self.sign(b"BCAST:", &self.node_id, &destinations, &payload),
        });

        // ACK mechanism will track pending confirmation
        // On ACK receipt, we learn who successfully stored the backup
    }
}
```

The backup holder can verify the entry belongs to the sender by checking the PUBLISH's `dest_addr` against the sender's keyspace range (known from their Pulse).

#### Storing Backups (8-step verification)

Backup holders perform a comprehensive verification chain:

```rust
impl Node {
    fn on_broadcast_received(&mut self, bcast: &Broadcast) {
        // 1. Verify I'm a designated recipient
        if !bcast.destinations.contains(&self.my_child_hash()) {
            return;
        }

        // 2. Verify sender is a known neighbor (we've heard their Pulse)
        let sender_info = match self.neighbor_info(&bcast.src_node_id) {
            Some(info) => info,
            None => return, // Unknown sender
        };

        // 3. Verify Broadcast signature
        if !self.verify_signature(&bcast.src_node_id, b"BCAST:", &bcast) {
            return;
        }

        // Parse payload
        let (payload_type, payload_data) = parse_broadcast_payload(&bcast.payload);

        match payload_type {
            BACKUP_PUBLISH => self.handle_backup_publish(bcast, sender_info, payload_data),
            DATA => self.handle_broadcast_data(bcast, payload_data),
            _ => return, // Unknown payload type
        }
    }

    fn handle_backup_publish(&mut self, bcast: &Broadcast, sender_info: &NeighborInfo, data: &[u8]) {
        let entry = match decode_location_entry(data) {
            Ok(e) => e,
            Err(_) => return,
        };

        // 4. Verify sender owns the keyspace for this entry
        //    (PUBLISH dest_addr must be in sender's keyspace range from their Pulse)
        let dest_addr = replica_addr(&entry.node_id, entry.replica_index);
        if !sender_info.keyspace_contains(dest_addr) {
            return; // Sender doesn't own this entry
        }

        // 5. Verify the PUBLISH's LOC: signature
        if !self.verify_location_signature(&entry) {
            return;
        }

        // 6. Check seq (only store if newer)
        let key = (entry.node_id, entry.replica_index);
        if let Some(existing) = self.backup_store.get(&key) {
            if entry.seq <= existing.entry.seq {
                return; // Old entry
            }
        }

        // 7. Per-neighbor limit
        let sender_hash = truncated_hash(&bcast.src_node_id);
        let count = self.backup_store.values()
            .filter(|b| b.backed_up_for == sender_hash)
            .count();
        if count >= MAX_BACKUPS_PER_NEIGHBOR {
            return; // Reject to prevent pollution
        }

        // 8. Evict oldest if at capacity
        if self.backup_store.len() >= MAX_BACKUP_STORE {
            self.evict_oldest_backup();
        }

        // Store backup
        self.backup_store.insert(key, BackupEntry {
            entry,
            backed_up_for: sender_hash,
        });

        // Send ACK - sender will learn we have the backup
        self.send_ack(ack_hash(&bcast));
    }
}
```

**Verification summary:**
1. I'm a designated recipient
2. Sender is a known neighbor (heard their Pulse)
3. Broadcast signature is valid
4. Sender's keyspace contains the PUBLISH dest_addr
5. PUBLISH LOC: signature is valid
6. Seq is newer than existing backup
7. Sender hasn't exceeded per-neighbor limit
8. Evict oldest if at capacity

### Backup Persistence and Recovery

#### Watching Your Backup Providers

When a storage node stores a location entry, it sends BACKUP_PUBLISH and tracks which neighbors ACK'd:

```rust
impl Node {
    fn on_ack_received(&mut self, ack: &Ack) {
        // Check if this ACK is for a pending Broadcast
        if let Some(pending) = self.pending_broadcast_acks.get_mut(&ack.hash) {
            // Record which neighbor confirmed (using sender_hash from ACK)
            if pending.destinations.contains(&ack.sender_hash) &&
               !pending.confirmed_by.contains(&ack.sender_hash) {
                pending.confirmed_by.push(ack.sender_hash);
            }

            // If all destinations confirmed, we're done
            if pending.confirmed_by.len() >= pending.destinations.len() {
                self.pending_broadcast_acks.remove(&ack.hash);
            }
        }

        // ... also check for Routed ACKs ...
    }
}
```

**No explicit backup tracking needed.** The `sender_hash` in the ACK identifies which neighbor confirmed. The storage node doesn't maintain separate backup tracking—ACKs provide confirmation, and timeouts trigger retries to new random neighbors.

On ACK timeout, retry behavior depends on payload type:

```rust
impl Node {
    fn on_broadcast_timeout(&mut self, pending: &PendingBroadcast) {
        match pending.payload_type {
            DATA => {
                // Retry to same destinations
                self.retry_broadcast(pending);
            }
            BACKUP_PUBLISH => {
                // Pick new random neighbors (any backup holder works)
                let new_destinations = self.select_random_neighbors(2);
                if !new_destinations.is_empty() {
                    self.send_broadcast_with_destinations(pending.payload, new_destinations);
                }
            }
        }
    }
}
```

#### Watching Your Backup Clients

When a backup holder detects the storage node has departed (stopped sending Pulses), it republishes:

```rust
impl Node {
    fn on_neighbor_timeout(&mut self, departed: ChildHash, now: Timestamp) {
        // Find all entries we backed up for this storage node
        let to_republish: Vec<LocationEntry> = self.backup_store
            .iter()
            .filter(|(_, b)| b.backed_up_for == departed)
            .map(|(_, b)| b.entry.clone())
            .collect();

        // Schedule republishes with jitter
        for entry in to_republish {
            let delay = self.tau() + self.random_jitter(2 * self.tau());
            self.pending_republish.push(PendingRepublish {
                entry: entry.clone(),
                dest_addr: replica_addr(&entry.node_id, entry.replica_index),
                scheduled_at: now + delay,
            });
        }

        // Remove entries for departed storage node
        self.backup_store.retain(|_, b| b.backed_up_for != departed);
    }
}
```

**Republish target:** Entries are republished to their original replica address. Routing delivers them to whoever now owns that keyspace.

**Hops handling:** When creating the PUBLISH message for republish, use `hops = entry.hops.saturating_add(1)` (same as storage node rebalancing). This ensures intermediate nodes correctly handle the republish as a new routing cycle rather than a retransmission.

**Deduplication:** When multiple backup holders detect the same departure, both schedule republishes. The first to fire may be overheard by the second:

```rust
impl Node {
    fn on_publish_overheard(&mut self, entry: &LocationEntry) {
        // Cancel pending republish if we see a newer or equal seq
        self.pending_republish.retain(|pending| {
            !(pending.entry.node_id == entry.node_id &&
              pending.entry.replica_index == entry.replica_index &&
              entry.seq >= pending.entry.seq)
        });
    }
}
```

**Note:** Overhear-based cancellation is opportunistic. Duplicate entries at the storage node are handled by seq comparison—only the highest seq is kept.

**Jitter timing:** 1τ base + 0-2τ random jitter spreads republishes over 1-3τ.

### LOOKUP

Lookups find a node's current keyspace address by querying replicas.

```rust
// LOOKUP_TIMEOUT = 3τ + 3τ × max_tree_depth per replica
// Accounts for: multi-hop routing (2×depth), retransmissions at each hop
// For LoRa (τ=6.7s) with 10-deep tree: ~33τ ≈ 3.7 minutes per replica
// For UDP (τ=0.1s) with 10-deep tree: ~33τ ≈ 3.3 seconds per replica
//
// max_tree_depth source: use the root's max_depth from its Pulse if known,
// otherwise use a conservative estimate based on expected network size.
fn lookup_timeout(&self) -> Duration {
    self.tau() * (3 + 3 * self.max_tree_depth as u32)
}

impl Node {
    fn lookup_node(&mut self, target: NodeId) {
        self.pending_lookups.insert(target, PendingLookup {
            replica_index: 0,
            started: now(),
        });
        self.send_lookup(target, 0);
    }

    fn send_lookup(&self, target: NodeId, replica: usize) {
        let key = hash_to_u32(&[&target[..], &[replica as u8]].concat());
        self.send_routed(Routed {
            flags_and_type: LOOKUP | HAS_DEST_HASH | HAS_SRC_ADDR,
            dest_addr: key,                           // route toward this key
            dest_hash: Some(hash(&target)[..4]),      // identifies who we're looking for
            src_addr: Some(self.my_address()),        // for FOUND reply
            payload: encode(replica as u8),           // just replica_index
            ...
        });
    }

    fn handle_lookup(&self, msg: Routed) {
        let replica: u8 = decode(&msg.payload);
        let dest_hash = msg.dest_hash.unwrap();

        // Find entry matching dest_hash
        if let Some(entry) = self.location_store.values()
            .find(|e| hash(&e.node_id)[..4] == dest_hash)
        {
            // Verify key matches (dest_addr should equal hash(node_id || replica))
            let expected_key = hash_to_u32(&[&entry.node_id[..], &[replica]].concat());
            if expected_key != msg.dest_addr {
                return;  // key mismatch, wrong replica
            }

            // Return complete location entry
            let payload = encode(&entry.node_id, &entry.pubkey, entry.keyspace_addr,
                                 entry.seq, entry.replica_index, &entry.signature);
            self.send_routed(Routed {
                flags_and_type: FOUND | HAS_DEST_HASH,
                dest_addr: msg.src_addr.unwrap(),     // route back to requester
                dest_hash: Some(hash(&msg.src_node_id)[..4]),
                src_addr: None,  // no reply expected
                payload,
                ...
            });
        }
        // No response if not found — requester will try next replica
    }
}
```

**LOOKUP payload:** `replica_index (1)` = 1 byte

**Non-standard dest_hash usage:** Unlike DATA and FOUND where `dest_hash` identifies the *recipient* of the message, in LOOKUP `dest_hash` identifies the *node being looked up* (the subject of the query). The storage node receiving the LOOKUP is determined by `dest_addr` (the replica key), not `dest_hash`. This allows the storage node to find the correct location entry by matching `dest_hash` against stored entries, and verify the key matches the expected replica address.

**Lookup process:**
1. Send LOOKUP for replica 0
2. If no FOUND within LOOKUP_TIMEOUT (3τ + 3τ × max_tree_depth), try replica 1
3. If still no response, try replica 2
4. After all replicas timeout, lookup fails

### FOUND

FOUND returns a location entry to the requesting node.

```rust
impl Node {
    fn handle_found(&mut self, msg: Routed) {
        let (node_id, pubkey, keyspace_addr, seq, _, signature) = decode(&msg.payload);

        if !self.pending_lookups.contains_key(&node_id) {
            return;  // no matching pending lookup
        }

        // Verify pubkey binds to node_id
        if hash(&pubkey)[..16] != node_id {
            return;
        }

        // Verify location signature
        let sign_data = encode(b"LOC:", &node_id, keyspace_addr, seq);
        if !verify(&pubkey, &sign_data, &signature) {
            return;
        }

        // Replay protection: reject stale entries
        // This prevents attackers from redirecting traffic to old keyspace addresses
        if let Some(&(_, cached_seq)) = self.location_cache.get(&node_id) {
            if seq <= cached_seq {
                return;  // stale entry, ignore
            }
        }

        self.pending_lookups.remove(&node_id);

        // Cache location (with seq for replay protection) and pubkey
        self.location_cache.insert(node_id, (keyspace_addr, seq));
        self.pubkey_cache.insert(node_id, pubkey);
    }
}
```

**FOUND payload:** `node_id (16) || pubkey (32) || keyspace_addr (4) || seq (varint) || replica_index (1) || location_signature (65)` = 119-123 bytes

FOUND returns the complete location entry, including the location signature. The requester can verify the location claim and cache both the pubkey and keyspace address.

### TTL and Expiration

Expiry is handled entirely by storage nodes using local clocks:

| Parameter | Value |
|-----------|-------|
| Storage TTL | 12 hours |
| Backup TTL | 12 hours (same as primary) |
| Refresh interval | 8 hours |
| Republish trigger | Published address no longer in our keyspace range |

```rust
fn cleanup_expired(&mut self) {
    let cutoff = Instant::now() - Duration::from_secs(12 * 3600);
    // Clean both primary and backup stores
    self.location_store.retain(|_, e| e.received_at > cutoff);
    self.backup_store.retain(|_, b| b.entry.received_at > cutoff);
}
```

Dead nodes stop refreshing → entries expire → no stale data.

**Backup expiration:** Backups use the same 12-hour TTL as primary entries. If the storage node doesn't refresh (because it died), backup holders will republish on neighbor timeout. If the owning node doesn't refresh (because it died), entries naturally expire after 12 hours—this is correct behavior for a dead node.

---

## ID Routing

This section shows the complete flow for finding and messaging a node by ID.

### Complete Example

Node A wants to send data to node B:

**Step 1: A looks up B's location**
```
A computes: key = hash(B.node_id || 0x00) → 0x7A3F0000
A sends: LOOKUP with dest_addr=0x7A3F0000, dest_hash=hash(B)[..4]
```

**Step 2: Storage node responds**
```
Storage node finds B's entry, sends FOUND to A
Payload: B.pubkey || B.keyspace_addr || B.seq
```

**Step 3: A verifies and sends DATA**
```
A derives B.node_id from B.pubkey, caches both
A sends: DATA with dest_addr=B.keyspace_addr, dest_hash=hash(B)[..4]
```

**Step 4: B receives DATA**
```
B's keyspace range contains dest_addr
B verifies dest_hash matches hash(B.node_id)[..4]
B processes payload
```

---

## Wire Format

This section provides byte-level layouts for all message types.

### Protocol Version

The first byte of every message encodes both version and type:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|  Version  |Typ|
+-+-+-+-+-+-+-+-+

Byte 0: [version:5][type:3]
- Upper 5 bits (bits 7-3): Protocol version (0-31)
- Lower 3 bits (bits 2-0): Message type (0-7)

Current version: 0 (version 0)
Message types:
  0 = reserved
  1 = Pulse     (0x01)
  2 = Routed    (0x02)
  3 = ACK       (0x03)
  4 = Broadcast (0x04)
  5-7 = reserved

Example: Pulse message = 0x01 (version 0, type 1)
Future version 1 Pulse = 0x09 (version 1, type 1) — (1 << 3) | 1
```

- Nodes SHOULD ignore messages with unknown versions
- Version 0 is the initial protocol version
- 5 bits allows versions 0-31 (ample room for evolution)
- 3 bits allows 8 message types (4 defined, 4 reserved)

### Pulse Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver=0 |Typ=1|                                                 |
+-+-+-+-+-+-+-+-+                                               +
|                          node_id (16 bytes)                   |
+                                               +-+-+-+-+-+-+-+-+
|                                               |     flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   parent_hash (0 or 4 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         root_hash (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| depth (varint 1-5) | max_depth (varint 1-5) | subtree_size ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
... (varint 1-5)  |   tree_size (varint 1-5)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       keyspace_lo (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       keyspace_hi (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     pubkey (0 or 32 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    children (N × 4+varint)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| alg=1 |                  signature (64 bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Flags byte:**
- bit 0: has_parent
- bit 1: need_pubkey
- bit 2: has_pubkey
- bit 3: unstable (node is in transition, don't join as child)
- bits 4-7: child_count (0-12)

**Depth fields:**
- `depth` (varint): Distance from root. Root has depth=0. No protocol limit; bounded by physics.
- `max_depth` (varint): Maximum depth in this node's subtree. Leaf has max_depth=depth.

Pulses with `max_depth < depth` MUST be rejected during parsing (invalid by construction). Typical shallow trees use 1 byte per field (values < 128).

**Note:** The `subtree_size` and `tree_size` fields are varints with variable length (1-3 bytes each). Fields after these varints have variable byte offsets. The diagram shows typical placement; actual offsets depend on varint lengths.

### Routed Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver=0 |Typ=2| flags_and_type|                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                        next_hop (4 bytes)                     |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+         dest_addr (4 bytes)                   +
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |   dest_hash (0 or 4 bytes)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    src_addr (0 or 4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       src_node_id (16 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   src_pubkey (0 or 32 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ttl (varint)  | hops (varint) |      payload (variable)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| alg=1 |                  signature (64 bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**flags_and_type byte:**
- bits 0-3: msg_type (0=PUBLISH, 1=LOOKUP, 2=FOUND, 3=DATA)
- bit 4: has_dest_hash
- bit 5: has_src_addr
- bit 6: has_src_pubkey
- bit 7: reserved (must be 0)

**ttl** is a varint (typically 1-2 bytes) computed as `max(255, max_depth * 3)`. On bounce-back, TTL is restored to the value when first forwarded (not reset), because bounce-backs are retransmission attempts, not forward progress.

**hops** is a varint (typically 1 byte) that counts actual forwards. hops always increments at each hop.

### ACK Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver=0 |Typ=3|                    hash (4 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   (continued) |             sender_hash (4 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   (continued) |
+-+-+-+-+-+-+-+-+

Total: 9 bytes
```

### Broadcast Layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver=0 |Typ=4|                                                 |
+-+-+-+-+-+-+-+-+                                               +
|                       src_node_id (16 bytes)                  |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  dest_count   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                   destinations (N × 4 bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       payload (variable)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| alg=1 |                  signature (64 bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Routed Payload Types

| Type | Value | Payload Format |
|------|-------|----------------|
| PUBLISH | 0 | node_id (16), pubkey (32), keyspace_addr (4), seq (varint), replica_index (1), location_sig (65) |
| LOOKUP | 1 | replica_index (1) |
| FOUND | 2 | node_id (16), pubkey (32), keyspace_addr (4), seq (varint), replica_index (1), location_sig (65) |
| DATA | 3 | application data |

### Broadcast Payload Types

| Type | Value | Payload Format |
|------|-------|----------------|
| DATA | 0x00 | application data |
| BACKUP_PUBLISH | 0x01 | LocationEntry (same format as PUBLISH/FOUND payload) |

### Domain Separation Prefixes

| Prefix | Usage |
|--------|-------|
| `"PULSE:"` | Pulse signatures (tree maintenance) |
| `"ROUTE:"` | Routed message signatures (all message types) |
| `"LOC:"` | Location signatures (PUBLISH/FOUND payloads) |
| `"BCAST:"` | Broadcast message signatures |

### Byte Order

All multi-byte integers are encoded in **big-endian** (network byte order).

### Varint Encoding

All varint fields use **unsigned LEB128** encoding with canonical (minimal) form required. Non-minimal encodings MUST be rejected.

**Maximum byte lengths:**
- `subtree_size`, `tree_size`: 3 bytes max (values up to 2,097,151)
- `seq`: 5 bytes max (full u32 range)
- `dest_count` in Broadcast: 1 byte (u8, not varint)

### Payload Length Determination

For Routed and Broadcast messages, the payload has variable length. Receivers determine payload boundaries as follows:

1. Parse fixed fields and optional fields (based on flags)
2. The last 65 bytes are always the signature (1 byte algorithm + 64 bytes Ed25519)
3. Payload = remaining bytes between parsed fields and signature

For Routed: `payload_length = message_length - fixed_header - optional_fields - 65`

### Hash Functions

**hash_to_u32(data):** Computes a 32-bit hash from arbitrary data. Used for replica addresses and other keyspace mappings.
```
hash_to_u32(data) = big_endian_u32(sha256(data)[0..4])
```

**ack_hash(msg):** Computes the 4-byte hash used for ACK matching and duplicate detection. Excludes TTL and next_hop (which change during forwarding) so the same logical message produces the same hash at every hop.

For Routed messages:
```
ack_hash(routed) = sha256(
    flags_and_type ||
    dest_addr (4 bytes, big-endian) ||
    dest_hash (0 or 4 bytes, per flags) ||
    src_addr (0 or 4 bytes, per flags) ||
    src_node_id (16 bytes) ||
    payload
)[0..4]
```

For Broadcast messages:
```
ack_hash(broadcast) = sha256(
    src_node_id (16 bytes) ||
    dest_count (1 byte) ||
    destinations (N × 4 bytes) ||
    payload
)[0..4]
```

### Signature Encoding

Signatures are computed over a canonical byte encoding of message fields. The encoding concatenates fields in the order listed, using:
- Fixed-size fields: raw bytes in big-endian order
- Varints: LEB128 encoded bytes (same as wire format)
- Optional fields: omitted entirely if not present (not encoded as zeros)
- Variable-length fields (payload, children): raw bytes as they appear on wire

**Pulse signature input:**
```
"PULSE:" || node_id || flags || [parent_hash if has_parent] || root_hash ||
depth || max_depth || subtree_size (varint) || tree_size (varint) ||
keyspace_lo || keyspace_hi || [pubkey if has_pubkey] || children (raw wire encoding)
```

**Routed signature input:**
```
"ROUTE:" || flags_and_type || dest_addr || [dest_hash if has_dest_hash] ||
[src_addr if has_src_addr] || src_node_id || payload
```
Note: src_pubkey is NOT signed (it's bound to src_node_id via hash).

**Broadcast signature input:**
```
"BCAST:" || src_node_id || dest_count || destinations || payload
```

**Location signature input:**
```
"LOC:" || node_id || keyspace_addr (4 bytes) || seq (varint)
```

---

## Security Model

### Protected by Signatures

| Threat | Protection |
|--------|------------|
| Node impersonation | Can't forge Pulses (signature covers node_id) |
| DHT poisoning | Can't overwrite others' locations (LOC: signature) |
| Message forgery | Can't fake messages (ROUTE: signature) |
| PUBLISH replay | Sequence numbers prevent old locations overwriting new |

### Not Protected

| Threat | Notes |
|--------|-------|
| Sybil attacks | Can create many identities cheaply |
| Malicious behavior | Selective dropping, strategic positioning |
| Traffic analysis | Routing is observable |
| Route manipulation | `next_hop` is unsigned; attacker can redirect route path (but not destination or content) |
| ACK forgery | Attacker who observes a message can forge ACK, potentially stopping retries prematurely |
| Eclipse attacks | See below |

### Eclipse Attacks

An attacker who controls all radio neighbors of a victim can completely isolate them:

```
    Legitimate network
         /    \
        A      B
                        M1   M2   M3  ← attacker nodes surround victim
                          \  |  /
                           \ | /
                             V       ← victim hears only attackers
```

The attacker feeds V false tree information, intercepts all traffic, or isolates V entirely. This is a physical-layer attack: attackers position nodes near the victim and/or transmit at higher power.

**Mitigations (application layer):**
- Out-of-band verification of known peers
- Anomaly detection (all neighbors suddenly change)
- Geographic diversity in peer selection

This attack is fundamentally hard to prevent at the protocol layer — it requires physical access or proximity to the victim.

### Strict Message Parsing (Defense in Depth)

The wire format parser rejects messages with any unexpected values, providing early rejection of non-darktree traffic. This complements sync word filtering (which is unreliable due to RF interference) and signature verification (which requires more computation).

| Check | Location | Invalid values rejected |
|-------|----------|------------------------|
| Wire type | First byte lower 3 bits | Type not in {1=Pulse, 2=Routed, 3=ACK, 4=Broadcast} |
| Varint canonical | All varints | Non-minimal encodings (e.g., 0x80 0x00 for 0) |
| Child count | Pulse flags | Values > MAX_CHILDREN (12) |
| Reserved bit 7 | Routed flags | Must be 0 |
| Message type | Routed bits 0-3 | Values > 3 (only 0-3 valid: PUBLISH, LOOKUP, FOUND, DATA) |
| Signature algorithm | All signatures | Values other than 0x01 (Ed25519) |
| Replica index | PUBLISH/FOUND | Values >= K_REPLICAS (3) |
| Children order | Pulse | Non-ascending hash order |
| Trailing bytes | All messages | Extra bytes after valid message |

This strict parsing ensures that random radio noise or collisions from other protocols (Meshtastic 0x2B, LoRaWAN 0x12/0x34) are quickly rejected without expensive signature verification.

### Left to Application

- End-to-end encryption
- Partner authentication

---

## Protocol Invariants

These properties MUST hold for correct protocol operation.

### Tree Invariants

1. **Single parent:** Every non-root node has exactly one parent
2. **Consistent root:** All nodes in a tree agree on root_hash and tree_size
3. **Subtree accounting:** For any node: `subtree_size = 1 + Σ(child.subtree_size)`
4. **Connected:** The tree is connected (every node reachable from root)

### Keyspace Invariants

1. **Partition:** Keyspace ranges `[0, 2³²)` are partitioned with no overlaps or gaps
2. **Containment:** Every child's range is strictly contained within parent's range
3. **Coverage:** The union of all nodes' ranges equals `[0, 2³²)`
4. **Proportionality:** Range size is proportional to subtree_size

### Signature Invariants

1. **Immutable fields only:** Signatures cover only fields that cannot change in transit
2. **Domain separation:** Each signature type uses a unique prefix
3. **Binding:** `node_id == hash(pubkey)[..16]` for all identity claims

### Routing Invariants

1. **Progress:** Each hop either delivers locally or moves closer to destination
2. **Termination:** TTL ensures messages don't loop indefinitely
3. **Single forwarder:** Only the node matching next_hop forwards

---

## Document Principles

This section describes the conventions used in this document. Future edits should follow these principles to maintain consistency.

### Structure

- **Concept-first:** Each major section fully explains one concept. Avoid splitting related information across distant sections.
- **Self-contained:** Sections should be readable without extensive cross-references. Repeat brief context rather than saying "see above."
- **Normative vs informational:** The main document specifies protocol behavior. Performance analysis and implementation guidance belong in appendices.

### Code Examples

- **Illustrative, not normative:** Code blocks demonstrate concepts but are not the specification. The prose defines behavior; code shows one way to implement it.
- **Pseudocode style:** Use Rust-like syntax for clarity, but don't require exact Rust semantics. Prioritize readability.
- **Explicit about omissions:** When code is simplified, note what's omitted (e.g., "error handling omitted for clarity").

### Terminology

- Use MUST, MUST NOT, SHOULD, SHOULD NOT, MAY per RFC 2119 for normative requirements.
- Define terms on first use. Key terms: τ (tau), keyspace, replica, node_id, child_hash.
- Be consistent: "keyspace address" not sometimes "keyspace location."

### Wire Format

- Specify byte order (big-endian for multi-byte integers).
- Use ASCII diagrams for complex layouts.
- List all domain separation prefixes in one place.

### Updates

- When adding features, update all affected sections (Wire Format, Security Model, relevant concept sections).
- Keep Appendix: Performance marked as informational — numbers may change with implementation.
- Maintain Protocol Invariants when changing tree or DHT behavior.

### Constants

This document specifies constants that affect protocol behavior or interoperability. Implementation-only constants belong in code documentation.

**Document in design.md:**
- Protocol-visible behavior (MAX_CHILDREN, K_REPLICAS)
- Correctness constraints with mathematical rationale (RECENTLY_FORWARDED_TTL, LOOKUP_TIMEOUT, MAX_RETRIES)
- Security policies (DISTRUST_TTL, MISSED_PULSES_TIMEOUT)
- Dynamic calculations (TTL = max(255, max_depth * 3))
- Memory bounds that affect node capacity (in the Memory Analysis table)

**Implementation-only (code docs):**
- Internal async channel sizes (OUTGOING_QUEUE_SIZE, etc.)
- Optimization caches (MAX_LOCATION_CACHE)
- Secondary flow control (MAX_PENDING_DATA, MAX_PENDING_PUBKEY_NODES)

---

## Appendix: Performance Analysis

**Note:** This appendix is informational. The values below are estimates based on stated assumptions and may vary in practice.

### Assumptions

- **LoRa configuration:** SF8 @ 125kHz, 10% duty cycle (g3 sub-band)
- **τ = 6.7 seconds** for LoRa
- **50% packet loss** under congested conditions
- **Tree depth ≈ ceil(log₁₆(N))** for network size N

### Bandwidth Allocation

**Recommended: SF8 @ 125 kHz, g3 10% sub-band (869.4–869.65 MHz)**

| Metric | Value |
|--------|-------|
| Data rate | ~3.1 kbps |
| Urban range | 3–7 km |
| Duty cycle | 10% |

**Bandwidth allocation:** 20% Pulse, 80% data (of actual available bandwidth)

```
pulse_budget = 0.20 × duty_cycle
min_interval = max(2τ, airtime / pulse_budget)
```

**Sync word:** `0x42` (discriminates from Meshtastic 0x14, LoRaWAN 0x12/0x34)

### Tree Dynamics Latency

| Scenario | With Proactive Pulses |
|----------|----------------------|
| Join (get keyspace range) | 2-4τ (~13-27s) |
| Merge detection | 1-2τ (~7-13s) |
| Shopping | 3τ (~20s) |
| State propagation | 1-2τ (~7-13s) |
| Pubkey exchange | 2-4τ (~13-27s) |
| Parent timeout | 24τ (~160s) |

### DHT Latency

**Tree depth vs network size:**

| Network Size | Typical Depth | Avg Hops (random pair) |
|--------------|---------------|------------------------|
| 10 nodes | 2 | 2 |
| 100 nodes | 3 | 3 |
| 1,000 nodes | 4 | 4 |
| 10,000 nodes | 5 | 5 |

**With prefetched keyspace address (DATA only):**

| Network | Congestion | Hops | Total | LoRa Time |
|---------|------------|------|-------|-----------|
| 10 nodes | Light (10%) | 2 | 0.5τ | ~3s |
| 10 nodes | Typical (30%) | 2 | 1.6τ | ~11s |
| 10 nodes | Congested (50%) | 2 | 6.4τ | ~43s |
| 100 nodes | Typical | 3 | 2.4τ | ~16s |
| 1,000 nodes | Typical | 4 | 3.2τ | ~21s |

**Without prefetched address (LOOKUP + FOUND + DATA):**

Total hops ≈ 3 × depth

| Network | Congestion | Hops | Total | LoRa Time |
|---------|------------|------|-------|-----------|
| 10 nodes | Light | 6 | 1.5τ | ~10s |
| 10 nodes | Typical | 6 | 4.8τ | ~32s |
| 100 nodes | Typical | 9 | 7.2τ | ~48s |
| 1,000 nodes | Typical | 12 | 9.6τ | ~64s |

**Key takeaways:**
1. **Prefetching cuts latency by ~3×** — Cache keyspace addresses when possible
2. **Congestion has dramatic impact** — 50× between light and severe loss
3. **Network size has modest impact** — Logarithmic scaling
4. **For LoRa, expect seconds to minutes** — This is a low-bandwidth, high-latency network

### Memory Analysis

**Node state memory:**

| Component | DefaultConfig | SmallConfig | Notes |
|-----------|---------------|-------------|-------|
| Neighbor tracking | ~10 KB | ~1.3 KB | 128/16 neighbors × 80 B |
| Pubkey cache | ~3 KB | ~0.8 KB | 64/16 entries × 48 B |
| Location store | ~26 KB | ~3.2 KB | 256/32 entries × 100 B |
| Backup store | ~26 KB | ~6.4 KB | 256/64 entries × 100 B |
| Pending ACKs | ~9.6 KB | ~2.4 KB | 32/8 entries × 300 B |
| Recently forwarded | ~10 KB | ~2.5 KB | 512/128 entries × 20 B (reclaimable) |
| Pending routed | ~140 KB | ~35 KB | 512/128 entries × 280 B (reclaimable) |
| Delayed forwards | ~70 KB | ~18 KB | 256/64 entries × 280 B (reclaimable) |
| Fraud detection | 256 B | 256 B | HyperLogLog registers |
| **Peak (churn)** | **~295 KB** | **~70 KB** | All queues full |
| **Idle (stable)** | **~75 KB** | **~15 KB** | Reclaimable queues empty |

**Reclaimable memory:** Collections marked "reclaimable" use shrinking data structures that automatically release memory after 1/16 × capacity consecutive removals without additions. During network churn (tree restructuring, message bursts), these queues may fill. Once traffic subsides, memory is reclaimed. This allows generous limits without permanent memory cost.

### Traffic Overhead (10k network)

| Traffic Type | Messages/hour | % of Total |
|--------------|---------------|------------|
| Pulses | 1,200,000 | 97.1% |
| PUBLISH routing | 22,500 | 1.8% |
| Broadcast backup | 3,750 | 0.3% |
| Broadcast ACKs | 7,500 | 0.6% |

### Failure Scenarios

| Scenario | Detection | Effect |
|----------|-----------|--------|
| Leaf dies | Parent: 8 missed Pulses (~24τ) | Remove from children |
| Internal node dies | Children: 8 missed Pulses (~24τ) | Each child starts shopping (parent lost) |
| Root dies | Children: 8 missed Pulses (~24τ) | Children start shopping, merge if they meet |
| Partition | 8 missed Pulses (~24τ) | Affected nodes start shopping (parent lost) |
| Partition heals | Pulses from other tree | Shopping (dominating tree, larger wins) |

### Cryptographic Performance

Ed25519 and SHA-256 are computationally intensive. Typical performance on Cortex-M4 at 48-72 MHz (software implementation):

| Operation | Time | Notes |
|-----------|------|-------|
| Ed25519 sign | 10-20ms | Per outgoing Pulse/Routed |
| Ed25519 verify | 8-15ms | Per incoming Pulse/Routed |
| SHA-256 (256 bytes) | 1-2ms | Hashing, ack_hash |

Hardware crypto acceleration (when available) reduces these by 5-10×.

**Implications:**
- At LoRa speeds (τ ≈ 6.7s), crypto overhead is negligible (<1% of τ)
- On faster links, verify throughput may limit message rate (~50-100 msg/sec software)
- Implementations on highly constrained MCUs should profile to ensure Pulse validation completes well before neighbor timeout (8 Pulses = 24τ)
