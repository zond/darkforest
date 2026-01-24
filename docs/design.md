# Tree-Based DHT for LoRa Mesh Networks

A protocol for building mesh networks over LoRa radios with O(log N) routing.

**Key properties:**
- Nodes form a spanning tree via periodic broadcasts
- Keyspace addresses enable efficient routing without flooding
- A distributed hash table maps node IDs to keyspace addresses
- Ed25519 signatures prevent impersonation
- No clock synchronization required

---

## Part 1: Tree Formation

This part describes how nodes discover each other and form a spanning tree.

### Node Identity

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

### Pulse Messages

Nodes broadcast periodic **Pulse** messages to maintain the tree:

```rust
struct Pulse {
    node_id: NodeId,                    // 16 bytes
    flags: u8,                          // 1 byte (see layout below)
    parent_hash: Option<[u8; 4]>,       // 0 or 4 bytes (truncated hash of parent node_id)
    root_hash: [u8; 4],                 // 4 bytes (truncated hash of root node_id)
    subtree_size: varint,               // 1-3 bytes
    tree_size: varint,                  // 1-3 bytes
    keyspace_lo: u32,                   // 4 bytes (start of owned keyspace range)
    keyspace_hi: u32,                   // 4 bytes (end of owned keyspace range, exclusive)
    pubkey: Option<PublicKey>,          // 0 or 32 bytes (if has_pubkey flag set)
    children: ChildList,                // N × (4 + varint) bytes (see encoding below)
    signature: Signature,               // 65 bytes (1 algorithm + 64 sig)
}

// Flags byte layout:
// - bit 0: has_parent (if set, parent_hash is present)
// - bit 1: need_pubkey (requesting pubkeys from neighbors)
// - bit 2: has_pubkey (if set, pubkey field is present)
// - bits 3-7: child_count (0-12, number of children)
//
// Example: 5 children, has parent, includes pubkey → 0b00101_101 = 0x2D

// Keyspace range [keyspace_lo, keyspace_hi): The portion of 32-bit keyspace this node owns.
// Root owns [0, u32::MAX). Since keyspace_hi is u32, the keyspace contains u32::MAX valid
// addresses (0 through u32::MAX-1). The value u32::MAX itself is not a valid address.
// Children compute their range from parent's Pulse (see Keyspace section).
// A node's "address" for routing is the center of its range: (keyspace_lo + keyspace_hi) / 2.

// Signature covers ALL fields (domain-separated):
// "PULSE:" || node_id || flags || parent_hash || root_hash || subtree_size ||
//            tree_size || keyspace_lo || keyspace_hi || pubkey || children
```

**Children encoding (ChildList):**

Each child is identified by a 4-byte truncated hash of its node_id:
```rust
fn child_hash(node_id: &NodeId) -> [u8; 4] {
    hash(node_id)[..4].try_into().unwrap()
}
```

**Format:** For each child (count from flags bits 3-7):
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

**Hash collision handling:**

With 4-byte hashes, the probability of two children having the same hash is 1 in 2³² (~2.3 × 10⁻¹⁰). Even with 12 children (66 pairs), collision probability is ~1.5 × 10⁻⁸.

To prevent collisions:
- **Parents** MUST NOT accept a child whose hash matches an existing child's hash
- **Children** SHOULD NOT attempt to join a parent that already has a child with their hash

**Known limitation:** If two nodes with the same 4-byte hash race to join the same parent simultaneously, one will be silently rejected. The rejected node sees its hash in the parent's child list and believes it was accepted, but messages routed to that keyspace range will be delivered to the other node. This doesn't self-correct—it persists until one node leaves. Given the ~10⁻¹⁰ probability per join attempt, this is an acceptable trade-off for simpler encoding.

A Pulse serves multiple purposes:
- **Liveness signal** for parent and children
- **Tree state** for merge decisions (root_hash, tree_size)
- **Children list** for keyspace range computation
- **Pubkey exchange** for signature verification

**Replay consideration:** Pulses have no sequence number. This is a deliberate tradeoff:

- **Attack:** Replaying an old Pulse causes ~25s confusion until the legitimate node's next Pulse corrects it. Extending the attack requires jamming the legitimate Pulses.
- **Why no seq:** Adding seq (4 bytes) would require recovery after reboot. Since neighbors track `last_seen_seq`, a rebooted node's Pulses would be rejected until neighbors timeout (~75-90s). This recovery delay costs more than the 25s confusion it prevents.
- **Conclusion:** Pulses are frequent and self-correcting. The brief confusion window is acceptable given the recovery complexity seq would introduce.

**Typical sizes:**

| Scenario | Size |
|----------|------|
| Root (no parent, no children, no pubkey) | ~94 bytes |
| Leaf (no pubkey) | ~98 bytes |
| Leaf (with pubkey) | ~130 bytes |
| 8 children + pubkey | ~175 bytes |
| 12 children + pubkey | ~205 bytes |
| 12 children + pubkey (worst) | ~247 bytes |

**Size formula:** `94 + has_parent×4 + has_pubkey×32 + children×(4+varint) + varint_overhead`

Base: 16 (node_id) + 1 (flags) + 4 (root_hash) + 2 (subtree_size) + 2 (tree_size) + 4 (keyspace_lo) + 4 (keyspace_hi) + 64 (signature) = 97 bytes. Subtract 4 for no parent ≈ 94 bytes minimum.

**MTU constraints:** MAX_CHILDREN is set to 12 to guarantee worst-case Pulse (with pubkey and maximum varints) fits within 252 bytes, leaving headroom for any transport framing.

### Timing Model

All protocol timeouts scale with transport bandwidth to work correctly across vastly different link speeds (LoRa at ~38 bytes/sec vs UDP at effectively unlimited).

**τ (tau) — the bandwidth time unit:**

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

**Example values:**

| Transport | MTU | Effective BW | τ |
|-----------|-----|--------------|---|
| LoRa SF8, 10% duty | 255 | 38 bytes/sec | 6.7s |
| LoRa SF8, 1% duty | 255 | 3.8 bytes/sec | 67s |
| BLE extended | 252 | ~1000 bytes/sec | 252ms |
| UDP | 512 | unlimited | 100ms (floor) |

**Why τ = MTU / bw?** This represents the worst-case time to "afford" one maximum-size transmission under duty cycle constraints. For LoRa with 10% duty cycle, even though actual transmission of 255 bytes takes ~670ms, you can only transmit 10% of the time, so the effective cost is ~6.7 seconds of "budget."

All protocol timeouts are expressed as multiples of τ, ensuring they scale appropriately for both slow constrained links and fast unconstrained ones.

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

**Bandwidth budget:** Proactive Pulses count toward the maintenance bandwidth budget (1/5 of available bandwidth). If budget is exhausted, proactive Pulses are delayed until budget recovers. This prevents proactive sending from starving other traffic.

**Latency improvement:**

Pulse interval is approximately 3τ (based on 150-byte pulse, PULSE_BW_DIVISOR=5, and τ = MTU/bw).

| Scenario | Periodic only | With proactive |
|----------|---------------|----------------|
| Join (get keyspace range) | 6-9τ | 2-4τ |
| Merge detection | 0-3τ | 1-2τ |
| State propagation | 0-3τ | 1-2τ |
| Pubkey exchange | 3-6τ | 2-4τ |

For LoRa (τ=6.7s): periodic join takes ~40-60s, proactive takes ~13-27s.
For UDP (τ=0.1s): periodic join takes ~0.6-0.9s, proactive takes ~0.2-0.4s.

**Why this works:** The 1-2τ batch window coalesces multiple triggers (e.g., receiving several unknown Pulses at once) into a single proactive Pulse. The bandwidth budget prevents runaway sending during network churn.

### Node State

```rust
// Protocol limits (theoretical maximums)
const MAX_TREE_DEPTH: usize = 127;     // TTL 255 / 2 for round-trip routing
const MAX_CHILDREN: usize = 12;        // Guarantees worst-case Pulse fits in 252 bytes

// MTU is transport-dependent (LoRa: 255, BLE: 252, etc.)
// All message builders MUST check result size against transport.mtu() and return
// an error if exceeded. This naturally limits practical depth based on message type.

// Memory bounds for embedded systems
const MAX_NEIGHBORS: usize = 128;      // for congested environments; ~5KB
const MAX_PUBKEY_CACHE: usize = 128;   // LRU eviction
const MAX_LOCATION_STORE: usize = 256; // bounded by keyspace fraction
const MAX_LOCATION_CACHE: usize = 64;  // LRU eviction
const MAX_PENDING_LOOKUPS: usize = 16; // oldest eviction

struct Node {
    // Identity
    node_id: NodeId,
    pubkey: PublicKey,
    secret: SecretKey,

    // Tree position
    parent: Option<NodeId>,
    root_id: NodeId,
    tree_size: u32,
    subtree_size: u32,
    keyspace_lo: u32,                       // start of owned keyspace range
    keyspace_hi: u32,                       // end of owned keyspace range (exclusive)

    // Neighbors (bounded by MAX_NEIGHBORS)
    children: HashMap<NodeId, u32>,         // child -> subtree_size
    child_ranges: HashMap<NodeId, (u32, u32)>, // child -> (keyspace_lo, keyspace_hi)
    shortcuts: HashMap<NodeId, (u32, u32)>, // shortcut -> (keyspace_lo, keyspace_hi)
    neighbor_times: HashMap<NodeId, (Timestamp, Option<Timestamp>)>,

    // Caches (bounded with LRU/oldest eviction)
    pubkey_cache: HashMap<NodeId, PublicKey>,
    need_pubkey: HashSet<NodeId>,
}
```

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

### Bootstrap (Alone)

When a node N boots and finds no neighbors:

```
N generates keypair: (pubkey_N, secret_N)
N.node_id = hash(pubkey_N)[0:16]

N → Pulse{
  node_id: N,
  parent_hash: None,
  root_hash: hash(N)[..4],
  subtree_size: 1,
  tree_size: 1,
  keyspace_lo: 0,
  keyspace_hi: 2³²,
  children: []
}

N state:
  parent = None
  root = N
  tree_size = 1
  keyspace = [0, 2³²)
```

N is root of its own single-node tree.

### Joining an Existing Tree

When node N boots, it has no parent and no children. It enters a **discovery phase** to find the best parent:

**Discovery phase:**
1. N sends its first Pulse (as root of single-node tree)
2. N starts a discovery timer (3τ) to collect neighbor Pulses
3. When timer fires, N evaluates all discovered neighbors

**Candidate filtering:** A neighbor is skipped if:
- It has `children.len() >= MAX_CHILDREN` (parent is full)
- It is in the distrusted set

**Parent selection algorithm:**
1. **Pick the best tree** — if multiple roots visible, choose largest tree_size (tie-break: lowest root_hash). This makes N a bridge that triggers tree merging.
2. **Filter by signal strength** — if 3+ candidates and RSSI data available, remove bottom 50% by RSSI. This ensures reliable parent links. Skip this step for non-radio transports (e.g., UDP) or when fewer than 3 candidates.
3. **Pick shallowest** — from remaining candidates, choose the one with largest keyspace range (tie-break: best RSSI, or arbitrary if no RSSI). This keeps trees wide and shallow.

If no valid candidates remain after filtering, N stays root of its single-node tree and will join via normal merge when it hears a larger tree.

**After joining:** Once N has a parent, it only switches parent when:
- **Merge** — N sees a better tree (larger tree_size, or equal size with lower root_hash)
- **Parent timeout** — after 8 missed Pulses, N becomes root of its own subtree (see "Partition and Reconnection")

There is no "parent shopping" after joining. This provides stability while still allowing trees to merge and recover from partitions.

This prioritization naturally produces wide, shallow trees. Larger keyspace ranges indicate shallower positions in the tree.

**Implicit rejection:** When a node claims a parent (by setting `parent_hash` in its Pulse), the parent decides whether to accept by including the child in its `children` list. A parent silently ignores a child if it already has `MAX_CHILDREN` children.

If a joining node doesn't see itself in the parent's `children` list after 3 Pulses, it assumes rejection and tries another neighbor.

```
t=0: N → Pulse{node_id: N, parent_hash: None, root_hash: hash(N), tree_size: 1, ...}

t=0: P receives N's Pulse:
  - Unknown node_id → schedule proactive Pulse, need_pubkey=true

t=2s: P → proactive Pulse{node_id: P, parent_hash: hash(G), root_hash: hash(R), tree_size: 500,
          keyspace_lo: X, keyspace_hi: Y, need_pubkey: true, ...}

t=2s: N receives P's Pulse:
  - Different root_hash
  - N.tree_size(1) < P.tree_size(500) → N joins P's tree
  - N.parent = P, N.root = R
  - State changed → schedule proactive Pulse with pubkey

t=4s: N → proactive Pulse{node_id: N, parent_hash: hash(P), root_hash: hash(R), tree_size: 500,
          keyspace_lo: 0, keyspace_hi: 0,  // doesn't know range yet
          pubkey: pubkey_N, ...}

t=4s: P receives N's Pulse:
  - N.pubkey present → cache it
  - N claims parent_hash = hash(P) → P.children.insert(N)
  - P.subtree_size += 1
  - State changed → schedule proactive Pulse

t=6s: P → proactive Pulse{..., children: [(hash(N), 1), ...], ...}

t=6s: N receives P's Pulse:
  - N finds itself in P.children (by hash) → computes keyspace range from P's range
```

**Total join time: ~6 seconds** (vs 50-75 seconds with periodic-only Pulses)

### Tree Merging

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

t=2s: Y → proactive Pulse (claiming parent=X, root_hash=hash(Ra))

t=2s: Py receives Y's Pulse:
  - Py.tree_size < Y's tree_size → Py dominated
  - INVERSION: Py.parent = Y (former child becomes parent!)
  - Py.root = Ra
  - State changed → schedule proactive Pulse

t=4s: Py → proactive Pulse (inversion propagates up tree B)

(proactive Pulses propagate inversion to Rb in seconds, not minutes)
```

**Merge time:** With proactive Pulses, the entire tree B inverts in ~2 seconds per hop. A 10-hop deep tree merges in ~20 seconds instead of 4-8 minutes.

**Visual sequence:**

```
Step 1: Initial state
═══════════════════════

Tree A (900 nodes)              Tree B (100 nodes)
     Ra                              Rb
    /  \                             |
   .    X  · · · · · · · · · ·  Y ← Py
                                    / \


Step 2: Y switches parent to X
══════════════════════════════

     Ra                              Rb
    /  \                             |
   .    X─────────────────────Y     Py (orphaned)


Step 3: Py inverts, claims Y as parent
══════════════════════════════════════

     Ra
    /  \
   .    X────────────────────Y
                             |
                             Py
                            / \


Step 4: Inversion propagates to Rb
══════════════════════════════════

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

#### Implementation

```rust
const FRAUD_CONFIDENCE: f64 = 0.99;  // 99% confidence before acting
const FRAUD_Z_THRESHOLD: f64 = 2.33; // Z-score for 99% confidence
const MIN_EXPECTED: f64 = 5.0;       // need λ ≥ 5 for valid Poisson approximation
const DISTRUST_TTL: Duration = Duration::from_secs(24 * 3600);
const MAX_DISTRUSTED: usize = 64;

struct Node {
    join_context: Option<JoinContext>,
    distrusted: HashMap<NodeId, Instant>,
    fraud_detection: FraudDetection,
    // ...
}

struct JoinContext {
    parent_at_join: NodeId,
    join_time: Instant,
}

struct FraudDetection {
    unique_publishers: HashSet<NodeId>,  // count unique nodes, not total messages
    count_start: Instant,
    subtree_size_at_start: u32,
}

fn on_publish_received(&mut self, msg: &Routed) {
    if self.is_storage_node_for(msg) {
        // Count unique node_ids to prevent spoofing via repeated PUBLISH
        self.fraud_detection.unique_publishers.insert(msg.src_node_id);
    }
}

fn on_subtree_size_changed(&mut self) {
    // Reset fraud detection if subtree_size changed significantly (2x either way)
    let old = self.fraud_detection.subtree_size_at_start;
    let new = self.subtree_size;
    if new > old * 2 || new < old / 2 {
        self.fraud_detection = FraudDetection {
            unique_publishers: HashSet::new(),
            count_start: Instant::now(),
            subtree_size_at_start: new,
        };
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

    let observed = fd.unique_publishers.len() as f64;
    let z = (expected - observed) / expected.sqrt();

    if z > FRAUD_Z_THRESHOLD {
        // We received significantly fewer PUBLISH than expected.
        // With 99% confidence, the tree is smaller than claimed.
        self.add_distrust(ctx.parent_at_join);
        self.leave_and_rejoin();
    }
}

fn leave_and_rejoin(&mut self) {
    self.join_context = None;
    self.fraud_detection = FraudDetection {
        unique_publishers: HashSet::new(),
        count_start: Instant::now(),
        subtree_size_at_start: self.subtree_size,
    };
    self.parent = None;
    self.root_id = self.node_id;
    self.tree_size = self.subtree_size;
}
```

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

### Partition and Reconnection

**Network partition:**

```
Before:
      R (tree_size=100)
     / \
    A   B
   /
  C (subtree_size=30)

Link A-C breaks. After ~24τ (8 missed Pulses, ~160s for LoRa):

C (no Pulse from parent A):
  C.parent = None
  C.root_id = C
  C.tree_size = 30

A (no Pulse from child C):
  A.children.remove(C)
  A.subtree_size -= 30

Two separate trees: R (70 nodes), C (30 nodes)
```

**Partition heals:**

```
A and C back in radio range.

C receives A's Pulse:
  - C.tree_size(30) < A.tree_size(70) → C dominated
  - C.parent = A
  - C.root_id = R

Tree reunified: R.tree_size = 100
```

### Liveness and Timeouts

Nodes track Pulse timestamps for all neighbors. After 8 missed Pulses, a neighbor is presumed dead.

**Why 8 Pulses?** With 50% packet loss per Pulse:
- P(miss 3 in a row) = 12.5% — too high, causes spurious timeouts
- P(miss 8 in a row) = 0.4% — rare enough to be acceptable

At ~3τ Pulse intervals (20 seconds for LoRa), 8 missed Pulses = ~24τ (~160 seconds for LoRa) before declaring a neighbor dead.

Since Pulse intervals vary by node, we track the observed interval:

```rust
const MIN_PULSE_INTERVAL: Duration = Duration::from_secs(10);  // rate limit floor
const MISSED_PULSES_TIMEOUT: u32 = 8;  // pulses before declaring neighbor dead

impl Node {
    fn on_pulse_received(&mut self, pulse: &Pulse) {
        let neighbor = &pulse.node_id;

        // Rate limiting: ignore Pulses that arrive too fast
        if let Some((last_seen, _)) = self.neighbor_times.get(neighbor) {
            if now() - *last_seen < MIN_PULSE_INTERVAL {
                return;  // Too soon, ignore (possible replay or attack)
            }
        }

        // Update timestamps
        let prev = self.neighbor_times.get(neighbor).map(|(last, _)| *last);
        self.neighbor_times.insert(*neighbor, (now(), prev));

        // Process pulse...
    }

    fn expected_interval(&self, neighbor: &NodeId) -> Duration {
        match self.neighbor_times.get(neighbor) {
            Some((last, Some(prev))) => *last - *prev,
            _ => self.tau() * 5,  // conservative default (~5τ ≈ Pulse interval + margin)
        }
    }

    fn is_timed_out(&self, neighbor: &NodeId) -> bool {
        match self.neighbor_times.get(neighbor) {
            Some((last_seen, _)) => {
                now() > *last_seen + MISSED_PULSES_TIMEOUT * self.expected_interval(neighbor)
            }
            None => false,
        }
    }
}
```

| Relationship | Timeout | Effect |
|--------------|---------|--------|
| Parent | ~24τ (8 × ~3τ interval) | Become root of subtree |
| Child | ~24τ (8 × ~3τ interval) | Remove from children |
| Shortcut | ~24τ (8 × ~3τ interval) | Remove from shortcuts |

### Shortcuts

Shortcuts are non-tree neighbors that enable faster routing by skipping tree hops.

**Discovery:** Shortcuts are discovered passively:
1. Pulses are broadcast (heard by all nodes in radio range)
2. Non-parent/child nodes that hear you add you as a shortcut
3. Shortcuts expire after 8 missed Pulses
4. No additional bandwidth cost

**Routing optimization:** When routing, we check children and shortcuts whose range contains the destination, picking the tightest. If none contain it, we route up to parent (who can continue routing upward).

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

A owns range [60M, 1B) and has a shortcut to R (heard R's Pulse).
A sends to dest_addr = 3B (in B's range):

- Normal route: A → L → Root → R → B = **4 hops**
- Via shortcut to R: A → R → B = **2 hops**

R's range [2B, 4B) contains dest=3B, and is tighter than any other candidate, so we use the shortcut.

---

## Part 2: Tree Routing

This part describes how messages travel through the tree.

### Keyspace Ranges

Each node owns a range `[keyspace_lo, keyspace_hi)` of the 32-bit keyspace. A child computes its range from its parent's Pulse:

1. Parent's Pulse contains `keyspace_lo`, `keyspace_hi`, `subtree_size`, and `children` list
2. Parent keeps the first slice: `[lo, lo + range/subtree_size)` (weight 1 for itself)
3. Children (sorted by hash) divide the remainder proportionally by their `subtree_size`
4. Child finds its entry by matching `hash(node_id)[..4]`, computes its slice

A node's **keyspace address** is the center of its range: `(keyspace_lo + keyspace_hi) / 2`. This is what gets published to the location directory and used in `dest_addr` for routing.

See the Keyspace section in Part 3 for the precise `compute_my_range` algorithm.

### Routed Messages

Unicast messages route through the tree using keyspace addresses:

```rust
struct Routed {
    flags_and_type: u8,             // combined flags + message type (see below)
    dest_addr: u32,                 // keyspace location to route toward
    dest_hash: Option<[u8; 4]>,     // truncated hash(node_id) for recipient verification
    src_addr: Option<u32>,          // sender's keyspace address for replies
    src_node_id: NodeId,            // sender identity
    src_pubkey: Option<PublicKey>,  // sender's public key (optional, for signature verification)
    ttl: u8,                        // hop limit, decremented at each hop
    payload: Vec<u8>,               // type-specific content
    signature: Signature,           // Ed25519 signature (see below)
}

// flags_and_type byte layout:
// - bits 0-3: msg_type (0-15)
// - bit 4: has_dest_hash (1 = dest_hash present for recipient verification)
// - bit 5: has_src_addr (1 = src_addr present for replies)
// - bit 6: has_src_pubkey (1 = src_pubkey present for signature verification)
// - bit 7: reserved (must be 0)

// msg_type values: 0=PUBLISH, 1=LOOKUP, 2=FOUND, 3=DATA, 4=ACK
// Messages with undefined msg_type MUST be dropped silently (future extensions)

// dest_addr is a keyspace location (u32). All messages route uniformly toward dest_addr:
// - PUBLISH/LOOKUP: dest_addr = hash(node_id || replica_index) (the key)
// - DATA/FOUND: dest_addr = target node's published keyspace address

// dest_hash verifies the intended recipient. Present for LOOKUP/DATA/FOUND, absent for PUBLISH.
// Recipient verifies: hash(my_node_id)[..4] == dest_hash
// Collision probability ~2.3×10⁻¹⁰ per message (negligible).

// src_addr is the sender's keyspace address (center of their range) for replies.

// src_pubkey enables signature verification for messages from far-away nodes
// whose pubkey isn't cached from Pulses. Receivers MUST verify:
//   src_node_id == hash(src_pubkey)[..16]
// Include src_pubkey when: first message to a node, PUBLISH, LOOKUP, FOUND.
// Omit src_pubkey when: established DATA exchange (receiver has cached pubkey).
// If receiver lacks pubkey and message has none, drop message (sender retries with pubkey).

// Typical flag combinations:
// - PUBLISH: has_dest_hash=0, has_src_addr=1, has_src_pubkey=1 (storage nodes need pubkey)
// - LOOKUP:  has_dest_hash=1, has_src_addr=1, has_src_pubkey=1 (FOUND sender needs pubkey)
// - FOUND:   has_dest_hash=1, has_src_addr=0, has_src_pubkey=0 (requester has target's pubkey)
// - DATA:    has_dest_hash=1, has_src_addr=0/1, has_src_pubkey=0/1 (app decides)

// Signature covers all fields EXCEPT ttl (forwarders must decrement it):
// "ROUTE:" || flags_and_type || dest_addr || dest_hash || src_addr || src_node_id || payload
// Note: src_pubkey not signed (bound to src_node_id via hash)

fn routed_sign_data(msg: &Routed) -> Vec<u8> {
    encode(b"ROUTE:", msg.flags_and_type, msg.dest_addr, &msg.dest_hash,
           &msg.src_addr, &msg.src_node_id, &msg.payload)
}
```

The signature covers all fields except `ttl` to prevent:
- Routing manipulation (changing dest_addr)
- Reply redirection (changing src_addr)
- Type confusion (changing msg_type)
- Payload tampering

The `ttl` field is not signed because forwarders must decrement it. An attacker could reset TTL to extend message lifetime, but cannot forge the message itself. TTL exists to prevent routing loops during tree restructuring.

The `dest_hash` field indicates recipient verification:
- `None` — message is for whoever owns the keyspace location (PUBLISH)
- `Some(hash)` — message is for a specific node/entry matching the hash (LOOKUP/DATA/FOUND)

### Routing Algorithm

Messages route toward `dest_addr` using keyspace ranges. Each hop forwards to the neighbor with the tightest range containing the destination, or upward to parent:

```rust
const DEFAULT_TTL: u8 = 255;  // max hops

impl Node {
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

        // Find best next hop among children and shortcuts whose range contains dest
        if let Some(next) = self.best_downward_hop(dest) {
            self.send_to(next, msg);
        } else if let Some(parent) = self.parent {
            // No child/shortcut contains dest → route up
            self.send_to(parent, msg);
        }
        // else: we're root and no child contains dest - shouldn't happen
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

Node in A's subtree sends to dest_addr = 0xC0000000 (in C's range):
  Sender → A (up)       dest not in sender's or children's range
  A → Root (up)         dest not in A's range, route to parent
  Root → C (down)       C's range contains dest, tightest match
```

---

## Part 3: Location Directory

This part describes how nodes publish and discover each other's keyspace addresses.

### Keyspace

The keyspace is `[0, u32::MAX)`. Since `keyspace_hi` is stored as `u32`, the keyspace contains exactly `u32::MAX` valid addresses (0 through u32::MAX-1). The value `u32::MAX` itself is not a valid address - it serves as the exclusive upper bound.

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

**A node's "address"** is the center of its keyspace range:
```rust
fn my_address(&self) -> u32 {
    (self.keyspace_lo / 2) + (self.keyspace_hi / 2)  // avoid overflow
}
```

This address is what gets published to the location directory and used in `dest_addr` for routing.

### Location Entries

The directory stores node locations (`node_id → keyspace_addr`). Each entry includes a location signature:

```rust
struct LocationEntry {
    node_id: NodeId,            // owner's identity
    pubkey: PublicKey,          // owner's public key
    keyspace_addr: u32,         // center of owner's keyspace range
    seq: u32,                   // sequence number for replay protection
    replica_index: u8,          // 0, 1, or 2 (for rebalancing)
    signature: Signature,       // location signature (LOC: prefix)
    received_at: Instant,       // local timestamp for expiry
}

// Location signature covers:
// "LOC:" || node_id || keyspace_addr || seq
fn location_sign_data(node_id: &NodeId, keyspace_addr: u32, seq: u32) -> Vec<u8> {
    encode(b"LOC:", node_id, keyspace_addr, seq)
}
```

The location signature uses a separate "LOC:" domain prefix, allowing storage nodes to forward entries during rebalancing without re-signing. The signature proves the owner's claim to the keyspace address.

**Varint encoding:** All varint fields (seq, subtree_size, tree_size) use LEB128 encoding. Implementations MUST use canonical (minimal) encoding: the shortest byte sequence that represents the value. Non-minimal encodings (e.g., `0x80 0x00` for 0 instead of `0x00`) MUST be rejected during decoding to prevent signature ambiguity attacks. Standard libraries like `integer-encoding` or `postcard` handle this correctly.

The Routed signature authenticates the entire PUBLISH message (including `src_addr` which carries the keyspace address). Storage nodes reject entries with `seq <= current_seq` for the same node_id. The `"ROUTE:"` prefix provides domain separation from Pulse signatures.

**Sequence number recovery after reboot:**

If a node loses its `location_seq` state, all its PUBLISH messages will be rejected until `seq` exceeds the value stored at replicas. Options:

1. **Accept delay (recommended)** — Do nothing special. Old entries expire after 12 hours, then new publishes succeed. Simplest, and state loss is rare enough that 12-hour delay is acceptable.

2. **Persist reliably** — Write `location_seq` to flash before each publish. Faster recovery but causes flash wear on embedded devices.

3. **Epoch-based sequence** — Use `seq = (coarse_time << 24) | counter` where `coarse_time` is hours since some epoch. Requires rough time source.

Implementers may choose based on their hardware constraints and recovery time requirements.

### Publishing (PUBLISH)

A node publishes its location to k=3 replica locations:

```rust
const K_REPLICAS: usize = 3;
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

**PUBLISH verification order** (storage node receiving a PUBLISH):
1. Verify Routed signature (defense-in-depth; LOC: signature is critical protection)
2. Parse PUBLISH payload: `node_id`, `pubkey`, `keyspace_addr`, `seq`, `replica_index`, `location_signature`
3. Verify keyspace ownership: we own a replica key for `payload.node_id`
4. Verify `payload.pubkey` binds to `payload.node_id`: `hash(pubkey)[..16] == node_id`
5. Verify LOC: signature: `verify(pubkey, "LOC:" || node_id || keyspace_addr || seq, signature)`
6. Verify `seq > existing_seq` for this `node_id` (replay protection)
7. Store entry with current timestamp for expiry tracking

Note: The Routed `src_node_id` may differ from `payload.node_id` during rebalancing (storage nodes forward entries they no longer own). The LOC: signature is the authoritative proof of the location claim.

### Lookup (LOOKUP / FOUND)

Lookups try each replica until one responds:

```rust
// LOOKUP_TIMEOUT = 32τ per replica
// Accounts for: multi-hop routing (2×depth), retransmissions at each hop
// For LoRa (τ=6.7s): ~3.5 minutes per replica
// For UDP (τ=0.1s): ~3 seconds per replica
fn lookup_timeout(&self) -> Duration {
    self.tau() * 32
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

        self.pending_lookups.remove(&node_id);

        // Cache both location and pubkey
        self.location_cache.insert(node_id, keyspace_addr);
        self.pubkey_cache.insert(node_id, pubkey);
    }
}
```

**LOOKUP payload:** `replica_index (1)` = 1 byte

The target is identified by `dest_hash`. The storage node finds an entry matching that hash and verifies the key.

**FOUND payload:** `node_id (16) || pubkey (32) || keyspace_addr (4) || seq (varint) || replica_index (1) || location_signature (65)` = 119-123 bytes

FOUND returns the complete location entry, including the location signature. The requester can verify the location claim and cache both the pubkey and keyspace address.

**Lookup process:**
1. Send LOOKUP for replica 0
2. If no FOUND within 32τ, try replica 1
3. If still no response, try replica 2
4. After all replicas timeout, lookup fails

### Replication

Each location is published to k=3 independent storage nodes:

```
replica_0_key = hash(node_id || 0x00)
replica_1_key = hash(node_id || 0x01)
replica_2_key = hash(node_id || 0x02)
```

Replicas are distributed across different parts of the tree.

### TTL and Expiration

Expiry is handled entirely by storage nodes using local clocks:

| Parameter | Value |
|-----------|-------|
| Storage TTL | 12 hours |
| Refresh interval | 8 hours |
| Republish trigger | Published address no longer in our keyspace range |

```rust
fn cleanup_expired(&mut self) {
    let cutoff = Instant::now() - Duration::from_secs(12 * 3600);
    self.location_store.retain(|_, e| e.received_at > cutoff);
}
```

Dead nodes stop refreshing → entries expire → no stale data.

### Rebalancing

When subtree sizes change, keyspace ranges shift. Storage nodes push entries to new owners:

```rust
fn on_range_change(&mut self, old_range: (u32, u32), new_range: (u32, u32)) {
    for entry in self.location_store.values() {
        let key = hash_to_u32(&[&entry.node_id[..], &[entry.replica_index]].concat());
        if key < new_range.0 || key >= new_range.1 {
            // Entry's key is no longer in our range - forward it
            self.forward_entry_to_new_owner(entry);
        }
    }
}
```

---

## Part 4: Sending Messages

This part shows how to find and message any node in the network.

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

## Part 5: Link-Layer Reliability

This part describes how nodes handle packet loss on half-duplex radio links.

### The Problem

LoRa radios are half-duplex: a node cannot receive while transmitting. When node A sends to node B:
- B may be transmitting simultaneously (can't hear A)
- Radio interference may corrupt the packet
- B's receive buffer may be full

Without acknowledgment, A doesn't know if B received the message. For multi-hop Routed messages, each hop has independent loss probability. With 50% loss per hop and 64 hops, delivery probability approaches zero.

### Implicit ACKs via Overhearing

Since all transmissions are broadcasts, A can overhear when B forwards A's message. This serves as an implicit acknowledgment.

**For Routed messages:**
1. A sends `Routed` with TTL=X to B
2. A stores `hash(Routed with TTL=X-1)` in pending set
3. A starts exponential backoff timer
4. If A hears B's forwarded message (matching hash): implicit ACK, done
5. If timeout without ACK: A resends original (TTL=X), up to 8 retries

**Hash comparison:**
The sender computes the expected hash by taking the message with TTL decremented. When overhearing any broadcast, nodes compare hashes against their pending set to detect if it's a forwarded version of a pending message.

### Explicit ACK Messages

When B receives a duplicate (same message, same TTL), B knows A didn't hear B's original forward. Instead of re-forwarding (which would create duplicates), B sends an explicit ACK:

```rust
// New message type: ACK = 4
struct Ack {
    hash: [u8; 8],  // truncated hash of the message being ACKed
}
```

**Forwarder (B) behavior:**
1. B receives `Routed` with TTL=X from A
2. B decrements TTL to X-1 and forwards
3. B stores `hash(Routed with TTL=X)` in recently_forwarded set
4. If B receives same message again (same hash, same TTL=X):
   - Send `ACK(hash(Routed with TTL=X-1))` back
   - Do NOT re-forward (duplicate suppression)

The ACK contains the hash A is waiting for (the forwarded version with TTL-1).

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

### Retransmission Policy

All retransmission timeouts use τ (see [Timing Model](#timing-model)) to scale with bandwidth:

```rust
const MAX_RETRIES: u8 = 8;

// Base backoffs: 1τ, 2τ, 4τ, 8τ, 16τ, 32τ, 64τ, 128τ (with ±10% jitter)
// Total worst-case: ~280τ (255τ base + jitter margin)
// For LoRa (τ=6.7s): ~31 minutes
// For UDP (τ=0.1s): ~28 seconds

struct PendingAck {
    expected_hash: [u8; 8],  // hash of message with TTL-1
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

### Memory Bounds

```rust
const MAX_PENDING_ACKS: usize = 32;          // messages awaiting ACK
const MAX_RECENTLY_FORWARDED: usize = 256;   // for duplicate detection
const ACK_HASH_SIZE: usize = 8;              // truncated hash bytes

// RECENTLY_FORWARDED_TTL = 300τ (must exceed worst-case retry sequence of ~280τ with jitter)
// For LoRa (τ=6.7s): ~33 minutes
// For UDP (τ=0.1s): ~30 seconds
fn recently_forwarded_ttl(&self) -> Duration {
    self.tau() * 300
}
```

**Memory usage:**
- `pending_acks`: 32 entries × ~16 bytes (hash + metadata) = ~512 bytes
  - Plus original messages for retransmission (bounded by MTU × 32 ≈ 8KB worst case)
- `recently_forwarded`: 256 entries × ~16 bytes (hash + timestamp) = ~4KB
- Total: ~4.5KB metadata + up to 8KB message storage

**Why these values:**
- `RECENTLY_FORWARDED_TTL = 300τ`: Must exceed worst-case retry sequence (~280τ with jitter). Provides ~7% margin.
- `MAX_RECENTLY_FORWARDED = 256`: Forwarding rate scales inversely with τ (slow links forward slowly), so the product (TTL × rate) stays roughly constant. For LoRa at 33 min TTL but ~0.05 msg/s: ~99 entries needed. For UDP at 30s TTL but ~0.5 msg/s: ~15 entries needed. 256 provides headroom for both.
- `MAX_PENDING_ACKS = 32`: Limits concurrent outbound messages awaiting ACK. With worst-case ~280τ per message, throughput floor is ~32/280τ messages per τ under heavy loss.

When collections are full, oldest entries are evicted (LRU). This may cause:
- Evicted pending_ack: give up on that message (application can retry)
- Evicted recently_forwarded: may forward a duplicate (harmless, just wasteful)

### Why This Works

1. **Uses existing broadcasts:** No extra transmissions for implicit ACKs
2. **Handles half-duplex:** Retries when sender was transmitting during forward
3. **Prevents duplicates:** Explicit ACK + duplicate detection prevents message explosion
4. **Bounded memory:** Fixed-size hash storage, LRU eviction
5. **Graceful degradation:** After max retries, message is dropped (application can retry)

### What This Doesn't Provide

- **End-to-end reliability:** Only hop-by-hop. Multi-hop messages may still fail if every hop loses 50%.
- **Ordering guarantees:** Messages may arrive out of order
- **Exactly-once delivery:** Receivers must handle duplicates (same signature = same message)

Applications needing stronger guarantees should implement their own ack/retry at the DATA message level.

---

## Part 6: Reference

### Message Summary

**Pulse (broadcast):**

| Field | Size |
|-------|------|
| node_id | 16 |
| flags | 1 (bits 0-2: has_parent, need_pubkey, has_pubkey; bits 3-7: child_count) |
| parent_hash | 0 or 4 |
| root_hash | 4 |
| subtree_size | 1-3 (varint) |
| tree_size | 1-3 (varint) |
| keyspace_lo | 4 |
| keyspace_hi | 4 |
| pubkey | 0 or 32 |
| children | N × (4 + varint) — 4-byte hash + subtree_size, sorted by hash |
| signature | 65 |

**Routed (unicast):**

| Field | Size |
|-------|------|
| flags_and_type | 1 (bits 0-3: msg_type; bit 4: has_dest_hash; bit 5: has_src_addr; bit 6: has_src_pubkey) |
| dest_addr | 4 (u32 keyspace location) |
| dest_hash | 0 or 4 |
| src_addr | 0 or 4 (u32 keyspace location) |
| src_node_id | 16 |
| src_pubkey | 0 or 32 |
| ttl | 1 |
| payload | variable |
| signature | 65 |

*Keyspace addresses are fixed 4-byte u32 values. Signature is 65 bytes: 1 byte algorithm + 64 bytes Ed25519.*

**Message types:**

| Type | Value | dest_hash | src_addr | src_pubkey | Payload |
|------|-------|-----------|----------|------------|---------|
| PUBLISH | 0 | None | Some | Some | node_id (16), pubkey (32), keyspace_addr (4), seq (varint), replica_index (1), location_sig (65) |
| LOOKUP | 1 | Some | Some | Some | replica_index (1) |
| FOUND | 2 | Some | None | None | node_id (16), pubkey (32), keyspace_addr (4), seq (varint), replica_index (1), location_sig (65) |
| DATA | 3 | Some | 0/1 | 0/1 | application data |
| ACK | 4 | — | — | — | hash (8 bytes) |

*Routed signature covers all fields except ttl. PUBLISH/FOUND payloads include a dedicated location signature ("LOC:" prefix) that binds node_id to keyspace_addr. This allows storage nodes to forward entries during rebalancing without re-signing. For DATA, src_pubkey can be omitted after initial exchange (receiver has cached pubkey).*

**Domain separation prefixes:**
- `"PULSE:"` — Pulse signatures (tree maintenance)
- `"ROUTE:"` — Routed message signatures (all message types)
- `"LOC:"` — Location signatures (PUBLISH/FOUND payloads, signs: node_id || keyspace_addr || seq)

### Bandwidth

**Recommended: SF8 @ 125 kHz, g3 10% sub-band (869.4–869.65 MHz)**

| Metric | Value |
|--------|-------|
| Data rate | ~3.1 kbps |
| Urban range | 3–7 km |
| Duty cycle | 10% |

**Bandwidth allocation:** 20% Pulse, 80% data (of actual available bandwidth)

```
pulse_budget = 0.20 × duty_cycle
min_interval = max(10s, airtime / pulse_budget)
```

**Transport priority queues:** The Transport trait provides two outgoing queues:
- `protocol_outgoing()` — high priority: Pulse, PUBLISH, LOOKUP, FOUND, ACK
- `app_outgoing()` — lower priority: DATA messages

Transport implementations MUST drain the protocol queue before the app queue. This ensures tree maintenance and DHT operations work even when application traffic is heavy. Without this, a flood of DATA messages could starve Pulse broadcasts, causing neighbors to timeout and the tree to degrade.

**Pulse intervals (SF8):**

| Duty Cycle | Pulse Budget | Typical Interval | Data Budget |
|------------|--------------|------------------|-------------|
| 10% (g3) | 2% | ~25s | 8% (~1,860 bytes/min) |
| 1% (standard) | 0.2% | ~250s | 0.8% (~186 bytes/min) |

**PUBLISH overhead (10k node network):**

| Metric | Value |
|--------|-------|
| PUBLISH as % of data budget | 0.6% |
| Remaining for LOOKUP/DATA | ~99.4% |

**Sync word:** `0x42` (discriminates from Meshtastic 0x14, LoRaWAN 0x12/0x34)

### Failure Scenarios

| Scenario | Detection | Effect |
|----------|-----------|--------|
| Leaf dies | Parent: 8 missed Pulses (~24τ) | Remove from children |
| Internal node dies | Children: 8 missed Pulses (~24τ) | Each child becomes subtree root |
| Root dies | Children: 8 missed Pulses (~24τ) | Children merge (largest wins) |
| Partition | 8 missed Pulses (~24τ) | Two independent trees |
| Partition heals | Pulses from other tree | Merge (larger wins) |

*For LoRa (τ=6.7s): 24τ ≈ 160 seconds*

### Security Model

**Protected by signatures:**
- Node impersonation — can't forge Pulses
- DHT poisoning — can't overwrite others' locations
- Message forgery — can't fake messages
- PUBLISH replay — sequence numbers prevent old locations from overwriting new

**Not protected:**
- Sybil attacks — can create many identities
- Malicious behavior — selective dropping, strategic positioning
- Traffic analysis — routing is observable
- Eclipse attacks — see below

**Eclipse attacks:**

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

**Left to application:** End-to-end encryption, partner authentication

### Design Properties

**Clock-free operation:**
- Node IDs from keypairs (no timestamps)
- Pulse intervals measured locally
- Storage expiry uses local clocks
- Refresh counted in Pulse cycles

**Best-effort delivery:**
- Request-response: timeout triggers re-lookup
- Fire-and-forget: accept possible loss
- DHT lookups: try multiple replicas

The protocol is designed to tolerate packet loss at the transport layer. When send queues are full, messages are dropped rather than blocking. This is acceptable because:

1. **Pulse loss is tolerable:** Neighbors timeout after 8 missed Pulses (~24τ ≈ 160s for LoRa). With 50% packet loss, P(miss 8) = 0.4%, so spurious timeouts are rare. The priority queue ensures Pulses are rarely dropped unless severely overloaded.

2. **PUBLISH has redundancy:** Published to K=3 replicas, and refreshed every 8 hours. Missing one PUBLISH rarely matters.

3. **LOOKUP has retries:** Tries each of K=3 replicas sequentially. One dropped LOOKUP just moves to the next replica.

4. **FOUND is idempotent:** If lost, the requester will timeout and retry the LOOKUP.

5. **DATA is application's responsibility:** Applications needing reliability should implement acks/retries.

The transport's priority queue model (protocol messages before application data) ensures that infrastructure traffic (Pulse, PUBLISH, LOOKUP, FOUND) is protected from application traffic floods. Metrics are exposed so applications can monitor queue health and back off if needed.

**Consistency during rebalancing:**
- Keyspace ranges shift with tree structure
- Lookups may temporarily fail
- Entries pushed to new owners

### Expected Latency

This section provides expected latency for delivering application-level DATA messages under various conditions.

**Assumptions (LoRa SF8, 10% duty cycle):**
- τ = 6.7 seconds (see [Timing Model](#timing-model))
- Per-hop on success: ~0.1τ (forwarder receives and transmits)
- Per-hop on failure: sender waits backoff (1τ, 2τ, 4τ...) then retries
- Tree depth ≈ ceil(log₁₆(N)) for network size N

**Tree depth vs network size:**

| Network Size | Typical Depth | Avg Hops (random pair) |
|--------------|---------------|------------------------|
| 10 nodes | 2 | 2 |
| 100 nodes | 3 | 3 |
| 1,000 nodes | 4 | 4 |
| 10,000 nodes | 5 | 5 |

**Real-world LoRa packet loss rates:**

Based on studies of deployed LoRa networks (see `docs/lora-packet-loss-study.md`):

| Congestion Level | Device Density | Typical Loss Rate |
|------------------|----------------|-------------------|
| Light | Optimized, sparse | 6-15% |
| Typical | Normal deployment | 25-35% |
| Congested | 100-200 devices/gateway | 35-50% |
| Severe | 500+ devices/gateway | 50-75% |
| Extreme | 1000+ devices, high traffic | 75-95% |

**Per-hop latency model:**

With packet loss probability P and exponential backoff retries (1τ, 2τ, 4τ...), expected latency is:

```
E[hop] = Σ P^k × (1-P) × time(k)   where time(k) ≈ 2^k τ for k retries
```

| Loss Rate | Expected Per-Hop | Calculation |
|-----------|------------------|-------------|
| 10% (light) | ~0.25τ | 90% succeed first try (0.1τ), 9% need one retry (1.2τ) |
| 30% (typical) | ~0.8τ | 70% first try, 21% one retry, 6% two retries... |
| 50% (congested) | ~3.2τ | Each retry tier contributes ~0.5τ, series converges slowly |
| 70% (severe) | ~12τ | Series converges very slowly; most packets need 3+ retries |

*Note: Exponential backoff (1τ, 2τ, 4τ, 8τ...) makes repeated failures very costly. At 50% loss, P(need 3+ retries) = 12.5%. At 70% loss, P(need 3+ retries) = 34%.*

**With prefetched keyspace address (DATA only):**

| Network | Congestion | Hops | Per-Hop | Total | LoRa Time |
|---------|------------|------|---------|-------|-----------|
| 10 nodes | Light (10%) | 2 | 0.25τ | 0.5τ | ~3s |
| 10 nodes | Typical (30%) | 2 | 0.8τ | 1.6τ | ~11s |
| 10 nodes | Congested (50%) | 2 | 3.2τ | 6.4τ | ~43s |
| 10 nodes | Severe (70%) | 2 | 12τ | 24τ | ~3 min |
| 100 nodes | Light | 3 | 0.25τ | 0.75τ | ~5s |
| 100 nodes | Typical | 3 | 0.8τ | 2.4τ | ~16s |
| 100 nodes | Congested | 3 | 3.2τ | 9.6τ | ~64s |
| 100 nodes | Severe | 3 | 12τ | 36τ | ~4 min |
| 1,000 nodes | Light | 4 | 0.25τ | 1τ | ~7s |
| 1,000 nodes | Typical | 4 | 0.8τ | 3.2τ | ~21s |
| 1,000 nodes | Congested | 4 | 3.2τ | 12.8τ | ~86s |
| 1,000 nodes | Severe | 4 | 12τ | 48τ | ~5 min |

**Without prefetched address (LOOKUP round-trip + DATA):**

Total hops ≈ 3 × depth (LOOKUP to storage node + FOUND back + DATA to destination)

| Network | Congestion | Hops | Per-Hop | Total | LoRa Time |
|---------|------------|------|---------|-------|-----------|
| 10 nodes | Light | 6 | 0.25τ | 1.5τ | ~10s |
| 10 nodes | Typical | 6 | 0.8τ | 4.8τ | ~32s |
| 10 nodes | Congested | 6 | 3.2τ | 19.2τ | ~2 min |
| 10 nodes | Severe | 6 | 12τ | 72τ | ~8 min |
| 100 nodes | Light | 9 | 0.25τ | 2.25τ | ~15s |
| 100 nodes | Typical | 9 | 0.8τ | 7.2τ | ~48s |
| 100 nodes | Congested | 9 | 3.2τ | 28.8τ | ~3 min |
| 100 nodes | Severe | 9 | 12τ | 108τ | ~12 min |
| 1,000 nodes | Light | 12 | 0.25τ | 3τ | ~20s |
| 1,000 nodes | Typical | 12 | 0.8τ | 9.6τ | ~64s |
| 1,000 nodes | Congested | 12 | 3.2τ | 38.4τ | ~4 min |
| 1,000 nodes | Severe | 12 | 12τ | 144τ | ~16 min |

**Summary:**

| Scenario | Light | Typical | Congested | Severe |
|----------|-------|---------|-----------|--------|
| Small network, prefetched | ~3s | ~11s | ~43s | ~3 min |
| Small network, lookup | ~10s | ~32s | ~2 min | ~8 min |
| Large network (1K), prefetched | ~7s | ~21s | ~86s | ~5 min |
| Large network (1K), lookup | ~20s | ~64s | ~4 min | ~16 min |

**Key takeaways:**
1. **Prefetching cuts latency by ~3×** — Cache keyspace addresses when possible
2. **Congestion has dramatic impact** — 50× between light and severe loss
3. **Network size has modest impact** — Logarithmic scaling (4 vs 12 hops for 10 vs 1000 nodes)
4. **For LoRa, expect seconds to minutes** — This is a low-bandwidth, high-latency network
5. **At severe congestion, consider giving up** — Applications should set realistic timeouts; waiting 15+ minutes for a message is often worse than failing fast and retrying later
