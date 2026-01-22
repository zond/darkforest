# Tree-Based DHT for LoRa Mesh Networks

A protocol for building mesh networks over LoRa radios with O(log N) routing.

**Key properties:**
- Nodes form a spanning tree via periodic broadcasts
- Tree addresses enable efficient routing without flooding
- A distributed hash table maps node IDs to tree addresses
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
    parent_id: Option<NodeId>,          // 17 bytes (1 + 16)
    root_id: NodeId,                    // 16 bytes
    subtree_size: varint,               // 1-3 bytes
    tree_size: varint,                  // 1-3 bytes
    tree_addr: TreeAddr,                // nibble-packed: 1 + ⌈D/2⌉ bytes
    need_pubkey: bool,                  // 1 byte
    pubkey: Option<PublicKey>,          // 0 or 32 bytes
    child_prefix_len: u8,               // 1 byte
    children: Vec<(prefix, varint)>,    // variable
    signature: Signature,               // 65 bytes (1 algorithm + 64 sig)
}

// TreeAddr: nibble-packed path from root. Each level uses 4 bits (0-15 for child index).
// Wire format: 1 byte depth + ⌈depth/2⌉ bytes of nibbles (high nibble first).
// Example: depth 5, path [3,7,2,15,1] → 0x05 0x37 0x2F 0x10 (last nibble padded with 0)
//
// Validation requirements:
// - For odd depths, the low nibble of the final byte MUST be 0x0
// - Exactly ⌈depth/2⌉ nibble bytes MUST follow the depth byte
// - Messages violating these requirements MUST be rejected
// - depth=0 (root) is encoded as just 0x00 with zero additional bytes

// Signature covers ALL fields (domain-separated):
// "PULSE:" || node_id || parent_id || root_id || subtree_size || tree_size ||
//            tree_addr || need_pubkey || pubkey || child_prefix_len || children
```

A Pulse serves multiple purposes:
- **Liveness signal** for parent and children
- **Tree state** for merge decisions (root_id, tree_size)
- **Children list** for tree address computation
- **Pubkey exchange** for signature verification

**Replay consideration:** Pulses have no sequence number. This is a deliberate tradeoff:

- **Attack:** Replaying an old Pulse causes ~25s confusion until the legitimate node's next Pulse corrects it. Extending the attack requires jamming the legitimate Pulses.
- **Why no seq:** Adding seq (4 bytes) would require recovery after reboot. Since neighbors track `last_seen_seq`, a rebooted node's Pulses would be rejected until neighbors timeout (~75-90s). This recovery delay costs more than the 25s confusion it prevents.
- **Conclusion:** Pulses are frequent and self-correcting. The brief confusion window is acceptable given the recovery complexity seq would introduce.

**Typical sizes:**

| Scenario | Size |
|----------|------|
| Leaf (no pubkey) | ~122 bytes |
| Leaf (with pubkey) | ~154 bytes |
| 8 children + pubkey | ~194 bytes |
| 16 children (max) + pubkey | ~218 bytes |

The protocol limits nodes to `MAX_CHILDREN = 16` to ensure Pulse messages fit within transport MTU limits.

### Proactive Pulse Sending

In addition to periodic Pulses, nodes send **proactive Pulses** to accelerate state propagation. This reduces join/merge latency from 25-75 seconds to just a few seconds while keeping the protocol simple (one message type).

**Triggers for proactive Pulse:**

1. **State change** — When your tree state changes (parent, children, root_id, tree_size, tree_addr)
2. **Unknown neighbor** — When you receive a Pulse from an unrecognized node_id
3. **Pubkey request** — When you see `need_pubkey=true` in a neighbor's Pulse and they need yours

**Batching:** To avoid message storms during rapid changes, proactive Pulses are batched:

```rust
const PROACTIVE_PULSE_DELAY: Duration = Duration::from_secs(2);

impl Node {
    fn schedule_proactive_pulse(&mut self) {
        // If already scheduled, don't reschedule (coalesce triggers)
        if self.proactive_pulse_pending.is_none() {
            self.proactive_pulse_pending = Some(now() + PROACTIVE_PULSE_DELAY);
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

| Scenario | Periodic only | With proactive |
|----------|---------------|----------------|
| Join (get tree_addr) | 50-75s | ~5s |
| Merge detection | 0-25s | ~2s |
| State propagation | 0-25s | ~2s |
| Pubkey exchange | 25-50s | ~5s |

**Why this works:** The 2-second batch window coalesces multiple triggers (e.g., receiving several unknown Pulses at once) into a single proactive Pulse. The bandwidth budget prevents runaway sending during network churn.

### Node State

```rust
// Protocol limits (theoretical maximums)
const MAX_TREE_DEPTH: usize = 127;     // TTL 255 / 2 for round-trip routing
const MAX_CHILDREN: usize = 16;        // 4-bit nibble encoding limit

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
    tree_addr: Vec<u8>,

    // Neighbors (bounded by MAX_NEIGHBORS)
    children: HashMap<NodeId, u32>,         // child -> subtree_size
    shortcuts: HashSet<NodeId>,
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
  parent_id: None,
  root_id: N,
  subtree_size: 1,
  tree_size: 1,
  tree_addr: [],
  children: []
}

N state:
  parent = None
  root_id = N
  tree_size = 1
  tree_addr = []
```

N is root of its own single-node tree.

### Joining an Existing Tree

When node N boots and discovers neighbor P (in a tree with 500 nodes):

**Parent selection:** N evaluates all neighbors as potential parents. A neighbor is skipped if:
- It has `children.len() >= MAX_CHILDREN` (parent is full)
- It is in the distrusted set
- Its tree_size is smaller than N's current tree

**Parent selection priority** (among valid candidates):
1. **Good enough signal strength** — reliability first; skip neighbors with poor signal
2. **Shortest tree address** — minimizes routing hops; keeps trees wide and shallow
3. **Fewest children** — leaves room for other nodes to join

This prioritization naturally produces wide, shallow trees. Deep chains are discouraged because nodes prefer shorter addresses. This matters because message size grows with depth (nibble-packed addresses), and MTU limits will cause errors for very deep nodes.

**Practical depth limits for LoRa (MTU=255):**

| Message Type | Overhead Formula | Max Depth |
|--------------|------------------|-----------|
| PUBLISH | 170 + D bytes | ~85 |
| LOOKUP | 103 + D bytes | ~152 |
| FOUND | 186 + D bytes | **~69** |
| DATA (empty) | 103 + D bytes | ~152 |

FOUND is the limiting case because it includes both `dest_node_id` (Some, 17 bytes) and the location payload (tree_addr + seq + signature). A node at depth 69 can participate fully; deeper nodes may fail to receive lookup responses. In practice, trees rarely exceed depth 20-30 even in large networks.

**Implicit rejection:** When a node claims a parent (by setting `parent_id` in its Pulse), the parent decides whether to accept by including the child in its `children` list. A parent silently ignores a child if:
- It already has `MAX_CHILDREN` children
- Adding the child would cause the Pulse to exceed the transport MTU

If a joining node doesn't see itself in the parent's `children` list after 3 Pulses, it assumes rejection and tries another neighbor.

This ensures Pulse messages always fit within transport MTU limits (LoRa: 255 bytes, BLE: 252 bytes). With `MAX_CHILDREN = 16` and ~4 bytes per child entry, the children list typically uses ~64 bytes, keeping total Pulse size under 220 bytes. The MTU check handles rare edge cases (unlucky prefix collisions in large trees) without penalizing the common case.

```
t=0: N → Pulse{node_id: N, parent_id: None, root_id: N, tree_size: 1, ...}

t=0: P receives N's Pulse:
  - Unknown node_id → schedule proactive Pulse, need_pubkey=true

t=2s: P → proactive Pulse{node_id: P, parent_id: G, root_id: R, tree_size: 500,
          tree_addr: [2], need_pubkey: true, ...}

t=2s: N receives P's Pulse:
  - Different root_id (N ≠ R)
  - N.tree_size(1) < P.tree_size(500) → N joins P's tree
  - N.parent = P, N.root_id = R
  - State changed → schedule proactive Pulse with pubkey

t=4s: N → proactive Pulse{node_id: N, parent_id: P, root_id: R, tree_size: 500,
          tree_addr: [],  // knows P's addr, not own ordinal yet
          pubkey: pubkey_N, ...}

t=4s: P receives N's Pulse:
  - N.pubkey present → cache it
  - N claims parent_id = P → P.children.insert(N)
  - P.subtree_size += 1
  - State changed → schedule proactive Pulse

t=6s: P → proactive Pulse{..., children: [(N_prefix, 1), ...], ...}

t=6s: N receives P's Pulse:
  - N finds itself in P.children → computes tree_addr = [2, 0]
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

**Merge decision:** Larger tree_size wins. If equal, lower root_id wins.

```
X: root_id=Ra, tree_size=900
Y: root_id=Rb, tree_size=100

t=0: X and Y exchange Pulses (or X's periodic Pulse reaches Y)

t=0: Y receives X's Pulse:
  - Unknown node → schedule proactive Pulse
  - Y.tree_size(100) < X.tree_size(900) → Y dominated
  - Y.parent = X, Y.root_id = Ra
  - State changed → schedule proactive Pulse

t=2s: Y → proactive Pulse (claiming parent=X, root=Ra)

t=2s: Py receives Y's Pulse:
  - Py.tree_size < Y's tree_size → Py dominated
  - INVERSION: Py.parent = Y (former child becomes parent!)
  - Py.root_id = Ra
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
    publish_count: u32,
    count_start: Instant,
    subtree_size_at_start: u32,
}

fn on_publish_received(&mut self, msg: &Routed) {
    if self.is_storage_node_for(msg) {
        self.fraud_detection.publish_count += 1;
    }
}

fn on_subtree_size_changed(&mut self) {
    // Reset fraud detection if subtree_size changed significantly (2x either way)
    let old = self.fraud_detection.subtree_size_at_start;
    let new = self.subtree_size;
    if new > old * 2 || new < old / 2 {
        self.fraud_detection = FraudDetection {
            publish_count: 0,
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

    let observed = fd.publish_count as f64;
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
        publish_count: 0,
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
- **PUBLISH spoofing:** Attacker can generate fake PUBLISH by grinding keypairs until `hash(node_id || replica)` lands in victim's keyspace. Cost: ~`tree_size/(3×S)` keypairs per fake message. For S=10 in 1000-node tree: ~33 keypairs per fake PUBLISH. Sustaining fraud indefinitely requires ongoing computation.
- **Identity rotation:** After being distrusted, attacker generates new keypair and rejoins. The distrust mechanism provides temporary relief only. Possible mitigation: progressive backoff (after N frauds in time T, become more conservative about joining any tree).

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

Link A-C breaks. After ~200s (8 missed Pulses):

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

Nodes track Pulse timestamps for all neighbors. After 8 missed Pulses, a neighbor is presumed dead. (See Part 6 for rationale: with 50% packet loss, P(miss 8) = 0.4%.)

Since Pulse intervals vary by node, we track the observed interval:

```rust
const MIN_PULSE_INTERVAL: Duration = Duration::from_secs(8);  // rate limit
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
            _ => Duration::from_secs(30),  // conservative default
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
| Parent | 8 × observed interval (~200s) | Become root of subtree |
| Child | 8 × observed interval (~200s) | Remove from children |
| Shortcut | 8 × observed interval (~200s) | Remove from shortcuts |

### Shortcut Discovery

Shortcuts (non-tree neighbors) are discovered passively:

1. Pulses are broadcast (heard by all nodes in radio range)
2. Non-parent/child nodes that hear you add you as a shortcut
3. Shortcuts expire after 8 missed Pulses
4. No additional bandwidth cost

---

## Part 2: Tree Routing

This part describes how messages travel through the tree.

### Tree Addresses

A tree address is a `Vec<u8>` representing the path from root to node. Each byte is the child's index among its siblings (sorted by node_id).

- Root: `[]`
- Root's 2nd child (by node_id order): `[1]`
- That child's 1st child: `[1, 0]`

A child computes its tree address from the parent's Pulse:
1. Parent's Pulse contains `tree_addr` and `children` list
2. Child sorts children by node_id prefix, finds its index
3. Child's address = `parent.tree_addr ++ [index]`

**Prefix-compressed children:**

Children in a Pulse are identified by the minimum unique prefix of their node_id. A single `child_prefix_len` applies to all children:

| Children | Typical prefix_len |
|----------|--------------------|
| 2-4 | 1 byte |
| 5-8 | 1-2 bytes |
| 9-16 | 2 bytes |

### Routed Messages

Unicast messages use tree addresses for routing:

```rust
struct Routed {
    dest_addr: TreeAddr,            // nibble-packed tree address (4 bits per level)
    dest_node_id: Option<NodeId>,   // Some(id) for specific node, None for keyspace
    src_addr: Option<TreeAddr>,     // for replies; None if no response expected
    src_node_id: NodeId,            // sender identity
    msg_type: u8,                   // message type (0-3)
    ttl: u8,                        // hop limit, decremented at each hop
    payload: Vec<u8>,               // type-specific content
    signature: Signature,           // Ed25519 signature (see below)
}

// Tree addresses are nibble-packed: 4 bits per level, 2 levels per byte.
// Depth D uses ⌈D/2⌉ bytes. This enables deeper trees within MTU limits.

// msg_type values: 0=PUBLISH, 1=LOOKUP, 2=FOUND, 3=DATA
// Messages with undefined msg_type (4-255) MUST be dropped silently (future extensions)

// src_addr is optional:
// - PUBLISH: None (no response expected)
// - LOOKUP: Some (FOUND needs to route back); MUST drop if None
// - FOUND: None (no further response)
// - DATA: application-dependent

// Signature covers all fields EXCEPT ttl (forwarders must decrement it):
// "ROUTE:" || dest_addr || dest_node_id || src_addr || src_node_id || msg_type || payload

fn routed_sign_data(msg: &Routed) -> Vec<u8> {
    encode(b"ROUTE:", &msg.dest_addr, &msg.dest_node_id,
           &msg.src_addr, &msg.src_node_id, msg.msg_type, &msg.payload)
}
```

The signature covers all fields except `ttl` to prevent:
- Routing manipulation (changing dest_addr)
- Reply redirection (changing src_addr)
- Type confusion (changing msg_type)
- Payload tampering

The `ttl` field is not signed because forwarders must decrement it. An attacker could reset TTL to extend message lifetime, but cannot forge the message itself. TTL exists to prevent routing loops during tree restructuring.

The `dest_node_id` field distinguishes:
- `None` — route to whoever owns this tree address (keyspace routing)
- `Some(id)` — route to a specific node (if address is stale, detect mismatch)

### Routing Algorithm

Messages route up to a common ancestor, then down to the destination:

```rust
const DEFAULT_TTL: u8 = 255;  // max hops; theoretical max depth 127

impl Node {
    fn route(&mut self, mut msg: Routed) {
        // TTL check - prevent routing loops
        if msg.ttl == 0 {
            return;  // drop message
        }
        msg.ttl -= 1;

        let dest = &msg.dest_addr;

        // Am I the destination?
        if dest == &self.tree_addr {
            match msg.dest_node_id {
                Some(id) if id != self.node_id => {
                    // Stale address - node moved
                    return;
                }
                _ => {
                    self.handle_locally(msg);
                    return;
                }
            }
        }

        // Destination in my subtree → route down
        if dest.starts_with(&self.tree_addr) {
            let next_ordinal = dest[self.tree_addr.len()];
            self.send_to_child_by_ordinal(next_ordinal, msg);
            return;
        }

        // Destination elsewhere → route up
        self.send_to_parent(msg);
    }
}
```

**Routing example:**

```
         []
        / | \
      [0] [1] [2]
      /
   [0,0]

Node [0,0] sends to [2]:
  [0,0] → [0] (up)     not in subtree, route to parent
  [0]   → []  (up)     not in subtree, route to parent
  []    → [2] (down)   in subtree, route to child ordinal 2
```

### Shortcuts

Shortcuts enable faster routing by skipping tree hops. When routing up, a node can send directly to a shortcut if:
- The shortcut is an ancestor of the destination, OR
- The destination is in the shortcut's subtree

---

## Part 3: Location Directory

This part describes how nodes publish and discover each other's tree addresses.

### Keyspace

The keyspace is `[0, 2³²)`. Each node owns a range proportional to its subtree_size:

```
Root has range [0, 2³²), subtree_size=200
Children (sorted by prefix): A (100), B (50), C (50)

Assigned:
  A: [0, 2³¹)           // 50% → tree_addr [0]
  B: [2³¹, 3×2³⁰)       // 25% → tree_addr [1]
  C: [3×2³⁰, 2³²)       // 25% → tree_addr [2]
```

**Keyspace range calculation** (precise algorithm with integer math):

```rust
/// Calculate the keyspace range [start, end) owned by a node at the given tree address.
/// Uses u64 intermediate values to avoid overflow when multiplying u32 × u32.
fn range_for_addr(
    addr: &[u8],                           // tree address (nibbles)
    children_at_level: &[Vec<(u8, u32)>],  // children list at each level: (prefix, subtree_size)
) -> (u32, u32) {
    let mut start: u64 = 0;
    let mut range_size: u64 = 1 << 32;  // 2³²

    for (level, &child_index) in addr.iter().enumerate() {
        let children = &children_at_level[level];
        let total_subtree: u64 = children.iter().map(|(_, s)| *s as u64).sum();

        // Find our position among siblings (sorted by prefix)
        let mut offset: u64 = 0;
        for (i, &(prefix, subtree_size)) in children.iter().enumerate() {
            if prefix == child_index {
                // This is us - calculate our range
                let my_fraction = (range_size * subtree_size as u64) / total_subtree;
                start += offset;
                range_size = my_fraction;
                break;
            }
            // Accumulate offset for siblings before us
            offset += (range_size * subtree_size as u64) / total_subtree;
        }
    }

    (start as u32, (start + range_size) as u32)
}

/// Check if this node owns the given key (for storage decisions)
fn owns_key(&self, key: u32) -> bool {
    let (start, end) = self.my_range();
    if start <= end {
        key >= start && key < end
    } else {
        // Range wraps around 2³² (only possible for root)
        key >= start || key < end
    }
}
```

**Important precision notes:**
- Use u64 for intermediate calculations to avoid overflow (u32 × u32 can exceed u32)
- Division truncates, so the sum of children's ranges may be slightly less than parent's range
- The "leftover" keyspace (due to truncation) goes to the parent node itself
- Children are always sorted by prefix for consistent range assignment across all nodes

To find which tree address owns a key:

```rust
impl Node {
    fn addr_for_key(&self, key: u32) -> Vec<u8> {
        // Walk down from root, narrowing range at each level
        // At each level: find which child's range contains the key
        // Append that child's prefix to the address
        // Stop when we reach a leaf or the key falls in "leftover" space
    }
}
```

### Location Entries

The directory stores node locations (`node_id → tree_addr`). Each entry is signed by its owner:

```rust
struct LocationEntry {
    node_id: NodeId,
    tree_addr: TreeAddr,        // nibble-packed
    seq: varint,                // monotonic sequence number (1-5 bytes)
    signature: Signature,       // sign("LOC:" || node_id || tree_addr || seq)
    received_at: Instant,       // local timestamp for expiry
}
```

**Varint encoding:** All varint fields (seq, subtree_size, tree_size) use LEB128 encoding. Implementations MUST use canonical (minimal) encoding: the shortest byte sequence that represents the value. Non-minimal encodings (e.g., `0x80 0x00` for 0 instead of `0x00`) MUST be rejected during decoding to prevent signature ambiguity attacks. Standard libraries like `integer-encoding` or `postcard` handle this correctly.

The signature includes a sequence number for replay protection. Storage nodes reject entries with `seq <= current_seq` for the same node_id. The `"LOC:"` prefix provides domain separation (prevents signature reuse across message types).

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
const REPUBLISH_JITTER: Range<u64> = 0..5000;  // 0-5 seconds

struct Node {
    location_seq: u64,  // persisted, incremented on each publish
    // ...
}

impl Node {
    fn publish_location(&mut self) {
        self.location_seq += 1;
        let sig = sign(&self.secret,
            &encode(b"LOC:", &self.node_id, &self.tree_addr, self.location_seq));

        for i in 0..K_REPLICAS {
            let key = hash_to_u32(&[&self.node_id[..], &[i as u8]].concat());
            let dest_addr = self.addr_for_key(key);

            self.send_routed(Routed {
                dest_addr,
                dest_node_id: None,  // keyspace routing
                msg_type: PUBLISH,
                payload: encode(&self.tree_addr, self.location_seq, &sig),
                ...
            });
        }
    }

    fn on_tree_addr_changed(&mut self) {
        // Jitter prevents publish storms during tree reshuffles
        let delay = rand::thread_rng().gen_range(REPUBLISH_JITTER);
        self.schedule_publish_after(Duration::from_millis(delay));
    }
}
```

**PUBLISH payload:** `owner_node_id (16) || tree_addr (1+⌈D/2⌉) || seq (varint, 1-5) || location_signature (65)`

Typical size: 83 + ⌈D/2⌉ to 87 + ⌈D/2⌉ bytes (seq usually 1-2 bytes at normal publish rates).

The `owner_node_id` is included explicitly (not inferred from Routed `src_node_id`) so that:
- Forwarders can re-publish entries during keyspace rebalancing with their own Routed signature
- Receivers can always verify the location signature against the correct owner

**Routing behavior:** Routed messages are forwarded as-is during normal routing (only TTL decremented). For keyspace rebalancing, a node creates a new Routed message (signed with their own key) containing the original PUBLISH payload.

**PUBLISH verification order** (storage node receiving a PUBLISH):
1. Verify Routed signature against `src_node_id` (authenticates sender)
   - If pubkey not cached: queue message, request via next Pulse (need_pubkey)
2. Parse PUBLISH payload to extract `owner_node_id`, `tree_addr`, `seq`, `location_signature`
3. Verify location signature against `owner_node_id` (covers `"LOC:" || owner_node_id || tree_addr || seq`)
   - If pubkey not cached: queue message, request via next Pulse (need_pubkey)
4. Verify keyspace ownership: at least one of `hash(owner_node_id || 0)`, `hash(owner_node_id || 1)`, `hash(owner_node_id || 2)` falls in my range
5. Verify `seq > existing_seq` for this `owner_node_id` (replay protection)
6. Store entry with current timestamp for expiry tracking

**Pubkey queue:** Messages awaiting pubkey verification are held in a small bounded queue (e.g., 16 entries). When a pubkey arrives via Pulse, queued messages for that node_id are re-processed. When the queue is full, oldest entries are evicted. This reduces retransmission overhead.

### Lookup (LOOKUP / FOUND)

Lookups try each replica until one responds:

```rust
// 4 minutes per replica to account for LoRa constraints:
// - Slow effective bandwidth (~38 bytes/sec at SF8, 10% duty)
// - Multi-hop routing through tree (each hop adds latency)
// - Potential retransmissions at each hop
// - Pulse intervals needed for route discovery
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(240);

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
            dest_addr: self.addr_for_key(key),
            dest_node_id: None,
            msg_type: LOOKUP,
            payload: target.to_vec(),
            ...
        });
    }

    fn handle_lookup(&self, msg: Routed) {
        let target: NodeId = msg.payload.try_into().unwrap();

        if let Some(entry) = self.location_store.get(&target) {
            self.send_routed(Routed {
                dest_addr: msg.src_addr,
                dest_node_id: Some(msg.src_node_id),
                msg_type: FOUND,
                payload: encode(&entry.node_id, &entry.tree_addr,
                               entry.seq, &entry.signature),
                ...
            });
        }
        // No response if not found — requester will try next replica
    }

    fn handle_found(&mut self, msg: Routed) {
        let (node_id, tree_addr, seq, signature) = decode(&msg.payload);

        if self.pending_lookups.remove(&node_id).is_none() {
            return;  // Unexpected
        }

        // Verify the location signature
        let pubkey = self.pubkey_cache.get(&node_id)?;
        if !verify(pubkey, &signature, &encode(b"LOC:", &node_id, &tree_addr, seq)) {
            return;
        }

        self.location_cache.insert(node_id, tree_addr);
    }
}
```

**LOOKUP payload:** `target_node_id` (16 bytes)

**FOUND payload:** `target_node_id (16) || tree_addr (1+⌈D/2⌉) || seq (varint, 1-5) || location_signature (65)`

**Lookup process:**
1. Send LOOKUP to replica 0
2. If no FOUND within 30s, try replica 1
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
| Republish trigger | Tree address change |

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
fn on_range_change(&mut self, old_range: Range, new_range: Range) {
    for entry in self.location_store.values() {
        let key = hash_to_u32(&entry.node_id);
        if !new_range.contains(key) {
            self.forward_entry_to_new_owner(entry);
        }
    }
}
```

---

## Part 4: Sending Messages

This part shows how to find and message any node in the network.

### Complete Example

Node A (at `[1, 2]`) wants to send data to node B:

**Step 1: A looks up B's location**
```
A computes: hash(B.node_id) → key 0x7A3F0000
A determines: key maps to tree address [0, 3]
A sends: LOOKUP to [0, 3] with payload B.node_id
```

**Step 2: Storage node responds**
```
Node [0,3] finds B's entry, sends FOUND to A
Payload: B.node_id || B.tree_addr || B's signature
```

**Step 3: A verifies and sends DATA**
```
A verifies B's signature using B's cached pubkey
A sends: DATA to B.tree_addr with dest_node_id = Some(B)
```

**Step 4: B receives DATA**
```
B receives message at its tree address
B verifies dest_node_id matches its own node_id
B processes payload
```

### Sending Data

```rust
impl Node {
    fn send_data(&self, target_id: NodeId, target_addr: Vec<u8>, data: Vec<u8>) {
        self.send_routed(Routed {
            dest_addr: target_addr,
            dest_node_id: Some(target_id),
            msg_type: DATA,
            payload: data,
            ...
        });
    }
}
```

### Stale Address Handling

During tree reshuffles, cached addresses may become stale.

**For request-response patterns:** Timeout triggers re-lookup and retry:

```rust
impl Node {
    fn send_request(&mut self, target_id: NodeId, data: Vec<u8>) {
        if let Some(addr) = self.location_cache.get(&target_id) {
            self.send_data(target_id, addr.clone(), data.clone());
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

## Part 5: Reference

### Message Summary

**Pulse (broadcast):**

| Field | Size |
|-------|------|
| node_id | 16 |
| parent_id | 1 or 17 |
| root_id | 16 |
| subtree_size | 1-3 (varint) |
| tree_size | 1-3 (varint) |
| tree_addr | 1 + ⌈D/2⌉ (nibble-packed) |
| need_pubkey | 1 |
| pubkey | 0 or 32 |
| child_prefix_len | 1 |
| children | variable |
| signature | 65 |

**Routed (unicast):**

| Field | Size |
|-------|------|
| dest_addr | 1 + ⌈D/2⌉ (nibble-packed) |
| dest_node_id | 1 or 17 |
| src_addr | 1 or 1 + ⌈D/2⌉ (optional, nibble-packed) |
| src_node_id | 16 |
| msg_type | 1 |
| ttl | 1 |
| payload | variable |
| signature | 65 |

*Tree addresses are nibble-packed: 1 byte depth + ⌈depth/2⌉ bytes of nibbles. Signature is 65 bytes: 1 byte algorithm + 64 bytes Ed25519.*

**Message types:**

| Type | Value | dest_node_id | Payload |
|------|-------|--------------|---------|
| PUBLISH | 0 | None | owner_node_id, tree_addr, seq (varint), location_signature |
| LOOKUP | 1 | None | target_node_id |
| FOUND | 2 | Some | target_node_id, tree_addr, seq (varint), location_signature |
| DATA | 3 | Some | application data |

*Location signature covers `"LOC:" || owner_node_id || tree_addr || seq`. Routed signature covers all fields except ttl. src_addr is None for PUBLISH and FOUND (no response expected).*

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
- `protocol_outgoing()` — high priority: Pulse, PUBLISH, LOOKUP, FOUND
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
| Leaf dies | Parent: 8 missed Pulses (~200s) | Remove from children |
| Internal node dies | Children: 8 missed Pulses (~200s) | Each child becomes subtree root |
| Root dies | Children: 8 missed Pulses (~200s) | Children merge (largest wins) |
| Partition | 8 missed Pulses (~200s) | Two independent trees |
| Partition heals | Pulses from other tree | Merge (larger wins) |

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

1. **Pulse loss is tolerable:** Neighbors timeout after 8 missed Pulses (~200 seconds). With 50% packet loss, P(miss 8) = 0.4%, so spurious timeouts are rare. The priority queue ensures Pulses are rarely dropped unless severely overloaded.

2. **PUBLISH has redundancy:** Published to K=3 replicas, and refreshed every 8 hours. Missing one PUBLISH rarely matters.

3. **LOOKUP has retries:** Tries each of K=3 replicas sequentially. One dropped LOOKUP just moves to the next replica.

4. **FOUND is idempotent:** If lost, the requester will timeout and retry the LOOKUP.

5. **DATA is application's responsibility:** Applications needing reliability should implement acks/retries.

The transport's priority queue model (protocol messages before application data) ensures that infrastructure traffic (Pulse, PUBLISH, LOOKUP, FOUND) is protected from application traffic floods. Metrics are exposed so applications can monitor queue health and back off if needed.

**Consistency during rebalancing:**
- Keyspace ranges shift with tree structure
- Lookups may temporarily fail
- Entries pushed to new owners

---

## Part 6: Link-Layer Reliability

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
3. Possible duty cycle delay (0-30+ seconds under congestion)
4. Transmit forwarded packet (~500ms)

Under normal conditions: ~1-2 seconds. Under duty cycle pressure: could be 30+ seconds.

### Retransmission Policy

```rust
const MAX_RETRIES: u8 = 8;
const INITIAL_BACKOFF_MS: u64 = 2000;  // 2 seconds minimum

// Note: Actual retry timing may be delayed beyond backoff by duty cycle.
// Logical backoffs: 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s
// With duty cycle delays, total worst-case could be 10+ minutes.

struct PendingAck {
    expected_hash: [u8; 8],  // hash of message with TTL-1
    original_msg: Vec<u8>,   // for retransmission
    retries: u8,
    next_retry: Instant,
}

fn retry_backoff(retries: u8) -> Duration {
    Duration::from_millis(INITIAL_BACKOFF_MS << retries)
}
```

### Pulse Liveness

For Pulse messages, we increase the liveness window from 3 to 8 missed Pulses.

**Rationale:** With 50% loss per Pulse:
- P(miss 3 in a row) = 0.5³ = 12.5% — too high, causes spurious timeouts
- P(miss 8 in a row) = 0.5⁸ = 0.4% — rare enough to be acceptable

At ~25 second Pulse intervals, 8 missed Pulses = ~200 seconds before declaring a neighbor dead. This balances robustness against loss with reasonable failure detection time.

### Memory Bounds

```rust
const MAX_PENDING_ACKS: usize = 32;          // messages awaiting ACK
const MAX_RECENTLY_FORWARDED: usize = 128;   // for duplicate detection
const ACK_HASH_SIZE: usize = 8;              // truncated hash bytes
const RECENTLY_FORWARDED_TTL: Duration = Duration::from_secs(180);  // 3 minutes
```

**Memory usage:**
- `pending_acks`: 32 entries × ~16 bytes (hash + metadata) = ~512 bytes
  - Plus original messages for retransmission (bounded by MTU × 32 ≈ 8KB worst case)
- `recently_forwarded`: 128 entries × ~16 bytes (hash + timestamp) = ~2KB
- Total: ~2.5KB metadata + up to 8KB message storage

**Why these values:**
- `RECENTLY_FORWARDED_TTL = 180s`: Must exceed worst-case time for duplicate to arrive (sender delayed by duty cycle, multiple backoffs). 3 minutes provides margin.
- `MAX_RECENTLY_FORWARDED = 128`: At 0.5 messages/second forwarded (high for LoRa), 180s × 0.5 = 90 entries. 128 provides headroom.
- `MAX_PENDING_ACKS = 32`: Limits concurrent outbound messages awaiting ACK. With ~10 minute worst-case per message, throughput floor is ~3 messages/minute under heavy loss.

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
