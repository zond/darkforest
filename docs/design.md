# Tree-Based DHT for LoRa Mesh Networks

## Overview

This document describes a two-layer protocol for LoRa mesh networks:

1. **Tree Layer** — Builds and maintains a spanning tree using Pulse broadcasts
2. **DHT Layer** — Stores key-value pairs using tree addresses for routing

**Key design choices:**
- **Two message types:** Pulse (broadcast, tree maintenance) and Routed (unicast, data transfer)
- **Tree addresses:** `Vec<u8>` path from root, computed from parent's Pulse
- **16-byte node IDs:** Derived from Ed25519 pubkey hash, enabling built-in signatures
- **20/80 bandwidth split:** 20% of available bandwidth for Pulse, 80% for data (adapts to duty cycle)
- **10% duty cycle recommended:** EU868 g3 sub-band (869.4–869.65 MHz) for practical performance
- **SF8 @ 125 kHz:** Balances range (3–7 km urban) and throughput (~1,860 bytes/min on 10% DC)

The tree provides O(log N) routing between any two nodes. The DHT maps permanent node IDs to current tree addresses, enabling node discovery.

## Part 1: Tree Layer

### Node Identity

Each node has a permanent 16-byte node ID derived from its Ed25519 public key:

```rust
type NodeId = [u8; 16];
type PublicKey = [u8; 32];
type Signature = [u8; 64];

fn generate_identity() -> (NodeId, PublicKey, SecretKey) {
    let (pubkey, secret) = ed25519_keygen();
    let node_id = hash(&pubkey)[..16].try_into().unwrap();
    (node_id, pubkey, secret)
}
```

**Properties:**
- **Cryptographically bound:** node_id is derived from pubkey, so ownership is provable
- **Collision resistant:** 128-bit hash provides ~2^64 collision resistance
- **Preimage resistant:** ~2^128 work to find a pubkey matching a target node_id

The keypair is generated once at first boot and stored in flash. The node_id never changes.

### Node State

```rust
struct Node {
    // Identity
    node_id: NodeId,                        // 16 bytes, hash(pubkey)
    pubkey: PublicKey,                      // 32 bytes, Ed25519 public key
    secret: SecretKey,                      // 32 bytes, Ed25519 secret key

    // Tree position
    parent: Option<NodeId>,
    root_id: NodeId,
    tree_size: u32,
    subtree_size: u32,
    tree_addr: Vec<u8>,                     // path from root (e.g., [1, 0, 3])
    range: (u32, u32),                      // keyspace range [start, end)

    // Neighbors
    children: HashMap<NodeId, u32>,         // child -> subtree_size
    shortcuts: HashSet<NodeId>,
    neighbor_times: HashMap<NodeId, (Timestamp, Option<Timestamp>)>, // (last_seen, prev_seen)
    pubkey_cache: HashMap<NodeId, PublicKey>, // cached pubkeys for verification
    need_pubkey: HashSet<NodeId>,           // nodes we need pubkeys from
}

impl Node {
    fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Compute child ranges from children map, sorted by node_id
    fn child_ranges(&self) -> Vec<(NodeId, u32, u32)> {
        let mut children: Vec<_> = self.children.iter().collect();
        children.sort_by_key(|(id, _)| *id);

        let total: u32 = children.iter().map(|(_, sz)| *sz).sum();
        let width = self.range.1 - self.range.0;

        let mut start = self.range.0;
        let mut result = Vec::new();

        for (child_id, subtree_size) in children {
            let child_width = (width as u64 * *subtree_size as u64 / total as u64) as u32;
            result.push((*child_id, start, start + child_width));
            start += child_width;
        }
        result
    }
}
```

### Messages

The protocol uses two message types: Pulse for tree maintenance and Routed for data transfer.

```rust
/// Periodic broadcast (20% of available bandwidth, min 10s interval)
/// - Liveness signal for parent and children
/// - Carries tree state for merge decisions
/// - Carries children list for tree address computation
/// - Optionally carries pubkey for signature verification
struct Pulse {
    node_id: NodeId,                    // 16 bytes
    parent_id: Option<NodeId>,          // 17 bytes (1 + 16)
    root_id: NodeId,                    // 16 bytes
    subtree_size: varint,               // 1-3 bytes
    tree_size: varint,                  // 1-3 bytes
    tree_addr: Vec<u8>,                 // 1 + len bytes (typically 1-6)
    need_pubkey: bool,                  // 1 byte - request pubkeys from neighbors
    pubkey: Option<PublicKey>,          // 0 or 32 bytes
    child_prefix_len: u8,               // 1 byte - prefix length for all children
    children: Vec<(prefix, varint)>,    // (prefix_len + 1-3) bytes per child
    signature: Signature,               // 64 bytes
}

/// Tree-routed message for DHT operations and application data
struct Routed {
    dest_addr: Vec<u8>,                 // tree address for routing
    dest_node_id: Option<NodeId>,       // Some(id) for specific node, None for keyspace
    src_addr: Vec<u8>,                  // tree address for replies
    src_node_id: NodeId,                // sender (for verification + replies)
    msg_type: u8,                       // PUBLISH, LOOKUP, FOUND, DATA
    payload: Vec<u8>,                   // type-specific
    signature: Signature,               // 64 bytes, signs all above
}
```

**Tree addresses:**

A tree address is a `Vec<u8>` representing the path from root to node. Each byte is the sorted ordinal (index) of the child among its siblings when sorted by node_id.

- Root: `[]`
- Root's 2nd child (by node_id order): `[1]`
- That child's 1st child: `[1, 0]`

A child computes its tree address from the parent's Pulse:
1. Parent's Pulse contains `tree_addr` and `children` list
2. Child sorts children by node_id prefix, finds its index (0, 1, 2...)
3. Child's address = `parent.tree_addr + [index]`

**Prefix-compressed children:**

Children are identified by the minimum unique prefix of their node_id. A single `child_prefix_len` applies to all children (saves 1 byte per child vs individual lengths). With random 16-byte node_ids, siblings almost always differ in the first 1-2 bytes:

| Children | Typical prefix_len |
|----------|--------------------|
| 2-4 | 1 byte |
| 5-8 | 1-2 bytes |
| 9-16 | 2 bytes |

**Pubkey exchange:**

Nodes cache pubkeys for signature verification. When a node sees a Pulse from an unknown node_id:
1. Set `need_pubkey = true` in next Pulse
2. Neighbors with matching node_ids include `pubkey` in their next Pulse
3. Receiver caches: `node_id → pubkey`
4. Future signatures can be verified

**Pulse sizes (typical, with signature):**

| Scenario | Without pubkey | With pubkey |
|----------|----------------|-------------|
| Leaf (depth 4) | ~122 bytes | ~154 bytes |
| 4 children | ~142 bytes | ~174 bytes |
| 8 children | ~162 bytes | ~194 bytes |

A node claims a parent by setting `parent_id` in its Pulse. The parent detects this and adds the node as a child.

### Tree Construction

#### Bootstrap (Alone)

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
  need_pubkey: false,
  pubkey: None,
  children: [],
  signature: sign(secret_N, ...)
}
    (no response)

N state:
  parent = None
  root_id = N
  tree_size = 1
  subtree_size = 1
  tree_addr = []
  range = [0, 2³²)
  children = {}
```

N is root of its own single-node tree. It continues pulsing within its Pulse bandwidth budget, waiting for neighbors.

#### Joining an Existing Tree

When node N boots and discovers neighbor P (in tree with root R, tree_size=500):

```
N → Pulse{node_id: N, parent_id: None, root_id: N, subtree_size: 1, tree_size: 1,
          tree_addr: [], need_pubkey: false, pubkey: None, children: [], sig: ...}

P receives N's Pulse:
  - Unknown node_id N, no pubkey cached
  - P.need_pubkey.insert(N)
  - Can't verify signature yet, but processes optimistically

P → Pulse{node_id: P, parent_id: G, root_id: R, subtree_size: 50, tree_size: 500,
          tree_addr: [2], need_pubkey: true, pubkey: None,
          children: [...], sig: ...}

N receives P's Pulse:
  - Unknown node_id P, no pubkey cached → N.need_pubkey.insert(P)
  - P.need_pubkey=true → N will include pubkey next Pulse
  - Different root_id (N ≠ R)
  - N.tree_size(1) < P.tree_size(500) → N joins P's tree
  - N.parent = P
  - N.root_id = R
  - N.tree_size = 500

N → Pulse{node_id: N, parent_id: P, root_id: R, subtree_size: 1, tree_size: 500,
          tree_addr: [],  // knows P's addr is [2], but not own ordinal yet
          need_pubkey: true, pubkey: pubkey_N, children: [], sig: ...}

P receives N's Pulse:
  - N.pubkey present → P.pubkey_cache.insert(N, pubkey_N)
  - Verify signature → valid
  - N claims parent_id = P → P.children.insert(N, subtree_size=1)
  - P.subtree_size = 50 + 1 = 51
  - N.need_pubkey=true → P will include pubkey next Pulse

P → Pulse{node_id: P, parent_id: G, root_id: R, subtree_size: 51, tree_size: 501,
          tree_addr: [2], need_pubkey: false, pubkey: pubkey_P,
          child_prefix_len: 1, children: [(N_prefix, 1), ...], sig: ...}

N receives P's Pulse:
  - P.pubkey present → N.pubkey_cache.insert(P, pubkey_P)
  - Verify signature → valid
  - N finds itself in P.children → computes tree_addr = [2, idx]
  - N.tree_addr = [2, 0]  // assuming N is first child by node_id order
  - N.range = computed from P's range and sibling subtree_sizes

N → Pulse{node_id: N, parent_id: P, root_id: R, subtree_size: 1, tree_size: 501,
          tree_addr: [2, 0], need_pubkey: false, pubkey: None, children: [], sig: ...}
```

After this exchange, both N and P have each other's pubkeys cached and can verify all future signatures.

### Tree Maintenance

#### Liveness Detection

Nodes track `last_seen` timestamps for all neighbors. After 3 missed Pulses (typically ~60-90 seconds depending on node's Pulse rate), a node is presumed dead.

**If parent dies:**
```
C had parent P. P stops sending Pulse.

After 90s with no Pulse from P:
  C.parent = None
  C.root_id = C                    // C becomes root
  C.tree_size = C.subtree_size

C → Pulse{node_id: C, parent_id: None, root_id: C, subtree_size: 30, tree_size: 30}

D (child of C) receives C's Pulse:
  - root_id changed → D.root_id = C
  - D.tree_size = 30

D → Pulse{node_id: D, parent_id: C, root_id: C, subtree_size: 10, tree_size: 30}
```

**If child dies:**
```
P had child C (with subtree_size=10). C stops sending Pulse.

After 90s with no Pulse from C:
  P.children.remove(C)
  P.subtree_size -= 10

P → Pulse{node_id: P, parent_id: G, root_id: R, subtree_size: 40, tree_size: 500}
```

### Tree Merging

When two nodes from different trees come into radio range:

```
Tree A (root Ra, 900 nodes)       Tree B (root Rb, 100 nodes)
        Ra                                Rb
       /  \                               |
      .    X  ←—— discover ——→  Y         Py
                                         / \
                                        .   .
```

**Merge decision:** Larger tree_size wins. If equal, lower root_id wins.

**Merge flow:**

```
X: parent=Px, root_id=Ra, tree_size=900, subtree_size=50, tree_addr=[1]
Y: parent=Py, root_id=Rb, tree_size=100, subtree_size=20, tree_addr=[0]

X → Pulse{node_id: X, parent_id: Px, root_id: Ra, subtree_size: 50, tree_size: 900,
          tree_addr: [1], need_pubkey: false, ..., sig: ...}

Y → Pulse{node_id: Y, parent_id: Py, root_id: Rb, subtree_size: 20, tree_size: 100,
          tree_addr: [0], need_pubkey: false, ..., sig: ...}

X receives Y's Pulse:
  - Unknown node_id Y → X.need_pubkey.insert(Y)
  - Different root_id, but X.tree_size(900) > Y.tree_size(100) → X stays

Y receives X's Pulse:
  - Unknown node_id X → Y.need_pubkey.insert(X)
  - Different root_id (Rb ≠ Ra)
  - Y.tree_size(100) < X.tree_size(900) → Y dominated
  - Y.parent = X
  - Y.root_id = Ra
  - Y.tree_size = 900

Y → Pulse{node_id: Y, parent_id: X, root_id: Ra, subtree_size: 100, tree_size: 900,
          tree_addr: [],  // knows X's addr is [1], but not own ordinal yet
          need_pubkey: true, pubkey: pubkey_Y, ..., sig: ...}

X receives Y's Pulse:
  - Y.pubkey present → X.pubkey_cache.insert(Y, pubkey_Y)
  - Verify signature → valid
  - Y claims parent_id = X → X.children.insert(Y, subtree_size=100)
  - X.subtree_size = 50 + 100 = 150

X → Pulse{node_id: X, parent_id: Px, root_id: Ra, subtree_size: 150, tree_size: 1000,
          tree_addr: [1], need_pubkey: false, pubkey: pubkey_X,
          child_prefix_len: 1, children: [(...), (Y_prefix, 100)], sig: ...}

Y receives X's Pulse:
  - X.pubkey present → Y.pubkey_cache.insert(X, pubkey_X)
  - Verify signature → valid
  - Y finds itself in X.children → Y.tree_addr = [1, idx]

Py receives Y's Pulse (Y now claims parent=X, root=Ra):
  - Y's parent_id = X (no longer Py)
  - Y's root_id = Ra, tree_size = 900
  - Py.tree_size(100) < 900 → Py dominated
  - Py.parent = Y (parent-child inversion!)
  - Py.root_id = Ra
  - Py.tree_size = 900

Py → Pulse{node_id: Py, parent_id: Y, root_id: Ra, subtree_size: 80, tree_size: 900,
           need_pubkey: true, pubkey: pubkey_Py, ..., sig: ...}

Y receives Py's Pulse:
  - Py.pubkey present → verify and cache
  - Py claims parent_id = Y → Y.children.insert(Py, subtree_size=80)
  - Y.subtree_size = 20 + 80 = 100

(inversion propagates up tree B until reaching Rb, entire tree B merged)
```

**Result:** The larger tree absorbs the smaller. Parent-child inversions propagate through the dominated tree via Pulse messages. Pubkeys are exchanged as nodes discover new neighbors.

**Visual sequence of tree merge with parent-child inversion:**

```
Step 1: Initial state - two separate trees
═══════════════════════════════════════════

Tree A (900 nodes)              Tree B (100 nodes)
     Ra                              Rb
    /  \                             |
   .    Px                           Py ←── parent of Y
        |                           / \
        X  · · · · · · · · · ·  Y  .   .
                    ↑
              (radio range)


Step 2: Y discovers X's larger tree, switches parent to X
═════════════════════════════════════════════════════════

Tree A (now 1000 nodes)         Tree B (shrinking)
     Ra                              Rb
    /  \                             |
   .    Px                           Py ←── Y was here
        |                           / \
        X───────────────────────Y  .   .
        ↑                       │
        └── Y.parent = X ───────┘

Y's Pulse: parent_id=X, root_id=Ra
(Y has "defected" to the larger tree)


Step 3: Py receives Y's Pulse, sees Y joined larger tree
════════════════════════════════════════════════════════

Py compares: own tree_size(100) < Y's tree_size(900)
→ Py is dominated, must join Y's tree
→ INVERSION: Py.parent = Y (former child becomes parent!)

     Ra
    /  \
   .    Px                           Rb
        |                            |
        X────────────────────Y      (orphaned, will
                             |       also invert)
                             Py
                            / \
                           .   .

Py's Pulse: parent_id=Y, root_id=Ra
(Py now claims Y as parent)


Step 4: Inversion propagates to Rb
══════════════════════════════════

Rb receives Py's Pulse: parent_id=Y, root_id=Ra
Rb compares: own tree_size < Py's tree_size
→ Rb.parent = Py (another inversion!)

     Ra
    /  \
   .    Px
        |
        X────────────────────Y
                             |
                             Py
                            /|\
                           . Rb .
                             |
                            ...

Rb's Pulse: parent_id=Py, root_id=Ra


Step 5: Final merged tree
═════════════════════════

           Ra (root, 1000 nodes)
          /  \
         .    Px
              |
              X (subtree_size: 150)
             /|
            / |
           .  Y (subtree_size: 100)
              |
              Py (subtree_size: 80)
             /|\
            . Rb .
              |
             ...

All nodes now share root_id=Ra
Tree B's hierarchy is inverted: Rb → Py → Y
(was: Y → Py → Rb)
```

### Partition and Reconnection

**Network partition:**
```
Before:
      R (tree_size=100)
     / \
    A   B
   /
  C (subtree_size=30, tree_addr=[0,0])
 / \
D   E

Link A-C breaks.

After ~60-90s (3 missed Pulses):

C (no Pulse from parent A):
  C.parent = None
  C.root_id = C
  C.tree_size = 30
  C.tree_addr = []  // C is now root

C → Pulse{node_id: C, parent_id: None, root_id: C, subtree_size: 30, tree_size: 30,
          tree_addr: [], ..., sig: ...}

A (no Pulse from child C):
  A.children.remove(C)
  A.subtree_size -= 30

A → Pulse{node_id: A, parent_id: R, root_id: R, subtree_size: 10, tree_size: 70,
          tree_addr: [0], ..., sig: ...}

R.tree_size = 70

Two separate trees now:
  - Tree R: 70 nodes
  - Tree C: 30 nodes (C is root)

D and E receive C's Pulse with new root_id=C:
  D.root_id = C, D.tree_addr = [0]
  E.root_id = C, E.tree_addr = [1]
```

**Partition heals:**
```
A and C back in radio range. Both already have each other's pubkeys cached from before.

A → Pulse{node_id: A, parent_id: R, root_id: R, subtree_size: 10, tree_size: 70,
          tree_addr: [0], need_pubkey: false, ..., sig: ...}

C → Pulse{node_id: C, parent_id: None, root_id: C, subtree_size: 30, tree_size: 30,
          tree_addr: [], need_pubkey: false, ..., sig: ...}

C receives A's Pulse:
  - Pubkey cached → verify signature → valid
  - Different root_id (C ≠ R)
  - C.tree_size(30) < A.tree_size(70) → C dominated
  - C.parent = A
  - C.root_id = R
  - C.tree_size = 70

C → Pulse{node_id: C, parent_id: A, root_id: R, subtree_size: 30, tree_size: 70,
          tree_addr: [],  // knows A's addr is [0], but not own ordinal yet
          need_pubkey: false, ..., sig: ...}

A receives C's Pulse:
  - Pubkey cached → verify signature → valid
  - C claims parent_id = A → A.children.insert(C, subtree_size=30)
  - A.subtree_size = 10 + 30 = 40

A → Pulse{node_id: A, parent_id: R, root_id: R, subtree_size: 40, tree_size: 100,
          tree_addr: [0], child_prefix_len: 1, children: [(C_prefix, 30)], sig: ...}

C receives A's Pulse:
  - C finds itself in A.children → C.tree_addr = [0, 0]
  - tree_size updated to 100

C → Pulse{node_id: C, parent_id: A, root_id: R, subtree_size: 30, tree_size: 100,
          tree_addr: [0, 0], children: [(D_prefix, ...), (E_prefix, ...)], sig: ...}

D and E receive C's Pulse:
  - root_id changed back to R
  - Update tree_addr accordingly

Tree reunified: R.tree_size = 100
```

### Shortcut Discovery

Shortcuts (non-tree neighbors) are discovered passively:

1. Pulses are broadcast (heard by all nodes in radio range)
2. Non-parent/child nodes that hear you add you as a shortcut
3. Shortcuts expire after 3 missed Pulses (same timeout as tree neighbors)
4. No additional bandwidth cost

Shortcuts enable faster routing by skipping tree hops.

### Timeouts

All neighbor timeouts use the same rule: **3 missed Pulses**.

Since Pulse intervals vary by node (leaf ~20s, 8 children ~26s), we track the last two Pulse times to estimate each neighbor's interval:

```rust
impl Node {
    fn on_pulse_received(&mut self, sender: NodeId) {
        let now = now();
        let prev = self.neighbor_times.get(&sender).map(|(last, _)| *last);
        self.neighbor_times.insert(sender, (now, prev));
    }

    fn expected_interval(&self, neighbor: &NodeId) -> Duration {
        match self.neighbor_times.get(neighbor) {
            Some((last, Some(prev))) => *last - *prev,  // observed interval
            _ => Duration::from_secs(30),               // conservative default
        }
    }

    fn is_timed_out(&self, neighbor: &NodeId) -> bool {
        match self.neighbor_times.get(neighbor) {
            Some((last_seen, _)) => {
                now() > *last_seen + 3 * self.expected_interval(neighbor)
            }
            None => false,
        }
    }
}
```

At SF8 on the 10% g3 band, typical Pulse intervals are 20-32 seconds, so timeout is ~60-96 seconds. On 1% bands, intervals are ~200-315 seconds, so timeout is ~10-16 minutes.

| Relationship | Timeout | Effect |
|--------------|---------|--------|
| Parent | 3 × observed interval | Become root of subtree |
| Child | 3 × observed interval | Remove from children |
| Shortcut | 3 × observed interval | Remove from shortcuts |

### Bandwidth Analysis

**Recommended default: SF8 @ 125 kHz, g3 10% sub-band (869.4–869.65 MHz)**

| Metric | Value |
|--------|-------|
| Data rate | ~3.1 kbps |
| Urban range | 3–7 km |
| Line-of-sight range | 7–15 km |
| Duty cycle limit | 10% |

This balances range, speed, and available bandwidth for DHT operations.

**LoRa Spreading Factors (SF):**

LoRa uses spreading factors SF7–SF12. Higher SF = longer range but slower data rate:

| SF | Data Rate | Urban Range | Line-of-Sight Range |
|----|-----------|-------------|---------------------|
| SF7 | 5.5 kbps | 2–5 km | 5–10 km |
| SF8 | 3.1 kbps | 3–7 km | 7–15 km |
| SF9 | 1.8 kbps | 5–10 km | 10–20 km |
| SF12 | 0.3 kbps | 10–15 km | 20–50+ km |

Each SF increase roughly doubles airtime and adds ~2.5 dB link budget. All nodes in a mesh must use the same SF (different SFs are orthogonal and can't hear each other).

*Ranges assume a decent antenna (3–5 dBi) at reasonable height. Actual range varies with terrain, obstructions, and antenna placement.*

**Bandwidth allocation:**

Available bandwidth is split **20% for Pulse, 80% for data**, based on *actual* available bandwidth (raw bitrate × duty cycle). This ensures the protocol works on any duty cycle band, gracefully degrading on more constrained bands.

```
pulse_budget = 0.20 × duty_cycle
min_interval = max(10s, airtime / pulse_budget)
```

The 10-second minimum prevents excessive pulsing during rapid tree changes.

**Pulse intervals by duty cycle (SF8, 150-byte Pulse, ~500ms airtime):**

| Duty Cycle | Pulse Budget | Min Interval | Data Budget |
|------------|--------------|--------------|-------------|
| 10% (g3 band) | 2% | ~25s | 8% |
| 1% (standard) | 0.2% | ~250s (~4 min) | 0.8% |

**Pulse sizes and airtime (SF8, 125 kHz, with signature):**

| Scenario | Size | Airtime | Interval @ 10% DC | Interval @ 1% DC |
|----------|------|---------|-------------------|------------------|
| Leaf (no pubkey) | ~122 bytes | ~395ms | ~20s | ~200s |
| Leaf (with pubkey) | ~154 bytes | ~500ms | ~25s | ~250s |
| 4 children | ~142 bytes | ~460ms | ~23s | ~230s |
| 8 children | ~162 bytes | ~525ms | ~26s | ~260s |
| 8 children + pubkey | ~194 bytes | ~630ms | ~32s | ~315s |

*Interval = airtime / (0.20 × duty_cycle), minimum 10s*

**Data capacity by duty cycle (SF8):**

| Duty Cycle | Data Budget | Capacity |
|------------|-------------|----------|
| 10% (g3 band) | 8% | ~1,860 bytes/min |
| 1% (standard) | 0.8% | ~186 bytes/min |

**Recommended: g3 10% sub-band (869.4–869.65 MHz)**

The 10% band is strongly recommended:
- Practical Pulse intervals (~25s vs ~4 min)
- Usable data throughput (~1.8 KB/min vs ~180 bytes/min)
- Trade-off: g3 is shared with other protocols — may be congested in dense urban areas

The protocol *works* on 1% bands but with significantly degraded performance (4-minute Pulse intervals, ~3 bytes/sec for data).

**Sync word:**

LoRa uses a sync word (1-2 bytes) to discriminate between protocols. Messages with non-matching sync words are discarded at the hardware level. Common values:
- `0x12` — LoRaWAN public
- `0x34` — LoRaWAN private
- `0x14` — Meshtastic

This protocol uses sync word `0x42` (configurable). Meshtastic and LoRaWAN packets won't even be passed to our code.

### Summary

| Scenario | Messages | Outcome |
|----------|----------|---------|
| Bootstrap alone | Pulse | Single-node tree |
| Join tree | Pulse | Node joins |
| Child dies | Pulse (timeout) | Subtree removed |
| Parent dies | Pulse (timeout) | Subtree becomes new tree |
| Root dies | Pulse (timeout) | Siblings merge |
| Trees merge | Pulse + inversion | Smaller joins larger |
| Partition | Pulse (timeout) | Two trees |
| Partition heals | Pulse | Trees reunify |

---

## Part 2: DHT Layer

The DHT layer uses tree addresses for routing. Each node is responsible for keys that hash to its tree address. The primary use case is node discovery: storing each node's tree address at `hash(node_id)`.

### Keyspace

The keyspace is `[0, 2³²)` (u32). Keys are mapped to tree addresses via a deterministic assignment based on subtree sizes.

Each node owns a range proportional to its subtree_size. Children are ordered by node_id, and ranges are assigned left-to-right:

```
Root has range [0, 2³²), subtree_size=200
Children (sorted by node_id): A (100 nodes), B (50 nodes), C (50 nodes)

Assigned:
  A: [0, 2³¹)           // 50% → tree_addr [0]
  B: [2³¹, 3×2³⁰)       // 25% → tree_addr [1]
  C: [3×2³⁰, 2³²)       // 25% → tree_addr [2]
```

```rust
impl Node {
    /// Compute the keyspace range for a tree address
    fn range_for_addr(&self, addr: &[u8]) -> (u32, u32) {
        // Walk down from root, narrowing range at each level
        // based on child ordinal and subtree sizes
    }

    /// Find which child (by ordinal) owns a key
    fn child_ordinal_for_key(&self, key: u32) -> Option<u8> {
        let mut offset = self.range.0;
        for (i, (_, subtree_size)) in self.sorted_children().enumerate() {
            let width = self.range_width() * subtree_size / self.subtree_size;
            if key < offset + width {
                return Some(i as u8);
            }
            offset += width;
        }
        None
    }
}
```

### Tree Address Routing

Messages route through the tree using tree addresses:

```rust
impl Node {
    fn route(&self, msg: Routed) {
        let dest = &msg.dest_addr;

        // Check if destination is at my tree address
        if dest == &self.tree_addr {
            match msg.dest_node_id {
                Some(id) if id != self.node_id => {
                    // Specific node requested, but I'm not it - stale address
                    // Drop or re-route via DHT lookup
                }
                _ => {
                    // Either: None (keyspace routing - I own this range)
                    // Or: Some(my_id) (addressed to me specifically)
                    self.handle_locally(msg);
                }
            }
            return;
        }

        // Destination is in my subtree → route down
        if dest.starts_with(&self.tree_addr) {
            let next_ordinal = dest[self.tree_addr.len()];
            self.send_to_child_by_ordinal(next_ordinal, msg);
            return;
        }

        // Destination is elsewhere → route up
        self.send_to_parent(msg);
    }
}
```

### Node Location Storage

The DHT stores only one type of data: node locations (`node_id → tree_addr`). Each entry is signed by the node it belongs to, preventing impersonation.

**Stored entry format:**

```rust
struct LocationEntry {
    node_id: NodeId,              // whose location this is
    tree_addr: Vec<u8>,           // their current tree address
    signature: Signature,         // sign(node_id || tree_addr)
    received_at: Instant,         // local timestamp (storage node's clock)
}
```

The signature covers only `node_id || tree_addr`. Expiry is purely a storage concern — the storage node tracks when it received the entry and expires it after `TTL_12_HOURS` using its own local clock. No clock synchronization needed.

The storage node validates:
1. `hash(entry.node_id) mod 2³²` falls in my keyspace range
2. Signature is valid for `entry.node_id`
3. Entry hasn't expired (based on local `received_at`)

### Publishing Location (PUBLISH)

A node publishes its own location to k=3 replica locations. Only self-publication is allowed.

```rust
const K_REPLICAS: usize = 3;
const REPUBLISH_JITTER: Range<u64> = 0..5000;  // 0-5 seconds

impl Node {
    fn publish_location(&self) {
        let location_sig = sign(&self.secret, &encode(&self.node_id, &self.tree_addr));

        for i in 0..K_REPLICAS {
            let replica_key = self.replica_key(i);
            let dest_addr = self.addr_for_key(replica_key);

            let msg = Routed {
                dest_addr,
                dest_node_id: None,           // keyspace routing
                src_addr: self.tree_addr.clone(),
                src_node_id: self.node_id,
                msg_type: PUBLISH,
                payload: encode_publish(&self.tree_addr, &location_sig),
                signature: sign_routed(&self.secret, ...),
            };
            self.route(msg);
        }
    }

    fn replica_key(&self, i: usize) -> u32 {
        hash_to_u32(&[&self.node_id[..], &[i as u8]].concat())
    }

    fn on_tree_addr_changed(&mut self) {
        // Jitter spreads out republish storms during tree reshuffles
        let delay = rand::thread_rng().gen_range(REPUBLISH_JITTER);
        self.schedule_publish_after(Duration::from_millis(delay));
    }
}

// Called:
// - On join (immediate)
// - On tree address change (after 0-5s jitter)
// - Every 8 hours (scheduled refresh)
```

**PUBLISH payload:** `tree_addr || location_signature`

(node_id is implicit from `src_node_id` of the Routed message)

**Timing:**
- Storage TTL: 12 hours (storage node's local clock)
- Refresh: every 8 hours (provides buffer before expiry)
- Republish on tree address change with 0-5s jitter (prevents publish storms)

### Looking Up Nodes (LOOKUP / FOUND)

Lookups try each replica in order until one responds. This handles the case where a storage node has failed or doesn't have the entry.

```rust
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

impl Node {
    /// Start lookup at replica 0, retry others on timeout
    fn lookup_node(&mut self, target: NodeId) {
        self.pending_lookups.insert(target, PendingLookup {
            target,
            replica_index: 0,
            started: now(),
        });
        self.send_lookup(target, 0);
    }

    fn send_lookup(&self, target: NodeId, replica_index: usize) {
        let replica_key = hash_to_u32(&[&target[..], &[replica_index as u8]].concat());
        let dest_addr = self.addr_for_key(replica_key);

        let msg = Routed {
            dest_addr,
            dest_node_id: None,           // keyspace routing
            src_addr: self.tree_addr.clone(),
            src_node_id: self.node_id,
            msg_type: LOOKUP,
            payload: target.to_vec(),
            signature: sign_routed(&self.secret, ...),
        };
        self.route(msg);
    }

    /// Called periodically to check for lookup timeouts
    fn check_lookup_timeouts(&mut self) {
        for lookup in self.pending_lookups.values_mut() {
            if now() - lookup.started > LOOKUP_TIMEOUT {
                lookup.replica_index += 1;
                lookup.started = now();

                if lookup.replica_index < K_REPLICAS {
                    // Try next replica
                    self.send_lookup(lookup.target, lookup.replica_index);
                } else {
                    // All replicas failed - node unreachable or not published
                    self.pending_lookups.remove(&lookup.target);
                    self.on_lookup_failed(lookup.target);
                }
            }
        }
    }

    fn handle_lookup(&self, msg: Routed) {
        let target: NodeId = msg.payload.try_into().unwrap();

        if let Some(entry) = self.location_store.get(&target) {
            let response = Routed {
                dest_addr: msg.src_addr,
                dest_node_id: Some(msg.src_node_id),
                src_addr: self.tree_addr.clone(),
                src_node_id: self.node_id,
                msg_type: FOUND,
                payload: encode_found(&entry),
                signature: sign_routed(&self.secret, ...),
            };
            self.route(response);
        }
        // If not found, no response - requester will try next replica
    }

    fn handle_found(&mut self, msg: Routed) {
        let (node_id, tree_addr, signature) = decode_found(&msg.payload);

        // Cancel pending lookup
        if self.pending_lookups.remove(&node_id).is_none() {
            return;  // Unexpected response, ignore
        }

        // Verify the location signature (covers node_id || tree_addr)
        let pubkey = self.pubkey_cache.get(&node_id)?;
        if !verify(pubkey, &signature, &encode(&node_id, &tree_addr)) {
            return;  // Invalid signature, ignore
        }

        // Cache and use the location
        self.location_cache.insert(node_id, tree_addr.clone());
        self.on_lookup_success(node_id, tree_addr);
    }
}
```

**LOOKUP payload:** `target_node_id` (16 bytes)

**FOUND payload:** `target_node_id || tree_addr || location_signature` (no expires - storage already validated)

**Lookup process:**
1. Send LOOKUP to replica 0
2. If no FOUND within 30s, try replica 1
3. If still no response, try replica 2
4. After all replicas timeout, lookup fails (node unknown or offline)

### Sending Data

Once you have a node's tree address (from FOUND response or cache):

```rust
impl Node {
    fn send_data(&self, target_id: NodeId, target_addr: Vec<u8>, data: Vec<u8>) {
        let msg = Routed {
            dest_addr: target_addr,
            dest_node_id: Some(target_id),  // specific node
            src_addr: self.tree_addr.clone(),
            src_node_id: self.node_id,
            msg_type: DATA,
            payload: data,
            signature: sign_routed(&self.secret, ...),
        };
        self.route(msg);
    }
}
```

### Stale Address Handling

During tree reshuffles, cached addresses may become stale. Handle this with timeouts:

```rust
impl Node {
    /// Send data expecting a response, with retry on stale address
    fn send_request(&mut self, target_id: NodeId, data: Vec<u8>) {
        if let Some(addr) = self.location_cache.get(&target_id) {
            self.send_data(target_id, addr.clone(), data.clone());
            self.pending_requests.insert(target_id, PendingRequest {
                data,
                sent_at: now(),
                retries: 0,
            });
        } else {
            // No cached address - lookup first
            self.pending_data.insert(target_id, data);
            self.lookup_node(target_id);
        }
    }

    fn check_request_timeouts(&mut self) {
        for (target_id, req) in self.pending_requests.iter_mut() {
            if now() - req.sent_at > REQUEST_TIMEOUT {
                if req.retries < MAX_RETRIES {
                    // Assume stale address - invalidate cache and re-lookup
                    self.location_cache.remove(target_id);
                    self.pending_data.insert(*target_id, req.data.clone());
                    self.lookup_node(*target_id);
                    req.retries += 1;
                    req.sent_at = now();
                } else {
                    // Give up
                    self.pending_requests.remove(target_id);
                    self.on_request_failed(*target_id);
                }
            }
        }
    }
}
```

**For fire-and-forget messages:** No retry mechanism. Accept possible loss during tree reshuffles (rare events).

**For request-response patterns:** Timeout triggers cache invalidation and re-lookup, then retry.

### Replication

Each location is published to k=3 independent storage nodes (see `publish_location`). The replica keys are deterministic:

```
replica_0_key = hash(node_id || 0x00)
replica_1_key = hash(node_id || 0x01)
replica_2_key = hash(node_id || 0x02)
```

This ensures replicas are distributed across different parts of the tree, so a single node failure doesn't lose all copies.

### TTL and Expiration

Expiry is handled entirely by storage nodes using their local clocks — no clock synchronization required across the network.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Storage TTL | 12 hours | Storage nodes expire entries 12h after receipt |
| Refresh interval | 8 hours | Publishers refresh before entries expire |
| Republish trigger | Tree address change | Keeps data immediately fresh |

```rust
// Storage node: expire old entries
fn cleanup_expired(&mut self) {
    let cutoff = Instant::now() - Duration::from_secs(12 * 3600);
    self.location_store.retain(|_, entry| entry.received_at > cutoff);
}

// Publisher: refresh periodically
// (every ~8 hours, measured by counting Pulse intervals)
```

Dead nodes stop refreshing → entries expire after 12h → no stale data.

### Rebalancing

When subtree sizes change, keyspace ranges shift. Storage nodes push entries to new owners:

```rust
impl Node {
    fn on_range_change(&mut self, old_range: Range, new_range: Range) {
        // Push entries that are no longer in my range to siblings
        for entry in self.location_store.values() {
            let key = hash_to_u32(&entry.node_id);
            if !new_range.contains(key) {
                self.forward_entry_to_new_owner(entry);
            }
        }
    }
}
```

Lookups during rebalancing may miss; clients should retry.

### Bandwidth Budget (10k Node Network)

Analysis for a large network with 10,000 nodes on 10% duty cycle (g3 band), SF8.

**Assumptions:**
- Tree depth: ~5 (with ~8 children per internal node)
- Average routing hops: ~10 (up to ancestor, down to target)
- PUBLISH message size: ~168 bytes (~545ms airtime)
- k=3 replicas per node

**PUBLISH overhead:**

| Metric | Value |
|--------|-------|
| Publishes per node per 8h | 3 (one per replica) |
| Total PUBLISH messages/hour | 10,000 × 3 / 8 = 3,750 |
| Transmissions/hour (with forwarding) | 3,750 × 10 hops = 37,500 |
| Network-wide bytes/hour | 37,500 × 168 = ~6.3 MB |

**Per-node load:**

| Component | Bytes/hour |
|-----------|------------|
| Own publishes | 3/8h × 168 = ~63 |
| Forwarding (average) | 37,500 / 10,000 × 168 = ~630 |
| **Total PUBLISH burden** | **~693 bytes/hour** |

**Comparison to capacity:**

| Budget | Value |
|--------|-------|
| Data budget (8% of 10% DC, SF8) | ~111,600 bytes/hour |
| PUBLISH overhead | ~693 bytes/hour |
| **PUBLISH as % of data budget** | **0.6%** |
| **Remaining for LOOKUP/DATA** | **~99.4%** ≈ 1.85 KB/min |

The 12h TTL with 8h refresh and event-driven republish reduces PUBLISH overhead to under 1% of available bandwidth, leaving ample capacity for lookups and application data.

---

## Part 3: Complete Example

Node A (at tree address `[1, 2]`) wants to send data to node B:

**Step 1: A sends LOOKUP for B**
```
A computes: hash(B.node_id) mod 2³² = 0x7A3F0000
A determines: key 0x7A3F0000 is owned by tree address [0, 3]
A sends: Routed{dest_addr: [0,3], dest_node_id: None, msg_type: LOOKUP, payload: B.node_id}
```

**Step 2: Storage node responds with FOUND**
```
Node [0,3] receives LOOKUP, finds B's entry in local storage
Node [0,3] sends: Routed{dest_addr: [1,2], dest_node_id: Some(A), msg_type: FOUND,
                         payload: B.node_id || [2,0,1] || B's_signature}
```

**Step 3: A verifies and sends DATA**
```
A receives FOUND, verifies B's location_signature using B's pubkey
A sends: Routed{dest_addr: [2,0,1], dest_node_id: Some(B), msg_type: DATA, payload: ...}
```

**Step 4: B receives DATA**
```
B receives message, verifies dest_node_id matches, processes payload
```

---

## Part 4: Message Types

### Pulse (Broadcast)

Sent using 20% of available bandwidth (min 10s interval). Used for tree maintenance and routing table distribution.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| node_id | NodeId | 16 | Sender's permanent ID (hash of pubkey) |
| parent_id | Option<NodeId> | 17 | Parent's ID (None if root) |
| root_id | NodeId | 16 | Tree's root ID |
| subtree_size | varint | 1-3 | Nodes in subtree |
| tree_size | varint | 1-3 | Total nodes in tree |
| tree_addr | Vec<u8> | 1+len | Sender's tree address |
| need_pubkey | bool | 1 | Request pubkeys from neighbors |
| pubkey | Option<PublicKey> | 0 or 32 | Ed25519 public key (if requested) |
| child_prefix_len | u8 | 1 | Prefix length for all children |
| children | Vec<(prefix, varint)> | (prefix_len + 2) each | Children (prefix + subtree_size) |
| signature | Signature | 64 | Ed25519 signature over all preceding fields |

**Typical sizes (with signature):**
| Scenario | Size |
|----------|------|
| Leaf (no pubkey) | ~122 bytes |
| Leaf (with pubkey) | ~154 bytes |
| 4 children | ~142 bytes |
| 8 children | ~162 bytes |

### Routed (Unicast)

Used for node discovery and application data. Routed via tree addresses.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| dest_addr | Vec<u8> | 1+len | Destination tree address |
| dest_node_id | Option<NodeId> | 0 or 17 | Some(id) for specific node, None for keyspace |
| src_addr | Vec<u8> | 1+len | Sender's tree address (for replies) |
| src_node_id | NodeId | 16 | Sender's permanent ID |
| msg_type | u8 | 1 | Message type |
| payload | Vec<u8> | variable | Type-specific content |
| signature | Signature | 64 | Ed25519 signature over all preceding fields |

**Message types:**

| Type | Value | dest_node_id | Payload |
|------|-------|--------------|---------|
| PUBLISH | 0x01 | None | tree_addr, location_signature |
| LOOKUP | 0x02 | None | target_node_id (16 bytes) |
| FOUND | 0x03 | Some(requester) | target_node_id, tree_addr, location_signature |
| DATA | 0x10 | Some(target) | application data |

*Signature covers `node_id || tree_addr`. Expiry is handled locally by storage nodes — no timestamps in messages.*

---

## Part 5: Failure Scenarios

### Leaf Node Dies

1. Parent detects missing Pulses (90s)
2. Parent removes child from children set
3. Parent.subtree_size decreases
4. Change propagates up to root via Pulses
5. Keys at dead node lost (unless replicated elsewhere)

### Internal Node Dies

1. Children detect missing Pulses from parent (90s)
2. Each child becomes root of its subtree:
   - `parent = None`
   - `root_id = own node_id`
   - `tree_size = subtree_size`
3. New root_id propagates to descendants via Pulses
4. Seeks new parent from shortcuts/neighbors
5. When partitions reconnect:
   - Different root_ids → merge (larger tree_size wins)
   - Parent-child inversions propagate via Pulses

### Root Dies

1. Root's children detect missing Pulses (90s)
2. Each child becomes root of its subtree
3. If children are in radio range of each other:
   - Different root_ids → merge
   - Larger subtree wins, or lower root_id as tiebreaker
4. Tree reunifies under winning child

### Network Partition

1. Link breaks, nodes detect via missing Pulses (90s)
2. Orphaned side: new root sets `root_id = own node_id`
3. Main side: removes dead child, reduces subtree_size
4. Each component functions independently
5. When partition heals:
   - Different root_ids → merge (larger tree_size wins)
   - Smaller component grafts under larger via Pulses

---

## Part 6: Security Model

### What's Protected

**Signatures on all messages (Pulse, Routed) protect against:**
- Node impersonation — can't forge Pulses for existing nodes
- DHT poisoning — can't overwrite someone else's location entry
- Message forgery — can't fake messages from other nodes

**Cryptographic identity:**
- Node ID = hash(pubkey) — ownership is provable
- Location entries signed by owner — only you can publish your address

### What's Not Protected

**Signatures don't prevent:**
- Sybil attacks — attacker can create many legitimate identities
- Malicious but correctly-signed behavior — selective dropping, strategic positioning
- Traffic analysis — message routing is observable

**Left to application layer:**
- End-to-end payload encryption
- Authentication of communication partners

### Mitigations for Hostile Environments

For networks where Sybil attacks are a concern:
- Proof-of-work for new node IDs
- Invitation/vouching systems
- Reputation tracking based on behavior

---

## Part 7: Design Properties

### Clock-Free Operation

The protocol has no clock synchronization requirements:
- Node IDs derived from keypairs (no timestamps)
- Pulse intervals measured locally
- Storage expiry uses local clocks (no network-wide time)
- Refresh intervals counted in Pulse cycles

Suitable for embedded devices without RTC.

### Best-Effort Delivery

Routing is best-effort. For reliability:
- Request-response: timeout triggers re-lookup and retry (see Stale Address Handling)
- Fire-and-forget: accept possible loss during tree reshuffles
- DHT lookups: try multiple replicas on timeout

### Consistency During Rebalancing

When tree structure changes, keyspace ranges shift. Lookups may temporarily fail. Clients should retry — entries are pushed to new owners during rebalancing.

