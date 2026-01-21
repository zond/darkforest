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
    tree_addr: Vec<u8>,                 // 1 + len bytes
    need_pubkey: bool,                  // 1 byte
    pubkey: Option<PublicKey>,          // 0 or 32 bytes
    child_prefix_len: u8,               // 1 byte
    children: Vec<(prefix, varint)>,    // variable
    signature: Signature,               // 64 bytes
}

// Signature covers ALL fields (domain-separated):
// "PULSE:" || node_id || parent_id || root_id || subtree_size || tree_size ||
//            tree_addr || need_pubkey || pubkey || child_prefix_len || children
```

A Pulse serves multiple purposes:
- **Liveness signal** for parent and children
- **Tree state** for merge decisions (root_id, tree_size)
- **Children list** for tree address computation
- **Pubkey exchange** for signature verification

**Replay consideration:** Pulses have no sequence number. An attacker replaying an old Pulse causes brief confusion (~25s) until the legitimate node's next Pulse corrects it. This is low-impact since Pulses are frequent and self-correcting.

**Typical sizes:**

| Scenario | Size |
|----------|------|
| Leaf (no pubkey) | ~122 bytes |
| Leaf (with pubkey) | ~154 bytes |
| 8 children + pubkey | ~194 bytes |

### Node State

```rust
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

    // Neighbors
    children: HashMap<NodeId, u32>,         // child -> subtree_size
    shortcuts: HashSet<NodeId>,
    neighbor_times: HashMap<NodeId, (Timestamp, Option<Timestamp>)>,
    pubkey_cache: HashMap<NodeId, PublicKey>,
    need_pubkey: HashSet<NodeId>,
}
```

### Pubkey Exchange

Nodes cache pubkeys for signature verification. When a node receives a Pulse from an unknown node_id:

1. Set `need_pubkey = true` in next Pulse
2. Neighbors with matching node_ids include `pubkey` in their next Pulse
3. **Verify binding:** `hash(pubkey)[..16] == node_id` (MUST check!)
4. Receiver caches: `node_id → pubkey`
5. Future signatures can be verified

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

```
N → Pulse{node_id: N, parent_id: None, root_id: N, tree_size: 1, ...}

P receives N's Pulse:
  - Unknown node_id → P.need_pubkey.insert(N)

P → Pulse{node_id: P, parent_id: G, root_id: R, tree_size: 500,
          tree_addr: [2], need_pubkey: true, ...}

N receives P's Pulse:
  - Different root_id (N ≠ R)
  - N.tree_size(1) < P.tree_size(500) → N joins P's tree
  - N.parent = P
  - N.root_id = R

N → Pulse{node_id: N, parent_id: P, root_id: R, tree_size: 500,
          tree_addr: [],  // knows P's addr, not own ordinal yet
          pubkey: pubkey_N, ...}

P receives N's Pulse:
  - N.pubkey present → cache it
  - N claims parent_id = P → P.children.insert(N)
  - P.subtree_size += 1

P → Pulse{..., children: [(N_prefix, 1), ...], ...}

N receives P's Pulse:
  - N finds itself in P.children → computes tree_addr = [2, 0]
```

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

Y receives X's Pulse:
  - Y.tree_size(100) < X.tree_size(900) → Y dominated
  - Y.parent = X
  - Y.root_id = Ra

Py receives Y's Pulse (Y now claims parent=X, root=Ra):
  - Py.tree_size < Y's tree_size → Py dominated
  - INVERSION: Py.parent = Y (former child becomes parent!)
  - Py.root_id = Ra

(inversion propagates up tree B until reaching Rb)
```

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
    publish_count: u32,
    // ...
}

struct JoinContext {
    parent_at_join: NodeId,
    join_time: Instant,
}

fn on_publish_received(&mut self, msg: &Routed) {
    if self.is_storage_node_for(msg) {
        self.publish_count += 1;
    }
}

fn check_tree_size_fraud(&mut self) {
    let ctx = match &self.join_context {
        Some(c) => c,
        None => return,
    };

    let t_hours = ctx.join_time.elapsed().as_secs_f64() / 3600.0;
    let expected = 3.0 * self.subtree_size as f64 * t_hours / 8.0;

    // Wait until we have enough expected samples for valid statistics
    if expected < MIN_EXPECTED {
        return;
    }

    let observed = self.publish_count as f64;
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
    self.publish_count = 0;
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

- **Small subtrees need more time:** A leaf node (`S=1`) needs ~14 hours to reach `λ=5` (minimum for reliable statistics).
- **Spoofing is possible but costly:** Attacker can generate fake PUBLISH, but must grind ~`tree_size/(3×S)` keypairs per fake message to hit the victim's keyspace range.
- **Distrust is local:** Each node detects fraud independently. No gossip (to avoid false-accusation attacks).
- **Timer required:** Needs monotonic timer. Distrust state is lost on reboot.

### Partition and Reconnection

**Network partition:**

```
Before:
      R (tree_size=100)
     / \
    A   B
   /
  C (subtree_size=30)

Link A-C breaks. After ~90s (3 missed Pulses):

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

Nodes track Pulse timestamps for all neighbors. After 3 missed Pulses, a neighbor is presumed dead.

Since Pulse intervals vary by node, we track the observed interval:

```rust
const MIN_PULSE_INTERVAL: Duration = Duration::from_secs(8);  // rate limit

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
                now() > *last_seen + 3 * self.expected_interval(neighbor)
            }
            None => false,
        }
    }
}
```

| Relationship | Timeout | Effect |
|--------------|---------|--------|
| Parent | 3 × observed interval | Become root of subtree |
| Child | 3 × observed interval | Remove from children |
| Shortcut | 3 × observed interval | Remove from shortcuts |

### Shortcut Discovery

Shortcuts (non-tree neighbors) are discovered passively:

1. Pulses are broadcast (heard by all nodes in radio range)
2. Non-parent/child nodes that hear you add you as a shortcut
3. Shortcuts expire after 3 missed Pulses
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
    dest_addr: Vec<u8>,             // tree address for routing
    dest_node_id: Option<NodeId>,   // Some(id) for specific node, None for keyspace
    src_addr: Vec<u8>,              // for replies
    src_node_id: NodeId,            // sender identity
    msg_type: u8,                   // message type
    ttl: u8,                        // hop limit, decremented at each hop
    payload: Vec<u8>,               // type-specific content
    signature: Signature,           // Ed25519 signature (see below)
}

// Signature covers all fields EXCEPT ttl (forwarders must decrement it):
// "ROUTE:" || dest_addr || dest_node_id || src_addr || src_node_id || msg_type || payload
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
const DEFAULT_TTL: u8 = 64;  // max hops, ~10x expected tree depth

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
Children (sorted by node_id): A (100), B (50), C (50)

Assigned:
  A: [0, 2³¹)           // 50% → tree_addr [0]
  B: [2³¹, 3×2³⁰)       // 25% → tree_addr [1]
  C: [3×2³⁰, 2³²)       // 25% → tree_addr [2]
```

To find which tree address owns a key:

```rust
impl Node {
    fn addr_for_key(&self, key: u32) -> Vec<u8> {
        // Walk down from root, narrowing range at each level
        // based on child ordinal and subtree sizes
    }
}
```

### Location Entries

The directory stores node locations (`node_id → tree_addr`). Each entry is signed by its owner:

```rust
struct LocationEntry {
    node_id: NodeId,
    tree_addr: Vec<u8>,
    seq: u64,                   // monotonic sequence number
    signature: Signature,       // sign("LOC:" || node_id || tree_addr || seq)
    received_at: Instant,       // local timestamp for expiry
}
```

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

**PUBLISH payload:** `tree_addr || seq || location_signature`

The storage node validates:
1. Key falls in my range
2. Signature is valid (covers `"LOC:" || node_id || tree_addr || seq`)
3. `seq > existing_seq` for this node_id (replay protection)
4. Entry hasn't expired

### Lookup (LOOKUP / FOUND)

Lookups try each replica until one responds:

```rust
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

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

**FOUND payload:** `target_node_id || tree_addr || seq || location_signature`

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
| parent_id | 17 |
| root_id | 16 |
| subtree_size | 1-3 |
| tree_size | 1-3 |
| tree_addr | 1+len |
| need_pubkey | 1 |
| pubkey | 0 or 32 |
| child_prefix_len | 1 |
| children | variable |
| signature | 65 |

**Routed (unicast):**

| Field | Size |
|-------|------|
| dest_addr | 1+len |
| dest_node_id | 0 or 17 |
| src_addr | 1+len |
| src_node_id | 16 |
| msg_type | 1 |
| ttl | 1 |
| payload | variable |
| signature | 65 |

*Signature is 65 bytes: 1 byte algorithm identifier + 64 bytes Ed25519 signature.*

**Message types:**

| Type | Value | dest_node_id | Payload |
|------|-------|--------------|---------|
| PUBLISH | 0x01 | None | tree_addr, seq, location_signature |
| LOOKUP | 0x02 | None | target_node_id |
| FOUND | 0x03 | Some | target_node_id, tree_addr, seq, location_signature |
| DATA | 0x10 | Some | application data |

*Location signature covers `"LOC:" || node_id || tree_addr || seq`. Routed signature covers all fields except ttl.*

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
| Leaf dies | Parent: 3 missed Pulses | Remove from children |
| Internal node dies | Children: 3 missed Pulses | Each child becomes subtree root |
| Root dies | Children: 3 missed Pulses | Children merge (largest wins) |
| Partition | 3 missed Pulses | Two independent trees |
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

**Consistency during rebalancing:**
- Keyspace ranges shift with tree structure
- Lookups may temporarily fail
- Entries pushed to new owners
