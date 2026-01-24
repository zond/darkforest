# Test Scenarios for darksim

Scenarios derived from the design doc. Each describes setup, actions, and expected outcome. Times are in τ (tau) units.

---

## 1. Bootstrap & Discovery

### 1.1 Single Node Bootstrap
- **Setup:** 1 node, no neighbors
- **Run:** 5τ
- **Expect:** Node is root, tree_size=1, subtree_size=1, keyspace=[0, 2³²)

### 1.2 Discovery Phase Timing
- **Setup:** 1 node boots, neighbors appear at t=2τ
- **Run:** 10τ
- **Expect:** Node waits until 3τ before selecting parent (discovery phase)

### 1.3 Discovery Skips Full Parents
- **Setup:** 3 nodes. P has MAX_CHILDREN (12) children already. N boots.
- **Run:** 10τ
- **Expect:** N does not select P as parent (P is full)

---

## 2. Tree Formation & Joining

### 2.1 Two Nodes Form Tree
- **Setup:** 2 nodes (A, B) in range
- **Run:** 10τ
- **Expect:** Single tree, one root, one child. tree_size=2.

### 2.2 Join Latency (~4.5τ)
- **Setup:** Existing tree (P as root). N boots at t=0.
- **Measure:** Time until N appears in P's children list
- **Expect:** ~4.5τ (discovery 3τ + exchange ~1.5τ)

### 2.3 Chain Topology
- **Setup:** 5 nodes in chain: A—B—C—D—E (each only sees neighbors)
- **Run:** 30τ
- **Expect:** Single tree formed. Depth ≤ 4.

### 2.4 Star Topology
- **Setup:** 1 central node, 10 edge nodes (edges only see center)
- **Run:** 20τ
- **Expect:** Central node is root with 10 children.

### 2.5 Fully Connected Small Network
- **Setup:** 10 nodes, all in range
- **Run:** 20τ
- **Expect:** Single tree, wide and shallow (depth 2-3).

### 2.6 Parent Selection Prefers Shallow
- **Setup:** 3 nodes A, B, C all in range. A boots first (root). B joins A. C boots.
- **Run:** 15τ
- **Expect:** C joins A (larger keyspace), not B.

### 2.7 Rejected by Full Parent
- **Setup:** P has 12 children. N attempts to join P.
- **Run:** 15τ
- **Expect:** After 3 failed pulses, N tries another parent or stays root.

---

## 3. Tree Merging

### 3.1 Larger Tree Wins
- **Setup:** Tree A (100 nodes), Tree B (50 nodes). Link them at t=10τ.
- **Run:** 40τ
- **Expect:** Single tree with A's root. tree_size=150.

### 3.2 Equal Size: Lower Root Hash Wins
- **Setup:** Tree A (50 nodes), Tree B (50 nodes), hash(A_root) < hash(B_root)
- **Link:** Connect at t=10τ
- **Expect:** Single tree with A's root.

### 3.3 Tree Inversion Propagation
- **Setup:** Tree B with depth 5 (chain). Tree A (larger) connects to leaf of B.
- **Run:** 30τ
- **Expect:** Inversion propagates up B (~1.5τ per hop). All nodes under A's root.

### 3.4 Bridge Node Triggers Merge
- **Setup:** Tree A, Tree B (both separate). Node N can reach both.
- **Run:** 30τ
- **Expect:** N joins larger tree, other tree eventually merges via N.

### 3.5 No Merge During Discovery
- **Setup:** N is in discovery phase. Receives pulse from larger tree.
- **Expect:** N waits until discovery ends before merging.

---

## 4. Partitions & Recovery

### 4.1 Link Break Creates Partition
- **Setup:** Tree with root R, child A, grandchild C. Break A—C link at t=10τ.
- **Run:** 40τ (need 8 missed pulses ≈ 24τ)
- **Expect:** Two trees: R's tree (without C), C's tree (C as root of subtree).

### 4.2 Partition Heals
- **Setup:** After 4.1, restore A—C link at t=50τ
- **Run:** 30τ more
- **Expect:** Trees remerge. Single tree again.

### 4.3 Root Dies, Children Remerge
- **Setup:** Tree: R—{A, B, C}. Remove R at t=10τ.
- **Run:** 50τ
- **Expect:** A, B, C become roots of own subtrees, then merge (largest wins).

### 4.4 Internal Node Dies
- **Setup:** R—A—{B, C, D}. Remove A at t=10τ.
- **Run:** 50τ
- **Expect:** B, C, D become separate subtrees, rejoin R if in range.

---

## 5. Liveness & Timeouts

### 5.1 Parent Timeout (8 Pulses)
- **Setup:** Tree with parent P and child C. Stop P's pulses at t=10τ.
- **Run:** 40τ
- **Expect:** C becomes root after ~24τ (8 missed pulses × ~3τ interval).

### 5.2 Child Timeout
- **Setup:** Tree with P—C. Stop C's pulses at t=10τ.
- **Run:** 40τ
- **Expect:** P removes C from children after ~24τ. P.subtree_size decreases.

### 5.3 Neighbor Expiry
- **Setup:** Two nodes exchange pulses. One goes silent at t=10τ.
- **Run:** 50τ
- **Expect:** Neighbor removed from neighbor_times after timeout.

---

## 6. DHT Operations

### 6.1 PUBLISH Stores Location
- **Setup:** 20-node tree. Node N publishes location.
- **Run:** 10τ
- **Expect:** 3 storage nodes (K_REPLICAS=3) have N's location entry.

### 6.2 LOOKUP Finds Published
- **Setup:** After 6.1, node M does lookup for N.
- **Run:** 40τ (LOOKUP_TIMEOUT = 32τ per replica)
- **Expect:** M receives FOUND with N's keyspace address.

### 6.3 DATA Delivery End-to-End
- **Setup:** 20-node tree. N publishes. M looks up N. M sends DATA to N.
- **Run:** 100τ
- **Expect:** N receives DATA from M.

### 6.4 LOOKUP Tries Multiple Replicas
- **Setup:** Storage node for replica 0 is unreachable.
- **Run:** LOOKUP
- **Expect:** After timeout, tries replica 1, then replica 2.

### 6.5 Stale Location Handling
- **Setup:** N publishes, then moves (keyspace changes). M has old location cached.
- **Run:** M sends DATA to old address.
- **Expect:** DATA fails to reach N. M must re-lookup.

### 6.6 PUBLISH Sequence Numbers
- **Setup:** N publishes seq=5. Attacker replays old PUBLISH with seq=3.
- **Expect:** Storage node rejects seq=3 (seq <= existing).

---

## 7. Routing

### 7.1 Route to Self
- **Setup:** Tree. Node N owns keyspace containing address X.
- **Action:** N receives Routed destined for X.
- **Expect:** N handles locally (no forward).

### 7.2 Route to Child
- **Setup:** P has children C1, C2 with disjoint keyspace.
- **Action:** P receives Routed for address in C1's range.
- **Expect:** P forwards to C1.

### 7.3 Route to Parent
- **Setup:** Child C, parent P. P owns wider range.
- **Action:** C receives Routed for address outside C's range.
- **Expect:** C forwards to P.

### 7.4 Multi-Hop Routing
- **Setup:** Chain of 10 nodes forming single tree.
- **Action:** Leaf sends Routed to address owned by node at other end.
- **Expect:** Message traverses tree (up then down).

### 7.5 TTL Exhaustion
- **Setup:** Routed message with TTL=2 needs 5 hops.
- **Expect:** Message dropped after 2 hops.

---

## 8. Reliability (ACK/Retransmit)

### 8.1 Implicit ACK via Overhearing
- **Setup:** A sends Routed to B. A can overhear B's forward.
- **Expect:** A detects forward, clears pending ACK. No retransmit.

### 8.2 Explicit ACK on Duplicate
- **Setup:** A sends Routed to B. A doesn't hear forward, retransmits.
- **Expect:** B sends explicit ACK (doesn't re-forward duplicate).

### 8.3 Exponential Backoff
- **Setup:** A sends Routed. No ACK received.
- **Expect:** Retransmit at 1τ, 2τ, 4τ, 8τ, ... (with jitter).

### 8.4 Max Retries (8)
- **Setup:** Message consistently lost (100% loss on link).
- **Run:** 300τ
- **Expect:** Sender gives up after 8 retries (~255τ total).

### 8.5 Duplicate Suppression
- **Setup:** B receives same Routed twice (same TTL).
- **Expect:** B forwards only once, sends ACK for duplicate.

---

## 9. Fraud Detection

### 9.1 Inflated tree_size Detection
- **Setup:** Attacker claims tree_size=10000 but only has 100 nodes.
- **Run:** 8 hours simulated (PUBLISH refresh period)
- **Expect:** Honest nodes detect fraud via HLL (receive ~3% expected PUBLISH).

### 9.2 Distrusted Node Rejected
- **Setup:** Node X detected as fraudulent, added to distrusted set.
- **Expect:** X not selected as parent. X's merge offers ignored.

### 9.3 Distrust TTL Expiry
- **Setup:** X distrusted at t=0. DISTRUST_TTL = 24 hours.
- **Run:** 25 hours simulated
- **Expect:** X removed from distrusted set.

### 9.4 Fraud Reset Rate Limit
- **Setup:** Attacker fluctuates tree_size to reset HLL counters.
- **Expect:** Reset limited to once per hour (MIN_RESET_INTERVAL).

---

## 10. Pubkey Exchange

### 10.1 Pubkey Cached on First Pulse
- **Setup:** N receives pulse from unknown node P with has_pubkey=true.
- **Expect:** N caches P's pubkey. Subsequent pulses verified.

### 10.2 Need Pubkey Flag
- **Setup:** N receives pulse from P without pubkey. N needs it.
- **Expect:** N sets need_pubkey=true in next pulse. P includes pubkey.

### 10.3 Signature Verification Failure
- **Setup:** Attacker sends pulse with wrong signature.
- **Expect:** Pulse rejected after signature check.

---

## 11. Rate Limiting

### 11.1 Pulse Rate Limit (2τ)
- **Setup:** Node receives pulses from same neighbor faster than 2τ.
- **Expect:** Excess pulses ignored (rate limited).

### 11.2 Rate Limit Scales with Bandwidth
- **Setup:** Low bandwidth (τ=6.7s) vs high bandwidth (τ=0.1s).
- **Expect:** Rate limit is 13.4s vs 0.2s respectively.

---

## 12. Edge Cases

### 12.1 Child Hash Collision
- **Setup:** Two nodes with same 4-byte child hash try to join same parent.
- **Expect:** Parent accepts only one. Second is rejected.

### 12.2 Maximum Children (12)
- **Setup:** Parent has 12 children. 13th node tries to join.
- **Expect:** 13th node rejected (implicit, via missing from children list).

### 12.3 Keyspace Rebalance on Child Join
- **Setup:** P has children C1, C2. C3 joins.
- **Expect:** P recomputes keyspace ranges for all children.

### 12.4 Proactive Pulse on State Change
- **Setup:** Node's tree state changes (new child, new parent, etc.)
- **Expect:** Proactive pulse sent within ~1.5τ (jittered).

---

## 13. Scale Tests

### 13.1 100 Nodes Converge
- **Setup:** 100 nodes, random mesh topology (average 5 neighbors each)
- **Run:** 200τ
- **Expect:** Single tree. All nodes have same root_hash.

### 13.2 1000 Nodes Converge
- **Setup:** 1000 nodes, realistic topology
- **Run:** 500τ
- **Expect:** Single tree. Convergence within reasonable time.

### 13.3 Tree Depth Bounded
- **Setup:** 100 nodes in various topologies
- **Expect:** Tree depth ≤ O(log N) due to shallow preference.

---

## Timing Reference

| Transport | τ | 2τ (rate limit) | 3τ (discovery) | 24τ (timeout) |
|-----------|---|-----------------|----------------|---------------|
| LoRa SF8 10% | 6.7s | 13.4s | 20s | 160s |
| LoRa SF8 1% | 67s | 134s | 200s | 27 min |
| UDP | 0.1s | 0.2s | 0.3s | 2.4s |

---

## Implementation Notes

Use `ScenarioBuilder` for setup:
```rust
ScenarioBuilder::new(10)
    .with_seed(42)
    .topology(Topology::fully_connected(&nodes))
    .partition_at(Timestamp::from_secs(60), vec![group_a, group_b])
    .heal_at(Timestamp::from_secs(120))
    .run_for(Duration::from_secs(200))
```

Assert with metrics:
```rust
assert!(result.metrics.all_same_root());
assert_eq!(result.metrics.tree_count(), 1);
assert!(result.metrics.convergence_time().unwrap() < Duration::from_secs(100));
```
