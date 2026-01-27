# Embedded Rust Engineer Review Findings (2026-01-27)

## Previous Issues - All Resolved

| Issue | Status |
|-------|--------|
| BTreeMap fragmentation | Documented with TLSF recommendation |
| Encoding before capacity check | Fixed with pre-check |
| Message cloning | Fixed with Ackable trait |
| Timestamp overflow | Verified (all saturating) |
| Double critical section race window | Documented in code comments |
| Hash recomputation during sorting | Fixed with ChildrenStore (pre-computed hashes) |
| u64 division for bw | Fixed with cached FastDivisor |

## New Findings

### Medium (acceptable with documentation)

**Double critical section race window in try_send**

The `try_send` optimization (traits.rs lines 192-241) uses two critical sections:

```rust
// Pre-check (first critical section)
let dominated_by_higher = self.inner.lock(|cell| { ... });
if dominated_by_higher { return false; }

// Encode (outside critical section - can allocate/block)
let data = msg.encode();

// Insert with re-check (second critical section)
let success = self.inner.lock(|cell| { ... });
```

Between the two critical sections, the queue state can change. The code handles this correctly with a re-check, but there's a subtle issue:

1. Pre-check says "queue has room" (len < max_size)
2. Another context fills the queue AND evicts lower-priority items
3. Re-check finds queue full, evicts lowest item to make room

This is functionally correct, but if the "encode" step is expensive (e.g., cryptographic signing), you could waste CPU cycles encoding a message that will ultimately be rejected if the queue fills with higher-priority messages during encoding.

**Recommendation**: Document this tradeoff in the code comments.

### Minor Findings

1. **routed_sign_data() allocates on each ack_hash() call**
   - `routed_sign_data()` returns a `Writer` which wraps a `Vec<u8>`
   - This happens every time `ack_hash` is called
   - Acceptable for LoRa message rates (~6.7s between messages)

2. **Some u64 division on 32-bit MCUs**
   - Location: `/Users/zond/projects/darkforest/darktree/src/node.rs` lines 634-635
   - `let secs = (self.last_pulse_size as u64 * PULSE_BW_DIVISOR as u64) / (bw as u64);`
   - On 32-bit MCUs, this invokes software division
   - Low priority since pulse intervals are multiple seconds

3. **Hash recomputation during child sorting**
   - Location: `/Users/zond/projects/darkforest/darktree/src/tree.rs` lines 724-728
   - Recomputes hashes during sorting (O(n log n) hash computations)
   - With MAX_CHILDREN = 12, this is ~40-50 hash computations per sort

### Overall Assessment

> "Production-ready for the documented target hardware (ESP32-class, 256KB+ RAM with TLSF allocator). No high-severity issues identified."

---

## User Questions to Address

The user asked the following questions about the findings:

### 1. Double critical section race window
> "please comment"

**Action**: Add a comment to try_send explaining the race window is intentional.

### 2. routed_sign_data() allocates on each ack_hash()
> "is it reasonable to e.g. prealloc and send to the ack_hash function? Or something else?"

**Options to consider**:
- Pass a `&mut Writer` or `&mut Vec<u8>` to reuse
- Have the Ackable trait take a buffer parameter
- Cache the sign_data somewhere

### 3. u64 division on 32-bit MCUs
> "don't we have library code that does big divisions on u32 hardware with reasonable effectiveness and precision?"

**Note**: We have `FastDivisor` in tree.rs (lines 48-109) that handles this. Could potentially use it more broadly.

### 4. Hash recomputation during child sorting
> "maybe we should let messages cache their hash? Or keep the hash separate in the sorted structure? By the way, we are using BTreeMap anyway, why do we have structures that require separate sorting?"

**Questions raised**:
- Why sort when we have BTreeMap?
- Could messages cache their computed hash?
- Could we store (hash, data) tuples in a sorted structure?

**Locations where sorting occurs** (from grep):
- `wire.rs:1377` - fuzz test, sorts children by hash
- `tree.rs:663` - sort candidates by RSSI descending
- `tree.rs:670` - sort candidates by keyspace range
- `tree.rs:724` - sort children by hash (recomputes hash in comparator!)
- `tree.rs:905` - sort children by hash before building Pulse

The tree.rs:724 case is the problematic one - it calls `compute_node_hash()` inside the sort comparator.
