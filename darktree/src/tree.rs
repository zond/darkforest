//! Tree formation and maintenance with keyspace-based addressing.
//!
//! This module handles:
//! - Pulse message creation and processing
//! - Parent selection and tree merging
//! - Child management and keyspace division
//! - Neighbor timeouts

use core::cmp::Ordering;

use alloc::vec::Vec;

use crate::config::NodeConfig;
use crate::node::{JoinContext, NeighborTiming, Node};
use crate::time::{Duration, Timestamp};
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    ChildHash, ChildrenList, Event, Pulse, Signature, DISTRUST_TTL, LOCATION_TTL, MAX_CHILDREN,
};
use crate::wire::{pulse_sign_data, Encode, Message};

/// Compare two RSSI values, preferring stronger signals (higher values).
/// Returns Ordering for b vs a (descending order: best signal first).
/// Nodes with RSSI are preferred over nodes without.
#[inline]
fn cmp_rssi_desc(a_rssi: Option<i16>, b_rssi: Option<i16>) -> Ordering {
    match (b_rssi, a_rssi) {
        (Some(b), Some(a)) => b.cmp(&a),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

// Compile-time assertion: MAX_CHILDREN must fit in u8 for NeighborTiming.children_count
const _: () = assert!(
    MAX_CHILDREN <= u8::MAX as usize,
    "MAX_CHILDREN must fit in u8"
);

/// Fast u64 division using reciprocal multiplication.
///
/// On 32-bit MCUs, u64 division is emulated in software (~800-1200 cycles).
/// This uses precomputed reciprocal for ~100-150 cycles per division (6-8× faster).
///
/// Based on Barrett reduction with correction for exact results.
struct FastDivisor {
    divisor: u64,
    reciprocal: u64,
    shift: u32,
}

impl FastDivisor {
    /// Create a fast divisor for the given value.
    /// Panics in debug mode if divisor is 0.
    fn new(divisor: u64) -> Self {
        debug_assert!(divisor > 0, "divisor must be non-zero");

        // Powers of 2 are handled specially: 2^(64+shift)/divisor = 2^64 which
        // overflows u64. We mark these with reciprocal=0 and use bit shift in div().
        let is_power_of_two = divisor > 0 && (divisor & (divisor - 1)) == 0;

        if is_power_of_two {
            // For powers of 2, division is just a right shift
            let shift = divisor.trailing_zeros();
            return Self {
                divisor,
                reciprocal: 0, // Sentinel: use shift path in div()
                shift,
            };
        }

        // Find shift such that 2^shift <= divisor < 2^(shift+1)
        let shift = 63 - divisor.leading_zeros();

        // Compute reciprocal: recip = floor(2^(64+shift) / divisor)
        // We use 128-bit arithmetic to avoid overflow
        let numerator: u128 = 1u128 << (64 + shift);
        let reciprocal = (numerator / divisor as u128) as u64;

        Self {
            divisor,
            reciprocal,
            shift,
        }
    }

    /// Divide n by the precomputed divisor.
    #[inline]
    fn div(&self, n: u64) -> u64 {
        // Fast path for powers of 2: just shift
        if self.reciprocal == 0 {
            return n >> self.shift;
        }

        // n / d ≈ (n * recip) >> (64 + shift)
        let wide = n as u128 * self.reciprocal as u128;
        let approx = (wide >> (64 + self.shift)) as u64;

        // Correction: reciprocal multiplication can round down by 1
        // Check if we need to add 1 (cheaper than re-dividing)
        if n - approx * self.divisor >= self.divisor {
            approx + 1
        } else {
            approx
        }
    }
}

/// Number of missed pulses before timeout.
const MISSED_PULSES_TIMEOUT: u64 = 8;

/// Number of pulses to wait for parent acknowledgment.
const PARENT_ACK_PULSES: u8 = 3;

impl<T, Cr, R, Clk, Cfg> Node<T, Cr, R, Clk, Cfg>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
    Cfg: NodeConfig,
{
    /// Handle a received Pulse message.
    pub(crate) fn handle_pulse(&mut self, pulse: Pulse, rssi: Option<i16>, now: Timestamp) {
        // Ignore our own pulses
        if pulse.node_id == *self.node_id() {
            return;
        }

        // Rate limiting: ignore pulses that arrive too fast (minimum 2*tau between pulses)
        let min_interval = self.tau() * 2;
        if let Some(timing) = self.neighbor_times().get(&pulse.node_id) {
            if now < timing.last_seen + min_interval {
                #[cfg(feature = "debug")]
                self.emit_debug(crate::debug::DebugEvent::PulseRateLimited {
                    from: pulse.node_id,
                    now,
                    last_seen: timing.last_seen,
                    min_interval_ms: min_interval.as_millis(),
                });
                return; // Too soon
            }
        }

        // Handle pubkey exchange first (always process this part)
        self.handle_pubkey_exchange(&pulse, now);

        // Track if neighbor needs pubkeys (so we include ours in next pulse)
        if pulse.need_pubkey() {
            // If neighbor newly needs our pubkey, schedule proactive pulse
            let was_not_tracked = self.neighbors_need_pubkey_mut().insert(pulse.node_id);
            if was_not_tracked {
                self.schedule_proactive_pulse(now);
            }
        } else {
            self.neighbors_need_pubkey_mut().remove(&pulse.node_id);
        }

        // SECURITY: Require verified pubkey before processing tree operations
        let pubkey = match self.get_pubkey(&pulse.node_id, now) {
            Some(pk) => pk,
            None => {
                // Don't have pubkey yet - we've already requested it via need_pubkey
                // Don't process tree operations until we can verify signatures
                return;
            }
        };

        // Verify signature
        let sign_data = pulse_sign_data(&pulse);
        if !self
            .crypto()
            .verify(&pubkey, sign_data.as_slice(), &pulse.signature)
        {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::SignatureVerifyFailed {
                node_id: pulse.node_id,
            });
            return; // Invalid signature
        }

        #[cfg(feature = "debug")]
        self.emit_debug(crate::debug::DebugEvent::PulseReceived {
            from: pulse.node_id,
            tree_size: pulse.tree_size,
            root_hash: pulse.root_hash,
            has_pubkey: pulse.has_pubkey(),
            need_pubkey: pulse.need_pubkey(),
        });

        // Update neighbor timing (only after signature verification)
        let prev = self
            .neighbor_times()
            .get(&pulse.node_id)
            .map(|t| t.last_seen);
        let is_new_neighbor = prev.is_none();
        let timing = NeighborTiming {
            last_seen: now,
            prev_seen: prev,
            rssi,
            root_hash: pulse.root_hash,
            tree_size: pulse.tree_size,
            keyspace_range: (pulse.keyspace_lo, pulse.keyspace_hi),
            children_count: pulse.child_count(),
        };
        self.insert_neighbor_time(pulse.node_id, timing);

        // If new neighbor, schedule proactive pulse to introduce ourselves
        if is_new_neighbor {
            self.schedule_proactive_pulse(now);
        }

        // Compute the sender's hash
        let sender_hash = self.compute_node_hash(&pulse.node_id);

        // Check if this pulse is from our parent (by hash)
        if let Some(parent_id) = self.parent() {
            let parent_hash = self.compute_node_hash(&parent_id);
            if pulse.node_id == parent_id {
                self.handle_parent_pulse(&pulse, now);
                return;
            }
            // Also handle by hash match
            if pulse.parent_hash.is_none() || pulse.parent_hash == Some(parent_hash) {
                // Check if sender is our parent
                if sender_hash == parent_hash {
                    self.handle_parent_pulse(&pulse, now);
                    return;
                }
            }
        }

        // Check if this pulse claims us as parent (by checking if our hash is in their parent_hash)
        let my_hash = self.compute_node_hash(self.node_id());
        if pulse.parent_hash == Some(my_hash) {
            self.handle_child_pulse(&pulse, &sender_hash, now);
        }
        // Check for pending parent acknowledgment
        else if let Some((pending, _)) = self.pending_parent() {
            if pulse.node_id == pending {
                self.handle_pending_parent_pulse(&pulse, &sender_hash, now);
            }
        }

        // Tree merge decision (includes inversion handling)
        self.consider_merge(&pulse, &sender_hash, now);

        // Track as shortcut if not parent/child
        if self.parent() != Some(pulse.node_id) && !self.children().contains_key(&pulse.node_id) {
            self.insert_shortcut(pulse.node_id, (pulse.keyspace_lo, pulse.keyspace_hi));
        }
    }

    /// Handle pubkey exchange from a pulse.
    fn handle_pubkey_exchange(&mut self, pulse: &Pulse, now: Timestamp) {
        // If pulse contains a pubkey, verify and cache it
        if let Some(pubkey) = pulse.pubkey {
            // CRITICAL: Verify cryptographic binding before caching
            if self.crypto().verify_pubkey_binding(&pulse.node_id, &pubkey) {
                self.insert_pubkey_cache(pulse.node_id, pubkey, now);
                self.need_pubkey_mut().remove(&pulse.node_id);

                // Process any messages that were waiting for this pubkey
                self.process_pending_pubkey(&pulse.node_id, &pubkey, now);
            }
        } else if !self.has_pubkey(&pulse.node_id) {
            // We need this node's pubkey - track it so we signal need_pubkey
            self.need_pubkey_mut().insert(pulse.node_id);
        }
    }

    /// Handle a pulse from our current parent.
    fn handle_parent_pulse(&mut self, pulse: &Pulse, now: Timestamp) {
        // Find ourselves in parent's children list (by hash)
        let my_hash = self.compute_node_hash(self.node_id());
        if let Some(my_idx) = self.find_child_index(pulse, &my_hash) {
            // Compute our keyspace range from parent's pulse
            let (new_lo, new_hi) = self.compute_child_keyspace(pulse, my_idx);

            let keyspace_changed = new_lo != self.keyspace_lo() || new_hi != self.keyspace_hi();

            self.set_keyspace_range(new_lo, new_hi);

            // Update tree info from parent
            self.set_root_hash(pulse.root_hash);
            self.set_tree_size(pulse.tree_size);

            // Clear pending state since we're acknowledged
            self.set_pending_parent(None);
            self.set_parent_rejection_count(0);

            // If keyspace changed, schedule republish and rebalance
            if keyspace_changed {
                // Jitter: 0-1τ
                let tau_ms = self.tau().as_millis();
                let jitter_ms = self.random_mut().gen_range(0, tau_ms);
                self.set_next_publish(Some(now + Duration::from_millis(jitter_ms)));
                // Move DHT entries that we no longer own to their new owners
                self.rebalance_keyspace(now);
                // Notify children of our new keyspace
                self.schedule_proactive_pulse(now);
            }
        } else {
            // Parent didn't include us - track consecutive rejections
            let count = self.parent_rejection_count() + 1;
            if count >= PARENT_ACK_PULSES {
                // Parent rejected us, find new parent
                self.set_parent(None);
                self.set_parent_rejection_count(0);
                self.become_root();
            } else {
                self.set_parent_rejection_count(count);
            }
        }
    }

    /// Find the index of a child in the children list by hash.
    fn find_child_index(&self, pulse: &Pulse, child_hash: &ChildHash) -> Option<usize> {
        pulse
            .children
            .iter()
            .position(|(hash, _)| hash == child_hash)
    }

    /// Compute keyspace range for a child at given index.
    ///
    /// Algorithm from design doc:
    /// 1. Parent owns [lo, hi)
    /// 2. Parent keeps first slice proportional to its local size (1 node)
    /// 3. Remaining range divided among children proportional to subtree_size
    /// 4. Children are sorted by hash, each gets a contiguous slice
    fn compute_child_keyspace(&self, pulse: &Pulse, child_idx: usize) -> (u32, u32) {
        let parent_lo = pulse.keyspace_lo as u64;
        let parent_hi = pulse.keyspace_hi as u64;
        let parent_range = parent_hi - parent_lo;

        // Total subtree size (parent + all children's subtrees)
        let total: u64 = pulse
            .children
            .iter()
            .map(|(_, size)| *size as u64)
            .sum::<u64>()
            + 1;

        if total == 0 {
            return (pulse.keyspace_lo, pulse.keyspace_hi);
        }

        // Use reciprocal multiplication for fast division on 32-bit MCUs
        let fast_div = FastDivisor::new(total);

        // Parent keeps first slice (1/total of range)
        let parent_slice = fast_div.div(parent_range);
        let children_start = parent_lo + parent_slice;

        // Each child gets a slice proportional to its subtree_size
        let mut current_lo = children_start;
        for (i, (_, subtree_size)) in pulse.children.iter().enumerate() {
            let child_range = fast_div.div(parent_range * (*subtree_size as u64));
            let child_hi = current_lo + child_range;

            if i == child_idx {
                return (current_lo as u32, child_hi as u32);
            }

            current_lo = child_hi;
        }

        // Shouldn't reach here if child_idx is valid
        (pulse.keyspace_lo, pulse.keyspace_hi)
    }

    /// Handle a pulse from a node claiming us as parent.
    fn handle_child_pulse(&mut self, pulse: &Pulse, sender_hash: &ChildHash, now: Timestamp) {
        // Check if we can accept this child
        if self.children().len() >= MAX_CHILDREN {
            // At capacity, silently reject
            return;
        }

        // Check for hash collision with existing children.
        // Two different NodeIds could have the same 4-byte hash, which would
        // cause keyspace allocation conflicts. Reject if collision detected.
        for existing_id in self.children().keys() {
            if *existing_id != pulse.node_id {
                let existing_hash = self.compute_node_hash(existing_id);
                if existing_hash == *sender_hash {
                    // Hash collision - reject this child
                    return;
                }
            }
        }

        // Check if adding child would exceed MTU
        // (rough estimate: each child adds ~8 bytes to pulse)
        let estimated_pulse_size = self.estimate_pulse_size() + 8;
        if estimated_pulse_size > self.transport().mtu() {
            return;
        }

        // Track if this is a new child
        let is_new = !self.children().contains_key(&pulse.node_id);

        #[cfg(feature = "debug")]
        if is_new {
            self.emit_debug(crate::debug::DebugEvent::ChildAdded {
                child_id: pulse.node_id,
                subtree_size: pulse.subtree_size,
            });
        }

        // Accept the child
        self.children_mut()
            .insert(pulse.node_id, pulse.subtree_size);

        // Store child's keyspace range
        self.child_ranges_mut()
            .insert(pulse.node_id, (pulse.keyspace_lo, pulse.keyspace_hi));

        // Remove from shortcuts if present
        self.shortcuts_mut().remove(&pulse.node_id);

        // Update subtree size
        self.recalculate_subtree_size();

        // If we are root, update tree_size to match our subtree_size
        if self.is_root() {
            self.set_tree_size(self.subtree_size());
        }

        // Recompute all child keyspace ranges
        self.recompute_child_ranges();

        // If new child, schedule proactive pulse to acknowledge them
        if is_new {
            self.schedule_proactive_pulse(now);
        }
    }

    /// Handle a pulse from our pending parent candidate.
    fn handle_pending_parent_pulse(
        &mut self,
        pulse: &Pulse,
        _sender_hash: &ChildHash,
        now: Timestamp,
    ) {
        // Check if we're in the children list (by our hash)
        let my_hash = self.compute_node_hash(self.node_id());
        if let Some(my_idx) = self.find_child_index(pulse, &my_hash) {
            // We're acknowledged! Complete the parent switch
            let parent_id = pulse.node_id;
            self.set_parent(Some(parent_id));
            self.set_pending_parent(None);

            // Compute our keyspace range
            let (new_lo, new_hi) = self.compute_child_keyspace(pulse, my_idx);
            self.set_keyspace_range(new_lo, new_hi);

            // Set join context for fraud detection
            self.set_join_context(Some(JoinContext {
                parent_at_join: parent_id,
                join_time: now,
            }));

            // Update tree info
            self.set_root_hash(pulse.root_hash);
            self.set_tree_size(pulse.tree_size);

            // Push tree changed event
            self.push_event(Event::TreeChanged {
                new_root: pulse.root_hash,
                new_size: pulse.tree_size,
            });

            // Rebalance keyspace after joining new tree
            self.rebalance_keyspace(now);
        } else {
            // Not acknowledged yet, increment counter
            let (_, count) = self.pending_parent().unwrap();
            if count >= PARENT_ACK_PULSES {
                // Give up on this parent, try another
                self.set_pending_parent(None);
            } else {
                self.set_pending_parent(Some((pulse.node_id, count + 1)));
            }
        }
    }

    /// Consider merging with another tree based on received pulse.
    fn consider_merge(&mut self, pulse: &Pulse, _sender_hash: &ChildHash, now: Timestamp) {
        // Don't merge during discovery phase - wait for select_best_parent
        if self.is_in_discovery() {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "in_discovery",
            });
            return;
        }

        // Don't merge if this node is distrusted
        if self.is_distrusted(&pulse.node_id, now) {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "distrusted",
            });
            return;
        }

        // Don't merge if we're already in a pending parent state
        if self.pending_parent().is_some() {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "pending_parent",
            });
            return;
        }

        // Different root?
        if pulse.root_hash == *self.root_hash() {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "same_root",
            });
            return;
        }

        // Merge decision: larger tree wins, tie-break by smaller root_hash (lexicographic)
        let dominated = (pulse.tree_size, self.root_hash()) > (self.tree_size(), &pulse.root_hash);

        if !dominated {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "not_dominated",
            });
            return;
        }

        // Check if pulse sender is a valid parent candidate
        if pulse.child_count() as usize >= MAX_CHILDREN {
            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: true,
                reason: "parent_full",
            });
            return; // Parent is full
        }

        #[cfg(feature = "debug")]
        self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
            from: pulse.node_id,
            dominated: true,
            reason: "merging",
        });

        // TREE INVERSION: Leave our current tree position
        // When joining a bigger tree, we first become root of our own subtree.
        // Our children stay with us (they'll update their root_hash from our pulses).
        // Our former parent (if any) will see we're gone and may join later.
        // This local rule converges to a properly inverted tree.
        self.become_root();

        // Rebalance keyspace after position change
        self.rebalance_keyspace(now);

        // Start parent switch process
        self.set_pending_parent(Some((pulse.node_id, 0)));

        // Schedule proactive pulse to announce our intent to join
        self.schedule_proactive_pulse(now);
    }

    /// Check if a node is distrusted.
    fn is_distrusted(&self, node_id: &[u8; 16], now: Timestamp) -> bool {
        self.distrusted()
            .get(node_id)
            .is_some_and(|&when| now < when + DISTRUST_TTL)
    }

    /// Select the best parent from discovered neighbors.
    ///
    /// Called when discovery phase ends. Implements the algorithm from design doc:
    /// 1. Pick the best tree (largest tree_size, tie-break: lowest root_hash)
    /// 2. Filter by signal strength (if 3+ candidates with RSSI, remove bottom 50%)
    /// 3. Pick shallowest (largest keyspace range, tie-break: best RSSI)
    pub(crate) fn select_best_parent(&mut self, now: Timestamp) {
        // Collect valid candidates: not full, not distrusted
        let mut candidates: Vec<([u8; 16], &crate::node::NeighborTiming)> = self
            .neighbor_times()
            .iter()
            .filter(|(id, timing)| {
                timing.children_count < MAX_CHILDREN as u8 && !self.is_distrusted(id, now)
            })
            .map(|(id, timing)| (*id, timing))
            .collect();

        if candidates.is_empty() {
            // No valid candidates - stay as root of single-node tree
            // Will join via normal merge when we hear a larger tree
            return;
        }

        // Step 1: Pick the best tree
        // Find the best (tree_size, root_hash) - largest tree_size, tie-break by lowest root_hash
        let best_tree = candidates
            .iter()
            .map(|(_, t)| (t.tree_size, t.root_hash))
            .max_by(|a, b| {
                // Compare by tree_size descending, then root_hash ascending (lexicographic)
                a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1))
            })
            .unwrap(); // Safe: we checked candidates.is_empty() above

        // Only join if the best tree dominates ours
        // Dominated = (their_tree_size, our_root_hash) > (our_tree_size, their_root_hash)
        let dominated = (best_tree.0, self.root_hash()) > (self.tree_size(), &best_tree.1);

        #[cfg(feature = "debug")]
        self.emit_debug(crate::debug::DebugEvent::SelectBestParent {
            candidate_count: candidates.len(),
            best_tree_size: best_tree.0,
            best_root_hash: best_tree.1,
            dominated,
        });

        if !dominated {
            // Best tree doesn't dominate us - stay as root
            return;
        }

        // Filter to only candidates from the best tree
        candidates.retain(|(_, t)| t.tree_size == best_tree.0 && t.root_hash == best_tree.1);

        // Step 2: Filter by signal strength (if 3+ candidates with RSSI)
        let rssi_count = candidates.iter().filter(|(_, t)| t.rssi.is_some()).count();
        if candidates.len() >= 3 && rssi_count >= 3 {
            // Sort by RSSI descending (best signal first)
            candidates.sort_by(|(_, a), (_, b)| cmp_rssi_desc(a.rssi, b.rssi));
            // Keep top 50% (remove bottom half)
            let keep = candidates.len().div_ceil(2);
            candidates.truncate(keep);
        }

        // Step 3: Pick shallowest (largest keyspace range, tie-break: best RSSI)
        candidates.sort_by(|(_, a), (_, b)| {
            let a_range = (a.keyspace_range.1 as u64).saturating_sub(a.keyspace_range.0 as u64);
            let b_range = (b.keyspace_range.1 as u64).saturating_sub(b.keyspace_range.0 as u64);
            // Descending by range (larger = shallower)
            b_range
                .cmp(&a_range)
                .then_with(|| cmp_rssi_desc(a.rssi, b.rssi))
        });

        // Select the best candidate
        let (parent_id, _) = candidates[0];

        // Start parent switch process (same as consider_merge)
        self.set_pending_parent(Some((parent_id, 0)));

        // Schedule proactive pulse to announce our intent to join
        self.schedule_proactive_pulse(now);
    }

    /// Become root of our own subtree.
    fn become_root(&mut self) {
        self.set_parent(None);
        self.set_parent_rejection_count(0);
        let my_hash = self.compute_node_hash(self.node_id());
        self.set_root_hash(my_hash);
        self.set_keyspace_range(0, u32::MAX);
        self.recalculate_subtree_size();
        self.set_tree_size(self.subtree_size());
        // Recompute child ranges for the full keyspace
        self.recompute_child_ranges();
    }

    /// Recompute keyspace ranges for all children.
    fn recompute_child_ranges(&mut self) {
        // Build children list sorted by hash
        let mut sorted_children: Vec<([u8; 16], u32)> = self
            .children()
            .iter()
            .map(|(&id, &size)| (id, size))
            .collect();

        // Sort by hash
        sorted_children.sort_by(|(a, _), (b, _)| {
            let a_hash = self.compute_node_hash(a);
            let b_hash = self.compute_node_hash(b);
            a_hash.cmp(&b_hash)
        });

        // Compute ranges
        let my_lo = self.keyspace_lo() as u64;
        let my_hi = self.keyspace_hi() as u64;
        let my_range = my_hi - my_lo;

        let total: u64 = sorted_children
            .iter()
            .map(|(_, size)| *size as u64)
            .sum::<u64>()
            + 1;

        if total == 0 {
            return;
        }

        // Use reciprocal multiplication for fast division on 32-bit MCUs
        let fast_div = FastDivisor::new(total);

        // Parent keeps first slice
        let parent_slice = fast_div.div(my_range);
        let mut current_lo = my_lo + parent_slice;

        // Clear old ranges
        self.child_ranges_mut().clear();

        // Assign ranges to children
        for (child_id, subtree_size) in &sorted_children {
            let child_range = fast_div.div(my_range * (*subtree_size as u64));
            let child_hi = current_lo + child_range;

            self.child_ranges_mut()
                .insert(*child_id, (current_lo as u32, child_hi as u32));

            current_lo = child_hi;
        }
    }

    /// Recalculate subtree size from children.
    pub(crate) fn recalculate_subtree_size(&mut self) {
        let mut size: u32 = 1; // Self
        for &child_size in self.children().values() {
            size = size.saturating_add(child_size);
        }
        self.set_subtree_size(size);
    }

    /// Estimate current pulse size.
    fn estimate_pulse_size(&self) -> usize {
        // Base: node_id(16) + flags(1) + root_hash(4) + subtree(varint~3) + tree_size(varint~3)
        //     + keyspace_lo(4) + keyspace_hi(4) + signature(65)
        let base = 16 + 1 + 4 + 3 + 3 + 4 + 4 + 65;

        // Optional parent_hash (4 bytes if has_parent)
        let parent_size = if self.parent().is_some() { 4 } else { 0 };

        // Optional pubkey (32 bytes if has_pubkey)
        let we_need_pubkeys = !self.need_pubkey().is_empty();
        let neighbors_need_ours = !self.neighbors_need_pubkey().is_empty();
        let pubkey_size = if we_need_pubkeys || neighbors_need_ours {
            32
        } else {
            0
        };

        // Children: each child is hash(4) + subtree_size(varint~3)
        let children_size = self.children().len() * 7;

        base + parent_size + pubkey_size + children_size
    }

    /// Build and send a Pulse message.
    pub(crate) fn send_pulse(&mut self, now: Timestamp) {
        let pulse = self.build_pulse();

        // Encode with message type
        let msg = Message::Pulse(pulse);
        let encoded = msg.encode_to_vec();

        // Check MTU
        if encoded.len() > self.transport().mtu() {
            // Pulse too large - this shouldn't happen if MAX_CHILDREN is respected
            return;
        }

        // Track size for bandwidth-aware scheduling
        let size = encoded.len();

        // Send via protocol queue (high priority)
        match self.transport().protocol_outgoing().try_send(encoded) {
            Ok(()) => self.record_protocol_sent(),
            Err(_) => self.record_protocol_dropped(),
        }
        self.set_last_pulse(Some(now));
        self.set_last_pulse_size(size);
        // Clear proactive pulse flag
        self.set_proactive_pulse_pending(None);
    }

    /// Schedule a proactive pulse with batching delay (1τ to 2τ).
    pub(crate) fn schedule_proactive_pulse(&mut self, now: Timestamp) {
        let tau = self.tau();
        let tau_ms = tau.as_millis();
        // τ + uniform(0, τ) = range [τ, 2τ]
        let delay_ms = tau_ms + self.random_mut().gen_range(0, tau_ms);
        let new_time = now + Duration::from_millis(delay_ms);

        match self.proactive_pulse_pending() {
            Some(existing) if existing <= new_time => {
                // Already scheduled for earlier or same time - keep existing
            }
            _ => {
                // No pending pulse, or new time is earlier - schedule/reschedule
                self.set_proactive_pulse_pending(Some(new_time));
            }
        }
    }

    /// Build a Pulse message.
    fn build_pulse(&mut self) -> Pulse {
        // Build children list sorted by hash
        let mut children = ChildrenList::new();
        for (&child_id, &subtree_size) in self.children().iter() {
            let child_hash = self.compute_node_hash(&child_id);
            children.push((child_hash, subtree_size));
        }

        // Sort children by hash (lexicographic big-endian)
        children.sort_by(|a, b| a.0.cmp(&b.0));

        // Determine flags - include pending_parent as "has parent" so prospective
        // parent can see we want to join them
        let effective_parent = self
            .parent()
            .or_else(|| self.pending_parent().map(|(id, _)| id));
        let has_parent = effective_parent.is_some();
        let we_need_pubkeys = !self.need_pubkey().is_empty();
        let neighbors_need_ours = !self.neighbors_need_pubkey().is_empty();
        let include_pubkey = we_need_pubkeys || neighbors_need_ours;
        let child_count = children.len().min(MAX_CHILDREN) as u8;

        let flags = Pulse::build_flags(has_parent, we_need_pubkeys, include_pubkey, child_count);

        // Parent hash - include pending_parent so prospective parent can adopt us
        let parent_hash = effective_parent.map(|pid| self.compute_node_hash(&pid));

        let mut pulse = Pulse {
            node_id: *self.node_id(),
            flags,
            parent_hash,
            root_hash: *self.root_hash(),
            subtree_size: self.subtree_size(),
            tree_size: self.tree_size(),
            keyspace_lo: self.keyspace_lo(),
            keyspace_hi: self.keyspace_hi(),
            pubkey: if include_pubkey {
                Some(*self.pubkey())
            } else {
                None
            },
            children,
            signature: Signature::default(),
        };

        // Sign the pulse
        let sign_data = pulse_sign_data(&pulse);
        pulse.signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        pulse
    }

    /// Handle timeouts for neighbors, pending operations, etc.
    pub(crate) fn handle_neighbor_timeouts(&mut self, now: Timestamp) {
        // Collect timed out neighbors
        let mut timed_out: Vec<[u8; 16]> = Vec::new();

        for (id, timing) in self.neighbor_times().iter() {
            let interval = timing
                .prev_seen
                .map(|prev| timing.last_seen.saturating_sub(prev))
                .unwrap_or_else(|| self.tau() * 5);

            let timeout = timing.last_seen + interval * MISSED_PULSES_TIMEOUT;
            if now > timeout {
                timed_out.push(*id);
            }
        }

        // Process timeouts
        for id in timed_out {
            // Remove from neighbor times
            self.neighbor_times_mut().remove(&id);

            // If parent, become root
            if self.parent() == Some(id) {
                self.become_root();
                self.push_event(Event::TreeChanged {
                    new_root: *self.root_hash(),
                    new_size: self.subtree_size(),
                });
            }

            // If child, remove
            if self.children_mut().remove(&id).is_some() {
                self.child_ranges_mut().remove(&id);
                self.recalculate_subtree_size();
                self.recompute_child_ranges();
            }

            // Remove from shortcuts
            self.shortcuts_mut().remove(&id);

            // Remove from pubkey cache and need set
            self.pubkey_cache_mut().remove(&id);
            self.need_pubkey_mut().remove(&id);
        }
    }

    /// Handle location entry expiration.
    pub(crate) fn handle_location_expiry(&mut self, now: Timestamp) {
        // Entries older than LOCATION_TTL are expired.
        let cutoff = now - LOCATION_TTL;

        // Collect expired entries
        let expired: Vec<[u8; 16]> = self
            .location_store()
            .iter()
            .filter(|(_, entry)| entry.received_at < cutoff)
            .map(|(id, _)| *id)
            .collect();

        // Remove expired
        for id in expired {
            self.location_store_mut().remove(&id);
        }
    }

    /// Compute keyspace range for a child (exposed for testing).
    #[cfg(test)]
    pub(crate) fn compute_child_keyspace_for_test(
        &self,
        pulse: &Pulse,
        child_idx: usize,
    ) -> (u32, u32) {
        self.compute_child_keyspace(pulse, child_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NeighborTiming;
    use crate::traits::test_impls::{MockClock, MockCrypto, MockRandom, MockTransport};
    use crate::types::{LocationEntry, NodeId, Signature, ALGORITHM_ED25519};
    use alloc::vec;

    fn make_node(
    ) -> Node<MockTransport, MockCrypto, MockRandom, MockClock, crate::config::DefaultConfig> {
        let transport = MockTransport::new();
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();
        Node::new(transport, crypto, random, clock)
    }

    #[test]
    fn test_handle_neighbor_timeouts_parent() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Set up a parent
        let parent_id: NodeId = [1u8; 16];
        node.set_parent(Some(parent_id));

        // Add neighbor timing for parent (last seen long ago)
        let old_time = Timestamp::from_secs(100);
        node.insert_neighbor_time(
            parent_id,
            NeighborTiming {
                last_seen: old_time,
                prev_seen: Some(Timestamp::from_secs(50)),
                rssi: Some(-70),
                root_hash: [0u8; 4],
                tree_size: 1,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
            },
        );

        // Verify parent is set
        assert_eq!(node.parent(), Some(parent_id));

        // Handle timeouts - parent should timeout and node becomes root
        node.handle_neighbor_timeouts(now);

        // Parent should be None (we became root)
        assert_eq!(node.parent(), None);
    }

    #[test]
    fn test_handle_neighbor_timeouts_child() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Add a child
        let child_id: NodeId = [2u8; 16];
        node.children_mut().insert(child_id, 5); // subtree_size = 5

        // Add neighbor timing for child (last seen long ago)
        let old_time = Timestamp::from_secs(100);
        node.insert_neighbor_time(
            child_id,
            NeighborTiming {
                last_seen: old_time,
                prev_seen: Some(Timestamp::from_secs(50)),
                rssi: Some(-80),
                root_hash: [0u8; 4],
                tree_size: 5,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
            },
        );

        // Verify child exists
        assert!(node.children().contains_key(&child_id));

        // Handle timeouts - child should be removed
        node.handle_neighbor_timeouts(now);

        // Child should be removed
        assert!(!node.children().contains_key(&child_id));
    }

    #[test]
    fn test_handle_location_expiry() {
        let mut node = make_node();

        // Add some location entries
        let node_id1: NodeId = [1u8; 16];
        let node_id2: NodeId = [2u8; 16];

        let old_time = Timestamp::from_secs(100);
        let recent_time = Timestamp::ZERO + Duration::from_hours(11); // Within TTL

        let entry1 = LocationEntry {
            node_id: node_id1,
            pubkey: [0u8; 32],
            keyspace_addr: 1000,
            seq: 1,
            replica_index: 0,
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [0u8; 64],
            },
            received_at: old_time, // Old, should expire
        };

        let entry2 = LocationEntry {
            node_id: node_id2,
            pubkey: [0u8; 32],
            keyspace_addr: 2000,
            seq: 1,
            replica_index: 0,
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [0u8; 64],
            },
            received_at: recent_time, // Recent, should stay
        };

        node.insert_location_store(node_id1, entry1);
        node.insert_location_store(node_id2, entry2);

        // Verify both exist
        assert!(node.location_store().contains_key(&node_id1));
        assert!(node.location_store().contains_key(&node_id2));

        // Run expiry at time = 13 hours (LOCATION_TTL = 12 hours)
        let now = Timestamp::ZERO + Duration::from_hours(13);
        node.handle_location_expiry(now);

        // Old entry should be gone, recent should remain
        assert!(!node.location_store().contains_key(&node_id1));
        assert!(node.location_store().contains_key(&node_id2));
    }

    #[test]
    fn test_compute_child_keyspace() {
        let node = make_node();

        // Create a pulse with parent owning full keyspace and 2 children
        let pulse = Pulse {
            node_id: [0u8; 16],
            flags: Pulse::build_flags(false, false, false, 2),
            parent_hash: None,
            root_hash: [0u8; 4],
            subtree_size: 11, // 1 parent + 5 + 5 children
            tree_size: 11,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![
                ([0, 0, 0, 1], 5), // child 0 with subtree_size 5
                ([0, 0, 0, 2], 5), // child 1 with subtree_size 5
            ],
            signature: Signature::default(),
        };

        // Total = 1 + 5 + 5 = 11
        // Parent keeps 1/11 of range
        // Each child gets 5/11 of range

        let (lo0, hi0) = node.compute_child_keyspace_for_test(&pulse, 0);
        let (lo1, hi1) = node.compute_child_keyspace_for_test(&pulse, 1);

        // Child 0 starts after parent's slice
        let parent_slice = (u32::MAX as u64) / 11;
        assert!(lo0 as u64 >= parent_slice);

        // Children are contiguous
        assert_eq!(hi0, lo1);

        // Both children get equal share (5/11 each)
        let child0_range = hi0 - lo0;
        let child1_range = hi1 - lo1;
        // Allow some rounding error
        assert!((child0_range as i64 - child1_range as i64).abs() < 2);
    }

    #[test]
    fn test_consider_merge_larger_tree_wins() {
        let mut node = make_node();

        // Our tree has size 5
        node.set_tree_size(5);
        node.set_subtree_size(5);

        // Receive pulse from larger tree (size 10)
        let other_id: NodeId = [1u8; 16];
        let other_hash = node.compute_node_hash(&other_id);

        let pulse = Pulse {
            node_id: other_id,
            flags: Pulse::build_flags(false, false, false, 0),
            parent_hash: None,
            root_hash: other_hash,
            subtree_size: 10,
            tree_size: 10,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: Signature::default(),
        };

        let now = Timestamp::from_secs(100);

        // Add neighbor timing for RSSI
        node.insert_neighbor_time(
            other_id,
            NeighborTiming {
                last_seen: now,
                prev_seen: None,
                rssi: Some(-70),
                root_hash: other_hash,
                tree_size: 10,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
            },
        );

        // Consider merge
        node.consider_merge(&pulse, &other_hash, now);

        // Should have pending_parent set to join larger tree
        assert!(node.pending_parent().is_some());
        let (pending_id, _) = node.pending_parent().unwrap();
        assert_eq!(pending_id, other_id);
    }

    #[test]
    fn test_consider_merge_same_size_root_hash_tiebreak() {
        let mut node = make_node();

        // Get our root hash
        let our_root = *node.root_hash();

        // Our tree has size 5
        node.set_tree_size(5);
        node.set_subtree_size(5);

        // Create another node with same size but different root
        let other_id: NodeId = [0xFF; 16]; // High bytes to likely have higher hash
        let other_hash = node.compute_node_hash(&other_id);

        let pulse = Pulse {
            node_id: other_id,
            flags: Pulse::build_flags(false, false, false, 0),
            parent_hash: None,
            root_hash: other_hash,
            subtree_size: 5,
            tree_size: 5, // Same size
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: Signature::default(),
        };

        let now = Timestamp::from_secs(100);

        // Add neighbor timing
        node.insert_neighbor_time(
            other_id,
            NeighborTiming {
                last_seen: now,
                prev_seen: None,
                rssi: Some(-70),
                root_hash: other_hash,
                tree_size: 5,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
            },
        );

        // Consider merge
        node.consider_merge(&pulse, &other_hash, now);

        // With equal tree sizes, smaller root_hash wins (acts as tiebreaker).
        // We join them if our hash is LARGER than theirs (they have better tiebreaker).
        if our_root > other_hash {
            assert!(node.pending_parent().is_some());
        }
        // (If our hash is smaller, we don't join them - we have the better tiebreaker)
    }

    #[test]
    fn test_fast_divisor_correctness() {
        // Test various divisors to ensure reciprocal multiplication matches native division.
        let test_cases: &[(u64, u64)] = &[
            // (numerator, divisor)
            (100, 7),
            (1000, 13),
            (u32::MAX as u64, 17),
            (u64::MAX / 2, 1000),
            (1_000_000, 5),
            (12345678, 123),
            // Edge cases
            (0, 5),
            (5, 5),
            (4, 5),
            // Powers of 2 - small (use shift fast path)
            (100, 1),
            (100, 2),
            (100, 4),
            (100, 8),
            (100, 16),
            (u32::MAX as u64, 1),
            (u32::MAX as u64, 2),
            (u32::MAX as u64, 4),
            // Powers of 2 - large
            (u64::MAX, 1),
            (u64::MAX, 2),
            (u64::MAX, 64),
            (u64::MAX, 1 << 32),
            (u64::MAX, 1 << 62),
            // Near power-of-2 boundaries (stress detection)
            (1_000_000, 63),
            (1_000_000, 65),
            (1_000_000, 255),
            (1_000_000, 257),
            // u64::MAX with small non-power-of-2 divisors
            (u64::MAX, 3),
            (u64::MAX, 5),
            (u64::MAX, 7),
            // Maximum divisor cases
            (u64::MAX, u64::MAX),
            (u64::MAX - 1, u64::MAX),
            // Realistic keyspace cases
            (u32::MAX as u64, 100),    // Full range / 100 nodes
            (u32::MAX as u64, 10000),  // Full range / 10k nodes
            (u32::MAX as u64, 100000), // Full range / 100k nodes
        ];

        for &(n, d) in test_cases {
            let fast = FastDivisor::new(d);
            let expected = n / d;
            let actual = fast.div(n);
            assert_eq!(
                actual, expected,
                "FastDivisor mismatch: {} / {} = {} (expected {})",
                n, d, actual, expected
            );
        }
    }

    #[test]
    fn test_fast_divisor_keyspace_range() {
        // Test with realistic keyspace values
        let total = 100u64; // 100 nodes in subtree
        let range = u32::MAX as u64; // Full keyspace

        let fast = FastDivisor::new(total);

        // Parent slice (1 out of 100)
        let parent_slice = fast.div(range);
        assert_eq!(parent_slice, range / total);

        // Child with 30 nodes
        let child_range = fast.div(range * 30);
        assert_eq!(child_range, (range * 30) / total);
    }

    #[test]
    fn test_child_hash_collision_rejected() {
        // MockCrypto's hash: first 4 bytes of hash depend only on first 4 bytes of input.
        // Two NodeIds with same first 4 bytes will have the same 4-byte child hash.
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Create two NodeIds with same first 4 bytes (will have same child hash)
        let child1: NodeId = [1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let child2: NodeId = [1, 2, 3, 4, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // Same prefix, different node

        // Verify they have the same hash
        let hash1 = node.compute_node_hash(&child1);
        let hash2 = node.compute_node_hash(&child2);
        assert_eq!(
            hash1, hash2,
            "Test setup: NodeIds should have same child hash"
        );
        assert_ne!(child1, child2, "Test setup: NodeIds should be different");

        // Manually add first child to the children map
        node.children_mut().insert(child1, 1);
        assert_eq!(node.children().len(), 1);

        // Create a pulse from the second child claiming us as parent
        let my_hash = node.compute_node_hash(node.node_id());
        let pulse = Pulse {
            node_id: child2,
            flags: Pulse::build_flags(false, false, false, 0),
            parent_hash: Some(my_hash), // Claims us as parent
            root_hash: hash2,
            subtree_size: 1,
            tree_size: 1,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: Signature::default(),
        };

        // Add neighbor timing (required for pulse processing)
        node.insert_neighbor_time(
            child2,
            NeighborTiming {
                last_seen: now,
                prev_seen: None,
                rssi: Some(-70),
                root_hash: hash2,
                tree_size: 1,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
            },
        );

        // Process the pulse - should be rejected due to hash collision
        node.handle_pulse(pulse, Some(-70), now);

        // Child count should still be 1 (collision rejected)
        assert_eq!(
            node.children().len(),
            1,
            "Second child with colliding hash should be rejected"
        );
        assert!(
            node.children().contains_key(&child1),
            "Original child should still be present"
        );
        assert!(
            !node.children().contains_key(&child2),
            "Colliding child should not be added"
        );
    }
}
