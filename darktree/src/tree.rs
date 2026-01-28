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
    ChildHash, ChildrenList, Event, NodeId, Pulse, Signature, DISTRUST_TTL, LOCATION_TTL,
    MAX_CHILDREN,
};
use crate::wire::{pulse_sign_data, Encode, Message};

/// Compare two RSSI values for use with `min_by`, preferring stronger signals.
///
/// Returns Ordering such that min_by selects the entry with higher RSSI (stronger signal).
/// Entries with RSSI are preferred over entries without RSSI.
#[inline]
fn cmp_rssi_for_min_by(a_rssi: Option<i16>, b_rssi: Option<i16>) -> Ordering {
    match (a_rssi, b_rssi) {
        // Higher RSSI is "less" so min_by keeps it
        (Some(a), Some(b)) => b.cmp(&a),
        // Entry with RSSI is "less" (preferred)
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
pub(crate) struct FastDivisor {
    divisor: u64,
    reciprocal: u64,
    shift: u32,
}

impl FastDivisor {
    /// Create a fast divisor for the given value.
    ///
    /// # Panics
    ///
    /// Panics if divisor is 0.
    pub(crate) fn new(divisor: u64) -> Self {
        assert!(divisor > 0, "divisor must be non-zero");

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
    pub(crate) fn div(&self, n: u64) -> u64 {
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

        // SECURITY: Require verified pubkey before updating timing or tree state
        let pubkey = match self.get_pubkey(&pulse.node_id, now) {
            Some(pk) => pk,
            None => {
                // Don't have pubkey yet - we've already requested it via need_pubkey
                // Don't process anything until we can verify signatures
                return;
            }
        };

        // Verify signature before any state updates
        let sign_data = pulse_sign_data(&pulse);
        if !self
            .crypto()
            .verify(&pubkey, sign_data.as_slice(), &pulse.signature)
        {
            self.emit_debug(crate::debug::DebugEvent::SignatureVerifyFailed {
                node_id: pulse.node_id,
            });
            return; // Invalid signature
        }

        // ALWAYS update neighbor timing after signature verification.
        // This prevents spurious timeouts even if we rate-limit tree operations.
        let prev = self
            .neighbor_times()
            .get(&pulse.node_id)
            .map(|t| t.last_seen);
        let is_new_neighbor = prev.is_none();
        let timing = NeighborTiming {
            last_seen: now,
            rssi,
            root_hash: pulse.root_hash,
            tree_size: pulse.tree_size,
            keyspace_range: (pulse.keyspace_lo, pulse.keyspace_hi),
            children_count: pulse.child_count(),
            depth: pulse.depth,
            max_depth: pulse.max_depth,
            unstable: pulse.is_unstable(),
        };
        self.insert_neighbor_time(pulse.node_id, timing);

        // Rate limiting: skip tree operations if pulses arrive too fast.
        // Timing is already updated above, so this only affects tree processing.
        let min_interval = self.tau() * 2;
        if let Some(prev_seen) = prev {
            if now < prev_seen + min_interval {
                self.emit_debug(crate::debug::DebugEvent::PulseRateLimited {
                    from: pulse.node_id,
                    now,
                    last_seen: prev_seen,
                    min_interval_ms: min_interval.as_millis(),
                });
                return; // Too soon for tree operations, but timing is updated
            }
        }

        self.emit_debug(crate::debug::DebugEvent::PulseReceived {
            timestamp: now,
            from: pulse.node_id,
            tree_size: pulse.tree_size,
            root_hash: pulse.root_hash,
            has_pubkey: pulse.has_pubkey(),
            need_pubkey: pulse.need_pubkey(),
        });

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
        } else {
            // If we had this node as a child but they now claim a different parent,
            // remove them from our children list (they switched parents)
            if self.children().contains_key(&pulse.node_id) {
                self.remove_child(&pulse.node_id);
            }
        }
        // Check for pending parent acknowledgment
        if let Some((pending, count)) = self.pending_parent() {
            if pulse.node_id == pending {
                self.handle_pending_parent_pulse(&pulse, count, now);
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

            // Propagate depth: our depth = parent's depth + 1
            let new_depth = pulse.depth.saturating_add(1);
            let depth_changed = new_depth != self.depth();
            if depth_changed {
                self.set_depth(new_depth);
                // Depth change affects max_depth calculation
                self.recalculate_max_depth();
            }

            // Clear pending state since we're acknowledged
            self.set_pending_parent(None);
            self.set_parent_rejection_count(0);

            // If keyspace or depth changed, schedule republish and rebalance
            if keyspace_changed || depth_changed {
                // Jitter: 0-1τ
                let tau_ms = self.tau().as_millis();
                let jitter_ms = self.random_mut().gen_range(0, tau_ms);
                self.set_next_publish(Some(now + Duration::from_millis(jitter_ms)));
                // Move DHT entries that we no longer own to their new owners
                self.rebalance_keyspace(now);
                // Notify children of our new keyspace/depth
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

        // Each child gets a slice proportional to its subtree_size.
        // IMPORTANT: Last child's range extends to parent_hi to avoid gaps from integer division.
        let num_children = pulse.children.len();
        let mut current_lo = children_start;
        for (i, (_, subtree_size)) in pulse.children.iter().enumerate() {
            let child_range = fast_div.div(parent_range * (*subtree_size as u64));
            let child_hi = if i == num_children - 1 {
                parent_hi // Last child extends to parent_hi to avoid gaps
            } else {
                current_lo + child_range
            };

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
        let is_new = !self.children().contains_key(&pulse.node_id);

        // Only check capacity for NEW children - existing children must be able to update
        if is_new && self.children().len() >= MAX_CHILDREN {
            return;
        }

        // Check for hash collision with existing children.
        // Two different NodeIds could have the same 4-byte hash, which would
        // cause keyspace allocation conflicts. Reject if collision detected.
        // (Note: ChildrenStore.contains_hash() provides O(1) collision check)
        if self.children().contains_hash(sender_hash) {
            // Hash exists - check if it's the same node (update) or different (collision)
            if !self.children().contains_key(&pulse.node_id) {
                return; // Collision with different node, reject
            }
        }

        // Check if adding child would exceed MTU
        // (rough estimate: each child adds ~8 bytes to pulse)
        let estimated_pulse_size = self.estimate_pulse_size() + 8;
        if estimated_pulse_size > self.transport().mtu() {
            return;
        }

        if is_new {
            self.emit_debug(crate::debug::DebugEvent::ChildAdded {
                timestamp: now,
                child_id: pulse.node_id,
                subtree_size: pulse.subtree_size,
            });
        }

        // Accept the child (hash already computed as sender_hash)
        self.children_mut()
            .insert(*sender_hash, pulse.node_id, pulse.subtree_size);

        // Store child's keyspace range
        self.children_mut()
            .set_range(&pulse.node_id, pulse.keyspace_lo, pulse.keyspace_hi);

        // Remove from shortcuts if present
        self.shortcuts_mut().remove(&pulse.node_id);

        // Update subtree size and max_depth
        self.recalculate_subtree_size();
        self.recalculate_max_depth();

        // If we are root, update tree_size to match our subtree_size
        if self.is_root() {
            self.set_tree_size(self.subtree_size());
        }

        // Recompute all child keyspace ranges
        self.recompute_child_ranges();

        // Rebalance keyspace after subtree size changed (owned slice may have shrunk)
        self.rebalance_keyspace(now);

        // If new child, schedule proactive pulse to acknowledge them
        if is_new {
            self.schedule_proactive_pulse(now);
        }
    }

    /// Handle a pulse from our pending parent candidate.
    fn handle_pending_parent_pulse(&mut self, pulse: &Pulse, current_count: u8, now: Timestamp) {
        // Check if we're in the children list (by our hash)
        let my_hash = self.compute_node_hash(self.node_id());
        if let Some(my_idx) = self.find_child_index(pulse, &my_hash) {
            // We're acknowledged! Complete the parent switch
            let parent_id = pulse.node_id;
            self.set_parent(Some(parent_id));
            self.set_pending_parent(None);

            // Remove new parent from our children/shortcuts (prevents cycles and stale routing)
            self.remove_child(&parent_id);
            self.shortcuts_mut().remove(&parent_id);

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

            // Schedule location publish (with jitter) after joining tree
            self.schedule_location_publish(now);

            // Rebalance keyspace after joining new tree
            self.rebalance_keyspace(now);
        } else {
            // Not acknowledged yet, increment counter
            let new_count = current_count + 1;
            if new_count >= PARENT_ACK_PULSES {
                // Give up on this parent, try another
                self.set_pending_parent(None);
            } else {
                self.set_pending_parent(Some((pulse.node_id, new_count)));
            }
        }
    }

    /// Consider merging with another tree based on received pulse.
    ///
    /// When a dominating tree is detected, starts a shopping phase (3τ) to
    /// collect candidates before selecting the best parent. This is the same
    /// mechanism used at first boot, providing unified parent selection.
    fn consider_merge(&mut self, pulse: &Pulse, _sender_hash: &ChildHash, now: Timestamp) {
        // Don't start merge if already shopping - wait for select_best_parent
        if self.is_shopping() {
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "shopping",
            });
            return;
        }

        // Don't merge if already switching parents
        if self.pending_parent().is_some() {
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "pending_parent",
            });
            return;
        }

        // Ignore merge offers from distrusted nodes
        if self.is_distrusted(&pulse.node_id, now) {
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "distrusted",
            });
            return;
        }

        // Same tree? No merge needed.
        if pulse.root_hash == *self.root_hash() {
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
            self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
                from: pulse.node_id,
                dominated: false,
                reason: "not_dominated",
            });
            return;
        }

        self.emit_debug(crate::debug::DebugEvent::ConsiderMerge {
            from: pulse.node_id,
            dominated: true,
            reason: "start_shopping",
        });

        // TREE INVERSION: Leave our current tree position
        // When joining a bigger tree, we first become root of our own subtree.
        // Our children stay with us (they'll update their root_hash from our pulses).
        // Our former parent (if any) will see we're gone and may join later.
        // This local rule converges to a properly inverted tree.
        self.become_root();

        // Rebalance keyspace after position change
        self.rebalance_keyspace(now);

        // Start shopping phase (3τ) to collect candidates from dominating tree
        // When shopping ends, select_best_parent picks the shallowest position
        self.start_shopping(now);

        // Schedule proactive pulse to announce we're looking for a parent
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
    /// Called when shopping phase ends. Implements unified parent selection:
    /// 1. Filter: not full, not distrusted, not unstable (except old_parent)
    /// 2. Preference order:
    ///    a. Dominating tree candidates - pick shallowest by depth
    ///    b. Old parent still valid?
    ///    c. Current tree candidates - pick shallowest by depth
    ///    d. Become root
    pub(crate) fn select_best_parent(&mut self, now: Timestamp) {
        let old_parent = self.old_parent();
        let old_tree = self.old_tree();

        // Collect valid candidates: not full, not distrusted, not unstable (except old_parent)
        // Also filter by transport's RSSI threshold to avoid unreliable links
        let candidates: Vec<([u8; 16], &crate::node::NeighborTiming)> = self
            .neighbor_times()
            .iter()
            .filter(|(id, timing)| {
                timing.children_count < MAX_CHILDREN as u8
                    && !self.is_distrusted(id, now)
                    && (!timing.unstable || Some(**id) == old_parent)
                    && self.transport().is_acceptable_rssi(timing.rssi)
            })
            .map(|(id, timing)| (*id, timing))
            .collect();

        if candidates.is_empty() {
            // No valid candidates - stay as root
            self.become_root();
            self.clear_shopping();
            self.schedule_location_publish(now);
            return;
        }

        // Find the dominating tree (largest tree_size, tie-break by lowest root_hash)
        let best_tree = candidates
            .iter()
            .map(|(_, t)| (t.tree_size, t.root_hash))
            .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
            .unwrap(); // Safe: we checked candidates.is_empty() above

        // Check if the best tree dominates us
        let dominated = (best_tree.0, self.root_hash()) > (self.tree_size(), &best_tree.1);

        self.emit_debug(crate::debug::DebugEvent::SelectBestParent {
            candidate_count: candidates.len(),
            best_tree_size: best_tree.0,
            best_root_hash: best_tree.1,
            dominated,
        });

        // 5a. Dominating tree candidates - pick shallowest by depth
        if dominated {
            let dominating: Vec<_> = candidates
                .iter()
                .filter(|(_, t)| t.tree_size == best_tree.0 && t.root_hash == best_tree.1)
                .collect();

            if let Some(best) = Self::pick_shallowest(&dominating) {
                self.set_pending_parent(Some((best, 0)));
                self.clear_shopping();
                self.schedule_proactive_pulse(now);
                return;
            }
        }

        // 5b. Old parent still valid?
        if let Some(old_p) = old_parent {
            let old_p_valid = candidates.iter().any(|(id, _)| *id == old_p);
            if old_p_valid {
                self.set_pending_parent(Some((old_p, 0)));
                self.clear_shopping();
                self.schedule_proactive_pulse(now);
                return;
            }
        }

        // 5c. Current tree candidates - pick shallowest from same tree
        if let Some(old_root) = old_tree {
            let same_tree: Vec<_> = candidates
                .iter()
                .filter(|(_, t)| t.root_hash == old_root)
                .collect();

            if let Some(best) = Self::pick_shallowest(&same_tree) {
                self.set_pending_parent(Some((best, 0)));
                self.clear_shopping();
                self.schedule_proactive_pulse(now);
                return;
            }
        }

        // 5d. Become root
        self.become_root();
        self.clear_shopping();
        self.schedule_location_publish(now);
    }

    /// Pick the shallowest candidate by depth (lowest depth value).
    /// Tie-break by best RSSI.
    fn pick_shallowest(
        candidates: &[&([u8; 16], &crate::node::NeighborTiming)],
    ) -> Option<[u8; 16]> {
        candidates
            .iter()
            .min_by(|(_, a), (_, b)| {
                // Primary: depth ascending (shallowest first)
                a.depth.cmp(&b.depth).then_with(|| {
                    // Secondary: RSSI descending (best signal first)
                    cmp_rssi_for_min_by(a.rssi, b.rssi)
                })
            })
            .map(|(id, _)| *id)
    }

    /// Become root of our own subtree.
    fn become_root(&mut self) {
        self.set_parent(None);
        self.set_parent_rejection_count(0);
        let my_hash = self.compute_node_hash(self.node_id());
        self.set_root_hash(my_hash);
        self.set_keyspace_range(0, u32::MAX);
        self.set_depth(0); // Root is at depth 0
        self.recalculate_subtree_size();
        self.recalculate_max_depth();
        self.set_tree_size(self.subtree_size());
        // Recompute child ranges for the full keyspace
        self.recompute_child_ranges();
    }

    /// Schedule a location publish with jitter.
    ///
    /// Used when a node stays as root after shopping ends (either no candidates
    /// or the node dominates all candidates). The root needs to publish its
    /// location so other nodes can find it via DHT lookup.
    fn schedule_location_publish(&mut self, now: Timestamp) {
        // Jitter: 0-1τ to spread out PUBLISH messages
        let tau_ms = self.tau().as_millis();
        let jitter_ms = self.random_mut().gen_range(0, tau_ms);
        self.set_next_publish(Some(now + Duration::from_millis(jitter_ms)));
    }

    /// Recompute keyspace ranges for all children.
    fn recompute_child_ranges(&mut self) {
        // ChildrenStore.iter_by_hash() returns entries already sorted by hash,
        // so no explicit sorting needed! This gives O(n) instead of O(n log n).

        // First pass: compute total subtree size
        let total: u64 = self
            .children()
            .subtree_sizes()
            .map(|s| s as u64)
            .sum::<u64>()
            + 1;

        if total == 0 {
            return;
        }

        // Compute ranges
        let my_lo = self.keyspace_lo() as u64;
        let my_hi = self.keyspace_hi() as u64;
        let my_range = my_hi - my_lo;

        // Use reciprocal multiplication for fast division on 32-bit MCUs
        let fast_div = FastDivisor::new(total);

        // Parent keeps first slice
        let parent_slice = fast_div.div(my_range);
        let mut current_lo = my_lo + parent_slice;

        // Collect children info in hash order (avoids borrow issues with iter_by_hash_mut)
        let children_info: Vec<(NodeId, u32)> = self
            .children()
            .iter_by_hash()
            .map(|(_, entry)| (entry.node_id, entry.subtree_size))
            .collect();

        // Assign ranges to children.
        // IMPORTANT: Last child's range extends to my_hi to avoid gaps from integer division.
        // Without this fix, integer division precision loss creates unclaimed addresses at the
        // end of the keyspace, causing DHT PUBLISH messages to those addresses to be dropped.
        let num_children = children_info.len();
        for (i, (child_id, subtree_size)) in children_info.iter().enumerate() {
            let child_range = fast_div.div(my_range * (*subtree_size as u64));
            let child_hi = if i == num_children - 1 {
                // Last child gets everything up to my_hi to avoid gaps
                my_hi
            } else {
                current_lo + child_range
            };

            self.children_mut()
                .set_range(child_id, current_lo as u32, child_hi as u32);

            current_lo = child_hi;
        }
    }

    /// Recalculate subtree size from children.
    pub(crate) fn recalculate_subtree_size(&mut self) {
        let mut size: u32 = 1; // Self
        for child_size in self.children().subtree_sizes() {
            size = size.saturating_add(child_size);
        }
        self.set_subtree_size(size);
    }

    /// Recalculate max_depth from children's max_depth values.
    ///
    /// max_depth = max(depth, max(child.max_depth for all children))
    /// If no children, max_depth = depth (leaf node).
    pub(crate) fn recalculate_max_depth(&mut self) {
        if self.children().is_empty() {
            self.set_max_depth(self.depth());
        } else {
            // Get max of children's max_depth from neighbor_times
            let max_child_depth = self
                .children()
                .iter_by_hash()
                .filter_map(|(_, entry)| self.neighbor_times().get(&entry.node_id))
                .map(|t| t.max_depth)
                .max()
                .unwrap_or(self.depth());
            self.set_max_depth(max_child_depth.max(self.depth()));
        }
    }

    /// Remove a child and update all related state.
    ///
    /// Returns true if the child was present and removed.
    fn remove_child(&mut self, child_id: &NodeId) -> bool {
        if self.children_mut().remove(child_id).is_some() {
            // Range is removed with the entry (stored in ChildEntry)
            self.recalculate_subtree_size();
            self.recalculate_max_depth();
            self.recompute_child_ranges();
            // If we are root, update tree_size to match subtree_size
            if self.is_root() {
                self.set_tree_size(self.subtree_size());
            }
            true
        } else {
            false
        }
    }

    /// Estimate current pulse size.
    fn estimate_pulse_size(&self) -> usize {
        // Base: node_id(16) + flags(1) + root_hash(4) + depth(1) + max_depth(1)
        //     + subtree(varint~3) + tree_size(varint~3) + keyspace_lo(4) + keyspace_hi(4) + signature(65)
        let base = 16 + 1 + 4 + 1 + 1 + 3 + 3 + 4 + 4 + 65;

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

        // Extract info for debug event before encoding consumes the pulse
        let debug_info = (
            pulse.tree_size,
            pulse.root_hash,
            pulse.child_count(),
            pulse.has_pubkey(),
            pulse.need_pubkey(),
        );

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

        // Send via priority queue (BroadcastProtocol priority)
        if self.transport().outgoing().try_send(msg) {
            self.record_protocol_sent();

            self.emit_debug(crate::debug::DebugEvent::PulseSent {
                timestamp: now,
                tree_size: debug_info.0,
                root_hash: debug_info.1,
                child_count: debug_info.2,
                has_pubkey: debug_info.3,
                need_pubkey: debug_info.4,
            });
        } else {
            self.record_protocol_dropped();
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
        // Build children list - iter_by_hash() returns entries already in hash order
        let children: ChildrenList = self
            .children()
            .iter_by_hash()
            .map(|(hash, entry)| (*hash, entry.subtree_size))
            .collect();

        // Determine flags - include pending_parent as "has parent" so prospective
        // parent can see we want to join them
        let effective_parent = self
            .parent()
            .or_else(|| self.pending_parent().map(|(id, _)| id));
        let has_parent = effective_parent.is_some();
        let we_need_pubkeys = !self.need_pubkey().is_empty();
        let neighbors_need_ours = !self.neighbors_need_pubkey().is_empty();
        let include_pubkey = we_need_pubkeys || neighbors_need_ours;
        let unstable = self.is_shopping();
        let child_count = children.len().min(MAX_CHILDREN) as u8;

        let flags = Pulse::build_flags(
            has_parent,
            we_need_pubkeys,
            include_pubkey,
            unstable,
            child_count,
        );

        // Parent hash - include pending_parent so prospective parent can adopt us
        let parent_hash = effective_parent.map(|pid| self.compute_node_hash(&pid));

        let mut pulse = Pulse {
            node_id: *self.node_id(),
            flags,
            parent_hash,
            root_hash: *self.root_hash(),
            depth: self.depth(),
            max_depth: self.max_depth(),
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

    /// Calculate timeout timestamp for a neighbor.
    ///
    /// Timeout is fixed at 24τ (= 8 missed pulses × 3τ expected interval).
    /// This uses the expected pulse interval (3τ) rather than observed interval,
    /// ensuring that rapidly-pulsing neighbors don't get spuriously short timeouts.
    fn neighbor_timeout(&self, timing: &NeighborTiming) -> Timestamp {
        // Expected pulse interval is 3τ (see design.md timing model)
        // Timeout after 8 missed pulses = 24τ
        let expected_interval = self.tau() * 3;
        timing.last_seen + expected_interval * MISSED_PULSES_TIMEOUT
    }

    /// Check neighbor timeouts, returning timed out IDs and next timeout time.
    ///
    /// Returns (timed_out_neighbors, next_timeout_time).
    pub(crate) fn check_neighbor_timeouts(
        &self,
        now: Timestamp,
    ) -> (Vec<[u8; 16]>, Option<Timestamp>) {
        let mut timed_out: Vec<[u8; 16]> = Vec::new();
        let mut next_timeout: Option<Timestamp> = None;

        for (id, timing) in self.neighbor_times().iter() {
            let timeout = self.neighbor_timeout(timing);
            if now > timeout {
                timed_out.push(*id);
            } else {
                // Track earliest future timeout
                next_timeout = Some(match next_timeout {
                    Some(t) => t.min(timeout),
                    None => timeout,
                });
            }
        }

        (timed_out, next_timeout)
    }

    /// Handle timeouts for neighbors, pending operations, etc.
    ///
    /// Returns the next timeout time (if any neighbors remain).
    pub(crate) fn handle_neighbor_timeouts(&mut self, now: Timestamp) -> Option<Timestamp> {
        let (timed_out, next_timeout) = self.check_neighbor_timeouts(now);

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
            self.remove_child(&id);

            // Remove from shortcuts
            self.shortcuts_mut().remove(&id);

            // Remove from pubkey cache and need set
            self.pubkey_cache_mut().remove(&id);
            self.need_pubkey_mut().remove(&id);
        }

        next_timeout
    }

    /// Handle location entry expiration.
    pub(crate) fn handle_location_expiry(&mut self, now: Timestamp) {
        // Entries older than LOCATION_TTL are expired.
        let cutoff = now - LOCATION_TTL;

        // Collect expired entries (key is (node_id, replica_index))
        let expired: Vec<(NodeId, u8)> = self
            .location_store()
            .iter()
            .filter(|(_, entry)| entry.received_at < cutoff)
            .map(|(key, _)| *key)
            .collect();

        // Remove expired
        for key in expired {
            self.emit_debug(crate::debug::DebugEvent::LocationRemoved {
                owner: key.0,
                replica_index: key.1,
                reason: "expiry",
            });
            self.location_store_mut().remove(&key);
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
    use crate::traits::test_impls::{FastTestCrypto, MockClock, MockRandom, MockTransport};
    use crate::types::{LocationEntry, NodeId, Signature, ALGORITHM_ED25519};
    use alloc::vec;

    fn make_node(
    ) -> Node<MockTransport, FastTestCrypto, MockRandom, MockClock, crate::config::DefaultConfig>
    {
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
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
                rssi: Some(-70),
                root_hash: [0u8; 4],
                tree_size: 1,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
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
        let child_hash = node.compute_node_hash(&child_id);
        node.children_mut().insert(child_hash, child_id, 5); // subtree_size = 5

        // Add neighbor timing for child (last seen long ago)
        let old_time = Timestamp::from_secs(100);
        node.insert_neighbor_time(
            child_id,
            NeighborTiming {
                last_seen: old_time,
                rssi: Some(-80),
                root_hash: [0u8; 4],
                tree_size: 5,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
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

        node.insert_location_store(node_id1, 0, entry1);
        node.insert_location_store(node_id2, 0, entry2);

        // Verify both exist
        assert!(node.location_store().contains_key(&(node_id1, 0)));
        assert!(node.location_store().contains_key(&(node_id2, 0)));

        // Run expiry at time = 13 hours (LOCATION_TTL = 12 hours)
        let now = Timestamp::ZERO + Duration::from_hours(13);
        node.handle_location_expiry(now);

        // Old entry should be gone, recent should remain
        assert!(!node.location_store().contains_key(&(node_id1, 0)));
        assert!(node.location_store().contains_key(&(node_id2, 0)));
    }

    #[test]
    fn test_compute_child_keyspace() {
        let node = make_node();

        // Create a pulse with parent owning full keyspace and 2 children
        let pulse = Pulse {
            node_id: [0u8; 16],
            flags: Pulse::build_flags(false, false, false, false, 2),
            parent_hash: None,
            root_hash: [0u8; 4],
            depth: 0,
            max_depth: 0,
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
            flags: Pulse::build_flags(false, false, false, false, 0),
            parent_hash: None,
            root_hash: other_hash,
            depth: 0,
            max_depth: 0,
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
                rssi: Some(-70),
                root_hash: other_hash,
                tree_size: 10,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
            },
        );

        // Consider merge - starts shopping phase
        node.consider_merge(&pulse, &other_hash, now);

        // Should be in shopping phase, not immediately joined
        assert!(node.is_shopping(), "Should start shopping phase");
        assert!(
            node.pending_parent().is_none(),
            "Should not set pending_parent yet"
        );

        // After shopping ends (3τ), select_best_parent is called
        let tau = node.tau();
        let after_shopping = now + tau * 3 + Duration::from_millis(1);
        node.handle_timer(after_shopping);

        // Now should have pending_parent set to join larger tree
        assert!(!node.is_shopping(), "Shopping should be done");
        assert!(
            node.pending_parent().is_some(),
            "Should have pending_parent after shopping"
        );
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
            flags: Pulse::build_flags(false, false, false, false, 0),
            parent_hash: None,
            root_hash: other_hash,
            depth: 0,
            max_depth: 0,
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
                rssi: Some(-70),
                root_hash: other_hash,
                tree_size: 5,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
            },
        );

        // Consider merge - if dominated, starts shopping phase
        node.consider_merge(&pulse, &other_hash, now);

        // With equal tree sizes, smaller root_hash wins (acts as tiebreaker).
        // We join them if our hash is LARGER than theirs (they have better tiebreaker).
        if our_root > other_hash {
            // Should be in shopping phase
            assert!(node.is_shopping(), "Should start shopping when dominated");

            // After shopping ends, should have pending_parent
            let tau = node.tau();
            let after_shopping = now + tau * 3 + Duration::from_millis(1);
            node.handle_timer(after_shopping);
            assert!(node.pending_parent().is_some());
        } else {
            // Not dominated, should not be shopping
            assert!(!node.is_shopping(), "Should not shop when not dominated");
        }
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
        use crate::traits::Crypto;

        // A minimal crypto that produces hash collisions: hash output = first 4 bytes repeated.
        // This lets us test collision rejection without needing real SHA-256 collisions.
        struct CollisionCrypto;
        impl Crypto for CollisionCrypto {
            fn algorithm(&self) -> u8 {
                1
            }
            fn sign(&self, _: &crate::types::SecretKey, _: &[u8]) -> Signature {
                Signature::default()
            }
            fn verify(&self, _: &crate::types::PublicKey, _: &[u8], _: &Signature) -> bool {
                true // Accept all signatures for this test
            }
            fn generate_keypair(&mut self) -> (crate::types::PublicKey, crate::types::SecretKey) {
                // Return a fixed keypair - actual values don't matter for this test
                ([0xAA; 32], [0xBB; 32])
            }
            fn hash(&self, data: &[u8]) -> [u8; 32] {
                // Hash = first 4 bytes repeated, so same prefix = same hash
                let mut h = [0u8; 32];
                for (i, item) in h.iter_mut().enumerate() {
                    *item = data.get(i % 4).copied().unwrap_or(0);
                }
                h
            }
        }

        let transport = MockTransport::new();
        let crypto = CollisionCrypto;
        let random = MockRandom::new();
        let clock = MockClock::new();
        let mut node: Node<_, _, _, _, crate::config::DefaultConfig> =
            Node::new(transport, crypto, random, clock);
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
        node.children_mut().insert(hash1, child1, 1);
        assert_eq!(node.children().len(), 1);

        // Add pubkey to cache for child2 (required for pulse processing)
        // CollisionCrypto.verify() always returns true, so any pubkey works
        let fake_pubkey: crate::PublicKey = [0xCC; 32];
        node.insert_pubkey_cache(child2, fake_pubkey, now);

        // Create a pulse from the second child claiming us as parent
        let my_hash = node.compute_node_hash(node.node_id());
        let pulse = Pulse {
            node_id: child2,
            flags: Pulse::build_flags(false, false, false, false, 0),
            parent_hash: Some(my_hash), // Claims us as parent
            root_hash: hash2,
            depth: 0,
            max_depth: 0,
            subtree_size: 1,
            tree_size: 1,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: Signature::default(),
        };

        // Add neighbor timing (required for pulse processing)
        // Use old last_seen to avoid rate limiting (min_interval = 2*tau)
        let old_time = Timestamp::from_secs(100);
        node.insert_neighbor_time(
            child2,
            NeighborTiming {
                last_seen: old_time,
                rssi: Some(-70),
                root_hash: hash2,
                tree_size: 1,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
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

    #[test]
    fn test_direct_child_update() {
        // Simplified test: directly update child via insert (bypassing handle_pulse)
        let mut node = make_node();

        let child_id: NodeId = [2u8; 16];
        let child_hash = node.compute_node_hash(&child_id);

        // Insert initial child
        node.children_mut().insert(child_hash, child_id, 5);
        assert_eq!(node.children().get(&child_id).unwrap().subtree_size, 5);

        // Update via insert (same hash, same node_id, new subtree_size)
        node.children_mut().insert(child_hash, child_id, 10);
        assert_eq!(
            node.children().get(&child_id).unwrap().subtree_size,
            10,
            "Direct insert should update subtree_size"
        );
    }

    #[test]
    fn test_existing_child_update_with_same_hash_accepted() {
        // Tests that an existing child can update its subtree_size via pulse
        // (same NodeId, same hash - should be accepted as update, not rejected as collision)
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Add a child
        let child_id: NodeId = [2u8; 16];
        let child_hash = node.compute_node_hash(&child_id);
        node.children_mut().insert(child_hash, child_id, 5); // Initial subtree_size = 5
        assert_eq!(node.children().len(), 1);
        assert_eq!(node.children().get(&child_id).unwrap().subtree_size, 5);

        // Add pubkey to cache for child (required for pulse processing)
        // FastTestCrypto requires valid pubkey and signature
        let fake_pubkey: crate::PublicKey = [0xDD; 32];
        node.insert_pubkey_cache(child_id, fake_pubkey, now);

        // Add neighbor timing (required for pulse processing)
        // Use an old last_seen time to avoid rate limiting (min_interval = 2*tau)
        let old_time = Timestamp::from_secs(100); // Well before `now`
        node.insert_neighbor_time(
            child_id,
            NeighborTiming {
                last_seen: old_time,
                rssi: Some(-70),
                root_hash: child_hash,
                tree_size: 10,
                keyspace_range: (0, u32::MAX),
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
            },
        );

        // Create a valid signature for FastTestCrypto (algorithm=0x01, non-zero sig)
        let valid_sig = Signature {
            algorithm: 0x01, // FastTestCrypto's algorithm
            sig: [0xFF; 64], // Non-zero signature passes FastTestCrypto::verify()
        };

        // Create a pulse from the same child with updated subtree_size
        let my_hash = node.compute_node_hash(node.node_id());
        let pulse = Pulse {
            node_id: child_id,
            flags: Pulse::build_flags(true, false, false, false, 0), // has_parent = true
            parent_hash: Some(my_hash),                              // Claims us as parent
            root_hash: *node.root_hash(),
            depth: 1,
            max_depth: 1,
            subtree_size: 10, // Updated from 5 to 10
            tree_size: node.tree_size(),
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: valid_sig,
        };

        // Verify hashes match (same compute_node_hash should produce same result)
        let computed_my_hash = node.compute_node_hash(node.node_id());
        assert_eq!(my_hash, computed_my_hash, "my_hash should be deterministic");
        assert_eq!(
            pulse.parent_hash,
            Some(my_hash),
            "pulse.parent_hash should match my_hash"
        );
        assert_eq!(
            node.children().get(&child_id).unwrap().subtree_size,
            5,
            "subtree_size should be 5 before handle_pulse"
        );

        // Process the pulse - should be accepted as update
        node.handle_pulse(pulse, Some(-70), now);

        // Child should still exist with updated subtree_size
        assert_eq!(node.children().len(), 1, "Child count should remain 1");
        assert!(
            node.children().contains_key(&child_id),
            "Child should still be present"
        );
        assert_eq!(
            node.children().get(&child_id).unwrap().subtree_size,
            10,
            "Subtree size should be updated to 10"
        );
    }
}
