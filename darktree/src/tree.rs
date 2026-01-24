//! Tree formation and maintenance with keyspace-based addressing.
//!
//! This module handles:
//! - Pulse message creation and processing
//! - Parent selection and tree merging
//! - Child management and keyspace division
//! - Neighbor timeouts

use core::cmp::Ordering;

use alloc::vec::Vec;

use crate::node::{JoinContext, NeighborTiming, Node};
use crate::time::{Duration, Timestamp};
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    ChildHash, ChildrenList, Event, Pulse, Signature, DISTRUST_TTL, LOCATION_TTL, MAX_CHILDREN,
    MIN_PULSE_INTERVAL,
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

/// Number of missed pulses before timeout.
#[allow(dead_code)]
const MISSED_PULSES_TIMEOUT: u64 = 8;

/// Number of pulses to wait for parent acknowledgment.
const PARENT_ACK_PULSES: u8 = 3;

impl<T, Cr, R, Clk> Node<T, Cr, R, Clk>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
{
    /// Handle a received Pulse message.
    pub(crate) fn handle_pulse(&mut self, pulse: Pulse, rssi: Option<i16>, now: Timestamp) {
        // Ignore our own pulses
        if pulse.node_id == *self.node_id() {
            return;
        }

        // Rate limiting: ignore pulses that arrive too fast
        if let Some(timing) = self.neighbor_times().get(&pulse.node_id) {
            if now < timing.last_seen + MIN_PULSE_INTERVAL {
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
        let pubkey = match self.pubkey_cache().get(&pulse.node_id) {
            Some(pk) => *pk,
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
            return; // Invalid signature
        }

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
                self.handle_parent_pulse(&pulse, &sender_hash, now);
                return;
            }
            // Also handle by hash match
            if pulse.parent_hash.is_none() || pulse.parent_hash == Some(parent_hash) {
                // Check if sender is our parent
                if sender_hash == parent_hash {
                    self.handle_parent_pulse(&pulse, &sender_hash, now);
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
            self.shortcuts_mut()
                .insert(pulse.node_id, (pulse.keyspace_lo, pulse.keyspace_hi));
        }
    }

    /// Handle pubkey exchange from a pulse.
    fn handle_pubkey_exchange(&mut self, pulse: &Pulse, now: Timestamp) {
        // If pulse contains a pubkey, verify and cache it
        if let Some(pubkey) = pulse.pubkey {
            // CRITICAL: Verify cryptographic binding before caching
            if self.crypto().verify_pubkey_binding(&pulse.node_id, &pubkey) {
                self.insert_pubkey_cache(pulse.node_id, pubkey);
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
    fn handle_parent_pulse(&mut self, pulse: &Pulse, sender_hash: &ChildHash, now: Timestamp) {
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

            // Clear pending parent since we're acknowledged
            self.set_pending_parent(None);

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
            // Parent didn't include us - we might have been rejected
            // Increment pending parent counter (reuse for rejection tracking)
            if let Some((parent, count)) = self.pending_parent() {
                let parent_hash = self.compute_node_hash(&parent);
                if *sender_hash == parent_hash {
                    if count >= PARENT_ACK_PULSES {
                        // Parent rejected us, find new parent
                        self.set_parent(None);
                        self.set_pending_parent(None);
                        self.become_root();
                    } else {
                        self.set_pending_parent(Some((parent, count + 1)));
                    }
                }
            } else {
                // Start tracking rejection
                self.set_pending_parent(Some((pulse.node_id, 1)));
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

        // Parent keeps first slice (1/total of range)
        let parent_slice = parent_range / total;
        let children_start = parent_lo + parent_slice;

        // Each child gets a slice proportional to its subtree_size
        let mut current_lo = children_start;
        for (i, (_, subtree_size)) in pulse.children.iter().enumerate() {
            let child_range = (parent_range * (*subtree_size as u64)) / total;
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
    fn handle_child_pulse(&mut self, pulse: &Pulse, _sender_hash: &ChildHash, now: Timestamp) {
        // Check if we can accept this child
        if self.children().len() >= MAX_CHILDREN {
            // At capacity, silently reject
            return;
        }

        // Check if adding child would exceed MTU
        // (rough estimate: each child adds ~8 bytes to pulse)
        let estimated_pulse_size = self.estimate_pulse_size() + 8;
        if estimated_pulse_size > self.transport().mtu() {
            return;
        }

        // Track if this is a new child
        let is_new = !self.children().contains_key(&pulse.node_id);

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
            return;
        }

        // Don't merge if this node is distrusted
        if self.is_distrusted(&pulse.node_id, now) {
            return;
        }

        // Don't merge if we're already in a pending parent state
        if self.pending_parent().is_some() {
            return;
        }

        // Different root?
        if pulse.root_hash == *self.root_hash() {
            return;
        }

        // Merge decision: larger tree wins, tie-break by smaller root_hash (lexicographic)
        let dominated = (pulse.tree_size, self.root_hash()) > (self.tree_size(), &pulse.root_hash);

        if !dominated {
            return;
        }

        // Check if pulse sender is a valid parent candidate
        if pulse.child_count() as usize >= MAX_CHILDREN {
            return; // Parent is full
        }

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

        // Parent keeps first slice
        let parent_slice = my_range / total;
        let mut current_lo = my_lo + parent_slice;

        // Clear old ranges
        self.child_ranges_mut().clear();

        // Assign ranges to children
        for (child_id, subtree_size) in &sorted_children {
            let child_range = (my_range * (*subtree_size as u64)) / total;
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

        // Determine flags
        let has_parent = self.parent().is_some();
        let we_need_pubkeys = !self.need_pubkey().is_empty();
        let neighbors_need_ours = !self.neighbors_need_pubkey().is_empty();
        let include_pubkey = we_need_pubkeys || neighbors_need_ours;
        let child_count = children.len().min(MAX_CHILDREN) as u8;

        let flags = Pulse::build_flags(has_parent, we_need_pubkeys, include_pubkey, child_count);

        // Parent hash
        let parent_hash = self.parent().map(|pid| self.compute_node_hash(&pid));

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
    #[allow(dead_code)]
    fn handle_neighbor_timeouts(&mut self, now: Timestamp) {
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
    #[allow(dead_code)]
    fn handle_location_expiry(&mut self, now: Timestamp) {
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
}
