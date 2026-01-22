//! Tree formation and maintenance.
//!
//! This module handles:
//! - Pulse message creation and processing
//! - Parent selection and tree merging
//! - Child management
//! - Neighbor timeouts

use crate::node::{JoinContext, NeighborTiming, Node};
use crate::time::{Duration, Timestamp};
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    ChildPrefix, ChildrenList, Event, Pulse, Signature, DISTRUST_TTL, K_REPLICAS, LOCATION_TTL,
    MAX_CHILDREN, MIN_PULSE_INTERVAL, MSG_PUBLISH,
};
use crate::wire::{pulse_sign_data, Encode, Message};

/// Number of missed pulses before timeout.
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
        if pulse.need_pubkey {
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
        };
        self.insert_neighbor_time(pulse.node_id, timing);

        // If new neighbor, schedule proactive pulse to introduce ourselves
        if is_new_neighbor {
            self.schedule_proactive_pulse(now);
        }

        // Check if this pulse is from our parent
        if Some(pulse.node_id) == self.parent() {
            self.handle_parent_pulse(&pulse, now);
        }
        // Check if this pulse claims us as parent
        else if pulse.parent_id == Some(*self.node_id()) {
            self.handle_child_pulse(&pulse, now);
        }
        // Check for pending parent acknowledgment
        else if let Some((pending, _)) = self.pending_parent() {
            if pulse.node_id == pending {
                self.handle_pending_parent_pulse(&pulse, now);
            }
        }

        // Tree merge decision (includes inversion handling)
        self.consider_merge(&pulse, now);

        // Track as shortcut if not parent/child
        if self.parent() != Some(pulse.node_id) && !self.children().contains_key(&pulse.node_id) {
            self.shortcuts_mut().insert(pulse.node_id);
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
                if let Some(pending_msgs) = self.take_pending_pubkey(&pulse.node_id) {
                    for msg in pending_msgs {
                        // Re-process PUBLISH messages now that we have the pubkey
                        if msg.msg_type == MSG_PUBLISH {
                            self.handle_publish(msg, now);
                        }
                    }
                }
            }
        } else if !self.has_pubkey(&pulse.node_id) {
            // We need this node's pubkey - track it so we signal need_pubkey
            self.need_pubkey_mut().insert(pulse.node_id);
        }
    }

    /// Handle a pulse from our current parent.
    fn handle_parent_pulse(&mut self, pulse: &Pulse, now: Timestamp) {
        // Find our ordinal in parent's children list
        if let Some(ordinal) = self.find_ordinal_in_children(pulse) {
            // Compute our tree address
            let mut new_addr = pulse.tree_addr.clone();
            new_addr.push(ordinal);

            let addr_changed = new_addr != *self.tree_addr();
            self.set_tree_addr(new_addr);

            // Update tree info from parent
            self.set_root_id(pulse.root_id);
            self.set_tree_size(pulse.tree_size);

            // Clear pending parent since we're acknowledged
            self.set_pending_parent(None);

            // If address changed, schedule republish and rebalance keyspace
            if addr_changed {
                // Jitter: 0-1τ
                let tau_ms = self.tau().as_millis();
                let jitter_ms = self.random_mut().gen_range(0, tau_ms);
                self.set_next_publish(Some(now + Duration::from_millis(jitter_ms)));
                // Move DHT entries that we no longer own to their new owners
                self.rebalance_keyspace(now);
                // Notify children of our new address
                self.schedule_proactive_pulse(now);
            }
        } else {
            // Parent didn't include us - we might have been rejected
            // Increment pending parent counter (reuse for rejection tracking)
            if let Some((parent, count)) = self.pending_parent() {
                if parent == pulse.node_id {
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

    /// Handle a pulse from a node claiming us as parent.
    fn handle_child_pulse(&mut self, pulse: &Pulse, now: Timestamp) {
        // Check if we can accept this child
        if self.children().len() >= MAX_CHILDREN {
            // At capacity, silently reject
            return;
        }

        // Check if adding child would exceed MTU
        // (rough estimate: each child adds ~4-6 bytes to pulse)
        let estimated_pulse_size = self.estimate_pulse_size() + 6;
        if estimated_pulse_size > self.transport().mtu() {
            return;
        }

        // Track if this is a new child
        let is_new = !self.children().contains_key(&pulse.node_id);

        // Accept the child
        self.children_mut()
            .insert(pulse.node_id, pulse.subtree_size);

        // Remove from shortcuts if present
        self.shortcuts_mut().remove(&pulse.node_id);

        // Update subtree size
        self.recalculate_subtree_size();

        // If new child, schedule proactive pulse to acknowledge them
        if is_new {
            self.schedule_proactive_pulse(now);
        }
    }

    /// Handle a pulse from our pending parent candidate.
    fn handle_pending_parent_pulse(&mut self, pulse: &Pulse, now: Timestamp) {
        // Check if we're in the children list
        if self.find_ordinal_in_children(pulse).is_some() {
            // We're acknowledged! Complete the parent switch
            let parent_id = pulse.node_id;
            self.set_parent(Some(parent_id));
            self.set_pending_parent(None);

            // Set join context for fraud detection
            self.set_join_context(Some(JoinContext {
                parent_at_join: parent_id,
                join_time: now,
            }));

            // Update tree info
            self.set_root_id(pulse.root_id);
            self.set_tree_size(pulse.tree_size);

            // Push tree changed event
            self.push_event(Event::TreeChanged {
                new_root: pulse.root_id,
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
    fn consider_merge(&mut self, pulse: &Pulse, now: Timestamp) {
        // Don't merge if this node is distrusted
        if self.is_distrusted(&pulse.node_id, now) {
            return;
        }

        // Don't merge if we're already in a pending parent state
        if self.pending_parent().is_some() {
            return;
        }

        // Different root?
        if pulse.root_id == *self.root_id() {
            return;
        }

        // Merge decision: larger tree wins, tie-break by smaller root_id
        let dominated = (pulse.tree_size, *self.root_id()) > (self.tree_size(), pulse.root_id);

        if !dominated {
            return;
        }

        // Check if pulse sender is a valid parent candidate
        if pulse.children.len() >= MAX_CHILDREN {
            return; // Parent is full
        }

        // TREE INVERSION: Leave our current tree position
        // When joining a bigger tree, we first become root of our own subtree.
        // Our children stay with us (they'll update their root_id from our pulses).
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

    /// Become root of our own subtree.
    fn become_root(&mut self) {
        self.set_parent(None);
        self.set_root_id(*self.node_id());
        self.set_tree_addr(Vec::new());
        self.recalculate_subtree_size();
        self.set_tree_size(self.subtree_size());
    }

    /// Find our ordinal in a parent's children list.
    fn find_ordinal_in_children(&self, pulse: &Pulse) -> Option<u8> {
        let prefix_len = pulse.child_prefix_len as usize;
        if prefix_len == 0 || prefix_len > self.node_id().len() {
            return None;
        }

        let our_prefix = &self.node_id()[..prefix_len];

        // Collect and sort children by prefix
        let mut sorted_prefixes: Vec<&ChildPrefix> =
            pulse.children.iter().map(|(prefix, _)| prefix).collect();
        sorted_prefixes.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));

        // Find our index
        sorted_prefixes
            .iter()
            .position(|prefix| prefix.as_slice() == our_prefix)
            .map(|idx| idx as u8)
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
        // Base size: node_id(16) + parent_id(17) + root_id(16) + subtree(3) + tree_size(3)
        //          + tree_addr(1+len) + need_pubkey(1) + pubkey(1 or 33) + child_prefix_len(1)
        //          + children_count(1) + signature(65)
        let base = 16 + 17 + 16 + 3 + 3 + 1 + self.tree_addr().len() + 1 + 1 + 65;
        let pubkey_size = if self.need_pubkey().is_empty() { 1 } else { 33 };

        // Children: each child is prefix_len + varint(subtree_size)
        let prefix_len = self.child_prefix_len();
        let children_size = self.children().len() * (prefix_len as usize + 3);

        base + pubkey_size + 1 + children_size
    }

    /// Calculate minimum prefix length needed to distinguish all children.
    pub(crate) fn child_prefix_len(&self) -> u8 {
        if self.children().is_empty() {
            return 0;
        }

        // Collect child node IDs
        let ids: Vec<[u8; 16]> = self.children().keys().copied().collect();

        // Find minimum prefix length that distinguishes all
        for prefix_len in 1..=16u8 {
            let mut prefixes = std::collections::HashSet::new();
            let mut unique = true;

            for id in &ids {
                let prefix = &id[..prefix_len as usize];
                if !prefixes.insert(prefix.to_vec()) {
                    unique = false;
                    break;
                }
            }

            if unique {
                return prefix_len;
            }
        }

        16 // Worst case: need full node ID
    }

    /// Build and send a Pulse message.
    ///
    /// Pulse is sent to the protocol queue (high priority). If the queue is full,
    /// the Pulse is dropped - this is acceptable because the protocol tolerates
    /// occasional missed Pulses (neighbors timeout after 8 missed Pulses).
    /// See design.md "Best-effort delivery" section.
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
        // Clear proactive pulse flag - it's been sent (or will be soon in regular schedule)
        self.set_proactive_pulse_pending(None);
    }

    /// Schedule a proactive pulse with batching delay (1τ to 2τ).
    /// If already scheduled, reschedules only if the new time would be earlier
    /// (coalesces multiple triggers while ensuring urgent events aren't delayed).
    pub(crate) fn schedule_proactive_pulse(&mut self, now: Timestamp) {
        let tau = self.tau();
        let tau_ms = tau.as_millis();
        // 1.5τ ± 0.5τ = range [1τ, 2τ]
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
        let child_prefix_len = self.child_prefix_len();

        // Build children list
        let mut children = ChildrenList::new();
        for (id, &size) in self.children().iter() {
            let prefix = id[..child_prefix_len as usize].to_vec();
            children.push((prefix, size));
        }

        // Sort children by prefix for deterministic ordering
        children.sort_by(|a, b| a.0.cmp(&b.0));

        // Include pubkey if:
        // 1. We need pubkeys from others (signal willingness to exchange), OR
        // 2. Any neighbor has signaled need_pubkey=true (they want our pubkey)
        let we_need_pubkeys = !self.need_pubkey().is_empty();
        let neighbors_need_ours = !self.neighbors_need_pubkey().is_empty();
        let include_pubkey = we_need_pubkeys || neighbors_need_ours;

        let mut pulse = Pulse {
            node_id: *self.node_id(),
            parent_id: self.parent(),
            root_id: *self.root_id(),
            subtree_size: self.subtree_size(),
            tree_size: self.tree_size(),
            tree_addr: self.tree_addr().clone(),
            need_pubkey: we_need_pubkeys,
            pubkey: if include_pubkey {
                Some(*self.pubkey())
            } else {
                None
            },
            child_prefix_len,
            children,
            signature: Signature::default(),
        };

        // Sign the pulse
        let sign_data = pulse_sign_data(&pulse);
        pulse.signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        pulse
    }

    /// Handle timeouts for neighbors, pending operations, etc.
    pub(crate) fn handle_timeouts(&mut self, now: Timestamp) {
        self.handle_neighbor_timeouts(now);
        self.handle_lookup_timeouts(now);
        self.handle_location_expiry(now);
    }

    /// Handle neighbor timeouts.
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
                    new_root: *self.node_id(),
                    new_size: self.subtree_size(),
                });
            }

            // If child, remove
            if self.children_mut().remove(&id).is_some() {
                self.recalculate_subtree_size();
            }

            // Remove from shortcuts
            self.shortcuts_mut().remove(&id);

            // Remove from pubkey cache and need set
            self.pubkey_cache_mut().remove(&id);
            self.need_pubkey_mut().remove(&id);
        }
    }

    /// Handle lookup timeouts.
    fn handle_lookup_timeouts(&mut self, now: Timestamp) {
        // Collect lookups that need action
        let mut to_retry: Vec<[u8; 16]> = Vec::new();
        let mut to_fail: Vec<[u8; 16]> = Vec::new();

        let lookup_timeout = self.lookup_timeout();
        for (target, lookup) in self.pending_lookups().iter() {
            if now > lookup.last_query_at + lookup_timeout {
                if lookup.replica_index + 1 < K_REPLICAS {
                    to_retry.push(*target);
                } else {
                    to_fail.push(*target);
                }
            }
        }

        // Process retries
        for target in to_retry {
            if let Some(lookup) = self.pending_lookups_mut().get_mut(&target) {
                lookup.replica_index += 1;
                lookup.last_query_at = now;
                let replica = lookup.replica_index;
                self.send_lookup(target, replica, now);
            }
        }

        // Process failures
        for target in to_fail {
            self.pending_lookups_mut().remove(&target);
            self.push_event(Event::LookupFailed { node_id: target });

            // Also remove any pending data
            self.pending_data_mut().remove(&target);
        }
    }

    /// Handle location entry expiration.
    fn handle_location_expiry(&mut self, now: Timestamp) {
        // Entries older than LOCATION_TTL are expired
        // Use checked subtraction to handle case where now < LOCATION_TTL
        let cutoff = if now.as_millis() >= LOCATION_TTL.as_millis() {
            now - LOCATION_TTL
        } else {
            Timestamp::ZERO
        };

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
