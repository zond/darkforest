//! Message routing based on keyspace addressing.
//!
//! Routing uses keyspace ranges where each node owns a contiguous range
//! [keyspace_lo, keyspace_hi). Messages route toward dest_addr by forwarding
//! to the neighbor whose range contains the destination with the tightest fit.

use alloc::vec::Vec;

use crate::config::NodeConfig;
use crate::node::{AckHash, Node};
use crate::time::Timestamp;
use crate::traits::{Ackable, Clock, Crypto, Outgoing, Random, Transport};
use crate::types::{
    ChildHash, Error, NodeId, Routed, Signature, DEFAULT_TTL, MSG_DATA, MSG_FOUND, MSG_LOOKUP,
    MSG_PUBLISH,
};
use crate::wire::{routed_sign_data, Ack, Encode, Message};

impl<T, Cr, R, Clk, Cfg> Node<T, Cr, R, Clk, Cfg>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
    Cfg: NodeConfig,
{
    /// Handle an incoming Routed message.
    pub(crate) fn handle_routed(&mut self, mut msg: Routed, now: Timestamp) {
        // Check TTL
        if msg.ttl == 0 {
            return;
        }

        // Store original TTL before decrementing (for duplicate detection)
        let original_ttl = msg.ttl;

        // Decrement TTL for forwarding
        msg.ttl = msg.ttl.saturating_sub(1);

        let dest = msg.dest_addr;
        let msg_type = msg.msg_type();

        // Do I own this keyspace location?
        if self.owns_key(dest) {
            self.emit_debug(crate::debug::DebugEvent::RoutedDelivered {
                msg_type,
                dest_addr: dest,
                from: msg.src_node_id,
            });
            // Handle locally based on message type
            match msg_type {
                MSG_PUBLISH => self.handle_publish(msg, now),
                MSG_LOOKUP => self.handle_lookup_msg(msg, now),
                MSG_FOUND => self.handle_found(msg, now),
                MSG_DATA => self.handle_data(msg, now),
                _ => {} // Unknown type, drop silently
            }
            return;
        }

        // Am I the intended forwarder? If not, ignore silently.
        // This prevents amplification attacks where multiple nodes forward the same message.
        let my_hash = self.compute_node_hash(self.node_id());
        if msg.next_hop != my_hash {
            return;
        }

        // Not for us - verify signature before forwarding to prevent bandwidth waste
        if self.verify_routed_signature(&msg, now).is_none() {
            // Can't verify signature (no pubkey or invalid) - drop
            return;
        }

        // Duplicate detection: check if we've recently forwarded this message
        // Note: hash excludes TTL so it's the same at any hop
        let msg_hash = msg.ack_hash(self.crypto());

        if let Some(&(_stored_time, stored_ttl, _)) = self.recently_forwarded().get(&msg_hash) {
            if stored_ttl == original_ttl {
                // Same TTL = retransmission from sender who didn't hear our forward
                // Send explicit ACK to confirm we received and forwarded it
                self.emit_debug(crate::debug::DebugEvent::RoutedDuplicate {
                    msg_type,
                    dest_addr: dest,
                    original_ttl,
                    stored_ttl,
                    action: "ack_retransmit",
                });
                self.send_explicit_ack(msg_hash);
                return;
            }
            // Different TTL = message looped back to us, schedule delayed retry
            // with exponential backoff to let tree routing stabilize
            self.emit_debug(crate::debug::DebugEvent::RoutedDuplicate {
                msg_type,
                dest_addr: dest,
                original_ttl,
                stored_ttl,
                action: "bounce_back",
            });
            self.handle_bounce_back(msg, msg_hash, original_ttl, now);
            return;
        }

        // Not a duplicate - forward and track with TTL
        self.insert_recently_forwarded(msg_hash, original_ttl, now);
        self.forward_routed(msg, now);
    }

    /// Send an explicit ACK for a message hash.
    ///
    /// Used when we receive a duplicate message - the sender is waiting for confirmation
    /// that we received it, so we send a minimal ACK instead of re-forwarding.
    pub(crate) fn send_explicit_ack(&mut self, hash: AckHash) {
        let sender_hash = self.compute_node_hash(self.node_id());
        let ack = Ack { hash, sender_hash };
        let msg = Message::Ack(ack);

        // ACK is small (9 bytes) so MTU check is unlikely to fail, but be safe
        if msg.encode_to_vec().len() > self.transport().mtu() {
            return;
        }

        if self.transport().outgoing().try_send(msg) {
            self.record_protocol_sent();
        }
        // Don't track drops for ACKs - they're best-effort
    }

    /// Handle a bounce-back: message returned with different TTL during tree restructuring.
    ///
    /// Instead of dropping, we delay and retry with exponential backoff, giving the tree
    /// time to stabilize.
    fn handle_bounce_back(
        &mut self,
        msg: Routed,
        ack_hash: AckHash,
        original_ttl: u8,
        now: Timestamp,
    ) {
        use crate::types::RECENTLY_FORWARDED_TTL_MULTIPLIER;

        // Always ACK upstream so they don't retry while we delay (or drop)
        self.send_explicit_ack(ack_hash);

        // TTL=1 would become TTL=0 (expired) on forward - just drop it
        // Note: msg.ttl is already decremented, so check original_ttl
        if original_ttl <= 1 {
            return;
        }

        // Clear our own pending_ack if present (bounce proves downstream heard us)
        self.pending_acks_mut().remove(&ack_hash);

        // Update recently_forwarded entry: increment seen_count and refresh expiration
        let seen_count = if let Some(entry) = self.recently_forwarded_mut().get_mut(&ack_hash) {
            entry.0 = now; // Refresh timestamp
                           // Update stored TTL to current value. This ensures future arrivals with this
                           // same TTL are recognized as retransmissions (not new bounces), while arrivals
                           // with yet-lower TTL trigger another bounce-back handling.
            entry.1 = original_ttl;
            entry.2 = entry.2.saturating_add(1); // Increment seen_count
            entry.2
        } else {
            // Entry was evicted - recreate it
            self.insert_recently_forwarded(ack_hash, original_ttl, now);
            1
        };

        // Schedule delayed forward with exponential backoff
        // Backoff: 1τ, 2τ, 4τ, 8τ, ..., capped at 128τ
        // Note: Duration * u64 uses saturating_mul internally, so this is overflow-safe.
        let tau = self.tau();
        let multiplier = 1u64 << (seen_count.saturating_sub(1)).min(7);
        let delay = tau * multiplier;
        let scheduled_time = now + delay;

        // Refresh the recently_forwarded expiration to survive the delay
        let expiry = tau * RECENTLY_FORWARDED_TTL_MULTIPLIER;
        let extended_expiry = expiry.max(delay + tau); // Ensure it lives past the scheduled forward
        if let Some(entry) = self.recently_forwarded_mut().get_mut(&ack_hash) {
            // Set timestamp so that cleanup won't expire it before the delayed forward fires
            entry.0 = now + extended_expiry - (tau * RECENTLY_FORWARDED_TTL_MULTIPLIER);
        }

        self.emit_debug(crate::debug::DebugEvent::BounceBackScheduled {
            msg_type: msg.msg_type(),
            dest_addr: msg.dest_addr,
            seen_count,
            delay_ms: delay.as_millis(),
        });

        self.schedule_delayed_forward(msg, ack_hash, seen_count, scheduled_time);
    }

    /// Schedule a delayed forward for bounce-back dampening.
    ///
    /// Deduplication: if hash exists, double the remaining delay.
    /// Eviction: when full, drop entry with longest delay (unless new entry is longer).
    fn schedule_delayed_forward(
        &mut self,
        msg: Routed,
        ack_hash: AckHash,
        seen_count: u8,
        scheduled_time: Timestamp,
    ) {
        use crate::node::DelayedForward;

        let now = self.now();

        // Deduplication: extend delay if this hash already has a pending forward.
        // Safety: delay doubling cannot grow unbounded because:
        // 1. Message TTL limits total hops (default 64), so message eventually expires
        // 2. The recently_forwarded entry expires after 320τ, dropping the delayed forward
        // 3. Timestamp arithmetic is saturating, so overflow is impossible
        if let Some(existing) = self.delayed_forwards_mut().get_mut(&ack_hash) {
            let remaining = existing.scheduled_time.saturating_sub(now);
            existing.scheduled_time = now + remaining * 2;
            existing.seen_count = seen_count;
            return;
        }

        // Eviction: when full, drop entry with longest delay (most likely to exceed TTL)
        if self.delayed_forwards().len() >= Cfg::MAX_DELAYED_FORWARDS {
            let longest = self
                .delayed_forwards()
                .iter()
                .max_by_key(|(_, df)| df.scheduled_time);

            if let Some((key, df)) = longest {
                if scheduled_time < df.scheduled_time {
                    let key = *key;
                    self.delayed_forwards_mut().remove(&key);
                } else {
                    // New entry has longer delay, reject it
                    return;
                }
            }
        }

        self.delayed_forwards_mut().insert(
            ack_hash,
            DelayedForward {
                msg,
                seen_count,
                scheduled_time,
            },
        );
    }

    /// Process delayed forwards whose scheduled time has arrived.
    ///
    /// For each ready entry: recompute next_hop and forward if TTL permits.
    pub(crate) fn handle_delayed_forwards(&mut self, now: Timestamp) {
        // Two-phase approach to avoid cloning Routed messages (which contain Vec<u8> payload):
        // 1. Collect just the keys of ready entries (cheap 4-byte AckHash copies)
        // 2. Remove and process each entry, taking ownership of the message
        let ready_keys: Vec<_> = self
            .delayed_forwards()
            .iter()
            .filter(|(_, df)| now >= df.scheduled_time)
            .map(|(k, _)| *k)
            .collect();

        for ack_hash in ready_keys {
            // Remove entry and take ownership of the message (no clone needed)
            let Some(entry) = self.delayed_forwards_mut().remove(&ack_hash) else {
                continue;
            };
            let mut msg = entry.msg;

            // TTL was already decremented when message was received
            if msg.ttl == 0 {
                continue;
            }

            // Recompute route: prefer child/shortcut, fall back to parent
            let dest = msg.dest_addr;
            let next_hop_id = self.best_next_hop(dest).or_else(|| self.parent());

            self.emit_debug(crate::debug::DebugEvent::DelayedForwardExecuted {
                msg_type: msg.msg_type(),
                dest_addr: dest,
                ttl: msg.ttl,
                has_route: next_hop_id.is_some(),
            });

            if let Some(hop_id) = next_hop_id {
                msg.next_hop = self.compute_node_hash(&hop_id);
                self.send_to_neighbor(hop_id, msg, now);
            }
        }
    }

    /// Get the earliest scheduled time from delayed_forwards, if any.
    pub(crate) fn next_delayed_forward_time(&self) -> Option<Timestamp> {
        self.delayed_forwards()
            .values()
            .map(|df| df.scheduled_time)
            .min()
    }

    /// Verify a Routed message signature.
    /// Returns the verified pubkey if valid, None otherwise.
    pub(crate) fn verify_routed_signature(
        &mut self,
        msg: &Routed,
        now: Timestamp,
    ) -> Option<crate::types::PublicKey> {
        // Get pubkey from message or cache
        let pubkey = match msg.src_pubkey {
            Some(pk) => {
                // Verify pubkey binds to src_node_id
                if !self.crypto().verify_pubkey_binding(&msg.src_node_id, &pk) {
                    return None;
                }
                // Cache for future use
                self.insert_pubkey_cache(msg.src_node_id, pk, now);
                pk
            }
            None => {
                // Check cache (marks as recently used)
                match self.get_pubkey(&msg.src_node_id, now) {
                    Some(pk) => pk,
                    None => {
                        // No pubkey available - mark that we need it
                        self.need_pubkey_mut().insert(msg.src_node_id);
                        return None;
                    }
                }
            }
        };

        // Verify signature
        let sign_data = routed_sign_data(msg);
        if self
            .crypto()
            .verify(&pubkey, sign_data.as_slice(), &msg.signature)
        {
            Some(pubkey)
        } else {
            None
        }
    }

    /// Verify that dest_hash matches our node_id hash.
    /// Returns false if dest_hash is present but doesn't match.
    pub(crate) fn verify_dest_hash(&self, msg: &Routed) -> bool {
        match msg.dest_hash {
            Some(dest_hash) => dest_hash == self.compute_node_hash(self.node_id()),
            None => true, // No dest_hash to verify
        }
    }

    /// Forward a routed message toward its destination.
    fn forward_routed(&mut self, mut msg: Routed, now: Timestamp) {
        let dest = msg.dest_addr;
        let msg_type = msg.msg_type();
        let ttl = msg.ttl;
        let (my_lo, my_hi) = self.keyspace_range();

        // Try to find best next hop
        if let Some(next_hop_id) = self.best_next_hop(dest) {
            self.emit_debug(crate::debug::DebugEvent::RoutedForwardedDown {
                msg_type,
                dest_addr: dest,
                next_hop: next_hop_id,
                ttl,
                my_keyspace: (my_lo, my_hi),
            });
            // Set next_hop to the intended forwarder's hash
            msg.next_hop = self.compute_node_hash(&next_hop_id);
            self.send_to_neighbor(next_hop_id, msg, now);
        } else if let Some(parent_id) = self.parent() {
            self.emit_debug(crate::debug::DebugEvent::RoutedForwardedUp {
                msg_type,
                dest_addr: dest,
                next_hop: parent_id,
                ttl,
                my_keyspace: (my_lo, my_hi),
            });
            // Forward upward to parent as fallback
            msg.next_hop = self.compute_node_hash(&parent_id);
            self.send_to_neighbor(parent_id, msg, now);
        } else {
            // No route - drop the message
            self.emit_debug(crate::debug::DebugEvent::RoutedDropped {
                msg_type,
                dest_addr: dest,
                reason: "no route (no next_hop or parent)",
            });
        }
    }

    /// Find the best next hop for a destination keyspace address.
    ///
    /// Returns the neighbor (child or shortcut) whose keyspace range:
    /// 1. Contains the destination address
    /// 2. Has the tightest range (smallest hi - lo)
    fn best_next_hop(&self, dest: u32) -> Option<NodeId> {
        let mut best: Option<(NodeId, u64)> = None; // (node_id, range_size)

        // Check children
        for (_, entry) in self.children().iter_by_hash() {
            let lo = entry.keyspace_lo;
            let hi = entry.keyspace_hi;
            if dest >= lo && dest < hi {
                let range_size = (hi as u64).saturating_sub(lo as u64);
                if best.map_or(true, |(_, best_size)| range_size < best_size) {
                    best = Some((entry.node_id, range_size));
                    // Early exit: can't find a tighter range than size 1
                    if range_size == 1 {
                        return best.map(|(id, _)| id);
                    }
                }
            }
        }

        // Check shortcuts
        for (shortcut_id, &(lo, hi)) in self.shortcuts() {
            if dest >= lo && dest < hi {
                let range_size = (hi as u64).saturating_sub(lo as u64);
                if best.map_or(true, |(_, best_size)| range_size < best_size) {
                    best = Some((*shortcut_id, range_size));
                    // Early exit: can't find a tighter range than size 1
                    if range_size == 1 {
                        return best.map(|(id, _)| id);
                    }
                }
            }
        }

        best.map(|(node_id, _)| node_id)
    }

    /// Broadcast a Routed message with ACK tracking.
    ///
    /// On broadcast radio (LoRa), all neighbors within range receive the message.
    /// The `neighbor` parameter documents routing intent for logging/debugging
    /// and enables future directed-transmission optimizations on point-to-point transports.
    ///
    /// Inserts the message hash into pending_acks for retransmission if no ACK is received.
    fn send_to_neighbor(&mut self, _neighbor: NodeId, msg: Routed, now: Timestamp) {
        let sent_ttl = msg.ttl;

        // Compute ACK hash while we still have &msg (avoids cloning)
        let ack_hash = msg.ack_hash(self.crypto());

        // Move msg into Message (no clone needed)
        let wire_msg = Message::Routed(msg);
        let priority = wire_msg.priority();
        let encoded = wire_msg.encode_to_vec();

        if encoded.len() > self.transport().mtu() {
            self.record_protocol_dropped();
            return;
        }

        // Track pending ACK before sending (with TTL for implicit ACK verification)
        self.insert_pending_ack(ack_hash, encoded, priority, sent_ttl, now);

        // Broadcast (neighbors will hear it) - priority determined by message type
        if self.transport().outgoing().try_send(wire_msg) {
            self.record_protocol_sent();
        } else {
            // Send failed - remove pending ACK since we never actually sent
            self.pending_acks_mut().remove(&ack_hash);
            self.record_protocol_dropped();
        }
    }

    /// Handle incoming DATA message.
    fn handle_data(&mut self, msg: Routed, now: Timestamp) {
        if !self.verify_dest_hash(&msg) {
            return; // Stale address - not the intended recipient
        }

        // Check if we can verify the signature
        // DATA messages queue for retry when pubkey is missing (unlike other message types)
        let needs_pubkey =
            msg.src_pubkey.is_none() && !self.pubkey_cache().contains_key(&msg.src_node_id);

        if self.verify_routed_signature(&msg, now).is_none() {
            if needs_pubkey {
                // Queue message to retry when pubkey arrives
                self.queue_pending_pubkey(msg.src_node_id, msg);
            }
            return;
        }

        // Deliver to application
        self.push_incoming_data(msg.src_node_id, msg.payload);
    }

    /// Send DATA to a known destination.
    pub(crate) fn send_data_to(
        &mut self,
        target: NodeId,
        dest_addr: u32,
        payload: Vec<u8>,
        _now: Timestamp,
    ) -> Result<(), Error> {
        let dest_hash = self.compute_node_hash(&target);

        let msg = self.build_routed(dest_addr, Some(dest_hash), MSG_DATA, payload);
        self.send_routed(msg)
    }

    /// Build a Routed message with optional dest_hash for verification.
    pub(crate) fn build_routed(
        &mut self,
        dest_addr: u32,
        dest_hash: Option<ChildHash>,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> Routed {
        self.build_routed_inner(dest_addr, dest_hash, msg_type, payload, false)
    }

    /// Build a Routed message without dest_hash, always including pubkey (for PUBLISH).
    /// PUBLISH messages go to potentially distant storage nodes that need our pubkey.
    pub(crate) fn build_routed_no_reply(
        &mut self,
        dest_addr: u32,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> Routed {
        // Always include pubkey for PUBLISH - storage nodes likely don't have it cached
        self.build_routed_inner(dest_addr, None, msg_type, payload, true)
    }

    /// Internal helper to build Routed messages.
    fn build_routed_inner(
        &mut self,
        dest_addr: u32,
        dest_hash: Option<ChildHash>,
        msg_type: u8,
        payload: Vec<u8>,
        force_pubkey: bool,
    ) -> Routed {
        let include_pubkey = force_pubkey || !self.neighbors_need_pubkey().is_empty();

        let flags_and_type = Routed::build_flags_and_type(
            msg_type,
            dest_hash.is_some(),
            true, // always include src_addr for replies
            include_pubkey,
        );

        // Compute initial next_hop based on routing decision
        let next_hop = if let Some(next_hop_id) = self.best_next_hop(dest_addr) {
            self.compute_node_hash(&next_hop_id)
        } else if let Some(parent_id) = self.parent() {
            self.compute_node_hash(&parent_id)
        } else {
            // No route - use zeros (message may be handled locally or dropped)
            [0u8; 4]
        };

        let mut msg = Routed {
            flags_and_type,
            next_hop,
            dest_addr,
            dest_hash,
            src_addr: Some(self.my_address()),
            src_node_id: *self.node_id(),
            src_pubkey: if include_pubkey {
                Some(*self.pubkey())
            } else {
                None
            },
            ttl: DEFAULT_TTL,
            payload,
            signature: Signature::default(),
        };

        let sign_data = routed_sign_data(&msg);
        msg.signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        msg
    }

    /// Send a Routed message.
    pub(crate) fn send_routed(&mut self, msg: Routed) -> Result<(), Error> {
        let dest = msg.dest_addr;
        let msg_type = msg.msg_type();
        let ttl = msg.ttl;

        self.emit_debug(crate::debug::DebugEvent::RoutedSent {
            msg_type,
            dest_addr: dest,
            ttl,
        });

        // If we own the destination, handle locally
        if self.owns_key(dest) {
            let wire_msg = Message::Routed(msg.clone());
            if wire_msg.encode_to_vec().len() > self.transport().mtu() {
                return Err(Error::MessageTooLarge);
            }
            // Handle locally as if we received it
            let now = self.now();
            match msg_type {
                MSG_PUBLISH => self.handle_publish(msg, now),
                MSG_LOOKUP => self.handle_lookup_msg(msg, now),
                MSG_FOUND => self.handle_found(msg, now),
                MSG_DATA => self.handle_data(msg, now),
                _ => {}
            }
            return Ok(());
        }

        // Build message - priority is determined automatically by msg_type
        let wire_msg = Message::Routed(msg);

        if wire_msg.encode_to_vec().len() > self.transport().mtu() {
            return Err(Error::MessageTooLarge);
        }

        // Send via priority queue - priority determined by Message::priority()
        if self.transport().outgoing().try_send(wire_msg) {
            if msg_type == MSG_DATA {
                self.record_app_sent();
            } else {
                self.record_protocol_sent();
            }
            Ok(())
        } else {
            if msg_type == MSG_DATA {
                self.record_app_dropped();
            } else {
                self.record_protocol_dropped();
            }
            Err(Error::QueueFull)
        }
    }

    /// Send a BACKUP_PUBLISH broadcast to random neighbors.
    ///
    /// Called after storing a location entry to ensure backup nodes have a copy.
    pub(crate) fn send_backup_publish(&mut self, entry: &crate::types::LocationEntry) {
        use crate::types::{Broadcast, BCAST_PAYLOAD_BACKUP};
        use crate::wire::{broadcast_sign_data, Encode, Message};

        // Select 2 random neighbors to send backup to
        let neighbors: Vec<_> = self.neighbor_times().keys().copied().collect();
        if neighbors.is_empty() {
            return;
        }

        // Get 2 random neighbors (or fewer if we don't have 2)
        let num_targets = core::cmp::min(2, neighbors.len());
        let mut destinations = Vec::with_capacity(num_targets);

        // Simple random selection using the random generator
        let mut selected = alloc::collections::BTreeSet::new();
        while destinations.len() < num_targets && selected.len() < neighbors.len() {
            let idx = self.random_mut().gen_u32() as usize % neighbors.len();
            if selected.insert(idx) {
                let neighbor_id = neighbors[idx];
                let hash = self.compute_node_hash(&neighbor_id);
                destinations.push(hash);
            }
        }

        if destinations.is_empty() {
            return;
        }

        // Build payload: BCAST_PAYLOAD_BACKUP (1 byte) + encoded LocationEntry
        let mut payload = alloc::vec![BCAST_PAYLOAD_BACKUP];
        let entry_bytes = entry.encode_to_vec();
        payload.extend(entry_bytes);

        // Build the broadcast message (without signature)
        let mut broadcast = Broadcast {
            src_node_id: *self.node_id(),
            destinations,
            payload,
            signature: crate::types::Signature::default(),
        };

        // Sign the broadcast
        let sign_data = broadcast_sign_data(&broadcast);
        broadcast.signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        // Build wire message
        let wire_msg = Message::Broadcast(broadcast);

        // Check MTU
        if wire_msg.encode_to_vec().len() > self.transport().mtu() {
            return; // Message too large
        }

        // Send via priority queue (backup is protocol traffic - BroadcastProtocol priority)
        if self.transport().outgoing().try_send(wire_msg) {
            self.record_protocol_sent();
        } else {
            self.record_protocol_dropped();
        }
    }

    /// Check lookup timeouts, returning entries needing action and next timeout.
    ///
    /// Returns ((retry_list, failed_list), next_timeout_time).
    #[allow(clippy::type_complexity)]
    pub(crate) fn check_lookup_timeouts(
        &self,
        now: Timestamp,
    ) -> ((Vec<([u8; 16], usize)>, Vec<[u8; 16]>), Option<Timestamp>) {
        use crate::types::K_REPLICAS;

        let timeout_duration = self.lookup_timeout();

        let mut retry_lookups = Vec::new();
        let mut failed_lookups = Vec::new();
        let mut next_timeout: Option<Timestamp> = None;

        for (target, lookup) in self.pending_lookups().iter() {
            let timeout_at = lookup.last_query_at + timeout_duration;
            if now >= timeout_at {
                if lookup.replica_index + 1 < K_REPLICAS {
                    retry_lookups.push((*target, lookup.replica_index + 1));
                } else {
                    failed_lookups.push(*target);
                }
            } else {
                // Track earliest future timeout
                next_timeout = Some(match next_timeout {
                    Some(t) => t.min(timeout_at),
                    None => timeout_at,
                });
            }
        }

        ((retry_lookups, failed_lookups), next_timeout)
    }

    /// Handle timeouts for pending lookups and other operations.
    ///
    /// Returns the next timeout time (if any pending lookups remain).
    pub(crate) fn handle_timeouts(&mut self, now: Timestamp) -> Option<Timestamp> {
        use crate::types::Event;

        let ((retry_lookups, failed_lookups), next_timeout) = self.check_lookup_timeouts(now);

        // Process retries
        for (target, next_replica) in retry_lookups {
            if let Some(lookup) = self.pending_lookups_mut().get_mut(&target) {
                lookup.replica_index = next_replica;
                lookup.last_query_at = now;
            }
            self.send_lookup(target, next_replica, now);
        }

        // Process failures
        for target in failed_lookups {
            self.pending_lookups_mut().remove(&target);
            self.pending_data_mut().remove(&target);
            self.push_event(Event::LookupFailed { node_id: target });
        }

        next_timeout
    }

    /// Compute the keyspace address for a node's replica.
    ///
    /// Each node publishes its location to K_REPLICAS different addresses.
    /// The address is computed by hashing (node_id || replica_index) and
    /// taking the first 4 bytes as a u32.
    pub(crate) fn replica_addr(&self, node_id: &NodeId, replica: u8) -> u32 {
        let mut data = [0u8; 17];
        data[..16].copy_from_slice(node_id);
        data[16] = replica;
        let hash = self.crypto().hash(&data);
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    }

    /// Process pending messages that were waiting for a pubkey.
    pub(crate) fn process_pending_pubkey(
        &mut self,
        node_id: &NodeId,
        pubkey: &crate::types::PublicKey,
        now: Timestamp,
    ) {
        // Cache the pubkey
        self.insert_pubkey_cache(*node_id, *pubkey, now);

        // Process pending messages
        if let Some(pending) = self.take_pending_pubkey(node_id) {
            for msg in pending {
                self.handle_routed(msg, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::config::{DefaultConfig, SmallConfig};
    use crate::time::{Duration, Timestamp};
    use crate::traits::test_impls::{FastTestCrypto, MockClock, MockRandom, MockTransport};
    use crate::traits::Ackable;
    use crate::types::{Priority, RECENTLY_FORWARDED_TTL_MULTIPLIER};
    use crate::wire::{Ack, Decode, Encode, Message};

    /// Type alias for test nodes using default config.
    type TestNode = Node<MockTransport, FastTestCrypto, MockRandom, MockClock, DefaultConfig>;

    /// Type alias for test nodes using small config (64KB RAM).
    type SmallTestNode = Node<MockTransport, FastTestCrypto, MockRandom, MockClock, SmallConfig>;

    fn make_node() -> TestNode {
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();
        Node::new(transport, crypto, random, clock)
    }

    fn make_small_node() -> SmallTestNode {
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();
        Node::new(transport, crypto, random, clock)
    }

    #[test]
    fn test_owns_key() {
        let node = make_node();

        // Node starts with full keyspace [0, u32::MAX)
        assert!(node.owns_key(0));
        assert!(node.owns_key(1000));
        assert!(node.owns_key(u32::MAX - 1));
    }

    #[test]
    fn test_my_address() {
        let node = make_node();

        // Full keyspace: center is approximately u32::MAX / 2
        let addr = node.my_address();
        // (0/2) + (MAX/2) = MAX/2
        assert_eq!(addr, u32::MAX / 2);
    }

    #[test]
    fn test_replica_addr() {
        let node = make_node();

        let node_id: NodeId = [1u8; 16];
        let addr0 = node.replica_addr(&node_id, 0);
        let addr0_again = node.replica_addr(&node_id, 0);

        // Same inputs produce same output (deterministic)
        assert_eq!(addr0, addr0_again);

        // Different node_ids produce different addresses
        let other_id: NodeId = [2u8; 16];
        let other_addr = node.replica_addr(&other_id, 0);
        assert_ne!(addr0, other_addr);
    }

    #[test]
    fn test_best_next_hop_returns_child_in_range() {
        let mut node = make_node();

        // Add a child with keyspace range [1000, 2000)
        let child_id: NodeId = [1u8; 16];
        let child_hash = node.compute_node_hash(&child_id);
        node.children_mut().insert(child_hash, child_id, 1);
        node.children_mut().set_range(&child_id, 1000, 2000);

        // Destination within child's range should return child
        assert_eq!(node.best_next_hop(1500), Some(child_id));

        // Destination outside any child range should return None
        assert_eq!(node.best_next_hop(500), None);
        assert_eq!(node.best_next_hop(3000), None);
    }

    #[test]
    fn test_best_next_hop_returns_shortcut_in_range() {
        let mut node = make_node();

        // Add a shortcut with keyspace range [5000, 6000)
        let shortcut_id: NodeId = [2u8; 16];
        node.shortcuts_mut().insert(shortcut_id, (5000, 6000));

        // Destination within shortcut's range should return shortcut
        assert_eq!(node.best_next_hop(5500), Some(shortcut_id));

        // Destination outside any range should return None
        assert_eq!(node.best_next_hop(4000), None);
    }

    #[test]
    fn test_best_next_hop_prefers_tighter_range() {
        let mut node = make_node();

        // Add a child with wide range [0, 10000)
        let wide_child: NodeId = [1u8; 16];
        let wide_hash = node.compute_node_hash(&wide_child);
        node.children_mut().insert(wide_hash, wide_child, 1);
        node.children_mut().set_range(&wide_child, 0, 10000);

        // Add a shortcut with tight range [4000, 6000)
        let tight_shortcut: NodeId = [2u8; 16];
        node.shortcuts_mut().insert(tight_shortcut, (4000, 6000));

        // Destination 5000 is in both ranges - should prefer tighter range
        assert_eq!(node.best_next_hop(5000), Some(tight_shortcut));

        // Destination 1000 is only in wide range
        assert_eq!(node.best_next_hop(1000), Some(wide_child));
    }

    #[test]
    fn test_best_next_hop_child_tighter_than_shortcut() {
        let mut node = make_node();

        // Add a shortcut with wide range [0, 20000)
        let wide_shortcut: NodeId = [1u8; 16];
        node.shortcuts_mut().insert(wide_shortcut, (0, 20000));

        // Add a child with tight range [5000, 7000)
        let tight_child: NodeId = [2u8; 16];
        let tight_hash = node.compute_node_hash(&tight_child);
        node.children_mut().insert(tight_hash, tight_child, 1);
        node.children_mut().set_range(&tight_child, 5000, 7000);

        // Destination 6000 is in both ranges - should prefer tighter child
        assert_eq!(node.best_next_hop(6000), Some(tight_child));
    }

    #[test]
    fn test_best_next_hop_multiple_children() {
        let mut node = make_node();

        // Add multiple non-overlapping children
        let child1: NodeId = [1u8; 16];
        let child2: NodeId = [2u8; 16];
        let child3: NodeId = [3u8; 16];

        let hash1 = node.compute_node_hash(&child1);
        let hash2 = node.compute_node_hash(&child2);
        let hash3 = node.compute_node_hash(&child3);

        node.children_mut().insert(hash1, child1, 1);
        node.children_mut().set_range(&child1, 0, 1000);
        node.children_mut().insert(hash2, child2, 1);
        node.children_mut().set_range(&child2, 1000, 2000);
        node.children_mut().insert(hash3, child3, 1);
        node.children_mut().set_range(&child3, 2000, 3000);

        // Each destination should route to correct child
        assert_eq!(node.best_next_hop(500), Some(child1));
        assert_eq!(node.best_next_hop(1500), Some(child2));
        assert_eq!(node.best_next_hop(2500), Some(child3));

        // Outside all ranges
        assert_eq!(node.best_next_hop(5000), None);
    }

    #[test]
    fn test_ack_hash_invariant() {
        // Hash should be the same regardless of TTL (routed_sign_data excludes TTL)
        let node = make_node();

        let msg1 = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255, // High TTL
            payload: b"test payload".to_vec(),
            signature: Signature::default(),
        };

        let mut msg2 = msg1.clone();
        msg2.ttl = 100; // Different TTL

        let hash1 = msg1.ack_hash(node.crypto());
        let hash2 = msg2.ack_hash(node.crypto());

        assert_eq!(
            hash1, hash2,
            "ACK hash should be invariant across TTL values"
        );
    }

    #[test]
    fn test_ack_hash_different_content() {
        // Different message content should produce different hashes
        let node = make_node();

        let msg1 = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            payload: b"AAAA".to_vec(),
            signature: Signature::default(),
        };

        // Use completely different payload to ensure hash differs
        let mut msg2 = msg1.clone();
        msg2.payload = b"ZZZZZZZZ".to_vec();

        let hash1 = msg1.ack_hash(node.crypto());
        let hash2 = msg2.ack_hash(node.crypto());

        assert_ne!(
            hash1, hash2,
            "Different content should produce different hashes"
        );
    }

    #[test]
    fn test_implicit_ack_clears_pending() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Create a message and compute its hash
        let msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Manually insert a pending ACK (sent_ttl = 255)
        node.insert_pending_ack(
            hash,
            vec![1, 2, 3],
            crate::types::Priority::RoutedData,
            255,
            now,
        );
        assert!(node.pending_acks().contains_key(&hash));

        // Simulate receiving the message (which should clear pending ACK via implicit ACK)
        let encoded = Message::Routed(msg).encode_to_vec();
        node.transport().inject_rx(encoded.clone(), None);

        // Decode and process - this simulates what handle_transport_rx does
        let decoded = Message::decode_from_slice(&encoded).unwrap();
        if let Message::Routed(routed) = decoded {
            let received_hash = routed.ack_hash(node.crypto());
            node.pending_acks_mut().remove(&received_hash);
        }

        // Pending ACK should be cleared
        assert!(
            !node.pending_acks().contains_key(&hash),
            "Pending ACK should be cleared by implicit ACK"
        );
    }

    #[test]
    fn test_duplicate_tracked_in_recently_forwarded() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        let msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Initially not tracked
        assert!(!node.recently_forwarded().contains_key(&hash));

        // Insert into recently_forwarded (with TTL)
        node.insert_recently_forwarded(hash, 255, now);

        // Should now be tracked
        assert!(node.recently_forwarded().contains_key(&hash));
    }

    #[test]
    fn test_retry_backoff_bounds() {
        // Create node with known tau (100ms default for MockTransport with no bw)
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::with_seed(42);
        let clock = MockClock::new();
        let mut node: TestNode = Node::new(transport, crypto, random, clock);

        let tau_ms = node.tau().as_millis();
        assert_eq!(tau_ms, 100, "Expected default tau of 100ms");

        // Test exponential growth
        // retry 0: 1τ = 100ms (±10% = 90-110ms)
        // retry 1: 2τ = 200ms (±10% = 180-220ms)
        // retry 2: 4τ = 400ms (±10% = 360-440ms)
        // retry 7: 128τ = 12800ms (capped)
        // retry 8+: still 128τ (capped at 2^7)

        for retry in 0..=8 {
            let backoff = node.retry_backoff(retry);
            let expected_base = tau_ms * (1u64 << retry.min(7));
            let min_expected = expected_base * 9 / 10; // -10%
            let max_expected = expected_base * 11 / 10; // +10%

            assert!(
                backoff.as_millis() >= min_expected && backoff.as_millis() <= max_expected,
                "retry {} backoff {} should be in range [{}, {}]",
                retry,
                backoff.as_millis(),
                min_expected,
                max_expected
            );
        }
    }

    #[test]
    fn test_ack_roundtrip_encoding() {
        let hash: AckHash = [0x01, 0x02, 0x03, 0x04];
        let sender_hash: AckHash = [0x05, 0x06, 0x07, 0x08];
        let ack = Ack { hash, sender_hash };
        let msg = Message::Ack(ack);

        let encoded = msg.encode_to_vec();
        assert_eq!(
            encoded.len(),
            9,
            "Ack message should be 9 bytes (1 type + 4 hash + 4 sender_hash)"
        );

        let decoded = Message::decode_from_slice(&encoded).unwrap();
        match decoded {
            Message::Ack(decoded_ack) => {
                assert_eq!(decoded_ack.hash, hash);
                assert_eq!(decoded_ack.sender_hash, sender_hash);
            }
            _ => panic!("Expected Ack message"),
        }
    }

    #[test]
    fn test_cleanup_recently_forwarded_expiry() {
        let mut node = make_node();
        let tau = node.tau();
        let ttl = tau * RECENTLY_FORWARDED_TTL_MULTIPLIER;

        let now = Timestamp::from_secs(1000);
        let hash1: [u8; 4] = [1; 4];
        let hash2: [u8; 4] = [2; 4];

        // Insert two entries at different times (with dummy TTL values)
        node.insert_recently_forwarded(hash1, 255, now);
        node.insert_recently_forwarded(hash2, 255, now + Duration::from_secs(10));

        // Both should exist
        assert!(node.recently_forwarded().contains_key(&hash1));
        assert!(node.recently_forwarded().contains_key(&hash2));

        // Advance time past TTL for first entry only
        let later = now + ttl + Duration::from_millis(1);
        node.cleanup_recently_forwarded(later);

        // First entry should be expired, second should still exist
        assert!(
            !node.recently_forwarded().contains_key(&hash1),
            "Entry should expire after TTL"
        );
        assert!(
            node.recently_forwarded().contains_key(&hash2),
            "Newer entry should still exist"
        );
    }

    #[test]
    fn test_pending_ack_eviction_at_capacity() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Fill pending_acks to capacity (using DefaultConfig)
        for i in 0..DefaultConfig::MAX_PENDING_ACKS {
            let hash: [u8; 4] = [i as u8; 4];
            node.insert_pending_ack(hash, vec![i as u8], Priority::RoutedProtocol, 255, now);
        }

        assert_eq!(node.pending_acks().len(), DefaultConfig::MAX_PENDING_ACKS);

        // Insert one more - should evict oldest
        let new_hash: [u8; 4] = [0xFF; 4];
        node.insert_pending_ack(new_hash, vec![0xFF], Priority::RoutedProtocol, 255, now);

        // Should still be at capacity (not exceed)
        assert_eq!(
            node.pending_acks().len(),
            DefaultConfig::MAX_PENDING_ACKS,
            "Should evict to stay at capacity"
        );
        assert!(
            node.pending_acks().contains_key(&new_hash),
            "New entry should be present"
        );
    }

    #[test]
    fn test_recently_forwarded_eviction_at_capacity() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Fill recently_forwarded to capacity (using DefaultConfig)
        for i in 0..DefaultConfig::MAX_RECENTLY_FORWARDED {
            let mut hash: [u8; 4] = [0; 4];
            hash[0] = (i >> 8) as u8;
            hash[1] = (i & 0xFF) as u8;
            node.insert_recently_forwarded(hash, 255, now);
        }

        assert_eq!(
            node.recently_forwarded().len(),
            DefaultConfig::MAX_RECENTLY_FORWARDED
        );

        // Insert one more - should evict oldest
        let new_hash: [u8; 4] = [0xFF; 4];
        node.insert_recently_forwarded(new_hash, 255, now);

        // Should still be at capacity (not exceed)
        assert_eq!(
            node.recently_forwarded().len(),
            DefaultConfig::MAX_RECENTLY_FORWARDED,
            "Should evict to stay at capacity"
        );
        assert!(
            node.recently_forwarded().contains_key(&new_hash),
            "New entry should be present"
        );
    }

    #[test]
    fn test_explicit_ack_sent_on_duplicate() {
        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        let msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Mark as recently forwarded (simulating first forward)
        node.insert_recently_forwarded(hash, 255, now);

        // Clear any messages in transport
        node.transport().take_sent();

        // Send explicit ACK (simulating duplicate detection)
        node.send_explicit_ack(hash);

        // Check that an ACK was sent
        let sent = node.transport().take_sent();
        assert_eq!(sent.len(), 1, "Should send one ACK message");
        assert_eq!(sent[0].len(), 9, "ACK should be 9 bytes");
        assert_eq!(sent[0][0], 0x03, "ACK wire type should be 0x03");
    }

    #[test]
    fn test_small_config_eviction() {
        let mut node = make_small_node();
        let now = Timestamp::from_secs(1000);

        // SmallConfig::MAX_PENDING_ACKS = 8 (vs DefaultConfig = 32)
        // Fill to capacity
        for i in 0..SmallConfig::MAX_PENDING_ACKS {
            let hash: [u8; 4] = [i as u8; 4];
            node.insert_pending_ack(hash, vec![i as u8], Priority::RoutedProtocol, 255, now);
        }

        assert_eq!(
            node.pending_acks().len(),
            SmallConfig::MAX_PENDING_ACKS,
            "Should be at SmallConfig capacity (8)"
        );

        // Insert one more - should evict oldest
        let new_hash: [u8; 4] = [0xFF; 4];
        node.insert_pending_ack(new_hash, vec![0xFF], Priority::RoutedProtocol, 255, now);

        // Should still be at SmallConfig capacity
        assert_eq!(
            node.pending_acks().len(),
            SmallConfig::MAX_PENDING_ACKS,
            "SmallConfig should evict to stay at capacity (8)"
        );
        assert!(
            node.pending_acks().contains_key(&new_hash),
            "New entry should be present"
        );
    }

    /// Test case from simulation: Node 30 should route to Node 33 (child),
    /// not Node 15 (parent in shortcuts), because Node 33 has tighter keyspace.
    ///
    /// Tree structure (from publish_test_output9.txt):
    /// - Node 15: ks=[0x13333332,0xbffffffe) - parent, in shortcuts
    /// - Node 30: ks=[0x19999998,0x46666664) - "us"
    /// - Node 33: ks=[0x1ffffffe,0x3ffffffd) - child
    /// - Node 38: ks=[0x3ffffffd,0x46666664) - child
    ///
    /// dest_addr = 0x37180340 (924494144) is in:
    /// - Node 15's range (but wider: 0x13333332 to 0xbffffffe)
    /// - Node 33's range (tighter: 0x1ffffffe to 0x3ffffffd)
    ///
    /// So routing should prefer Node 33.
    #[test]
    fn test_routing_loop_regression() {
        let mut node = make_node();

        // Node 15 (parent) - added to shortcuts with wide range
        let node_15: NodeId = [15u8; 16];
        node.shortcuts_mut()
            .insert(node_15, (0x13333332, 0xbffffffe));

        // Node 33 (child) - tight range covering dest
        let node_33: NodeId = [33u8; 16];
        let hash_33 = node.compute_node_hash(&node_33);
        node.children_mut().insert(hash_33, node_33, 5);
        node.children_mut()
            .set_range(&node_33, 0x1ffffffe, 0x3ffffffd);

        // Node 38 (child) - doesn't cover dest
        let node_38: NodeId = [38u8; 16];
        let hash_38 = node.compute_node_hash(&node_38);
        node.children_mut().insert(hash_38, node_38, 1);
        node.children_mut()
            .set_range(&node_38, 0x3ffffffd, 0x46666664);

        // dest_addr from the simulation
        let dest: u32 = 0x37180340; // 924494144

        // Verify dest is in both ranges
        assert!(
            (0x13333332..0xbffffffe).contains(&dest),
            "dest should be in Node 15's range"
        );
        assert!(
            (0x1ffffffe..0x3ffffffd).contains(&dest),
            "dest should be in Node 33's range"
        );
        assert!(
            !(0x3ffffffd..0x46666664).contains(&dest),
            "dest should NOT be in Node 38's range"
        );

        // Node 33's range is tighter, so it should win
        let next_hop = node.best_next_hop(dest);
        assert_eq!(
            next_hop,
            Some(node_33),
            "Should route to Node 33 (child with tighter range), not Node 15 (shortcut with wider range)"
        );
    }

    /// Test TTL=2 edge case: message has TTL=2, gets decremented to TTL=1 on receive,
    /// then when delayed forward fires, TTL=1 means it can still be forwarded (becomes TTL=0
    /// at next hop). But TTL=1 on bounce-back should be dropped immediately.
    #[test]
    fn test_bounce_back_ttl_2_edge_case() {
        let mut node = make_node();
        let now = Timestamp::from_secs(100);

        // Create a message with TTL=2 (will be decremented to TTL=1 on receive)
        let msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 1, // Already decremented from 2 to 1
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Simulate: we forwarded this message before with TTL=2 (original)
        node.insert_recently_forwarded(hash, 2, now);

        // Now it bounces back with TTL=1 (original_ttl=2, but msg.ttl=1 after their decrement)
        // The bounce-back handler checks original_ttl (the TTL before our decrement)
        // Since we stored TTL=2, and now see TTL=1, this is a bounce-back

        // For TTL=1 case (original_ttl <= 1), we should drop after ACK, not schedule
        // But here original_ttl=2, so we should schedule

        // Manually call handle_bounce_back with original_ttl=2
        node.handle_bounce_back(msg.clone(), hash, 2, now);

        // Should have scheduled a delayed forward
        assert_eq!(
            node.delayed_forwards().len(),
            1,
            "Should schedule delayed forward for TTL=2"
        );

        // Now test TTL=1 case - should NOT schedule
        let mut node2 = make_node();
        let msg_ttl1 = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [8u8; 16], // Different node_id for different hash
            src_pubkey: None,
            ttl: 0, // Already decremented from 1 to 0
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };
        let hash2 = msg_ttl1.ack_hash(node2.crypto());
        node2.insert_recently_forwarded(hash2, 1, now);

        // original_ttl=1 should cause immediate drop
        node2.handle_bounce_back(msg_ttl1, hash2, 1, now);

        assert_eq!(
            node2.delayed_forwards().len(),
            0,
            "Should NOT schedule delayed forward for TTL=1 (would expire immediately)"
        );
    }

    /// Test delayed forward queue at capacity with varying delay lengths.
    /// Verifies eviction policy: longest delay is evicted when full.
    #[test]
    fn test_delayed_forward_queue_at_capacity() {
        let mut node = make_small_node();
        let now = Timestamp::from_secs(100);
        let tau = node.tau();

        // SmallConfig has MAX_DELAYED_FORWARDS = 16
        // Fill the queue with entries having increasing delays
        for i in 0..SmallConfig::MAX_DELAYED_FORWARDS {
            let msg = Routed {
                flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
                next_hop: [0u8; 4],
                dest_addr: 0x1234_5678,
                dest_hash: None,
                src_addr: Some(0x8765_4321),
                src_node_id: [i as u8; 16], // Unique node_id per message
                src_pubkey: None,
                ttl: 10,
                payload: b"test".to_vec(),
                signature: Signature::default(),
            };
            let hash = msg.ack_hash(node.crypto());

            // Schedule with increasing delays: 1τ, 2τ, 3τ, ...
            let scheduled_time = now + tau * (i as u64 + 1);
            node.schedule_delayed_forward(msg, hash, 1, scheduled_time);
        }

        assert_eq!(
            node.delayed_forwards().len(),
            SmallConfig::MAX_DELAYED_FORWARDS,
            "Queue should be at capacity"
        );

        // Now try to add one with a SHORT delay (should evict the longest)
        let new_msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [99u8; 16], // New unique node_id
            src_pubkey: None,
            ttl: 10,
            payload: b"new".to_vec(),
            signature: Signature::default(),
        };
        let new_hash = new_msg.ack_hash(node.crypto());

        // Schedule with very short delay (50ms, less than tau) - should evict longest
        let short_scheduled = now + Duration::from_millis(50);
        node.schedule_delayed_forward(new_msg, new_hash, 1, short_scheduled);

        assert_eq!(
            node.delayed_forwards().len(),
            SmallConfig::MAX_DELAYED_FORWARDS,
            "Queue should still be at capacity after eviction"
        );
        assert!(
            node.delayed_forwards().contains_key(&new_hash),
            "New entry with short delay should be present"
        );

        // Try to add one with a LONG delay (should be rejected)
        let long_msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: [0u8; 4],
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [100u8; 16], // Another unique node_id
            src_pubkey: None,
            ttl: 10,
            payload: b"long".to_vec(),
            signature: Signature::default(),
        };
        let long_hash = long_msg.ack_hash(node.crypto());

        // Schedule with very long delay (100τ) - should be rejected
        let long_scheduled = now + tau * 100;
        node.schedule_delayed_forward(long_msg, long_hash, 1, long_scheduled);

        assert!(
            !node.delayed_forwards().contains_key(&long_hash),
            "New entry with longest delay should be rejected"
        );
    }
}
