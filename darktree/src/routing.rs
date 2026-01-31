//! Message routing based on keyspace addressing.
//!
//! Routing uses keyspace ranges where each node owns a contiguous range
//! [keyspace_lo, keyspace_hi). Messages route toward dest_addr by forwarding
//! to the neighbor whose range contains the destination with the tightest fit.

use alloc::vec::Vec;

use crate::config::NodeConfig;
#[cfg(feature = "debug")]
use crate::debug::HasDebugEmitter;
use crate::node::{AckHash, Node};
use crate::time::{Duration, Timestamp};
use crate::traits::{Ackable, Clock, Crypto, Outgoing, Random, Transport};
use crate::types::{
    Error, IdHash, NodeId, Routed, Signature, MSG_DATA, MSG_FOUND, MSG_LOOKUP, MSG_PUBLISH,
};
use crate::wire::{routed_sign_data, Ack};

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

        // Store original hops before incrementing (for duplicate detection).
        // "original_hops" = the hops value when we first received this message,
        // before we increment it for our own processing.
        let original_hops = msg.hops;

        // Decrement TTL and increment hops for forwarding
        msg.ttl = msg.ttl.saturating_sub(1);
        msg.hops = msg.hops.saturating_add(1);

        let dest = msg.dest_addr;
        let msg_type = msg.msg_type();
        let ack_hash = msg.ack_hash(self.crypto());

        // Compute addressing info upfront for routing decisions
        let my_hash = self.compute_id_hash(self.node_id());
        let is_for_me = msg.next_hop == Some(my_hash);
        let i_own_dest = self.owns_key(dest);

        // === Opportunistic Receipt ===
        // For PUBLISH/LOOKUP: if we own the keyspace but weren't the designated forwarder,
        // handle locally anyway. This improves reliability during tree restructuring.
        // We check this BEFORE the normal ownership path to handle the case where we
        // overheard a message not addressed to us but destined for our keyspace.
        let is_keyspace_targeted = msg_type == MSG_PUBLISH || msg_type == MSG_LOOKUP;

        if is_keyspace_targeted && !is_for_me && i_own_dest {
            // We overheard a message destined for our keyspace
            // Add to recently_forwarded to prevent duplicate processing
            if self.recently_forwarded().contains_key(&ack_hash) {
                return; // Already handled
            }
            self.insert_recently_forwarded(ack_hash, original_hops, msg.ttl, now);

            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedOpportunistic {
                    payload_hash: msg.payload_hash(self.crypto()),
                    msg_type,
                    dest_addr: dest,
                }
            );

            // Handle locally (but don't forward - we weren't designated)
            self.dispatch_routed(msg, now);
            return;
        }

        // Do I own this keyspace location and am I the designated forwarder?
        if i_own_dest {
            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedDelivered {
                    payload_hash: msg.payload_hash(self.crypto()),
                    msg_type,
                    dest_addr: dest,
                    from: msg.src_node_id,
                }
            );
            // Handle locally based on message type
            self.dispatch_routed(msg, now);
            return;
        }

        // Am I the intended forwarder? If not, ignore silently.
        // This prevents amplification attacks where multiple nodes forward the same message.
        if !is_for_me {
            return;
        }

        // Not for us - verify signature before forwarding to prevent bandwidth waste
        if self.verify_routed_signature(&msg, now).is_none() {
            // Can't verify signature (no pubkey or invalid) - drop
            return;
        }

        // Duplicate detection: check if we've recently forwarded this message
        // Note: ack_hash excludes TTL/hops so it's the same at any hop
        if let Some(&(_stored_time, stored_hops, _, _stored_ttl)) =
            self.recently_forwarded().get(&ack_hash)
        {
            if stored_hops == original_hops {
                // Same hops = retransmission from sender who didn't hear our forward
                // Send explicit ACK to confirm we received and forwarded it
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::RoutedDuplicate {
                        payload_hash: msg.payload_hash(self.crypto()),
                        msg_type,
                        dest_addr: dest,
                        original_hops,
                        stored_hops,
                        action: "ack_retransmit",
                    }
                );
                self.send_explicit_ack(ack_hash);
                return;
            }
            // Different hops = message looped back to us, schedule delayed retry
            // with exponential backoff to let tree routing stabilize
            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedDuplicate {
                    payload_hash: msg.payload_hash(self.crypto()),
                    msg_type,
                    dest_addr: dest,
                    original_hops,
                    stored_hops,
                    action: "bounce_back",
                }
            );
            self.handle_bounce_back(msg, ack_hash, original_hops, now);
            return;
        }

        // Not a duplicate - forward and track with hops and TTL
        self.insert_recently_forwarded(ack_hash, original_hops, msg.ttl, now);
        let _ = self.route_message(msg, now);
    }

    /// Send an explicit ACK for a message hash.
    ///
    /// Used when we receive a duplicate message - the sender is waiting for confirmation
    /// that we received it, so we send a minimal ACK instead of re-forwarding.
    pub(crate) fn send_explicit_ack(&mut self, hash: AckHash) {
        use crate::wire::Message;

        let sender_hash = self.compute_id_hash(self.node_id());
        let ack = Ack { hash, sender_hash };
        let msg = Message::Ack(ack);

        // ACK is small (9 bytes) so MTU check is unlikely to fail, but be safe
        if Outgoing::encode(&msg).len() > self.transport().mtu() {
            return;
        }

        if self.transport().outgoing().try_send(msg) {
            self.record_protocol_sent();
        }
        // Don't track drops for ACKs - they're best-effort
    }

    /// Handle a bounce-back: message returned with different hops during tree restructuring.
    ///
    /// Instead of dropping, we delay and retry with exponential backoff, giving the tree
    /// time to stabilize. Uses the same timing as ACK retransmits (1τ, 2τ, ..., 128τ) and
    /// gives up after MAX_RETRIES attempts.
    ///
    /// # Hops Terminology
    ///
    /// - `incoming_hops`: The hops value on the message we just received (after our increment)
    /// - `stored_hops`: The hops value we recorded when we first forwarded this message
    /// - When `incoming_hops != stored_hops`, the message has bounced (routing loop)
    ///
    /// We restore `msg.hops` to `stored_hops` before retrying so future duplicate detection
    /// can distinguish retransmissions from new bounces.
    fn handle_bounce_back(
        &mut self,
        mut msg: Routed,
        ack_hash: AckHash,
        incoming_hops: u32,
        now: Timestamp,
    ) {
        use crate::types::{MAX_RETRIES, RECENTLY_FORWARDED_TTL_MULTIPLIER};

        // Always ACK upstream so they don't retry while we delay (or drop)
        self.send_explicit_ack(ack_hash);

        // TTL check: if TTL is already 0 after decrement, drop
        // Note: msg.ttl is already decremented in handle_routed
        if msg.ttl == 0 {
            return;
        }

        // Clear our own pending_ack if present (bounce proves downstream heard us)
        self.pending_acks_mut().remove(&ack_hash);

        // Update recently_forwarded entry: increment seen_count and refresh expiration.
        // Keep the stored_hops and stored_ttl unchanged - they're from our first forward.
        let (seen_count, stored_hops, stored_ttl) =
            if let Some(entry) = self.recently_forwarded_mut().get_mut(&ack_hash) {
                entry.0 = now; // Refresh timestamp
                let hops_on_first_forward = entry.1; // Preserve for duplicate detection
                entry.2 = entry.2.saturating_add(1); // Increment seen_count
                let ttl_on_first_forward = entry.3; // Preserve for TTL restoration
                (entry.2, hops_on_first_forward, ttl_on_first_forward)
            } else {
                // Entry was evicted - recreate with current values as best guess
                self.insert_recently_forwarded(ack_hash, incoming_hops, msg.ttl, now);
                (1, incoming_hops, msg.ttl)
            };

        // Give up after MAX_RETRIES, same as ACK timeout behavior
        if seen_count > MAX_RETRIES {
            return;
        }

        // Restore hops and TTL to stored values so duplicate detection works correctly on retry.
        // TTL is restored to the value when we first forwarded - bounce-backs are retransmission
        // attempts, not forward progress, so TTL only decrements for actual routing advancement.
        msg.hops = stored_hops;
        msg.ttl = stored_ttl;

        // Schedule delayed forward with exponential backoff
        // Backoff: 1τ, 2τ, 4τ, 8τ, ..., capped at 128τ (same as ACK retransmit timing)
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

        emit_debug!(
            self,
            crate::debug::DebugEvent::BounceBackScheduled {
                payload_hash: msg.payload_hash(self.crypto()),
                msg_type: msg.msg_type(),
                dest_addr: msg.dest_addr,
                seen_count,
                delay_ms: delay.as_millis(),
            }
        );

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
    /// For each ready entry: recompute route and forward if TTL permits.
    /// Uses `route_message()` which handles routing and queuing.
    ///
    /// If the outgoing queue is full, re-schedules the message for 2τ later
    /// instead of losing it.
    pub(crate) fn handle_delayed_forwards(&mut self, now: Timestamp) {
        // Collect ready keys (cheap 4-byte AckHash copies)
        let ready_keys: Vec<_> = self
            .delayed_forwards()
            .iter()
            .filter(|(_, df)| now >= df.scheduled_time)
            .map(|(k, _)| *k)
            .collect();

        let tau = self.tau();

        for ack_hash in ready_keys {
            // Get entry info without removing yet
            let Some(entry) = self.delayed_forwards().get(&ack_hash) else {
                continue;
            };

            // TTL was already decremented when message was received
            if entry.msg.ttl == 0 {
                self.delayed_forwards_mut().remove(&ack_hash);
                continue;
            }

            // Clone msg for sending (entry stays in map until success)
            let msg = entry.msg.clone();

            emit_debug!(
                self,
                crate::debug::DebugEvent::DelayedForwardExecuted {
                    payload_hash: msg.payload_hash(self.crypto()),
                    msg_type: msg.msg_type(),
                    dest_addr: msg.dest_addr,
                    ttl: msg.ttl,
                    has_route: self.route_to(msg.dest_addr).is_some(),
                }
            );

            // Try to route
            match self.route_message(msg, now) {
                Ok(()) => {
                    // Success - remove from map
                    self.delayed_forwards_mut().remove(&ack_hash);
                }
                Err(Error::QueueFull) => {
                    // Queue full - reschedule for τ + jitter (entry stays in map)
                    // Jitter prevents thundering herd when multiple nodes retry together
                    let jitter_ms = self.random_mut().gen_range(0, tau.as_millis());
                    if let Some(entry) = self.delayed_forwards_mut().get_mut(&ack_hash) {
                        entry.scheduled_time = now + tau + Duration::from_millis(jitter_ms);
                    }
                }
                Err(_) => {
                    // Other error (e.g., MessageTooLarge) - remove, can't recover
                    self.delayed_forwards_mut().remove(&ack_hash);
                }
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
            Some(dest_hash) => dest_hash == self.compute_id_hash(self.node_id()),
            None => true, // No dest_hash to verify
        }
    }

    /// Find the best next hop for a destination keyspace address.
    ///
    /// Returns the same-tree neighbor (from neighbor_times) whose keyspace range:
    /// 1. Contains the destination address
    /// 2. Has the tightest range (smallest hi - lo)
    ///
    /// Uses pulse-reported keyspace_range from neighbor_times for all neighbors,
    /// filtering by same tree (root_hash). Parent is excluded (fallback only).
    ///
    /// Note: After a child joins and we assign them a new range, there's a brief
    /// window (~3τ) until they pulse back with their updated range. During this
    /// window, routing uses their old range. This is acceptable - messages will
    /// still route correctly via parent fallback, and the window is short.
    fn best_next_hop(&self, dest: u32) -> Option<NodeId> {
        let mut best: Option<(NodeId, u64)> = None; // (node_id, range_size)
        let my_root = *self.root_hash();

        // Check all same-tree neighbors (ranges from their pulses)
        for (neighbor_id, timing) in self.neighbor_times() {
            // Skip parent (fallback only) and different trees
            if self.parent() == Some(*neighbor_id) {
                continue;
            }
            if timing.root_hash != my_root {
                continue;
            }

            let (lo, hi) = timing.keyspace_range;
            if dest >= lo && dest < hi {
                let range_size = (hi as u64).saturating_sub(lo as u64);
                if best.map_or(true, |(_, best_size)| range_size < best_size) {
                    best = Some((*neighbor_id, range_size));
                    // Early exit: can't find a tighter range than size 1
                    if range_size == 1 {
                        return best.map(|(id, _)| id);
                    }
                }
            }
        }

        best.map(|(node_id, _)| node_id)
    }

    /// Get what we believe a neighbor's keyspace range is (from their last pulse).
    /// Debug-only helper for routing decision logging.
    #[cfg(feature = "debug")]
    fn believed_keyspace(&self, id: &NodeId) -> (u32, u32) {
        self.neighbor_times()
            .get(id)
            .map(|t| t.keyspace_range)
            .unwrap_or((0, 0))
    }

    /// Single source of truth for routing decisions.
    ///
    /// Returns (NodeId, IdHash) for the next hop, or None if no route available.
    /// Tries child/shortcut routing first. Falls back to parent only if dest is
    /// OUTSIDE our subtree keyspace. If dest is inside our subtree but no child
    /// covers it yet (stale keyspace info), returns None so caller can queue.
    fn route_to(&self, dest: u32) -> Option<(NodeId, IdHash)> {
        if let Some(id) = self.best_next_hop(dest) {
            #[cfg(feature = "debug")]
            if self.has_emitter() {
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::RoutingDecision {
                        dest_addr: dest,
                        selected: id,
                        believed_keyspace: self.believed_keyspace(&id),
                        is_parent_fallback: false,
                    }
                );
            }
            return Some((id, self.compute_id_hash(&id)));
        }

        // No child/shortcut covers dest. Check if dest is in our subtree keyspace.
        // If yes, we should queue rather than bounce to parent (child hasn't pulsed yet).
        // If no, dest is outside our subtree and we should route up to parent.
        let (ks_lo, ks_hi) = self.keyspace_range();
        let in_subtree = (dest as u64) >= (ks_lo as u64) && (dest as u64) < (ks_hi as u64);

        if in_subtree && !self.owns_key(dest) {
            // Dest is in our subtree but we don't own it personally, and no child
            // has pulsed with a range covering it. Queue for retry when child pulses.
            return None;
        }

        if let Some(id) = self.parent() {
            #[cfg(feature = "debug")]
            if self.has_emitter() {
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::RoutingDecision {
                        dest_addr: dest,
                        selected: id,
                        believed_keyspace: self.believed_keyspace(&id),
                        is_parent_fallback: true,
                    }
                );
            }
            return Some((id, self.compute_id_hash(&id)));
        }
        None
    }

    /// Record a sent message, categorizing by app vs protocol traffic.
    fn record_routed_sent(&mut self, is_app_data: bool) {
        if is_app_data {
            self.record_app_sent();
        } else {
            self.record_protocol_sent();
        }
    }

    /// Record a dropped message, categorizing by app vs protocol traffic.
    fn record_routed_dropped(&mut self, is_app_data: bool) {
        if is_app_data {
            self.record_app_dropped();
        } else {
            self.record_protocol_dropped();
        }
    }

    /// Low-level transmission with ACK tracking.
    ///
    /// Requires that `msg.next_hop` is set before calling.
    /// Always tracks ACK for retransmission. Derives is_app_data from msg_type.
    /// Returns error if message too large or queue full.
    fn transmit_with_ack(&mut self, msg: Routed, now: Timestamp) -> Result<(), Error> {
        use crate::wire::Message;

        let is_app_data = msg.msg_type() == MSG_DATA;
        let ack_hash = msg.ack_hash(self.crypto());
        let sent_ttl = msg.ttl;

        // Extract debug info before moving msg
        let msg_type = msg.msg_type();
        let dest_addr = msg.dest_addr;
        #[cfg(feature = "debug")]
        let payload_hash = msg.payload_hash(self.crypto());

        // Wrap once, reuse for priority, encode, and send
        let wrapped = Message::Routed(msg);
        let priority = Outgoing::priority(&wrapped);
        let encoded = Outgoing::encode(&wrapped);

        if encoded.len() > self.transport().mtu() {
            self.record_routed_dropped(is_app_data);
            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedDropped {
                    payload_hash,
                    msg_type,
                    dest_addr,
                    error: Error::MessageTooLarge,
                }
            );
            return Err(Error::MessageTooLarge);
        }

        // Always track ACK for retransmission
        self.insert_pending_ack(ack_hash, encoded, priority, sent_ttl, now);

        if self.transport().outgoing().try_send(wrapped) {
            self.record_routed_sent(is_app_data);
            Ok(())
        } else {
            self.pending_acks_mut().remove(&ack_hash);
            self.record_routed_dropped(is_app_data);
            emit_debug!(
                self,
                crate::debug::DebugEvent::OutgoingQueueFull {
                    payload_hash,
                    msg_type,
                    dest_addr,
                }
            );
            Err(Error::QueueFull)
        }
    }

    /// Dispatch a routed message to the appropriate handler based on msg_type.
    ///
    /// This is the single point of message type dispatch, used by:
    /// - handle_routed (for delivered and opportunistic messages)
    /// - route_message (when we now own the destination)
    fn dispatch_routed(&mut self, msg: Routed, now: Timestamp) {
        match msg.msg_type() {
            MSG_PUBLISH => self.handle_publish(msg, now),
            MSG_LOOKUP => self.handle_lookup_msg(msg, now),
            MSG_FOUND => self.handle_found(msg, now),
            MSG_DATA => self.handle_data(msg, now),
            _ => {} // Unknown type, drop silently
        }
    }

    /// Unified routing for all cases: originate, forward, delayed, retry.
    ///
    /// Checks ownership first (keyspace may have changed), then routes via
    /// route_to() or queues if no route available.
    fn route_message(&mut self, msg: Routed, now: Timestamp) -> Result<(), Error> {
        let dest = msg.dest_addr;

        // Check if we (now) own the destination
        // Keyspace changes during tree formation, so always check
        if self.owns_key(dest) {
            self.dispatch_routed(msg, now);
            return Ok(());
        }

        // Try to find a route
        #[allow(unused_variables)] // next_hop_id only used in debug builds
        if let Some((next_hop_id, next_hop_hash)) = self.route_to(dest) {
            // Emit forwarding debug event
            #[cfg(feature = "debug")]
            {
                let direction = if self.parent() == Some(next_hop_id) {
                    "up"
                } else {
                    "down"
                };
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::RoutedForwarded {
                        payload_hash: msg.payload_hash(self.crypto()),
                        msg_type: msg.msg_type(),
                        dest_addr: dest,
                        next_hop: next_hop_id,
                        ttl: msg.ttl,
                        my_keyspace: self.keyspace_range(),
                        direction,
                    }
                );
            }

            let mut msg = msg;
            msg.next_hop = Some(next_hop_hash);
            self.transmit_with_ack(msg, now)
        } else {
            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedQueued {
                    payload_hash: msg.payload_hash(self.crypto()),
                    msg_type: msg.msg_type(),
                    dest_addr: dest,
                }
            );
            self.queue_pending_routed(msg);
            Ok(())
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
        let dest_hash = self.compute_id_hash(&target);

        let msg = self.build_routed(dest_addr, Some(dest_hash), MSG_DATA, payload);
        self.send_routed(msg)
    }

    /// Build a Routed message with optional dest_hash for verification.
    pub(crate) fn build_routed(
        &mut self,
        dest_addr: u32,
        dest_hash: Option<IdHash>,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> Routed {
        // Include src_addr for messages expecting replies (DATA, LOOKUP)
        self.build_routed_inner(dest_addr, dest_hash, msg_type, payload, true, false)
    }

    /// Build a Routed message that doesn't expect a reply (PUBLISH, FOUND).
    /// No src_addr (saves 4 bytes). Set force_pubkey=true for PUBLISH (distant nodes need it).
    pub(crate) fn build_routed_no_reply(
        &mut self,
        dest_addr: u32,
        dest_hash: Option<IdHash>,
        msg_type: u8,
        payload: Vec<u8>,
        force_pubkey: bool,
    ) -> Routed {
        self.build_routed_inner(dest_addr, dest_hash, msg_type, payload, false, force_pubkey)
    }

    /// Internal helper to build Routed messages.
    fn build_routed_inner(
        &mut self,
        dest_addr: u32,
        dest_hash: Option<IdHash>,
        msg_type: u8,
        payload: Vec<u8>,
        include_src_addr: bool,
        force_pubkey: bool,
    ) -> Routed {
        let include_pubkey = force_pubkey || !self.neighbors_need_pubkey().is_empty();

        let flags_and_type = Routed::build_flags_and_type(
            msg_type,
            dest_hash.is_some(),
            include_src_addr,
            include_pubkey,
        );

        // Compute initial next_hop based on routing decision
        // Uses route_to() which is the single source of truth
        let next_hop = self.route_to(dest_addr).map(|(_, hash)| hash);

        let mut msg = Routed {
            flags_and_type,
            next_hop,
            dest_addr,
            dest_hash,
            src_addr: if include_src_addr {
                Some(self.my_address())
            } else {
                None
            },
            src_node_id: *self.node_id(),
            src_pubkey: if include_pubkey {
                Some(*self.pubkey())
            } else {
                None
            },
            // TTL = max_depth * 3 allows messages to traverse the tree and return.
            // Minimum of 255 (old u8 max) ensures messages can route during tree formation
            // when max_depth may not yet reflect the true network depth.
            ttl: self.max_depth().saturating_mul(3).max(255),
            hops: 0,
            payload,
            signature: Signature::default(),
        };

        let sign_data = routed_sign_data(&msg);
        msg.signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        msg
    }

    /// Send a Routed message (for originated messages).
    ///
    /// Thin wrapper that emits RoutedSent debug event, then delegates to route_message().
    /// All messages now track ACK for retransmission.
    pub(crate) fn send_routed(&mut self, msg: Routed) -> Result<(), Error> {
        emit_debug!(
            self,
            crate::debug::DebugEvent::RoutedSent {
                payload_hash: msg.payload_hash(self.crypto()),
                msg_type: msg.msg_type(),
                dest_addr: msg.dest_addr,
                ttl: msg.ttl,
            }
        );

        let now = self.now();
        self.route_message(msg, now)
    }

    /// Queue a routed message for later retry when no route is available.
    ///
    /// Used by roots when a child hasn't yet pulsed with their assigned keyspace range.
    fn queue_pending_routed(&mut self, msg: Routed) {
        use crate::node::PendingRouted;

        let now = self.now();

        // Evict oldest if at capacity (O(1) with VecDeque)
        if self.pending_routed().len() >= Cfg::MAX_PENDING_ROUTED {
            #[allow(unused_variables)] // evicted only used in debug builds
            if let Some(evicted) = self.pending_routed_mut().pop_front() {
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::RoutedEvicted {
                        payload_hash: evicted.msg.payload_hash(self.crypto()),
                        msg_type: evicted.msg.msg_type(),
                        dest_addr: evicted.msg.dest_addr,
                    }
                );
            }
        }

        self.pending_routed_mut().push_back(PendingRouted {
            msg,
            queued_at: now,
        });
        // Retry is scheduled when neighbors pulse (see handle_pulse -> schedule_pending_retry).
    }

    /// Re-check ONE pending routed message.
    ///
    /// Returns true if more messages remain to be checked.
    /// Called incrementally with 2τ delay between calls to spread traffic.
    ///
    /// If the outgoing queue is full, puts the message back for later retry.
    pub(crate) fn retry_one_pending(&mut self, now: Timestamp) -> bool {
        use crate::node::PendingRouted;

        // Pop front (FIFO), or return false if empty
        let Some(p) = self.pending_routed_mut().pop_front() else {
            return false;
        };

        let dest = p.msg.dest_addr;
        let queued_at = p.queued_at;

        // Check if we now own the destination (keyspace may have changed)
        if self.owns_key(dest) {
            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedRetried {
                    payload_hash: p.msg.payload_hash(self.crypto()),
                    msg_type: p.msg.msg_type(),
                    dest_addr: dest,
                }
            );
            self.dispatch_routed(p.msg, now);
            return !self.pending_routed().is_empty();
        }

        // Try to find a route
        if let Some((_next_hop_id, next_hop_hash)) = self.route_to(dest) {
            emit_debug!(
                self,
                crate::debug::DebugEvent::RoutedRetried {
                    payload_hash: p.msg.payload_hash(self.crypto()),
                    msg_type: p.msg.msg_type(),
                    dest_addr: dest,
                }
            );
            let mut msg = p.msg;
            msg.next_hop = Some(next_hop_hash);
            // Clone for potential re-queue (transmit_with_ack consumes msg)
            let msg_backup = msg.clone();
            match self.transmit_with_ack(msg, now) {
                Ok(()) => {} // Success
                Err(Error::QueueFull) => {
                    // Queue full - put back for later retry
                    self.pending_routed_mut().push_back(PendingRouted {
                        msg: msg_backup,
                        queued_at,
                    });
                }
                Err(_) => {} // Other error (e.g., MessageTooLarge) - drop
            }
        } else {
            // Still no route, put back at END of queue (round-robin fairness)
            self.pending_routed_mut().push_back(p);
        }

        !self.pending_routed().is_empty()
    }

    /// Send a BACKUP_PUBLISH broadcast to random neighbors.
    ///
    /// Called after storing a location entry to ensure backup nodes have a copy.
    pub(crate) fn send_backup_publish(&mut self, entry: &crate::types::LocationEntry) {
        use crate::types::{Broadcast, BCAST_PAYLOAD_BACKUP};
        use crate::wire::{broadcast_sign_data, Encode};

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
                let hash = self.compute_id_hash(&neighbor_id);
                destinations.push(hash);
            }
        }

        if destinations.is_empty() {
            return;
        }

        // Build payload: BCAST_PAYLOAD_BACKUP (1 byte) + encoded LocationEntry
        let mut payload = alloc::vec![BCAST_PAYLOAD_BACKUP];
        // LocationEntry encode never fails (no next_hop field to check)
        let entry_bytes = entry
            .encode_to_vec()
            .expect("LocationEntry encode never fails");
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

        use crate::wire::Message;
        let msg = Message::Broadcast(broadcast);

        // Check MTU
        if Outgoing::encode(&msg).len() > self.transport().mtu() {
            return; // Message too large
        }

        // Send via priority queue (backup is protocol traffic - BroadcastBackup priority)
        if self.transport().outgoing().try_send(msg) {
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
    use crate::wire::{Ack, Decode, Message};

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

    /// Helper to insert a neighbor for routing tests.
    /// Sets up neighbor_times entry with same root_hash as the node.
    fn insert_neighbor_for_routing(node: &mut TestNode, id: NodeId, range: (u32, u32)) {
        use crate::node::NeighborTiming;
        let root_hash = *node.root_hash(); // Get before mutable borrow
        node.neighbor_times_mut().insert(
            id,
            NeighborTiming {
                last_seen: Timestamp::ZERO,
                rssi: None,
                root_hash, // Same tree
                tree_size: 1,
                keyspace_range: range,
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
            },
        );
    }

    #[test]
    fn test_best_next_hop_returns_neighbor_in_range() {
        let mut node = make_node();

        // Add a neighbor with keyspace range [1000, 2000)
        let neighbor_id: NodeId = [1u8; 16];
        insert_neighbor_for_routing(&mut node, neighbor_id, (1000, 2000));

        // Destination within neighbor's range should return neighbor
        assert_eq!(node.best_next_hop(1500), Some(neighbor_id));

        // Destination outside any neighbor range should return None
        assert_eq!(node.best_next_hop(500), None);
        assert_eq!(node.best_next_hop(3000), None);
    }

    #[test]
    fn test_best_next_hop_prefers_tighter_range() {
        let mut node = make_node();

        // Add a neighbor with wide range [0, 10000)
        let wide_neighbor: NodeId = [1u8; 16];
        insert_neighbor_for_routing(&mut node, wide_neighbor, (0, 10000));

        // Add a neighbor with tight range [4000, 6000)
        let tight_neighbor: NodeId = [2u8; 16];
        insert_neighbor_for_routing(&mut node, tight_neighbor, (4000, 6000));

        // Destination 5000 is in both ranges - should prefer tighter range
        assert_eq!(node.best_next_hop(5000), Some(tight_neighbor));

        // Destination 1000 is only in wide range
        assert_eq!(node.best_next_hop(1000), Some(wide_neighbor));
    }

    #[test]
    fn test_best_next_hop_multiple_neighbors() {
        let mut node = make_node();

        // Add multiple non-overlapping neighbors
        let neighbor1: NodeId = [1u8; 16];
        let neighbor2: NodeId = [2u8; 16];
        let neighbor3: NodeId = [3u8; 16];

        insert_neighbor_for_routing(&mut node, neighbor1, (0, 1000));
        insert_neighbor_for_routing(&mut node, neighbor2, (1000, 2000));
        insert_neighbor_for_routing(&mut node, neighbor3, (2000, 3000));

        // Each destination should route to correct neighbor
        assert_eq!(node.best_next_hop(500), Some(neighbor1));
        assert_eq!(node.best_next_hop(1500), Some(neighbor2));
        assert_eq!(node.best_next_hop(2500), Some(neighbor3));

        // Outside all ranges
        assert_eq!(node.best_next_hop(5000), None);
    }

    #[test]
    fn test_best_next_hop_ignores_different_tree() {
        let mut node = make_node();

        // Insert neighbor with DIFFERENT root_hash (different tree)
        let other_tree_neighbor: NodeId = [99u8; 16];
        node.neighbor_times_mut().insert(
            other_tree_neighbor,
            crate::node::NeighborTiming {
                last_seen: Timestamp::ZERO,
                rssi: None,
                root_hash: [0xFF, 0xFF, 0xFF, 0xFF], // Different tree
                tree_size: 100,
                keyspace_range: (0, 10000), // Would match dest
                children_count: 0,
                depth: 0,
                max_depth: 0,
                unstable: false,
            },
        );

        // Should return None (no same-tree neighbor matches)
        assert_eq!(node.best_next_hop(5000), None);
    }

    #[test]
    fn test_best_next_hop_ignores_parent() {
        let mut node = make_node();

        // Set up a parent
        let parent_id: NodeId = [10u8; 16];
        node.set_parent(Some(parent_id));

        // Add parent to neighbor_times with a range that contains our destination
        insert_neighbor_for_routing(&mut node, parent_id, (0, 10000));

        // Parent should be skipped (it's fallback only), so no match
        assert_eq!(node.best_next_hop(5000), None);
    }

    #[test]
    fn test_ack_hash_invariant() {
        // Hash should be the same regardless of TTL (routed_sign_data excludes TTL)
        let node = make_node();

        let msg1 = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255, // High TTL
            hops: 0,
            payload: b"test payload".to_vec(),
            signature: Signature::default(),
        };

        let mut msg2 = msg1.clone();
        msg2.ttl = 100; // Different TTL
        msg2.hops = 5; // Different hops

        let hash1 = msg1.ack_hash(node.crypto());
        let hash2 = msg2.ack_hash(node.crypto());

        assert_eq!(
            hash1, hash2,
            "ACK hash should be invariant across TTL and hops values"
        );
    }

    #[test]
    fn test_ack_hash_different_content() {
        // Different message content should produce different hashes
        let node = make_node();

        let msg1 = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            hops: 0,
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
        let next_hop = [0u8; 4];
        let routed = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: Some(next_hop),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            hops: 0,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = routed.ack_hash(node.crypto());

        // Manually insert a pending ACK (sent_ttl = 255)
        node.insert_pending_ack(
            hash,
            vec![1, 2, 3],
            crate::types::Priority::RoutedData,
            255,
            now,
        );
        assert!(node.pending_acks().contains_key(&hash));

        // Simulate receiving the message (encode via Message::Routed, decode via Message)
        let mut routed_with_hop = routed;
        routed_with_hop.next_hop = Some(next_hop);
        let encoded = Outgoing::encode(&Message::Routed(routed_with_hop));
        node.transport().inject_rx(encoded.clone(), None);

        // Decode and process - this simulates what handle_transport_rx does
        let decoded = Message::decode_from_slice(&encoded).unwrap();
        if let Message::Routed(r) = decoded {
            let received_hash = r.ack_hash(node.crypto());
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
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            hops: 0,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Initially not tracked
        assert!(!node.recently_forwarded().contains_key(&hash));

        // Insert into recently_forwarded (with hops and TTL)
        node.insert_recently_forwarded(hash, 0, 100, now);

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

        let encoded = Outgoing::encode(&Message::Ack(ack.clone()));
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

        // Insert two entries at different times (with dummy hops and TTL values)
        node.insert_recently_forwarded(hash1, 255, 100, now);
        node.insert_recently_forwarded(hash2, 255, 100, now + Duration::from_secs(10));

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
            node.insert_pending_ack(hash, vec![i as u8], Priority::RoutedPublish, 255, now);
        }

        assert_eq!(node.pending_acks().len(), DefaultConfig::MAX_PENDING_ACKS);

        // Insert one more - should evict oldest
        let new_hash: [u8; 4] = [0xFF; 4];
        node.insert_pending_ack(new_hash, vec![0xFF], Priority::RoutedPublish, 255, now);

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
            node.insert_recently_forwarded(hash, 255, 100, now);
        }

        assert_eq!(
            node.recently_forwarded().len(),
            DefaultConfig::MAX_RECENTLY_FORWARDED
        );

        // Insert one more - should evict oldest
        let new_hash: [u8; 4] = [0xFF; 4];
        node.insert_recently_forwarded(new_hash, 255, 100, now);

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
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            hops: 0,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Mark as recently forwarded (simulating first forward with TTL=255)
        node.insert_recently_forwarded(hash, 0, 255, now);

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
            node.insert_pending_ack(hash, vec![i as u8], Priority::RoutedPublish, 255, now);
        }

        assert_eq!(
            node.pending_acks().len(),
            SmallConfig::MAX_PENDING_ACKS,
            "Should be at SmallConfig capacity (8)"
        );

        // Insert one more - should evict oldest
        let new_hash: [u8; 4] = [0xFF; 4];
        node.insert_pending_ack(new_hash, vec![0xFF], Priority::RoutedPublish, 255, now);

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

    /// Test case from simulation: Node 30 should route to Node 33 (neighbor with tight range),
    /// not Node 15 (neighbor with wide range), because Node 33 has tighter keyspace.
    ///
    /// Tree structure (from publish_test_output9.txt):
    /// - Node 15: ks=[0x13333332,0xbffffffe) - wide range neighbor
    /// - Node 30: ks=[0x19999998,0x46666664) - "us"
    /// - Node 33: ks=[0x1ffffffe,0x3ffffffd) - tight range neighbor
    /// - Node 38: ks=[0x3ffffffd,0x46666664) - neighbor (doesn't cover dest)
    ///
    /// dest_addr = 0x37180340 (924494144) is in:
    /// - Node 15's range (but wider: 0x13333332 to 0xbffffffe)
    /// - Node 33's range (tighter: 0x1ffffffe to 0x3ffffffd)
    ///
    /// So routing should prefer Node 33.
    #[test]
    fn test_routing_loop_regression() {
        let mut node = make_node();

        // Node 15 - wide range neighbor
        let node_15: NodeId = [15u8; 16];
        insert_neighbor_for_routing(&mut node, node_15, (0x13333332, 0xbffffffe));

        // Node 33 - tight range covering dest
        let node_33: NodeId = [33u8; 16];
        insert_neighbor_for_routing(&mut node, node_33, (0x1ffffffe, 0x3ffffffd));

        // Node 38 - doesn't cover dest
        let node_38: NodeId = [38u8; 16];
        insert_neighbor_for_routing(&mut node, node_38, (0x3ffffffd, 0x46666664));

        // dest_addr from the simulation
        let dest: u32 = 0x37180340; // 924494144

        // Verify dest is in both Node 15's and Node 33's ranges
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
            "Should route to Node 33 (tighter range), not Node 15 (wider range)"
        );
    }

    /// Test hops-based bounce-back detection and TTL=0 edge case.
    /// With hops-based detection, TTL can be reset to DEFAULT_TTL on bounce-back retry.
    /// But if TTL is already 0 after decrement, the message should be dropped.
    #[test]
    fn test_bounce_back_hops_based() {
        let mut node = make_node();
        let now = Timestamp::from_secs(100);

        // Create a message with hops=0 (will be incremented to hops=1 on receive)
        let msg = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 10, // TTL is still valid
            hops: 1, // Already incremented from 0 to 1
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };

        let hash = msg.ack_hash(node.crypto());

        // Simulate: we forwarded this message before with hops=0 and TTL=255
        node.insert_recently_forwarded(hash, 0, 255, now);

        // Now it bounces back with hops=1 (original_hops=0, but msg.hops=1 after their increment)
        // The bounce-back handler detects this because stored_hops (0) != original_hops (1)
        // It should schedule a delayed forward

        // Manually call handle_bounce_back with original_hops=1
        node.handle_bounce_back(msg.clone(), hash, 1, now);

        // Should have scheduled a delayed forward
        assert_eq!(
            node.delayed_forwards().len(),
            1,
            "Should schedule delayed forward for bounce-back"
        );

        // Now test TTL=0 case - should NOT schedule
        let mut node2 = make_node();
        let msg_ttl0 = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, false),
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [8u8; 16], // Different node_id for different hash
            src_pubkey: None,
            ttl: 0, // TTL already 0 (message expired)
            hops: 1,
            payload: b"test".to_vec(),
            signature: Signature::default(),
        };
        let hash2 = msg_ttl0.ack_hash(node2.crypto());
        node2.insert_recently_forwarded(hash2, 0, 0, now);

        // TTL=0 should cause immediate drop
        node2.handle_bounce_back(msg_ttl0, hash2, 1, now);

        assert_eq!(
            node2.delayed_forwards().len(),
            0,
            "Should NOT schedule delayed forward for TTL=0 (message expired)"
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
                next_hop: Some([0u8; 4]),
                dest_addr: 0x1234_5678,
                dest_hash: None,
                src_addr: Some(0x8765_4321),
                src_node_id: [i as u8; 16], // Unique node_id per message
                src_pubkey: None,
                ttl: 10,
                hops: 0,
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
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [99u8; 16], // New unique node_id
            src_pubkey: None,
            ttl: 10,
            hops: 0,
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
            next_hop: Some([0u8; 4]),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [100u8; 16], // Another unique node_id
            src_pubkey: None,
            ttl: 10,
            hops: 0,
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
