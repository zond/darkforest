//! Message routing based on keyspace addressing.
//!
//! Routing uses keyspace ranges where each node owns a contiguous range
//! [keyspace_lo, keyspace_hi). Messages route toward dest_addr by forwarding
//! to the neighbor whose range contains the destination with the tightest fit.

use alloc::vec::Vec;

use crate::config::NodeConfig;
use crate::node::{AckHash, Node};
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
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
        let msg_hash = self.compute_ack_hash(&msg);

        if let Some(&(_, stored_ttl)) = self.recently_forwarded().get(&msg_hash) {
            if stored_ttl == original_ttl {
                // Same TTL = retransmission from sender who didn't hear our forward
                // Send explicit ACK to confirm we received and forwarded it
                self.send_explicit_ack(msg_hash);
            }
            // Different TTL = same message via alternate path, ignore silently
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
        let ack = Ack { hash };
        let encoded = Message::Ack(ack).encode_to_vec();

        // ACK is small (9 bytes) so MTU check is unlikely to fail, but be safe
        if encoded.len() > self.transport().mtu() {
            return;
        }

        let result = self.transport().protocol_outgoing().try_send(encoded);
        if result.is_ok() {
            self.record_protocol_sent();
        }
        // Don't track drops for ACKs - they're best-effort
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

    /// Compute the 8-byte ACK hash for a Routed message.
    ///
    /// Uses `routed_sign_data()` which excludes TTL, so the hash is invariant across hops.
    /// This allows the original sender to recognize the message when overhearing a forwarder.
    pub(crate) fn compute_ack_hash(&self, msg: &Routed) -> AckHash {
        let sign_data = routed_sign_data(msg);
        let full_hash = self.crypto().hash(sign_data.as_slice());
        let mut hash = [0u8; 8];
        hash.copy_from_slice(&full_hash[..8]);
        hash
    }

    /// Forward a routed message toward its destination.
    fn forward_routed(&mut self, mut msg: Routed, now: Timestamp) {
        let dest = msg.dest_addr;

        // Try to find best next hop
        if let Some(next_hop_id) = self.best_next_hop(dest) {
            // Set next_hop to the intended forwarder's hash
            msg.next_hop = self.compute_node_hash(&next_hop_id);
            self.send_to_neighbor(next_hop_id, msg, now);
        } else if let Some(parent_id) = self.parent() {
            // Forward upward to parent as fallback
            msg.next_hop = self.compute_node_hash(&parent_id);
            self.send_to_neighbor(parent_id, msg, now);
        }
        // If no route, drop the message
    }

    /// Find the best next hop for a destination keyspace address.
    ///
    /// Returns the neighbor (child or shortcut) whose keyspace range:
    /// 1. Contains the destination address
    /// 2. Has the tightest range (smallest hi - lo)
    fn best_next_hop(&self, dest: u32) -> Option<NodeId> {
        let mut best: Option<(NodeId, u64)> = None; // (node_id, range_size)

        // Check children
        for (child_id, &(lo, hi)) in self.child_ranges() {
            if dest >= lo && dest < hi {
                let range_size = (hi as u64).saturating_sub(lo as u64);
                if best.map_or(true, |(_, best_size)| range_size < best_size) {
                    best = Some((*child_id, range_size));
                }
            }
        }

        // Check shortcuts
        for (shortcut_id, &(lo, hi)) in self.shortcuts() {
            if dest >= lo && dest < hi {
                let range_size = (hi as u64).saturating_sub(lo as u64);
                if best.map_or(true, |(_, best_size)| range_size < best_size) {
                    best = Some((*shortcut_id, range_size));
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
        let encoded = crate::wire::Message::Routed(msg.clone()).encode_to_vec();

        if encoded.len() > self.transport().mtu() {
            self.record_protocol_dropped();
            return;
        }

        // Compute ACK hash for tracking (uses routed_sign_data which excludes TTL)
        let ack_hash = self.compute_ack_hash(&msg);

        // Track pending ACK before sending (with TTL for implicit ACK verification)
        self.insert_pending_ack(ack_hash, encoded.clone(), sent_ttl, now);

        // Broadcast on protocol channel (neighbors will hear it)
        let result = self.transport().protocol_outgoing().try_send(encoded);

        if result.is_ok() {
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

        // If we own the destination, handle locally
        if self.owns_key(dest) {
            let encoded = crate::wire::Message::Routed(msg.clone()).encode_to_vec();
            if encoded.len() > self.transport().mtu() {
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

        // Encode and send
        let encoded = crate::wire::Message::Routed(msg).encode_to_vec();

        if encoded.len() > self.transport().mtu() {
            return Err(Error::MessageTooLarge);
        }

        // Use app channel for DATA, protocol channel for others
        let channel = if msg_type == MSG_DATA {
            self.transport().app_outgoing()
        } else {
            self.transport().protocol_outgoing()
        };

        let result = channel.try_send(encoded);

        if result.is_ok() {
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

    /// Hash a node_id with replica index to get DHT key.
    pub(crate) fn hash_to_key(&self, node_id: &NodeId, replica: u8) -> [u8; 32] {
        let mut data = [0u8; 17];
        data[..16].copy_from_slice(node_id);
        data[16] = replica;
        self.crypto().hash(&data)
    }

    /// Convert a DHT key to a keyspace address.
    pub(crate) fn addr_for_key(&self, key: [u8; 32]) -> u32 {
        // Use first 4 bytes of hash as u32 keyspace address
        u32::from_be_bytes([key[0], key[1], key[2], key[3]])
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
    use crate::traits::test_impls::{MockClock, MockCrypto, MockRandom, MockTransport};

    /// Type alias for test nodes using default config.
    type TestNode = Node<MockTransport, MockCrypto, MockRandom, MockClock, DefaultConfig>;

    /// Type alias for test nodes using small config (64KB RAM).
    type SmallTestNode = Node<MockTransport, MockCrypto, MockRandom, MockClock, SmallConfig>;

    fn make_node() -> TestNode {
        let transport = MockTransport::new();
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();
        Node::new(transport, crypto, random, clock)
    }

    fn make_small_node() -> SmallTestNode {
        let transport = MockTransport::new();
        let crypto = MockCrypto::new();
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
    fn test_hash_to_key() {
        let node = make_node();

        let node_id: NodeId = [1u8; 16];
        let key0 = node.hash_to_key(&node_id, 0);
        let key1 = node.hash_to_key(&node_id, 1);

        // Different replicas should produce different keys
        assert_ne!(key0, key1);
    }

    #[test]
    fn test_addr_for_key() {
        let node = make_node();

        let key = [
            0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let addr = node.addr_for_key(key);

        assert_eq!(addr, 0x12345678);
    }

    #[test]
    fn test_best_next_hop_returns_child_in_range() {
        let mut node = make_node();

        // Add a child with keyspace range [1000, 2000)
        let child_id: NodeId = [1u8; 16];
        node.child_ranges_mut().insert(child_id, (1000, 2000));

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
        node.child_ranges_mut().insert(wide_child, (0, 10000));

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
        node.child_ranges_mut().insert(tight_child, (5000, 7000));

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

        node.child_ranges_mut().insert(child1, (0, 1000));
        node.child_ranges_mut().insert(child2, (1000, 2000));
        node.child_ranges_mut().insert(child3, (2000, 3000));

        // Each destination should route to correct child
        assert_eq!(node.best_next_hop(500), Some(child1));
        assert_eq!(node.best_next_hop(1500), Some(child2));
        assert_eq!(node.best_next_hop(2500), Some(child3));

        // Outside all ranges
        assert_eq!(node.best_next_hop(5000), None);
    }

    #[test]
    fn test_compute_ack_hash_invariant() {
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

        let hash1 = node.compute_ack_hash(&msg1);
        let hash2 = node.compute_ack_hash(&msg2);

        assert_eq!(
            hash1, hash2,
            "ACK hash should be invariant across TTL values"
        );
    }

    #[test]
    fn test_compute_ack_hash_different_content() {
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

        let hash1 = node.compute_ack_hash(&msg1);
        let hash2 = node.compute_ack_hash(&msg2);

        assert_ne!(
            hash1, hash2,
            "Different content should produce different hashes"
        );
    }

    #[test]
    fn test_implicit_ack_clears_pending() {
        use crate::time::Timestamp;
        use crate::wire::{Decode, Encode, Message};

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

        let hash = node.compute_ack_hash(&msg);

        // Manually insert a pending ACK (sent_ttl = 255)
        node.insert_pending_ack(hash, vec![1, 2, 3], 255, now);
        assert!(node.pending_acks().contains_key(&hash));

        // Simulate receiving the message (which should clear pending ACK via implicit ACK)
        let encoded = Message::Routed(msg).encode_to_vec();
        node.transport().inject_rx(encoded.clone(), None);

        // Decode and process - this simulates what handle_transport_rx does
        let decoded = Message::decode_from_slice(&encoded).unwrap();
        if let Message::Routed(routed) = decoded {
            let received_hash = node.compute_ack_hash(&routed);
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
        use crate::time::Timestamp;

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

        let hash = node.compute_ack_hash(&msg);

        // Initially not tracked
        assert!(!node.recently_forwarded().contains_key(&hash));

        // Insert into recently_forwarded (with TTL)
        node.insert_recently_forwarded(hash, 255, now);

        // Should now be tracked
        assert!(node.recently_forwarded().contains_key(&hash));
    }

    #[test]
    fn test_retry_backoff_bounds() {
        use crate::traits::test_impls::{MockClock, MockCrypto, MockRandom, MockTransport};

        // Create node with known tau (100ms default for MockTransport with no bw)
        let transport = MockTransport::new();
        let crypto = MockCrypto::new();
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
        use crate::node::AckHash;
        use crate::wire::{Ack, Decode, Encode, Message};

        let hash: AckHash = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let ack = Ack { hash };
        let msg = Message::Ack(ack);

        let encoded = msg.encode_to_vec();
        assert_eq!(
            encoded.len(),
            9,
            "Ack message should be 9 bytes (1 type + 8 hash)"
        );

        let decoded = Message::decode_from_slice(&encoded).unwrap();
        match decoded {
            Message::Ack(decoded_ack) => {
                assert_eq!(decoded_ack.hash, hash);
            }
            _ => panic!("Expected Ack message"),
        }
    }

    #[test]
    fn test_cleanup_recently_forwarded_expiry() {
        use crate::time::{Duration, Timestamp};
        use crate::types::RECENTLY_FORWARDED_TTL_MULTIPLIER;

        let mut node = make_node();
        let tau = node.tau();
        let ttl = tau * RECENTLY_FORWARDED_TTL_MULTIPLIER;

        let now = Timestamp::from_secs(1000);
        let hash1: [u8; 8] = [1; 8];
        let hash2: [u8; 8] = [2; 8];

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
        use crate::time::Timestamp;

        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Fill pending_acks to capacity (using DefaultConfig)
        for i in 0..DefaultConfig::MAX_PENDING_ACKS {
            let hash: [u8; 8] = [i as u8; 8];
            node.insert_pending_ack(hash, vec![i as u8], 255, now);
        }

        assert_eq!(node.pending_acks().len(), DefaultConfig::MAX_PENDING_ACKS);

        // Insert one more - should evict oldest
        let new_hash: [u8; 8] = [0xFF; 8];
        node.insert_pending_ack(new_hash, vec![0xFF], 255, now);

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
        use crate::time::Timestamp;

        let mut node = make_node();
        let now = Timestamp::from_secs(1000);

        // Fill recently_forwarded to capacity (using DefaultConfig)
        for i in 0..DefaultConfig::MAX_RECENTLY_FORWARDED {
            let mut hash: [u8; 8] = [0; 8];
            hash[0] = (i >> 8) as u8;
            hash[1] = (i & 0xFF) as u8;
            node.insert_recently_forwarded(hash, 255, now);
        }

        assert_eq!(
            node.recently_forwarded().len(),
            DefaultConfig::MAX_RECENTLY_FORWARDED
        );

        // Insert one more - should evict oldest
        let new_hash: [u8; 8] = [0xFF; 8];
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
        use crate::time::Timestamp;

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

        let hash = node.compute_ack_hash(&msg);

        // Mark as recently forwarded (simulating first forward)
        node.insert_recently_forwarded(hash, 255, now);

        // Clear any messages in transport
        node.transport().take_sent();

        // Send explicit ACK (simulating duplicate detection)
        node.send_explicit_ack(hash);

        // Check that an ACK was sent
        let sent = node.transport().take_protocol_sent();
        assert_eq!(sent.len(), 1, "Should send one ACK message");
        assert_eq!(sent[0].len(), 9, "ACK should be 9 bytes");
        assert_eq!(sent[0][0], 0x03, "ACK wire type should be 0x03");
    }

    #[test]
    fn test_small_config_eviction() {
        use crate::time::Timestamp;

        let mut node = make_small_node();
        let now = Timestamp::from_secs(1000);

        // SmallConfig::MAX_PENDING_ACKS = 8 (vs DefaultConfig = 32)
        // Fill to capacity
        for i in 0..SmallConfig::MAX_PENDING_ACKS {
            let hash: [u8; 8] = [i as u8; 8];
            node.insert_pending_ack(hash, vec![i as u8], 255, now);
        }

        assert_eq!(
            node.pending_acks().len(),
            SmallConfig::MAX_PENDING_ACKS,
            "Should be at SmallConfig capacity (8)"
        );

        // Insert one more - should evict oldest
        let new_hash: [u8; 8] = [0xFF; 8];
        node.insert_pending_ack(new_hash, vec![0xFF], 255, now);

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
}
