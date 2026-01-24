//! Message routing based on keyspace addressing.
//!
//! Routing uses keyspace ranges where each node owns a contiguous range
//! [keyspace_lo, keyspace_hi). Messages route toward dest_addr by forwarding
//! to the neighbor whose range contains the destination with the tightest fit.

use alloc::vec::Vec;

use crate::node::Node;
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    ChildHash, Error, NodeId, Routed, Signature, DEFAULT_TTL, MSG_DATA, MSG_FOUND, MSG_LOOKUP,
    MSG_PUBLISH,
};
use crate::wire::{routed_sign_data, Encode};

impl<T, Cr, R, Clk> Node<T, Cr, R, Clk>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
{
    /// Handle an incoming Routed message.
    pub(crate) fn handle_routed(&mut self, mut msg: Routed, now: Timestamp) {
        // Check TTL
        if msg.ttl == 0 {
            return;
        }

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

        // Not for us - verify signature before forwarding to prevent bandwidth waste
        if self.verify_routed_signature(&msg, now).is_none() {
            // Can't verify signature (no pubkey or invalid) - drop
            return;
        }

        // Signature valid, forward
        self.forward_routed(msg);
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
    fn forward_routed(&mut self, msg: Routed) {
        let dest = msg.dest_addr;

        // Try to find best next hop
        if let Some(next_hop) = self.best_next_hop(dest) {
            self.send_to_neighbor(next_hop, msg);
        } else if let Some(parent) = self.parent() {
            // Forward upward to parent as fallback
            self.send_to_neighbor(parent, msg);
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

    /// Send a Routed message to a specific neighbor.
    fn send_to_neighbor(&mut self, _neighbor: NodeId, msg: Routed) {
        let encoded = crate::wire::Message::Routed(msg).encode_to_vec();

        if encoded.len() > self.transport().mtu() {
            self.record_protocol_dropped();
            return;
        }

        // Broadcast on protocol channel (neighbors will hear it)
        let result = self.transport().protocol_outgoing().try_send(encoded);

        if result.is_ok() {
            self.record_protocol_sent();
        } else {
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

        let mut msg = Routed {
            flags_and_type,
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

    /// Handle timeouts for pending lookups and other operations.
    pub(crate) fn handle_timeouts(&mut self, now: Timestamp) {
        use crate::types::{Event, K_REPLICAS};

        let timeout = self.lookup_timeout();

        // Collect lookups that need action
        let mut retry_lookups = Vec::new();
        let mut failed_lookups = Vec::new();

        for (target, lookup) in self.pending_lookups().iter() {
            let elapsed = now.saturating_sub(lookup.last_query_at);
            if elapsed >= timeout {
                if lookup.replica_index + 1 < K_REPLICAS {
                    retry_lookups.push((*target, lookup.replica_index + 1));
                } else {
                    failed_lookups.push(*target);
                }
            }
        }

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
    use super::*;
    use crate::traits::test_impls::{MockClock, MockCrypto, MockRandom, MockTransport};

    fn make_node() -> Node<MockTransport, MockCrypto, MockRandom, MockClock> {
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
}
