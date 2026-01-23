//! Routing algorithm and keyspace calculations.
//!
//! This module handles:
//! - Tree address routing (up to ancestor, down to destination)
//! - Keyspace calculations for DHT storage
//! - Shortcut optimization

use alloc::vec::Vec;

use crate::node::Node;
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    Error, NodeId, Routed, Signature, TreeAddr, DEFAULT_TTL, MSG_DATA, MSG_FOUND, MSG_LOOKUP,
    MSG_PUBLISH,
};
use crate::wire::{routed_sign_data, Encode, Message};

/// Calculate the length of the common prefix between two tree addresses.
///
/// Used for shortcut routing: a shortcut is useful if its common_prefix_len
/// with the destination is greater than our own.
#[inline]
fn common_prefix_len(a: &TreeAddr, b: &TreeAddr) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

impl<T, Cr, R, Clk> Node<T, Cr, R, Clk>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
{
    /// Handle a received Routed message.
    pub(crate) fn handle_routed(&mut self, mut msg: Routed, now: Timestamp) {
        // TTL check - prevent routing loops
        if msg.ttl == 0 {
            return; // Drop message
        }
        msg.ttl -= 1;

        // Am I the destination?
        if msg.dest_addr == *self.tree_addr() {
            match msg.dest_node_id {
                Some(id) if id != *self.node_id() => {
                    // Stale address - node moved, drop
                    return;
                }
                _ => {
                    self.handle_locally(msg, now);
                    return;
                }
            }
        }

        // Destination in my subtree → route down
        if msg.dest_addr.starts_with(self.tree_addr()) {
            let next_ordinal = msg.dest_addr[self.tree_addr().len()];
            self.send_to_child_by_ordinal(next_ordinal, msg);
            return;
        }

        // Destination elsewhere → route up (or via shortcut)
        self.route_up_or_shortcut(msg);
    }

    /// Handle a message that has reached its destination.
    fn handle_locally(&mut self, msg: Routed, now: Timestamp) {
        // SECURITY: Require verified pubkey for signature verification
        let pubkey = match self.pubkey_cache().get(&msg.src_node_id) {
            Some(pk) => *pk,
            None => {
                // Can't verify without pubkey - mark that we need it
                self.need_pubkey_mut().insert(msg.src_node_id);
                return;
            }
        };

        // Verify signature
        let sign_data = routed_sign_data(&msg);
        if !self
            .crypto()
            .verify(&pubkey, sign_data.as_slice(), &msg.signature)
        {
            return; // Invalid signature
        }

        match msg.msg_type {
            MSG_PUBLISH => self.handle_publish(msg, now),
            MSG_LOOKUP => self.handle_lookup_msg(msg, now),
            MSG_FOUND => self.handle_found(msg, now),
            MSG_DATA => self.handle_data(msg),
            _ => {} // Unknown message type, ignore
        }
    }

    /// Send to a child by ordinal index.
    fn send_to_child_by_ordinal(&mut self, ordinal: u8, msg: Routed) {
        // IMPORTANT: Ordinals are assigned based on prefix-sorted order (see build_pulse)
        let prefix_len = self.child_prefix_len();
        if prefix_len == 0 {
            return; // No children or invalid state
        }

        // Build sorted prefixes matching build_pulse order
        let mut prefixes: Vec<Vec<u8>> = self
            .children()
            .keys()
            .map(|id| id[..prefix_len as usize].to_vec())
            .collect();
        prefixes.sort();

        // Forward if ordinal is valid (broadcast, child will pick it up based on tree_addr)
        if (ordinal as usize) < prefixes.len() {
            let _ = self.send_routed(msg);
        }
        // If ordinal out of range, message is dropped (stale routing info)
    }

    /// Route up to parent or via shortcut.
    ///
    /// Uses shortcut S instead of normal tree path if:
    /// `common_prefix_len(S.tree_addr, dest_addr) > common_prefix_len(my_addr, dest_addr)`
    ///
    /// In other words: use the shortcut if it's "closer" to the destination's branch.
    fn route_up_or_shortcut(&mut self, msg: Routed) {
        let dest_addr = &msg.dest_addr;
        let my_addr = self.tree_addr();
        let my_prefix_len = common_prefix_len(my_addr, dest_addr);

        // Find the best shortcut (one with longest common prefix with dest_addr)
        let mut best_shortcut: Option<[u8; 16]> = None;
        let mut best_prefix_len = my_prefix_len;

        for shortcut_id in self.shortcuts().iter() {
            if let Some(timing) = self.neighbor_times().get(shortcut_id) {
                let shortcut_prefix_len = common_prefix_len(&timing.tree_addr, dest_addr);
                if shortcut_prefix_len > best_prefix_len {
                    best_shortcut = Some(*shortcut_id);
                    best_prefix_len = shortcut_prefix_len;
                }
            }
        }

        // Note: Both cases call send_routed() which broadcasts the message.
        // The shortcut (or parent) will hear the broadcast and forward it based
        // on their own routing logic. We don't explicitly address the shortcut.
        if best_shortcut.is_some() || self.parent().is_some() {
            let _ = self.send_routed(msg);
        }
        // If we're root and no shortcut helps, drop (destination unreachable)
    }

    /// Handle received DATA message.
    fn handle_data(&mut self, msg: Routed) {
        // Push to application incoming channel
        self.push_incoming_data(msg.src_node_id, msg.payload);
    }

    /// Send data to a specific node at a known tree address.
    pub(crate) fn send_data_to(
        &mut self,
        target: NodeId,
        addr: TreeAddr,
        data: Vec<u8>,
        _now: Timestamp,
    ) -> Result<(), Error> {
        let msg = self.build_routed(addr, Some(target), MSG_DATA, data);
        self.send_routed(msg)
    }

    /// Build a signed Routed message with src_addr included (for messages expecting replies).
    pub(crate) fn build_routed(
        &self,
        dest_addr: TreeAddr,
        dest_node_id: Option<NodeId>,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> Routed {
        self.build_routed_inner(dest_addr, dest_node_id, msg_type, payload, true)
    }

    /// Build a signed Routed message without src_addr (for one-way messages like PUBLISH).
    pub(crate) fn build_routed_no_reply(
        &self,
        dest_addr: TreeAddr,
        msg_type: u8,
        payload: Vec<u8>,
    ) -> Routed {
        self.build_routed_inner(dest_addr, None, msg_type, payload, false)
    }

    /// Internal helper for building signed Routed messages.
    fn build_routed_inner(
        &self,
        dest_addr: TreeAddr,
        dest_node_id: Option<NodeId>,
        msg_type: u8,
        payload: Vec<u8>,
        include_src_addr: bool,
    ) -> Routed {
        let src_addr = if include_src_addr {
            Some(self.tree_addr().clone())
        } else {
            None
        };

        let mut msg = Routed {
            dest_addr,
            dest_node_id,
            src_addr,
            src_node_id: *self.node_id(),
            msg_type,
            ttl: DEFAULT_TTL,
            payload,
            signature: Signature::default(),
        };

        let sign_data = routed_sign_data(&msg);
        msg.signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        msg
    }

    /// Calculate tree address for a keyspace key.
    ///
    /// Walks down from root, narrowing range at each level based on
    /// child ordinal and subtree sizes.
    pub fn addr_for_key(&self, key: u32) -> TreeAddr {
        // Start at root with full keyspace [0, 2^32)
        let mut addr = Vec::new();
        let mut range_start: u64 = 0;
        let mut range_size: u64 = 1u64 << 32;

        // Walk down the tree
        let mut current_addr = Vec::new();

        loop {
            // Find children info for current position
            // If we're at our own position, use our children
            if current_addr == *self.tree_addr() {
                if self.children().is_empty() {
                    // We're a leaf at this address
                    break;
                }

                // Divide range among children based on subtree sizes
                let total_subtree: u64 = self.children().values().map(|&s| s as u64).sum();
                if total_subtree == 0 {
                    break;
                }

                // Sort children by prefix to match ordinal assignment (see build_pulse)
                let prefix_len = self.child_prefix_len();
                let mut sorted_children: Vec<(Vec<u8>, u32)> = self
                    .children()
                    .iter()
                    .map(|(k, &v)| (k[..prefix_len as usize].to_vec(), v))
                    .collect();
                sorted_children.sort_by(|a, b| a.0.cmp(&b.0));

                let key_u64 = key as u64;
                let mut child_start = range_start;

                for (idx, (_, child_subtree)) in sorted_children.iter().enumerate() {
                    // Use u128 to avoid overflow: range_size * child_subtree can exceed u64
                    let child_range = ((range_size as u128) * (*child_subtree as u128)
                        / (total_subtree as u128)) as u64;
                    let child_end = child_start + child_range;

                    if key_u64 >= child_start && key_u64 < child_end {
                        addr.push(idx as u8);
                        current_addr.push(idx as u8);
                        range_start = child_start;
                        range_size = child_range;
                        break;
                    }
                    child_start = child_end;
                }

                // If we didn't find a child (shouldn't happen), break
                if addr.len() == current_addr.len() - 1 {
                    break;
                }
            } else {
                // We don't have visibility into other subtrees
                // Return the best address we can compute
                break;
            }
        }

        addr
    }

    /// Hash a node_id with replica index to get a keyspace key.
    pub fn hash_to_key(&self, node_id: &NodeId, replica: u8) -> u32 {
        let mut data = Vec::with_capacity(17);
        data.extend_from_slice(node_id);
        data.push(replica);
        let hash = self.crypto().hash(&data);
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    }

    /// Send a Routed message to the appropriate queue based on msg_type.
    ///
    /// Protocol messages (PUBLISH, LOOKUP, FOUND) go to the protocol queue.
    /// Application data (DATA) goes to the app queue.
    ///
    /// If the queue is full, the message is dropped and metrics are updated.
    /// This is acceptable because the protocol is designed for lossy operation
    /// (see design.md "Best-effort delivery" section).
    pub(crate) fn send_routed(&mut self, msg: Routed) -> Result<(), Error> {
        let is_data = msg.msg_type == MSG_DATA;
        let encoded = Message::Routed(msg).encode_to_vec();

        if encoded.len() > self.transport().mtu() {
            return Err(Error::MessageTooLarge);
        }

        let queue = if is_data {
            self.transport().app_outgoing()
        } else {
            self.transport().protocol_outgoing()
        };

        match queue.try_send(encoded) {
            Ok(()) => {
                if is_data {
                    self.record_app_sent();
                } else {
                    self.record_protocol_sent();
                }
                Ok(())
            }
            Err(_) => {
                if is_data {
                    self.record_app_dropped();
                } else {
                    self.record_protocol_dropped();
                }
                Err(Error::QueueFull)
            }
        }
    }
}
