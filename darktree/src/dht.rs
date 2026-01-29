//! DHT operations - PUBLISH, LOOKUP, and FOUND handling.
//!
//! This module handles:
//! - Publishing node locations to the DHT
//! - Looking up node locations
//! - Storing and retrieving location entries

use crate::config::NodeConfig;
use crate::node::Node;
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    Event, LocationEntry, NodeId, Routed, K_REPLICAS, LOCATION_REFRESH, MSG_FOUND, MSG_LOOKUP,
    MSG_PUBLISH,
};
use crate::wire::{location_sign_data, Reader, Writer};

impl<T, Cr, R, Clk, Cfg> Node<T, Cr, R, Clk, Cfg>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
    Cfg: NodeConfig,
{
    /// Check if we own any replica key for a node_id in our keyspace.
    #[cfg(test)]
    fn owns_replica_key(&self, node_id: &NodeId) -> bool {
        (0..K_REPLICAS).any(|replica| {
            let dest_addr = self.replica_addr(node_id, replica as u8);
            self.owns_key(dest_addr)
        })
    }

    /// Publish our location to the DHT.
    pub(crate) fn publish_location(&mut self, now: Timestamp) {
        let seq = self.next_location_seq();
        let my_addr = self.my_address();

        emit_debug!(
            self,
            crate::debug::DebugEvent::LocationPublishStarted {
                node_id: *self.node_id(),
                seq,
            }
        );

        // Build location signature
        let sign_data = location_sign_data(self.node_id(), my_addr, seq);
        let signature = self.crypto().sign(self.secret(), sign_data.as_slice());

        // Extract values needed for payload construction (avoids borrowing self in loop)
        let node_id = *self.node_id();
        let pubkey = *self.pubkey();

        // Publish to K_REPLICAS locations
        for replica in 0..K_REPLICAS {
            let dest_addr = self.replica_addr(&node_id, replica as u8);

            // Build payload: owner_node_id || pubkey || keyspace_addr || seq || replica_index || signature
            let mut payload = Writer::new();
            payload.write_node_id(&node_id);
            payload.write_pubkey(&pubkey);
            payload.write_u32_be(my_addr);
            payload.write_varint(seq);
            payload.write_u8(replica as u8);
            payload.write_signature(&signature);
            let payload_bytes = payload.finish();

            let msg = self.build_routed_no_reply(dest_addr, MSG_PUBLISH, payload_bytes);
            let _ = self.send_routed(msg);
        }

        // Schedule next publish
        self.set_next_publish(Some(now + LOCATION_REFRESH));
    }

    /// Handle a PUBLISH message.
    pub(crate) fn handle_publish(&mut self, msg: Routed, now: Timestamp) {
        // Verify Routed signature (defense-in-depth; location signature is critical protection)
        if self.verify_routed_signature(&msg, now).is_none() {
            return;
        }

        // Decode payload: owner_node_id || pubkey || keyspace_addr || seq || replica_index || signature
        let mut reader = Reader::new(&msg.payload);

        let owner_node_id = match reader.read_node_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let pubkey = match reader.read_pubkey() {
            Ok(pk) => pk,
            Err(_) => return,
        };
        let keyspace_addr = match reader.read_u32_be() {
            Ok(addr) => addr,
            Err(_) => return,
        };
        let seq = match reader.read_varint() {
            Ok(s) => s,
            Err(_) => return,
        };
        let replica_index = match reader.read_u8() {
            Ok(r) => r,
            Err(_) => return,
        };
        let signature = match reader.read_signature() {
            Ok(s) => s,
            Err(_) => return,
        };

        // SECURITY: Verify keyspace ownership to prevent DHT pollution attacks.
        // We must own the SPECIFIC replica key this PUBLISH is for, not just any replica.
        let dest_addr = self.replica_addr(&owner_node_id, replica_index);
        if !self.owns_key(dest_addr) {
            return;
        }

        // SECURITY: Verify pubkey binds to node_id
        if !self.crypto().verify_pubkey_binding(&owner_node_id, &pubkey) {
            return;
        }

        // Cache the pubkey
        self.insert_pubkey_cache(owner_node_id, pubkey, now);

        // Verify signature
        let sign_data = location_sign_data(&owner_node_id, keyspace_addr, seq);
        if !self
            .crypto()
            .verify(&pubkey, sign_data.as_slice(), &signature)
        {
            return; // Invalid signature
        }

        // Check if this is a newer entry for this specific replica
        // Reject if seq <= existing (design doc: "Verify seq > existing_seq")
        let store_key = (owner_node_id, replica_index);
        if let Some(existing) = self.location_store().get(&store_key) {
            if seq <= existing.seq {
                return; // Replay or old entry
            }
        }

        // Store the entry
        let entry = LocationEntry {
            node_id: owner_node_id,
            pubkey,
            keyspace_addr,
            seq,
            replica_index,
            signature,
            received_at: now,
        };

        self.insert_location_store(owner_node_id, replica_index, entry.clone());
        emit_debug!(self, {
            let (ks_lo, ks_hi) = self.keyspace_range();
            let ks_range = ks_hi as u64 - ks_lo as u64;
            let own_slice = ks_range / self.subtree_size() as u64;
            let own_hi = ks_lo as u64 + own_slice;
            crate::debug::DebugEvent::PublishStored {
                payload_hash: msg.payload_hash(self.crypto()),
                owner: owner_node_id,
                replica_index,
                dest_addr,
                keyspace_lo: ks_lo,
                keyspace_hi: ks_hi,
                own_hi: own_hi as u32,
            }
        });

        // Send BACKUP_PUBLISH to random neighbors
        self.send_backup_publish(&entry);

        // Update fraud detection counters (HyperLogLog cardinality estimation)
        let key = *self.hll_secret_key();
        self.fraud_detection_mut()
            .add_publisher(&owner_node_id, &key);
    }

    /// Send a LOOKUP message.
    pub(crate) fn send_lookup(&mut self, target: NodeId, replica: usize, _now: Timestamp) {
        let dest_addr = self.replica_addr(&target, replica as u8);

        // dest_hash identifies the target (4-byte truncated hash of target node_id)
        let dest_hash = self.compute_node_hash(&target);

        // Payload is just the replica_index (1 byte) per design doc
        let msg = self.build_routed(
            dest_addr,
            Some(dest_hash),
            MSG_LOOKUP,
            alloc::vec![replica as u8],
        );
        let _ = self.send_routed(msg);
    }

    /// Handle a LOOKUP message.
    pub(crate) fn handle_lookup_msg(&mut self, msg: Routed, now: Timestamp) {
        // Verify Routed signature before responding
        if self.verify_routed_signature(&msg, now).is_none() {
            return;
        }

        // dest_hash identifies the target entry
        let dest_hash = match msg.dest_hash {
            Some(hash) => hash,
            None => return, // LOOKUP requires dest_hash
        };

        // Payload is replica_index (1 byte)
        if msg.payload.len() != 1 {
            return;
        }

        // Find entry matching dest_hash by iterating location_store
        // (Design doc specifies this approach; MAX_LOCATION_STORE=256 makes this acceptable)
        let entry = match self
            .location_store()
            .iter()
            .find(|((node_id, _replica), _)| self.compute_node_hash(node_id) == dest_hash)
        {
            Some((_, entry)) => entry.clone(),
            None => return, // No matching entry
        };

        // Need src_addr to reply
        let src_addr = match msg.src_addr {
            Some(addr) => addr,
            None => return, // Can't reply without source address
        };

        // Build FOUND response
        // Payload: target_node_id || pubkey || keyspace_addr || seq || replica_index || location_signature
        let mut payload = Writer::new();
        payload.write_node_id(&entry.node_id);
        payload.write_pubkey(&entry.pubkey);
        payload.write_u32_be(entry.keyspace_addr);
        payload.write_varint(entry.seq);
        payload.write_u8(entry.replica_index);
        payload.write_signature(&entry.signature);
        let payload_bytes = payload.finish();

        // Compute dest_hash for the requester
        let response_dest_hash = self.compute_node_hash(&msg.src_node_id);

        let response =
            self.build_routed(src_addr, Some(response_dest_hash), MSG_FOUND, payload_bytes);
        let _ = self.send_routed(response);
    }

    /// Handle a FOUND response.
    pub(crate) fn handle_found(&mut self, msg: Routed, now: Timestamp) {
        if !self.verify_dest_hash(&msg) {
            return; // Not for us
        }

        // Verify Routed signature (defense-in-depth; location signature is critical protection)
        if self.verify_routed_signature(&msg, now).is_none() {
            return;
        }

        // Decode payload: target_node_id || pubkey || keyspace_addr || seq || replica_index || location_signature
        let mut reader = Reader::new(&msg.payload);

        let node_id = match reader.read_node_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let pubkey = match reader.read_pubkey() {
            Ok(pk) => pk,
            Err(_) => return,
        };
        let keyspace_addr = match reader.read_u32_be() {
            Ok(addr) => addr,
            Err(_) => return,
        };
        let seq = match reader.read_varint() {
            Ok(s) => s,
            Err(_) => return,
        };
        // Read replica_index to advance past it (required for signature parsing).
        // We don't use the value since we cache by node_id, not by replica.
        let _replica_index = match reader.read_u8() {
            Ok(r) => r,
            Err(_) => return,
        };
        let signature = match reader.read_signature() {
            Ok(s) => s,
            Err(_) => return,
        };

        // Check if we have a pending lookup for this node
        if self.pending_lookups().get(&node_id).is_none() {
            return; // Unexpected response
        }

        // SECURITY: Verify pubkey binds to node_id
        if !self.crypto().verify_pubkey_binding(&node_id, &pubkey) {
            return;
        }

        // SECURITY: Verify the location signature (signed by the target node)
        let sign_data = location_sign_data(&node_id, keyspace_addr, seq);
        if !self
            .crypto()
            .verify(&pubkey, sign_data.as_slice(), &signature)
        {
            return; // Invalid location signature
        }

        // Cache the pubkey
        self.insert_pubkey_cache(node_id, pubkey, now);

        // Cache the location
        self.insert_location_cache(node_id, keyspace_addr, now);

        // Remove pending lookup
        self.pending_lookups_mut().remove(&node_id);

        // Emit event
        self.push_event(Event::LookupComplete {
            node_id,
            keyspace_addr,
        });

        // Send any pending data
        if let Some(data) = self.pending_data_mut().remove(&node_id) {
            let _ = self.send_data_to(node_id, keyspace_addr, data, now);
        }
    }

    /// Rebalance keyspace: re-publish ONE entry that we no longer own.
    ///
    /// Returns `true` if there are more entries to rebalance.
    /// Call this when tree position changes (after merge, parent switch, etc.)
    /// to ensure entries are moved to their new owners.
    ///
    /// To avoid overwhelming the outgoing queue, this only processes one entry
    /// per call. If more work remains, schedule another rebalance in ~2τ.
    pub(crate) fn rebalance_one(&mut self, _now: Timestamp) -> bool {
        // Find entries we no longer own, take up to 2 to know if more work remains
        let mut unowned_entries = self
            .location_store()
            .iter()
            .filter(|((node_id, replica), _)| {
                let dest_addr = self.replica_addr(node_id, *replica);
                !self.owns_key(dest_addr)
            })
            .take(2)
            .map(|(_, entry)| entry.clone());

        let Some(entry) = unowned_entries.next() else {
            return false; // No more work
        };
        let has_more = unowned_entries.next().is_some();

        // Remove this entry
        emit_debug!(
            self,
            crate::debug::DebugEvent::LocationRemoved {
                owner: entry.node_id,
                replica_index: entry.replica_index,
                reason: "rebalance",
            }
        );
        self.location_store_mut()
            .remove(&(entry.node_id, entry.replica_index));

        // Re-publish to new owner
        let mut payload = Writer::new();
        payload.write_node_id(&entry.node_id);
        payload.write_pubkey(&entry.pubkey);
        payload.write_u32_be(entry.keyspace_addr);
        payload.write_varint(entry.seq);
        payload.write_u8(entry.replica_index);
        payload.write_signature(&entry.signature);
        let payload_bytes = payload.finish();

        let dest_addr = self.replica_addr(&entry.node_id, entry.replica_index);
        let msg = self.build_routed_no_reply(dest_addr, MSG_PUBLISH, payload_bytes);
        let _ = self.send_routed(msg);

        has_more
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{Duration, Timestamp};
    use crate::traits::test_impls::{FastTestCrypto, MockClock, MockRandom, MockTransport};
    use crate::types::{NodeId, K_REPLICAS};

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
    fn test_publish_stores_locally_when_owner() {
        let mut node = make_node();
        let node_id = *node.node_id();

        // Node owns full keyspace, so publish should store locally
        node.publish_location(Timestamp::ZERO);

        // Should have stored our own location entry (at least one replica)
        let has_entry = (0..K_REPLICAS as u8)
            .any(|replica| node.location_store().contains_key(&(node_id, replica)));
        assert!(has_entry);
    }

    #[test]
    fn test_rebalance_removes_entries_outside_keyspace() {
        let mut node = make_node();
        let now = Timestamp::from_secs(100);

        // Publish our location (will store locally since we own full keyspace)
        node.publish_location(now);
        let node_id = *node.node_id();

        // Verify at least one entry exists
        let has_entry = (0..K_REPLICAS as u8)
            .any(|replica| node.location_store().contains_key(&(node_id, replica)));
        assert!(has_entry);

        // Shrink our keyspace to a small range that doesn't include the replica keys
        // This simulates joining a tree and receiving a smaller keyspace allocation
        node.set_keyspace_range(0, 1000); // Very small range

        // Rebalance should remove entries we no longer own
        // (In production, trigger_rebalance processes one at a time; test needs all)
        while node.rebalance_one(now) {}

        // Entry should be removed (we no longer own it)
        // Note: This depends on how hash_to_key distributes - may need adjustment
        // if the node's replica keys happen to fall in [0, 1000)
        // For most node_ids, they won't, so entry should be removed
        let still_owns = node.owns_replica_key(&node_id);
        if !still_owns {
            let has_entry = (0..K_REPLICAS as u8)
                .any(|replica| node.location_store().contains_key(&(node_id, replica)));
            assert!(!has_entry);
        }
    }

    #[test]
    fn test_lookup_stores_pending() {
        let mut node = make_node();
        let now = Timestamp::from_secs(100);

        // Create a target node_id to lookup
        let target: NodeId = [1u8; 16];

        // Initiate lookup
        node.start_lookup(target, now);

        // Should have a pending lookup
        assert!(node.pending_lookups().contains_key(&target));
    }

    #[test]
    fn test_lookup_timeout_retries_replicas() {
        let mut node = make_node();
        let now = Timestamp::from_secs(100);

        // Create a target node_id to lookup
        let target: NodeId = [1u8; 16];

        // Initiate lookup
        node.start_lookup(target, now);

        // Check initial state
        let lookup = node.pending_lookups().get(&target).unwrap();
        assert_eq!(lookup.replica_index, 0);

        // Simulate timeout by advancing time
        let timeout_duration = node.lookup_timeout();
        let after_timeout = now + timeout_duration + Duration::from_secs(1);

        // Handle timeouts
        node.handle_timeouts(after_timeout);

        // Should have moved to next replica
        if let Some(lookup) = node.pending_lookups().get(&target) {
            assert_eq!(lookup.replica_index, 1);
        }
    }
}
