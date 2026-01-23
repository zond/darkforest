//! darktree - Tree-based DHT protocol for LoRa mesh networks
//!
//! A protocol for building mesh networks over LoRa radios with O(log N) routing.
//!
//! This crate is `no_std` compatible. Use the `std` feature (enabled by default)
//! for std environments, or disable default features for embedded targets.
//!
//! # Key Properties
//!
//! - Nodes form a spanning tree via periodic broadcasts
//! - Tree addresses enable efficient routing without flooding
//! - A distributed hash table maps node IDs to tree addresses
//! - Ed25519 signatures prevent impersonation
//! - No clock synchronization required
//!
//! # Example
//!
//! ```ignore
//! use darktree::{Node, Transport, Crypto, Random, Clock, OutgoingData};
//!
//! // Implement traits for your platform...
//!
//! // Create a node
//! // let mut node = Node::new(transport, crypto, random, clock);
//!
//! // Spawn the node's run loop
//! // spawn(async move {
//! //     node.run().await;
//! // });
//!
//! // Send data to another node
//! // node.outgoing().send(OutgoingData { target, payload }).await;
//!
//! // Receive data from other nodes
//! // let data = node.incoming().receive().await;
//! ```
//!
//! # Module Structure
//!
//! - [`types`] - Core types (NodeId, Pulse, Routed, etc.)
//! - [`wire`] - Wire format serialization
//! - [`traits`] - Transport, Crypto, Random, Clock traits
//! - [`node`] - Main Node struct and public API
//! - [`tree`] - Tree formation and maintenance
//! - [`routing`] - Message routing
//! - [`dht`] - DHT operations (PUBLISH/LOOKUP/FOUND)
//! - [`fraud`] - Fraud detection
//! - [`time`] - Timestamp and Duration types

#![no_std]

extern crate alloc;

pub mod dht;
pub mod fraud;
pub mod node;
pub mod routing;
pub mod time;
pub mod traits;
pub mod tree;
pub mod types;
pub mod wire;

// Re-export main types at crate root
pub use node::Node;
pub use time::{Duration, Timestamp};
pub use traits::{Clock, Crypto, IncomingData, OutgoingData, Random, Received, Transport};
pub use types::{
    Error, Event, LocationEntry, NodeId, Payload, PublicKey, Pulse, Routed, SecretKey, Signature,
    TreeAddr,
};
pub use wire::{Decode, DecodeError, Encode, Message};

// Re-export constants
pub use types::{
    ALGORITHM_ED25519, DEFAULT_TTL, K_REPLICAS, MAX_CHILDREN, MAX_PACKET_SIZE, MSG_DATA, MSG_FOUND,
    MSG_LOOKUP, MSG_PUBLISH,
};

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::node::JoinContext;
    use crate::traits::test_impls::{MockClock, MockCrypto, MockRandom, MockTransport};

    #[test]
    fn test_node_creation() {
        let transport = MockTransport::new();
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node = Node::new(transport, crypto, random, clock);

        // Node should be root of its own single-node tree
        assert!(node.is_root());
        assert_eq!(node.tree_size(), 1);
        assert_eq!(node.subtree_size(), 1);
        assert!(node.tree_addr().is_empty());
    }

    #[test]
    fn test_node_identity() {
        let transport = MockTransport::new();
        let mut crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        // Generate a keypair manually
        let (pubkey, secret) = crypto.generate_keypair();
        let node_id = crypto.node_id_from_pubkey(&pubkey);

        let node = Node::with_identity(transport, crypto, random, clock, node_id, pubkey, secret);

        assert_eq!(*node.node_id(), node_id);
        assert_eq!(*node.pubkey(), pubkey);
    }

    #[test]
    fn test_pulse_roundtrip() {
        let pulse = Pulse {
            node_id: [1u8; 16],
            parent_id: None,
            root_id: [1u8; 16],
            subtree_size: 1,
            tree_size: 1,
            tree_addr: vec![],
            need_pubkey: false,
            pubkey: None,
            child_prefix_len: 0,
            children: vec![],
            signature: Signature::default(),
        };

        let encoded = pulse.encode_to_vec();
        let decoded = Pulse::decode_from_slice(&encoded).unwrap();

        assert_eq!(pulse.node_id, decoded.node_id);
        assert_eq!(pulse.parent_id, decoded.parent_id);
        assert_eq!(pulse.tree_size, decoded.tree_size);
    }

    #[test]
    fn test_tau_lora_bandwidth() {
        // LoRa: 38 bytes/sec, 255 byte MTU
        // tau = 255 / 38 * 1000 = 6710 ms
        let transport = MockTransport::with_mtu_and_bw(255, Some(38));
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node = Node::new(transport, crypto, random, clock);
        let tau = node.tau();

        assert_eq!(tau.as_millis(), 6710);
    }

    #[test]
    fn test_tau_no_bandwidth() {
        // No bandwidth limit: should use MIN_TAU_MS (100ms)
        let transport = MockTransport::new(); // bw = None
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node = Node::new(transport, crypto, random, clock);
        let tau = node.tau();

        assert_eq!(tau.as_millis(), 100);
    }

    #[test]
    fn test_tau_high_bandwidth() {
        // High bandwidth (e.g., UDP): MTU / bw would be < MIN_TAU_MS
        // 512 byte MTU, 100000 bytes/sec -> 5.12ms, should floor to 100ms
        let transport = MockTransport::with_mtu_and_bw(512, Some(100_000));
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node = Node::new(transport, crypto, random, clock);
        let tau = node.tau();

        assert_eq!(tau.as_millis(), 100);
    }

    #[test]
    fn test_lookup_timeout() {
        // LoRa: tau = 6710ms, lookup_timeout = 32 * tau = 214720ms (~3.6 min)
        let transport = MockTransport::with_mtu_and_bw(255, Some(38));
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node = Node::new(transport, crypto, random, clock);
        let timeout = node.lookup_timeout();

        assert_eq!(timeout.as_millis(), 6710 * 32);
    }

    #[test]
    fn test_fraud_detection_triggers() {
        // Test that fraud detection fires when PUBLISH count is too low
        let transport = MockTransport::new();
        let crypto = MockCrypto::new();
        let random = MockRandom::new();
        let clock = MockClock::new();

        let mut node = Node::new(transport, crypto, random, clock);

        // Without join context, fraud detection should not trigger
        let now = Timestamp::from_secs(7200); // 2 hours
        assert!(!node.check_tree_size_fraud(now));

        // Set up join context (required for fraud detection)
        let fake_parent = [1u8; 16];
        node.set_join_context(Some(JoinContext {
            parent_at_join: fake_parent,
            join_time: Timestamp::ZERO,
        }));

        // Initialize fraud detection: subtree_size=10, starting at t=0
        node.fraud_detection_mut().reset(Timestamp::ZERO, 10);

        // After 2 hours with subtree_size=10:
        // expected = 3.0 * 10 * (2/8) = 7.5 PUBLISH messages
        // With 0 observed, z = 7.5 / sqrt(7.5) = 2.74 > 2.33 threshold
        assert!(node.check_tree_size_fraud(now));

        // Now record enough PUBLISH messages to avoid fraud detection
        // Need observed close to expected (7.5), let's do 6
        for _ in 0..6 {
            node.fraud_detection_mut().on_publish_received();
        }
        // z = (7.5 - 6) / sqrt(7.5) = 0.55 < 2.33
        assert!(!node.check_tree_size_fraud(now));
    }
}
