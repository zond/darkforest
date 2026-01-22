//! darktree - Tree-based DHT protocol for LoRa mesh networks
//!
//! A protocol for building mesh networks over LoRa radios with O(log N) routing.
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
//! ```no_run
//! use darktree::{Node, Transport, Crypto, Random, Clock};
//!
//! // Implement traits for your platform...
//!
//! // Create a node
//! // let mut node = Node::new(transport, crypto, random, clock);
//!
//! // Poll regularly in your main loop
//! // loop {
//! //     while let Some(event) = node.poll() {
//! //         // Handle events
//! //     }
//! // }
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

pub mod dht;
pub mod fraud;
pub mod node;
pub mod routing;
pub mod traits;
pub mod tree;
pub mod types;
pub mod wire;

// Re-export main types at crate root
pub use node::Node;
pub use traits::{Clock, Crypto, Random, Transport};
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
    use super::*;
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
}
