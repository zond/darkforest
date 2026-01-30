#![forbid(unsafe_code)]
//! darktree - Tree-based DHT protocol for LoRa mesh networks
//!
//! A protocol for building mesh networks over LoRa radios with O(log N) routing.
//!
//! This crate is `no_std` but **requires the `alloc` crate**. It uses heap-allocated
//! collections (`Vec`, `HashMap`, `BTreeMap`) with runtime-enforced capacity limits.
//! See [`PriorityQueue`](traits::PriorityQueue) documentation for rationale.
//!
//! # Platform Requirements
//!
//! - **RAM**: 256KB minimum, 512KB recommended (ESP32-class devices)
//! - **Allocator**: Use a real-time allocator like `embedded-alloc` with TLSF, or
//!   your platform's allocator (e.g., `esp-alloc`). Avoid `linked_list_allocator`
//!   or `wee_alloc` which handle fragmentation poorly.
//! - **Embassy**: Compatible with embassy async runtime
//!
//! # Key Properties
//!
//! - Nodes form a spanning tree via periodic broadcasts
//! - Keyspace-based routing: each node owns a range [lo, hi) of the 32-bit keyspace
//! - A distributed hash table maps node IDs to keyspace addresses
//! - Ed25519 signatures prevent impersonation
//! - No clock synchronization required
//!
//! # Example (basic usage)
//!
//! ```
//! use darktree::{Node, DefaultConfig};
//! use darktree::traits::test_impls::{MockTransport, FastTestCrypto, MockRandom, MockClock};
//!
//! // Create a node with mock implementations
//! let node = Node::<_, _, _, _, DefaultConfig>::new(
//!     MockTransport::new(),
//!     FastTestCrypto::new(0),
//!     MockRandom::new(),
//!     MockClock::new(),
//! );
//!
//! // Node starts as root of its own single-node tree
//! assert!(node.is_root());
//! assert_eq!(node.tree_size(), 1);
//! assert_eq!(node.subtree_size(), 1);
//!
//! // Node owns the full keyspace initially
//! let (lo, hi) = node.keyspace_range();
//! assert_eq!(lo, 0);
//! assert_eq!(hi, u32::MAX);
//! ```
//!
//! # Example (integration pattern)
//!
//! ```text
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
//! - [`config`] - Compile-time memory configuration

#![no_std]

// Prevent test/debug features from being used in release builds.
#[cfg(all(feature = "test-support", not(test), not(debug_assertions)))]
compile_error!(
    "The `test-support` feature must not be enabled in release builds. \
     It includes mock crypto implementations that are NOT cryptographically secure."
);

#[cfg(all(feature = "debug", not(test), not(debug_assertions)))]
compile_error!(
    "The `debug` feature must not be enabled in release builds. \
     It adds protocol tracing overhead intended only for development and simulation."
);

extern crate alloc;

pub mod children;
pub mod collections;
pub mod config;
#[macro_use]
pub mod debug;
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
pub use config::{DefaultConfig, NodeConfig, SmallConfig};
pub use node::Node;
pub use time::{Duration, Timestamp};
pub use traits::{Ackable, Clock, Crypto, IncomingData, Outgoing, OutgoingData, Random, Transport};
pub use types::{
    Error, Event, IdHash, Incoming, LocationEntry, NodeId, Payload, PreEncoded, Priority,
    PublicKey, Pulse, Routed, SecretKey, Signature,
};
pub use wire::{Decode, DecodeError, Encode, Message};

// Re-export constants
pub use types::{
    ALGORITHM_ED25519, DEFAULT_TTL, DISTRUST_TTL, K_REPLICAS, MAX_CHILDREN, MAX_PACKET_SIZE,
    MSG_DATA, MSG_FOUND, MSG_LOOKUP, MSG_PUBLISH,
};

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::node::JoinContext;
    use crate::traits::test_impls::{FastTestCrypto, MockClock, MockRandom, MockTransport};

    /// Type alias for test nodes using default config.
    type TestNode = Node<MockTransport, FastTestCrypto, MockRandom, MockClock, DefaultConfig>;

    #[test]
    fn test_node_creation() {
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);

        // Node should be root of its own single-node tree
        assert!(node.is_root());
        assert_eq!(node.tree_size(), 1);
        assert_eq!(node.subtree_size(), 1);
        // Node starts with full keyspace
        assert_eq!(node.keyspace_range(), (0, u32::MAX));
    }

    #[test]
    fn test_node_identity() {
        let transport = MockTransport::new();
        let mut crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        // Generate a keypair manually
        let (pubkey, secret) = crypto.generate_keypair();
        let node_id = crypto.node_id_from_pubkey(&pubkey);

        let node: TestNode =
            Node::with_identity(transport, crypto, random, clock, node_id, pubkey, secret);

        assert_eq!(*node.node_id(), node_id);
        assert_eq!(*node.pubkey(), pubkey);
    }

    #[test]
    fn test_pulse_roundtrip() {
        let pulse = Pulse {
            node_id: [1u8; 16],
            flags: Pulse::build_flags(false, false, false, false, 0),
            parent_hash: None,
            root_hash: [1u8, 2, 3, 4],
            depth: 0,
            max_depth: 0,
            subtree_size: 1,
            tree_size: 1,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: Signature::default(),
        };

        let encoded = pulse.encode_to_vec().unwrap();
        let decoded = Pulse::decode_from_slice(&encoded).unwrap();

        assert_eq!(pulse.node_id, decoded.node_id);
        assert_eq!(pulse.parent_hash, decoded.parent_hash);
        assert_eq!(pulse.tree_size, decoded.tree_size);
        assert_eq!(pulse.keyspace_lo, decoded.keyspace_lo);
        assert_eq!(pulse.keyspace_hi, decoded.keyspace_hi);
    }

    #[test]
    fn test_tau_lora_bandwidth() {
        // LoRa: 38 bytes/sec, 255 byte MTU
        // tau = 255 / 38 * 1000 = 6710 ms
        let transport = MockTransport::with_mtu_and_bw(255, Some(38));
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);
        let tau = node.tau();

        assert_eq!(tau.as_millis(), 6710);
    }

    #[test]
    fn test_tau_no_bandwidth() {
        // No bandwidth limit: should use MIN_TAU_MS (100ms)
        let transport = MockTransport::new(); // bw = None
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);
        let tau = node.tau();

        assert_eq!(tau.as_millis(), 100);
    }

    #[test]
    fn test_tau_high_bandwidth() {
        // High bandwidth (e.g., UDP): MTU / bw would be < MIN_TAU_MS
        // 512 byte MTU, 100000 bytes/sec -> 5.12ms, should floor to 100ms
        let transport = MockTransport::with_mtu_and_bw(512, Some(100_000));
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);
        let tau = node.tau();

        assert_eq!(tau.as_millis(), 100);
    }

    #[test]
    fn test_lookup_timeout() {
        // LoRa: tau = 6710ms, lookup_timeout = tau * (3 + 3*max_depth)
        // With max_depth=0 (default), timeout = 3 * tau = 20130ms
        let transport = MockTransport::with_mtu_and_bw(255, Some(38));
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);
        // New node has max_depth=0, so multiplier is 3 + 3*0 = 3
        let timeout = node.lookup_timeout();
        assert_eq!(timeout.as_millis(), 6710 * 3);
    }

    #[test]
    fn test_fraud_detection_triggers() {
        // Test that fraud detection fires when unique publisher count is too low
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let mut node: TestNode = Node::new(transport, crypto, random, clock);

        // Without join context, fraud detection should not trigger
        let now = Timestamp::from_secs(8 * 3600); // 8 hours
        assert!(!node.check_tree_size_fraud(now));

        // Set up join context (required for fraud detection)
        let fake_parent = [1u8; 16];
        node.set_join_context(Some(JoinContext {
            parent_at_join: fake_parent,
            join_time: Timestamp::ZERO,
        }));

        // Initialize fraud detection: subtree_size=10, starting at t=0
        node.fraud_detection_mut().reset(Timestamp::ZERO, 10);

        // After 8 hours with subtree_size=10:
        // expected = 10 unique publishers
        // With 0 observed, z = 10 / sqrt(10) = 3.16 > 2.33 threshold
        assert!(node.check_tree_size_fraud(now));

        // Now record enough unique PUBLISH messages to avoid fraud detection
        // Need HLL estimate close to expected (10), let's add 10 unique publishers
        let key = *node.hll_secret_key();
        for i in 0..10 {
            let publisher = [i; 16];
            node.fraud_detection_mut().add_publisher(&publisher, &key);
        }
        // With ~10 observed and expected=10, z ≈ 0 < 2.33 threshold
        assert!(!node.check_tree_size_fraud(now));
    }

    #[test]
    fn test_keyspace_ownership() {
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);

        // Node starts with full keyspace [0, u32::MAX)
        assert!(node.owns_key(0));
        assert!(node.owns_key(u32::MAX / 2));
        assert!(node.owns_key(u32::MAX - 1));
        // Note: hi is exclusive, so MAX itself is not owned
    }

    #[test]
    fn test_my_address() {
        let transport = MockTransport::new();
        let crypto = FastTestCrypto::new(0);
        let random = MockRandom::new();
        let clock = MockClock::new();

        let node: TestNode = Node::new(transport, crypto, random, clock);

        // my_address() should be center of keyspace range
        // For [0, MAX): center = MAX/2
        let addr = node.my_address();
        assert_eq!(addr, u32::MAX / 2);
    }
}
