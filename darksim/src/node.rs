//! SimNode wrapper for simulated darktree nodes.

use std::cell::Cell;
use std::future::{ready, Ready};

use darktree::config::DefaultConfig;
use darktree::traits::{
    Clock, Crypto, Random, Received, Transport, TransportInChannel, TransportOutChannel,
};
use darktree::{Duration, Node, NodeId, OutgoingData, PublicKey, SecretKey, Signature, Timestamp};
use embassy_sync::channel::Channel;

/// Mock transport for simulation.
///
/// Provides separate protocol and app channels, and tracks MTU/bandwidth.
pub struct SimTransport {
    mtu: usize,
    bw: Option<u32>,
    protocol_outgoing: TransportOutChannel,
    app_outgoing: TransportOutChannel,
    incoming: TransportInChannel,
}

impl SimTransport {
    pub fn new() -> Self {
        Self {
            mtu: 255,
            bw: None,
            protocol_outgoing: Channel::new(),
            app_outgoing: Channel::new(),
            incoming: Channel::new(),
        }
    }

    pub fn with_bandwidth(mut self, bw: u32) -> Self {
        self.bw = Some(bw);
        self
    }

    /// Inject a message as if received from the radio.
    pub fn inject_rx(&self, data: Vec<u8>, rssi: Option<i16>) {
        let _ = self.incoming.try_send(Received { data, rssi });
    }

    /// Take all outgoing messages (protocol first, then app).
    pub fn take_sent(&self) -> Vec<Vec<u8>> {
        let mut msgs = Vec::new();
        while let Ok(msg) = self.protocol_outgoing.try_receive() {
            msgs.push(msg);
        }
        while let Ok(msg) = self.app_outgoing.try_receive() {
            msgs.push(msg);
        }
        msgs
    }
}

impl Default for SimTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for SimTransport {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn bw(&self) -> Option<u32> {
        self.bw
    }

    fn protocol_outgoing(&self) -> &TransportOutChannel {
        &self.protocol_outgoing
    }

    fn app_outgoing(&self) -> &TransportOutChannel {
        &self.app_outgoing
    }

    fn incoming(&self) -> &TransportInChannel {
        &self.incoming
    }
}

/// Mock clock for simulation.
///
/// Time is controlled externally by the simulator.
pub struct SimClock {
    current: Cell<Timestamp>,
}

impl SimClock {
    pub fn new() -> Self {
        Self {
            current: Cell::new(Timestamp::ZERO),
        }
    }

    pub fn at(time: Timestamp) -> Self {
        Self {
            current: Cell::new(time),
        }
    }

    pub fn set(&self, time: Timestamp) {
        self.current.set(time);
    }

    pub fn advance(&self, duration: Duration) {
        self.current.set(self.current.get() + duration);
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SimClock {
    type SleepFuture<'a> = Ready<()>;

    fn now(&self) -> Timestamp {
        self.current.get()
    }

    fn sleep_until(&self, _time: Timestamp) -> Self::SleepFuture<'_> {
        ready(())
    }
}

/// Mock crypto for simulation (deterministic, NOT cryptographically secure).
pub struct SimCrypto {
    next_keypair_seed: u8,
}

impl SimCrypto {
    pub fn new() -> Self {
        Self {
            next_keypair_seed: 0,
        }
    }

    pub fn with_seed(seed: u8) -> Self {
        Self {
            next_keypair_seed: seed,
        }
    }
}

impl Default for SimCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Crypto for SimCrypto {
    fn algorithm(&self) -> u8 {
        0x01 // Ed25519
    }

    fn sign(&self, secret: &SecretKey, message: &[u8]) -> Signature {
        let mut sig = [0u8; 64];
        let hash = self.hash(&[secret.as_slice(), message].concat());
        sig[..32].copy_from_slice(&hash);
        sig[32..].copy_from_slice(&hash);
        Signature {
            algorithm: self.algorithm(),
            sig,
        }
    }

    fn verify(&self, _pubkey: &PublicKey, _message: &[u8], sig: &Signature) -> bool {
        sig.algorithm == self.algorithm() && sig.sig[..32] != [0u8; 32]
    }

    fn generate_keypair(&mut self) -> (PublicKey, SecretKey) {
        let seed = self.next_keypair_seed;
        self.next_keypair_seed = self.next_keypair_seed.wrapping_add(1);

        let mut secret = [seed; 32];
        secret[0] = seed;
        secret[1] = seed.wrapping_add(1);

        let pubkey = self.hash(&secret);
        (pubkey, secret)
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
            hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(byte);
        }
        hash
    }
}

/// Mock random for simulation (deterministic LCG).
pub struct SimRandom {
    state: u64,
}

impl SimRandom {
    pub fn new() -> Self {
        Self { state: 12345 }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl Default for SimRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl Random for SimRandom {
    fn gen_range(&mut self, min: u64, max: u64) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let range = max - min;
        if range == 0 {
            return min;
        }
        min + (self.state % range)
    }
}

/// Type alias for simulated nodes.
pub type SimNodeInner = Node<SimTransport, SimCrypto, SimRandom, SimClock, DefaultConfig>;

/// Wrapper around a darktree Node for simulation.
pub struct SimNode {
    /// The underlying darktree node.
    inner: SimNodeInner,
    /// When the node was created.
    pub created_at: Timestamp,
}

impl SimNode {
    /// Create a new SimNode with given seed for deterministic identity.
    pub fn new(seed: u64, created_at: Timestamp) -> Self {
        let transport = SimTransport::new();
        let crypto = SimCrypto::with_seed((seed & 0xFF) as u8);
        let random = SimRandom::with_seed(seed);
        let clock = SimClock::at(created_at);

        let inner = Node::new(transport, crypto, random, clock);

        Self { inner, created_at }
    }

    /// Create a SimNode with bandwidth-limited transport (for LoRa simulation).
    pub fn with_bandwidth(seed: u64, created_at: Timestamp, bw: u32) -> Self {
        let transport = SimTransport::new().with_bandwidth(bw);
        let crypto = SimCrypto::with_seed((seed & 0xFF) as u8);
        let random = SimRandom::with_seed(seed);
        let clock = SimClock::at(created_at);

        let inner = Node::new(transport, crypto, random, clock);

        Self { inner, created_at }
    }

    /// Get the node's ID.
    pub fn node_id(&self) -> NodeId {
        *self.inner.node_id()
    }

    /// Get a reference to the inner node.
    pub fn inner(&self) -> &SimNodeInner {
        &self.inner
    }

    /// Get a mutable reference to the inner node.
    pub fn inner_mut(&mut self) -> &mut SimNodeInner {
        &mut self.inner
    }

    /// Check if this node is the root of its tree.
    pub fn is_root(&self) -> bool {
        self.inner.is_root()
    }

    /// Check if this node is in shopping phase (looking for parent).
    pub fn is_shopping(&self) -> bool {
        self.inner.is_shopping()
    }

    /// Get the tree size.
    pub fn tree_size(&self) -> u32 {
        self.inner.tree_size()
    }

    /// Get the subtree size.
    pub fn subtree_size(&self) -> u32 {
        self.inner.subtree_size()
    }

    /// Get the root hash.
    pub fn root_hash(&self) -> [u8; 4] {
        *self.inner.root_hash()
    }

    /// Get the keyspace range.
    pub fn keyspace_range(&self) -> (u32, u32) {
        self.inner.keyspace_range()
    }

    /// Get the parent node ID, if any.
    pub fn parent_id(&self) -> Option<NodeId> {
        self.inner.parent_id()
    }

    /// Get the number of children.
    pub fn children_count(&self) -> usize {
        self.inner.children_count()
    }

    /// Get the number of known neighbors.
    pub fn neighbor_count(&self) -> usize {
        self.inner.neighbor_count()
    }

    /// Get tau (bandwidth-aware time unit).
    pub fn tau(&self) -> Duration {
        self.inner.tau()
    }

    /// Handle an incoming transport message.
    pub fn handle_transport_rx(&mut self, data: &[u8], rssi: Option<i16>, now: Timestamp) {
        // Update the clock so any code that reads clock.now() gets correct time
        self.inner.clock().set(now);
        self.inner.handle_transport_rx(data, rssi, now);
    }

    /// Handle timer events.
    pub fn handle_timer(&mut self, now: Timestamp) {
        // Update the clock so any code that reads clock.now() gets correct time
        self.inner.clock().set(now);
        self.inner.handle_timer(now);
    }

    /// Send application data to a target node.
    pub fn app_send(&mut self, target: NodeId, payload: Vec<u8>, now: Timestamp) {
        self.inner
            .handle_app_send(OutgoingData { target, payload }, now);
    }

    /// Take all outgoing messages from the transport.
    pub fn take_outgoing(&self) -> Vec<Vec<u8>> {
        self.inner.transport().take_sent()
    }

    /// Get the node's public key.
    pub fn pubkey(&self) -> PublicKey {
        *self.inner.pubkey()
    }

    /// Take all debug events from the node's debug channel.
    pub fn take_debug_events(&self) -> Vec<darktree::debug::DebugEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.inner.debug_channel().try_receive() {
            events.push(event);
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simnode_creation() {
        let node = SimNode::new(42, Timestamp::ZERO);
        assert!(node.is_root());
        assert_eq!(node.tree_size(), 1);
        assert_eq!(node.subtree_size(), 1);
    }

    #[test]
    fn test_simnode_identity_deterministic() {
        let node1 = SimNode::new(42, Timestamp::ZERO);
        let node2 = SimNode::new(42, Timestamp::ZERO);
        assert_eq!(node1.node_id(), node2.node_id());

        let node3 = SimNode::new(43, Timestamp::ZERO);
        assert_ne!(node1.node_id(), node3.node_id());
    }

    #[test]
    fn test_simnode_with_bandwidth() {
        // LoRa: 38 bytes/sec, tau = 255/38 = 6710ms
        let node = SimNode::with_bandwidth(42, Timestamp::ZERO, 38);
        assert_eq!(node.tau().as_millis(), 6710);
    }

    #[test]
    fn test_simnode_timer_fires_pulse() {
        let mut node = SimNode::new(42, Timestamp::ZERO);

        // Initialize the node (sends first pulse)
        node.inner_mut().initialize(Timestamp::ZERO);

        // Should have sent a pulse during initialization
        let msgs = node.take_outgoing();
        assert!(!msgs.is_empty(), "Should have sent at least one message");
    }
}
