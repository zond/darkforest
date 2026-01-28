//! SimNode wrapper for simulated darktree nodes.

use std::cell::Cell;
use std::future::{ready, Ready};
use std::sync::{Arc, Mutex};

use darktree::config::DefaultConfig;
use darktree::traits::{
    test_impls::FastTestCrypto, Clock, PriorityQueue, Random, Transport, TransportInChannel,
};
use darktree::{Duration, Incoming, Node, NodeId, OutgoingData, PublicKey, Timestamp};
use embassy_sync::channel::Channel;

/// Debug emitter that collects events into a shared Vec.
///
/// # Simulation Only
///
/// This emitter uses `std::sync::Mutex` which can block and panic on contention.
/// It is intended only for use in the simulation crate (darksim), not for embedded
/// deployment. Do not use in interrupt service routines or real-time contexts.
pub struct VecEmitter {
    events: Arc<Mutex<Vec<darktree::debug::DebugEvent>>>,
}

impl VecEmitter {
    pub fn new(events: Arc<Mutex<Vec<darktree::debug::DebugEvent>>>) -> Self {
        Self { events }
    }
}

impl darktree::debug::DebugEmitter for VecEmitter {
    fn emit(&mut self, event: darktree::debug::DebugEvent) {
        self.events.lock().unwrap().push(event);
    }
}

/// Debug emitter that prints events to stderr with node identification.
/// Events are printed immediately as they occur, providing chronological output.
pub struct PrintEmitter {
    node_idx: usize,
    node_id_short: [u8; 4],
}

impl PrintEmitter {
    pub fn new(node_idx: usize, node_id: &NodeId) -> Self {
        Self {
            node_idx,
            node_id_short: [node_id[0], node_id[1], node_id[2], node_id[3]],
        }
    }
}

impl darktree::debug::DebugEmitter for PrintEmitter {
    fn emit(&mut self, event: darktree::debug::DebugEvent) {
        eprintln!(
            "Node {:2} {:?}: {:?}",
            self.node_idx, self.node_id_short, event
        );
    }
}

/// Timestamped debug event with node identification.
#[derive(Debug, Clone)]
pub struct TimestampedEvent {
    pub time_ms: u64,
    pub node_idx: usize,
    pub node_id_short: [u8; 4],
    pub event: darktree::debug::DebugEvent,
}

/// Debug emitter that collects timestamped events into a shared Vec.
/// All nodes can share one SharedEmitter for chronological cross-node output.
///
/// # Simulation Only
///
/// This emitter uses `std::sync::Mutex` which can block and panic on contention.
/// It is intended only for use in the simulation crate (darksim), not for embedded
/// deployment. Do not use in interrupt service routines or real-time contexts.
pub struct SharedEmitter {
    events: Arc<Mutex<Vec<TimestampedEvent>>>,
    node_idx: usize,
    node_id_short: [u8; 4],
    time_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl SharedEmitter {
    pub fn new(
        events: Arc<Mutex<Vec<TimestampedEvent>>>,
        node_idx: usize,
        node_id: &NodeId,
        time_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            events,
            node_idx,
            node_id_short: [node_id[0], node_id[1], node_id[2], node_id[3]],
            time_ms: time_fn,
        }
    }
}

impl darktree::debug::DebugEmitter for SharedEmitter {
    fn emit(&mut self, event: darktree::debug::DebugEvent) {
        self.events.lock().unwrap().push(TimestampedEvent {
            time_ms: (self.time_ms)(),
            node_idx: self.node_idx,
            node_id_short: self.node_id_short,
            event,
        });
    }
}

/// Queue size for SimTransport.
const SIM_QUEUE_SIZE: usize = 32;

/// Mock transport for simulation.
///
/// Uses a single priority queue for all outgoing messages.
pub struct SimTransport {
    mtu: usize,
    bw: Option<u32>,
    outgoing: PriorityQueue,
    incoming: TransportInChannel,
}

impl SimTransport {
    pub fn new() -> Self {
        Self {
            mtu: 255,
            bw: None,
            outgoing: PriorityQueue::new(SIM_QUEUE_SIZE),
            incoming: Channel::new(),
        }
    }

    pub fn with_bandwidth(mut self, bw: u32) -> Self {
        self.bw = Some(bw);
        self
    }

    /// Inject a message as if received from the radio.
    pub fn inject_rx(&self, data: Vec<u8>, rssi: Option<i16>) {
        let _ = self.incoming.try_send(Incoming::new(data, rssi));
    }

    /// Take all outgoing messages in priority order.
    pub fn take_sent(&self) -> Vec<Vec<u8>> {
        let mut msgs = Vec::new();
        while let Some(msg) = self.outgoing.try_receive() {
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

    fn outgoing(&self) -> &PriorityQueue {
        &self.outgoing
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
pub type SimNodeInner = Node<SimTransport, FastTestCrypto, SimRandom, SimClock, DefaultConfig>;

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
        let crypto = FastTestCrypto::new(seed);
        let random = SimRandom::with_seed(seed);
        let clock = SimClock::at(created_at);

        let inner = Node::new(transport, crypto, random, clock);

        Self { inner, created_at }
    }

    /// Create a SimNode with bandwidth-limited transport (for LoRa simulation).
    pub fn with_bandwidth(seed: u64, created_at: Timestamp, bw: u32) -> Self {
        let transport = SimTransport::new().with_bandwidth(bw);
        let crypto = FastTestCrypto::new(seed);
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

    /// Set a custom debug emitter for this node.
    /// Use this to redirect debug events to a shared collector or printer.
    pub fn set_debug_emitter(&self, emitter: Box<dyn darktree::debug::DebugEmitter>) {
        self.inner.set_debug_emitter(emitter);
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
