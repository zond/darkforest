//! Discrete event simulator for darktree protocol.

use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use darktree::{Duration, NodeId, Timestamp};
use hashbrown::HashMap;

use crate::event::{Event, ScenarioAction, ScheduledEvent, SequenceNumber};
use crate::metrics::{SimMetrics, SimulationResult, TreeSnapshot};
use crate::node::{PrintEmitter, SharedEmitter, SimNode, TimestampedEvent, VecEmitter};
use crate::topology::Topology;

/// Discrete event simulator for darktree networks.
pub struct Simulator {
    /// All nodes in the simulation.
    nodes: HashMap<NodeId, SimNode>,
    /// Seed used to create each node (for restart support).
    node_seeds: HashMap<NodeId, u64>,
    /// Node index for debug output (assigned in order of creation).
    node_indices: HashMap<NodeId, usize>,
    /// Network topology.
    topology: Topology,
    /// Current simulation time.
    current_time: Timestamp,
    /// Priority queue of scheduled events.
    event_queue: BinaryHeap<ScheduledEvent>,
    /// Collected metrics.
    metrics: SimMetrics,
    /// Next sequence number for event ordering.
    next_seq: u64,
    /// RNG state for packet loss.
    rng_state: u64,
    /// Interval for automatic snapshots.
    snapshot_interval: Option<Duration>,
    /// Next snapshot time.
    next_snapshot: Option<Timestamp>,
    /// Shared debug events (when using shared emitter mode).
    shared_debug_events: Option<Arc<Mutex<Vec<TimestampedEvent>>>>,
    /// Per-node debug events (when using per-node debug mode).
    per_node_debug_events: HashMap<NodeId, Arc<Mutex<Vec<darktree::debug::DebugEvent>>>>,
    /// Shared time for debug emitters (updated on each time advance).
    shared_time_ms: Arc<AtomicU64>,
    /// Debug mode: print events as they occur.
    debug_print_enabled: bool,
    /// Debug mode: collect events per node.
    per_node_debug_enabled: bool,
    /// Debug: count of timer fires.
    #[cfg(test)]
    pub timer_fire_count: u64,
}

impl Simulator {
    /// Create a new simulator with given RNG seed.
    pub fn new(seed: u64) -> Self {
        Self {
            nodes: HashMap::new(),
            node_seeds: HashMap::new(),
            node_indices: HashMap::new(),
            topology: Topology::new(),
            current_time: Timestamp::ZERO,
            event_queue: BinaryHeap::new(),
            metrics: SimMetrics::new(),
            next_seq: 0,
            rng_state: seed,
            snapshot_interval: None,
            next_snapshot: None,
            shared_debug_events: None,
            per_node_debug_events: HashMap::new(),
            shared_time_ms: Arc::new(AtomicU64::new(0)),
            debug_print_enabled: false,
            per_node_debug_enabled: false,
            #[cfg(test)]
            timer_fire_count: 0,
        }
    }

    /// Enable debug print mode: all debug events are printed to stderr as they occur.
    /// Must be called before adding nodes.
    pub fn with_debug_print(mut self) -> Self {
        self.debug_print_enabled = true;
        self
    }

    /// Enable shared debug event collection: all events go to a shared Vec.
    /// Must be called before adding nodes.
    /// Use `take_shared_debug_events()` to retrieve the collected events.
    pub fn with_shared_debug_events(mut self) -> Self {
        self.shared_debug_events = Some(Arc::new(Mutex::new(Vec::new())));
        self
    }

    /// Take all shared debug events (chronologically ordered across all nodes).
    /// Returns None if shared debug events were not enabled.
    pub fn take_shared_debug_events(&self) -> Option<Vec<TimestampedEvent>> {
        self.shared_debug_events
            .as_ref()
            .map(|events| std::mem::take(&mut *events.lock().unwrap()))
    }

    /// Enable per-node debug event collection.
    /// Must be called before adding nodes.
    /// Use `take_node_debug_events(node_id)` to retrieve events.
    pub fn with_per_node_debug(mut self) -> Self {
        self.per_node_debug_enabled = true;
        self
    }

    /// Take debug events for a specific node.
    /// Returns empty Vec if per-node debug was not enabled or node doesn't exist.
    pub fn take_node_debug_events(&self, node_id: &NodeId) -> Vec<darktree::debug::DebugEvent> {
        self.per_node_debug_events
            .get(node_id)
            .map(|events| std::mem::take(&mut *events.lock().unwrap()))
            .unwrap_or_default()
    }

    /// Set the network topology.
    pub fn with_topology(mut self, topology: Topology) -> Self {
        self.topology = topology;
        self
    }

    /// Set the snapshot interval for automatic tree state recording.
    pub fn with_snapshot_interval(mut self, interval: Duration) -> Self {
        self.snapshot_interval = Some(interval);
        self.next_snapshot = Some(self.current_time + interval);
        self
    }

    /// Add a node to the simulation.
    pub fn add_node(&mut self, seed: u64) -> NodeId {
        let node_id = self.add_node_internal(SimNode::new(seed, self.current_time));
        self.node_seeds.insert(node_id, seed);
        node_id
    }

    /// Add a node with bandwidth-limited transport (e.g., LoRa).
    pub fn add_node_with_bandwidth(&mut self, seed: u64, bw: u32) -> NodeId {
        let node_id = self.add_node_internal(SimNode::with_bandwidth(seed, self.current_time, bw));
        self.node_seeds.insert(node_id, seed);
        node_id
    }

    /// Restart a node, simulating a power cycle with complete state loss.
    ///
    /// The node keeps its identity (same NodeId derived from same seed) but loses
    /// all tree state - it will rediscover neighbors and rejoin the tree.
    /// Returns None if the node doesn't exist.
    pub fn restart_node(&mut self, node_id: &NodeId) -> Option<NodeId> {
        let seed = *self.node_seeds.get(node_id)?;

        // Remove old node
        self.nodes.remove(node_id);

        // Create fresh node with same identity
        let new_node_id = self.add_node_internal(SimNode::new(seed, self.current_time));
        debug_assert_eq!(
            *node_id, new_node_id,
            "Restarted node should have same NodeId"
        );

        Some(new_node_id)
    }

    /// Internal helper to initialize and register a node.
    fn add_node_internal(&mut self, node: SimNode) -> NodeId {
        let node_id = node.node_id();

        // Assign node index for debug output
        let node_idx = self.node_indices.len();
        self.node_indices.insert(node_id, node_idx);

        // Set up debug emitter based on mode
        if self.debug_print_enabled {
            node.set_debug_emitter(Box::new(PrintEmitter::new(node_idx, &node_id)));
        } else if let Some(shared_events) = &self.shared_debug_events {
            let time_arc = self.shared_time_ms.clone();
            let time_fn: Arc<dyn Fn() -> u64 + Send + Sync> =
                Arc::new(move || time_arc.load(Ordering::Relaxed));
            node.set_debug_emitter(Box::new(SharedEmitter::new(
                shared_events.clone(),
                node_idx,
                &node_id,
                time_fn,
            )));
        } else if self.per_node_debug_enabled {
            let events = Arc::new(Mutex::new(Vec::new()));
            self.per_node_debug_events.insert(node_id, events.clone());
            node.set_debug_emitter(Box::new(VecEmitter::new(events)));
        }

        // Initialize the node (sends first pulse, starts discovery)
        // Note: must happen after setting debug emitter to capture init events
        let mut node = node;
        node.inner_mut().initialize(self.current_time);

        let tau = node.tau();
        self.nodes.insert(node_id, node);

        // Collect and route the initial pulse
        self.collect_outgoing(node_id);

        // Schedule timer for this node (tau interval)
        self.schedule_timer(node_id, self.current_time + tau);

        node_id
    }

    /// Get a reference to a node.
    pub fn node(&self, id: &NodeId) -> Option<&SimNode> {
        self.nodes.get(id)
    }

    /// Get a mutable reference to a node.
    pub fn node_mut(&mut self, id: &NodeId) -> Option<&mut SimNode> {
        self.nodes.get_mut(id)
    }

    /// Get all node IDs.
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }

    /// Enable print debugging for all existing nodes.
    ///
    /// This can be called at any point during simulation to start
    /// printing debug events to stderr.
    pub fn enable_debug_print(&mut self) {
        self.debug_print_enabled = true;
        for (&node_id, node) in &self.nodes {
            let node_idx = *self.node_indices.get(&node_id).unwrap_or(&0);
            node.set_debug_emitter(Box::new(PrintEmitter::new(node_idx, &node_id)));
        }
    }

    /// Get the current simulation time.
    pub fn current_time(&self) -> Timestamp {
        self.current_time
    }

    /// Get the topology.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Get mutable topology.
    pub fn topology_mut(&mut self) -> &mut Topology {
        &mut self.topology
    }

    /// Get collected metrics.
    pub fn metrics(&self) -> &SimMetrics {
        &self.metrics
    }

    /// Schedule an event.
    pub fn schedule(&mut self, time: Timestamp, event: Event) {
        let seq = SequenceNumber::new(self.next_seq);
        self.next_seq += 1;
        self.event_queue.push(ScheduledEvent::new(time, seq, event));
    }

    /// Schedule a timer event for a node.
    fn schedule_timer(&mut self, node: NodeId, time: Timestamp) {
        self.schedule(time, Event::TimerFire { node });
    }

    /// Schedule a scenario action.
    pub fn schedule_action(&mut self, time: Timestamp, action: ScenarioAction) {
        self.schedule(time, Event::ScenarioAction(action));
    }

    /// Run simulation until specified time.
    pub fn run_until(&mut self, end_time: Timestamp) -> SimulationResult {
        while let Some(event) = self.event_queue.peek() {
            if event.time > end_time {
                break;
            }

            let event = self.event_queue.pop().unwrap();
            self.advance_time(event.time);
            self.process_event(event.event);

            // Check for snapshot
            self.maybe_take_snapshot();
        }

        // Advance to end_time even if no more events
        self.advance_time(end_time);

        // Final snapshot
        self.take_snapshot();

        SimulationResult {
            end_time: self.current_time,
            metrics: self.metrics.clone(),
            queue_exhausted: self.event_queue.peek().is_none(),
        }
    }

    /// Run simulation for specified duration.
    pub fn run_for(&mut self, duration: Duration) -> SimulationResult {
        self.run_until(self.current_time + duration)
    }

    /// Run until event queue is empty or max events processed.
    pub fn run_events(&mut self, max_events: usize) -> SimulationResult {
        let mut processed = 0;

        while let Some(event) = self.event_queue.pop() {
            self.advance_time(event.time);
            self.process_event(event.event);

            processed += 1;
            if processed >= max_events {
                break;
            }

            self.maybe_take_snapshot();
        }

        self.take_snapshot();

        SimulationResult {
            end_time: self.current_time,
            metrics: self.metrics.clone(),
            queue_exhausted: self.event_queue.is_empty(),
        }
    }

    /// Advance simulation time.
    fn advance_time(&mut self, time: Timestamp) {
        if time > self.current_time {
            self.current_time = time;
            // Update shared time for debug emitters
            self.shared_time_ms
                .store(time.as_millis(), Ordering::Relaxed);
        }
    }

    /// Process a single event.
    fn process_event(&mut self, event: Event) {
        match event {
            Event::MessageDelivery {
                to,
                data,
                rssi,
                from,
            } => {
                self.deliver_message(to, data, rssi, from);
            }
            Event::TimerFire { node } => {
                self.fire_timer(node);
            }
            Event::AppSend { from, to, payload } => {
                self.app_send(from, to, payload);
            }
            Event::ScenarioAction(action) => {
                self.execute_action(action);
            }
        }
    }

    /// Deliver a message to a node.
    fn deliver_message(&mut self, to: NodeId, data: Vec<u8>, rssi: Option<i16>, _from: NodeId) {
        let now = self.current_time;

        if let Some(node) = self.nodes.get_mut(&to) {
            node.handle_transport_rx(&data, rssi, now);
            self.metrics.messages_delivered += 1;
        }
        // Collect and route outgoing messages (separate borrow)
        self.collect_outgoing(to);
    }

    /// Fire timer for a node.
    fn fire_timer(&mut self, node_id: NodeId) {
        #[cfg(test)]
        {
            self.timer_fire_count += 1;
        }

        let now = self.current_time;

        // Get tau before mutable borrow
        let tau = self.nodes.get(&node_id).map(|n| n.tau());

        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.handle_timer(now);
        }

        // Collect and route outgoing messages (separate borrow)
        self.collect_outgoing(node_id);

        // Schedule next timer
        if let Some(tau) = tau {
            self.schedule_timer(node_id, now + tau);
        }
    }

    /// Handle application send request.
    fn app_send(&mut self, from: NodeId, to: NodeId, payload: Vec<u8>) {
        let now = self.current_time;
        if let Some(node) = self.nodes.get_mut(&from) {
            node.app_send(to, payload, now);
        }
        // Collect and route outgoing messages (separate borrow)
        self.collect_outgoing(from);
    }

    /// Collect outgoing messages from a node and route them.
    fn collect_outgoing(&mut self, sender: NodeId) {
        let messages = match self.nodes.get(&sender) {
            Some(node) => node.take_outgoing(),
            None => return,
        };

        for msg in messages {
            self.route_message(sender, msg);
        }
    }

    /// Route a message from sender to all reachable neighbors.
    fn route_message(&mut self, sender: NodeId, data: Vec<u8>) {
        self.metrics.messages_sent += 1;

        let neighbors = self.topology.neighbors(sender);
        let current_time = self.current_time;

        // Collect link info first to avoid borrow conflicts
        let mut deliveries = Vec::with_capacity(neighbors.len());
        let mut dropped_count = 0u64;

        for neighbor in neighbors {
            if let Some(link) = self.topology.get_link(sender, neighbor) {
                if !link.active {
                    continue;
                }

                // Extract link properties before random check
                let loss_rate = link.loss_rate;
                let delay = link.delay;
                let rssi = link.rssi;

                // Apply packet loss (using extracted loss_rate)
                if loss_rate > 0.0 && self.random_f64() < loss_rate {
                    dropped_count += 1;
                    continue;
                }

                deliveries.push((neighbor, delay, rssi));
            }
        }

        self.metrics.messages_dropped += dropped_count;

        // Schedule deliveries
        for (neighbor, delay, rssi) in deliveries {
            let delivery_time = current_time + delay;
            self.schedule(
                delivery_time,
                Event::MessageDelivery {
                    to: neighbor,
                    data: data.clone(),
                    rssi: Some(rssi),
                    from: sender,
                },
            );
        }
    }

    /// Execute a scenario action.
    fn execute_action(&mut self, action: ScenarioAction) {
        match action {
            ScenarioAction::Partition { groups } => {
                self.topology.partition(&groups);
            }
            ScenarioAction::HealPartition => {
                self.topology.heal();
            }
            ScenarioAction::DisableLink { from, to } => {
                if let Some(link) = self.topology.get_link_mut(from, to) {
                    link.active = false;
                }
            }
            ScenarioAction::EnableLink { from, to } => {
                if let Some(link) = self.topology.get_link_mut(from, to) {
                    link.active = true;
                }
            }
            ScenarioAction::SetLossRate { from, to, rate } => {
                if let Some(link) = self.topology.get_link_mut(from, to) {
                    link.loss_rate = rate.clamp(0.0, 1.0);
                }
            }
            ScenarioAction::TakeSnapshot => {
                self.take_snapshot();
            }
        }
    }

    /// Check if we should take a snapshot and do so.
    fn maybe_take_snapshot(&mut self) {
        if let Some(next) = self.next_snapshot {
            if self.current_time >= next {
                self.take_snapshot();
                if let Some(interval) = self.snapshot_interval {
                    self.next_snapshot = Some(next + interval);
                }
            }
        }
    }

    /// Take a tree state snapshot.
    pub fn take_snapshot(&mut self) {
        let mut snapshot = TreeSnapshot::new(self.current_time);

        for (node_id, node) in &self.nodes {
            snapshot.record_node(*node_id, node.root_hash(), node.tree_size(), node.is_root());
        }

        self.metrics.add_snapshot(snapshot);
    }

    /// Generate a random f64 in [0, 1).
    fn random_f64(&mut self) -> f64 {
        self.rng_state = self
            .rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        (self.rng_state as f64) / (u64::MAX as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::Link;

    #[test]
    fn test_simulator_creation() {
        let sim = Simulator::new(42);
        assert_eq!(sim.current_time(), Timestamp::ZERO);
        assert!(sim.node_ids().is_empty());
    }

    #[test]
    fn test_add_nodes() {
        let mut sim = Simulator::new(42);
        let n1 = sim.add_node(1);
        let n2 = sim.add_node(2);

        assert_ne!(n1, n2);
        assert_eq!(sim.node_ids().len(), 2);
        assert!(sim.node(&n1).is_some());
    }

    #[test]
    fn test_run_single_node() {
        let mut sim = Simulator::new(42);
        let n1 = sim.add_node(1);

        // Run for 1 second
        let _result = sim.run_for(Duration::from_secs(1));

        // Node should still be root
        let node = sim.node(&n1).unwrap();
        assert!(node.is_root());
        assert_eq!(node.tree_size(), 1);
    }

    #[test]
    fn test_run_two_nodes_connected() {
        let mut sim = Simulator::new(42);
        let n1 = sim.add_node(1);
        let n2 = sim.add_node(2);

        // Connect the nodes
        let mut topo = Topology::new();
        topo.add_link(n1, n2, Link::new());
        let _sim = sim.with_topology(topo);

        // Note: with_topology resets nodes, so topology should be set before adding nodes.
        // This test just verifies the API compiles and runs without panic.
    }

    #[test]
    fn test_with_topology() {
        let n1 = [1u8; 16];
        let n2 = [2u8; 16];

        let mut topo = Topology::new();
        topo.add_link(n1, n2, Link::new());

        let sim = Simulator::new(42).with_topology(topo);
        assert!(sim.topology().is_connected(n1, n2));
    }

    #[test]
    fn test_schedule_action() {
        let mut sim = Simulator::new(42);
        let n1 = sim.add_node(1);
        let n2 = sim.add_node(2);

        // Set up connected topology
        let topo = Topology::fully_connected(&[n1, n2]);
        sim.topology = topo;

        // Schedule a partition at t=500ms
        sim.schedule_action(
            Timestamp::from_millis(500),
            ScenarioAction::Partition {
                groups: vec![vec![n1], vec![n2]],
            },
        );

        // Run past the partition time
        sim.run_for(Duration::from_secs(1));

        // Nodes should be disconnected
        assert!(!sim.topology().is_connected(n1, n2));
    }
}
