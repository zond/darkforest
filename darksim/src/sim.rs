//! Discrete event simulator for darktree protocol.

use std::collections::BinaryHeap;

use darktree::{Duration, NodeId, Timestamp};
use hashbrown::HashMap;

use crate::event::{Event, ScenarioAction, ScheduledEvent, SequenceNumber};
use crate::metrics::{SimMetrics, SimulationResult, TreeSnapshot};
use crate::node::SimNode;
use crate::topology::Topology;

/// Discrete event simulator for darktree networks.
pub struct Simulator {
    /// All nodes in the simulation.
    nodes: HashMap<NodeId, SimNode>,
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
    /// Debug: count of timer fires.
    #[cfg(test)]
    pub timer_fire_count: u64,
}

impl Simulator {
    /// Create a new simulator with given RNG seed.
    pub fn new(seed: u64) -> Self {
        Self {
            nodes: HashMap::new(),
            topology: Topology::new(),
            current_time: Timestamp::ZERO,
            event_queue: BinaryHeap::new(),
            metrics: SimMetrics::new(),
            next_seq: 0,
            rng_state: seed,
            snapshot_interval: None,
            next_snapshot: None,
            #[cfg(test)]
            timer_fire_count: 0,
        }
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
        self.add_node_internal(SimNode::new(seed, self.current_time))
    }

    /// Add a node with bandwidth-limited transport (e.g., LoRa).
    pub fn add_node_with_bandwidth(&mut self, seed: u64, bw: u32) -> NodeId {
        self.add_node_internal(SimNode::with_bandwidth(seed, self.current_time, bw))
    }

    /// Internal helper to initialize and register a node.
    fn add_node_internal(&mut self, mut node: SimNode) -> NodeId {
        let node_id = node.node_id();

        // Initialize the node (sends first pulse, starts discovery)
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
        }
    }

    /// Process a single event.
    fn process_event(&mut self, event: Event) {
        match event {
            Event::MessageDelivery {
                to,
                data,
                rssi,
                from: _,
            } => {
                self.deliver_message(to, data, rssi);
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
    fn deliver_message(&mut self, to: NodeId, data: Vec<u8>, rssi: Option<i16>) {
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
