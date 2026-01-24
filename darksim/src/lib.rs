//! darksim - Discrete event network simulator for darktree protocol testing.
//!
//! This crate provides a deterministic, discrete-event simulator for testing the
//! darktree protocol at scale without real-time delays.
//!
//! # Features
//!
//! - **Discrete event simulation**: No real-time delays, deterministic ordering
//! - **Multiple nodes in single process**: Simulate entire networks efficiently
//! - **Configurable topology**: Fully connected, chain, star, or custom topologies
//! - **Link properties**: RSSI, packet loss, delay per link
//! - **Scenario builder**: Easy test setup with scheduled partitions, healing
//! - **Metrics collection**: Tree snapshots, message counts, convergence time
//!
//! # Example
//!
//! ```
//! use darksim::{ScenarioBuilder, Duration};
//!
//! // Create a 5-node network and run for 10 seconds
//! let result = ScenarioBuilder::new(5)
//!     .with_seed(42)
//!     .run_for(Duration::from_secs(10));
//!
//! // Check if network converged to single tree
//! assert!(result.converged());
//! ```
//!
//! # Architecture
//!
//! The simulator uses a priority queue of events ordered by (time, sequence_number).
//! The main loop:
//! 1. Pop next event from queue
//! 2. Advance simulation time
//! 3. Process event (call node handlers)
//! 4. Collect outgoing messages
//! 5. Route through topology, schedule deliveries
//!
//! Key insight: We call handlers directly (`handle_transport_rx`, `handle_timer`)
//! instead of using the async `node.run()` method.

pub mod event;
pub mod metrics;
pub mod node;
pub mod scenario;
pub mod sim;
pub mod topology;

// Re-export main types
pub use darktree::{Duration, NodeId, Timestamp};
pub use event::{Event, ScenarioAction, ScheduledEvent};
pub use metrics::{SimMetrics, SimulationResult, TreeSnapshot};
pub use node::SimNode;
pub use scenario::{lora_scenario, simple_scenario, ScenarioBuilder};
pub use sim::Simulator;
pub use topology::{Link, Topology};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_node_becomes_root() {
        let result = ScenarioBuilder::new(1)
            .with_seed(42)
            .run_for(Duration::from_secs(5));

        // Single node should be root of tree_size=1
        let snapshot = result.metrics.latest_snapshot().unwrap();
        assert_eq!(snapshot.roots().len(), 1);
        assert_eq!(snapshot.max_tree_size(), 1);
    }

    #[test]
    fn test_two_nodes_form_tree() {
        // Run for 10 seconds to allow discovery and merge
        // Discovery takes 3*tau, then merge happens within 4.5*tau
        // With default tau=100ms, 10 seconds should be plenty
        let (mut sim, nodes) = ScenarioBuilder::new(2)
            .with_seed(42)
            .with_snapshot_interval(Duration::from_millis(500))
            .build();

        // Run in small steps to see what's happening
        println!("Starting simulation with {} nodes", nodes.len());
        for node_id in &nodes {
            let node = sim.node(node_id).unwrap();
            println!(
                "Node {:?}: tau={:?}ms",
                &node_id[0..4],
                node.tau().as_millis()
            );
        }

        // With tau=100ms (MIN_TAU_MS) and pulse_interval=2*tau:
        // t=0: initial pulses
        // t=200ms: next pulses, pubkey exchange continues
        // t=300ms: discovery ends (3*tau), select_best_parent called
        // t=400-800ms: pending_parent acknowledged, tree formed
        // Run for 2 seconds which should be plenty
        let result = sim.run_for(Duration::from_secs(2));

        // Debug output
        let snapshot = result.metrics.latest_snapshot().unwrap();
        println!("End time: {:?}", result.end_time);
        println!("Messages sent: {}", result.metrics.messages_sent);
        println!("Messages delivered: {}", result.metrics.messages_delivered);
        println!("Snapshots taken: {}", result.metrics.snapshots.len());
        println!("Tree count: {}", snapshot.tree_count());
        println!("Queue exhausted: {}", result.queue_exhausted);
        println!("Timer fires: {}", sim.timer_fire_count);

        for node_id in &nodes {
            let node = sim.node(node_id).unwrap();
            let metrics = node.inner().metrics();
            println!(
                "Node {:?}: is_root={}, tree_size={}, subtree_size={}, root_hash={:?}",
                &node_id[0..4],
                node.is_root(),
                node.tree_size(),
                node.subtree_size(),
                node.root_hash()
            );
            println!(
                "  Protocol: sent={}, dropped={}, received={}",
                metrics.protocol_sent, metrics.protocol_dropped, metrics.protocol_received
            );
            // Print debug events
            let debug_events = node.take_debug_events();
            if !debug_events.is_empty() {
                println!("  Debug events ({}):", debug_events.len());
                for event in debug_events.iter().take(50) {
                    println!("    {:?}", event);
                }
                if debug_events.len() > 50 {
                    println!("    ... and {} more", debug_events.len() - 50);
                }
            }
        }

        // Both nodes should have same root hash
        assert!(snapshot.all_same_tree(), "Two nodes should form one tree");
        assert_eq!(snapshot.tree_count(), 1);
    }

    /// Scenario 2.3: Chain Topology
    /// Setup: 5 nodes in chain: A—B—C—D—E (each only sees neighbors)
    /// Run: 30τ
    /// Expect: Single tree formed. Depth ≤ 4.
    #[test]
    fn test_chain_topology_forms_tree() {
        let result = ScenarioBuilder::new(5)
            .with_seed(42)
            .chain_topology()
            .run_for(Duration::from_secs(30));

        // Verify single tree formed
        assert!(result.converged(), "Chain should converge to single tree");
        assert_eq!(result.final_tree_count(), 1);
        assert_eq!(
            result.final_max_tree_size(),
            5,
            "Tree should have exactly 5 nodes"
        );
    }

    /// Scenario 2.4: Star Topology
    /// Setup: 1 central node, 10 edge nodes (edges only see center)
    /// Run: 20τ
    /// Expect: Central node is root with 10 children.
    #[test]
    fn test_star_topology_central_becomes_root() {
        let (mut sim, nodes) = ScenarioBuilder::new(11) // 1 hub + 10 spokes
            .with_seed(42)
            .star_topology()
            .build();

        // Verify star topology: hub (node 0) connected to all, spokes isolated
        let hub = nodes[0];
        assert_eq!(
            sim.topology().neighbors(hub).len(),
            10,
            "Hub should have 10 neighbors"
        );
        for spoke in &nodes[1..] {
            let spoke_neighbors = sim.topology().neighbors(*spoke);
            assert_eq!(spoke_neighbors.len(), 1, "Spoke should only see hub");
        }

        let result = sim.run_for(Duration::from_secs(20));

        // Verify single tree formed with central node as root
        assert!(result.converged(), "Star should converge to single tree");
        assert_eq!(result.final_tree_count(), 1);
        assert_eq!(
            result.final_max_tree_size(),
            11,
            "Tree should have exactly 11 nodes"
        );

        // Verify central node is root
        let snapshot = result.metrics.latest_snapshot().unwrap();
        let hub_is_root = snapshot.is_root.get(&hub).copied().unwrap_or(false);
        assert!(hub_is_root, "Central hub should be the root");
    }
}
