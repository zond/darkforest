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
    use hashbrown::HashMap;

    /// Compute the depth of each node in the tree (root = 0).
    /// Returns a map from node_id to depth.
    fn compute_depths(sim: &Simulator, nodes: &[NodeId]) -> HashMap<NodeId, usize> {
        let mut depths = HashMap::new();

        // First pass: find all roots (depth 0)
        for &node_id in nodes {
            let node = sim.node(&node_id).unwrap();
            if node.is_root() {
                depths.insert(node_id, 0);
            }
        }

        // Iteratively compute depths until all nodes have depths
        // (max iterations = tree depth, bounded by node count)
        for _ in 0..nodes.len() {
            let mut progress = false;
            for &node_id in nodes {
                if depths.contains_key(&node_id) {
                    continue;
                }
                let node = sim.node(&node_id).unwrap();
                if let Some(parent_id) = node.parent_id() {
                    if let Some(&parent_depth) = depths.get(&parent_id) {
                        depths.insert(node_id, parent_depth + 1);
                        progress = true;
                    }
                }
            }
            if !progress {
                break;
            }
        }

        depths
    }

    /// Get the maximum tree depth (root = depth 0, so max depth = tree height - 1).
    fn max_tree_depth(sim: &Simulator, nodes: &[NodeId]) -> usize {
        let depths = compute_depths(sim, nodes);
        depths.values().copied().max().unwrap_or(0)
    }

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
        let (mut sim, nodes) = ScenarioBuilder::new(5)
            .with_seed(42)
            .chain_topology()
            .build();

        let result = sim.run_for(Duration::from_secs(30));

        // Verify single tree formed
        assert!(result.converged(), "Chain should converge to single tree");
        assert_eq!(result.final_tree_count(), 1);
        assert_eq!(
            result.final_max_tree_size(),
            5,
            "Tree should have exactly 5 nodes"
        );

        // Verify depth ≤ 4 (root at depth 0, max depth 4 means 5 levels)
        let depth = max_tree_depth(&sim, &nodes);
        assert!(depth <= 4, "Chain tree depth should be ≤ 4, got {}", depth);
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

        // Verify hub has 10 children (all spokes attached)
        let hub_node = sim.node(&hub).unwrap();
        assert_eq!(hub_node.children_count(), 10, "Hub should have 10 children");
    }

    /// Scenario 2.5: Fully Connected Small Network
    /// Setup: 10 nodes, all in range
    /// Run: 20τ
    /// Expect: Single tree, wide and shallow (depth ≤ 3).
    #[test]
    fn test_fully_connected_10_nodes() {
        let (mut sim, nodes) = ScenarioBuilder::new(10)
            .with_seed(42)
            .fully_connected()
            .build();

        let result = sim.run_for(Duration::from_secs(20));

        // Verify single tree formed
        assert!(
            result.converged(),
            "Fully connected network should converge to single tree"
        );
        assert_eq!(result.final_tree_count(), 1);
        assert_eq!(
            result.final_max_tree_size(),
            10,
            "Tree should have exactly 10 nodes"
        );

        // Verify tree is shallow (depth ≤ 3)
        // With fully connected topology, nodes may all join root directly (depth 1)
        // which is actually the shallowest possible - meets "wide and shallow" goal
        let depth = max_tree_depth(&sim, &nodes);
        assert!(
            depth <= 3,
            "Fully connected tree depth should be ≤ 3, got {}",
            depth
        );
    }

    /// Scenario 5.1: Parent Timeout (8 Pulses)
    /// Setup: Tree with parent P and child C. Stop P's pulses at t=10τ.
    /// Run: 40τ
    /// Expect: C becomes root after ~24τ (8 missed pulses × ~3τ interval).
    #[test]
    fn test_parent_timeout_child_becomes_root() {
        use crate::event::ScenarioAction;

        // Create 2-node network
        let (mut sim, nodes) = ScenarioBuilder::new(2)
            .with_seed(42)
            .fully_connected()
            .build();

        // First, run until tree forms (should happen within 2 seconds)
        sim.run_for(Duration::from_secs(2));

        // Find which node is root and which is child
        let (parent_id, child_id) = if sim.node(&nodes[0]).unwrap().is_root() {
            (nodes[0], nodes[1])
        } else {
            (nodes[1], nodes[0])
        };

        // Verify we have a proper tree
        let child_node = sim.node(&child_id).unwrap();
        assert!(!child_node.is_root(), "Child should not be root initially");
        assert_eq!(
            child_node.parent_id(),
            Some(parent_id),
            "Child should have parent"
        );

        // Disable link from parent to child (child won't receive parent's pulses)
        // Also disable child to parent (to fully isolate)
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: parent_id,
                to: child_id,
            },
        );
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: child_id,
                to: parent_id,
            },
        );

        // Run for 30 seconds - timeout should occur within ~24τ = 2.4s at default τ=100ms
        // Using 30s to be safe
        sim.run_for(Duration::from_secs(30));

        // Child should now be root (parent timed out)
        let child_node = sim.node(&child_id).unwrap();
        assert!(
            child_node.is_root(),
            "Child should become root after parent timeout"
        );
        assert_eq!(child_node.tree_size(), 1, "Child's tree should have size 1");

        // Parent should have removed the timed-out child
        let parent_node = sim.node(&parent_id).unwrap();
        assert_eq!(
            parent_node.children_count(),
            0,
            "Parent should have removed timed-out child"
        );
        assert_eq!(
            parent_node.tree_size(),
            1,
            "Parent's tree should have size 1"
        );
    }

    /// Scenario 5.2: Child Timeout
    /// Setup: Tree with P—C. Stop C's pulses at t=10τ.
    /// Run: 40τ
    /// Expect: P removes C from children after ~24τ. P.subtree_size decreases.
    #[test]
    fn test_child_timeout_parent_removes_child() {
        use crate::event::ScenarioAction;

        // Create 2-node network
        let (mut sim, nodes) = ScenarioBuilder::new(2)
            .with_seed(42)
            .fully_connected()
            .build();

        // Run until tree forms
        sim.run_for(Duration::from_secs(2));

        // Find which node is root (parent) and which is child
        let (parent_id, child_id) = if sim.node(&nodes[0]).unwrap().is_root() {
            (nodes[0], nodes[1])
        } else {
            (nodes[1], nodes[0])
        };

        // Verify initial state: parent has 1 child, tree_size=2
        let parent_node = sim.node(&parent_id).unwrap();
        assert_eq!(
            parent_node.children_count(),
            1,
            "Parent should have 1 child"
        );
        assert_eq!(parent_node.tree_size(), 2, "Tree size should be 2");
        assert_eq!(parent_node.subtree_size(), 2, "Subtree size should be 2");

        // Disable links (stop child's pulses from reaching parent)
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: child_id,
                to: parent_id,
            },
        );
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: parent_id,
                to: child_id,
            },
        );

        // Run for timeout period
        sim.run_for(Duration::from_secs(30));

        // Parent should have removed the timed-out child
        let parent_node = sim.node(&parent_id).unwrap();
        assert_eq!(
            parent_node.children_count(),
            0,
            "Parent should have removed timed-out child"
        );
        assert_eq!(
            parent_node.subtree_size(),
            1,
            "Parent's subtree_size should be 1 after child removal"
        );
        assert_eq!(
            parent_node.tree_size(),
            1,
            "Parent's tree_size should be 1 after child removal"
        );
    }

    /// Scenario 5.3: Neighbor Expiry
    /// Setup: Two nodes exchange pulses. One goes silent at t=10τ.
    /// Run: 50τ
    /// Expect: Neighbor removed from neighbor_times after timeout.
    #[test]
    fn test_neighbor_expiry_removes_silent_neighbor() {
        use crate::event::ScenarioAction;

        // Create 2-node network
        let (mut sim, nodes) = ScenarioBuilder::new(2)
            .with_seed(42)
            .fully_connected()
            .build();

        // Run until tree forms and neighbors are established
        sim.run_for(Duration::from_secs(2));

        // Both nodes should know about each other as neighbors
        let node0 = sim.node(&nodes[0]).unwrap();
        let node1 = sim.node(&nodes[1]).unwrap();
        assert!(
            node0.neighbor_count() >= 1,
            "Node 0 should have at least 1 neighbor"
        );
        assert!(
            node1.neighbor_count() >= 1,
            "Node 1 should have at least 1 neighbor"
        );

        // Disable links (node 1 goes silent from node 0's perspective)
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: nodes[1],
                to: nodes[0],
            },
        );
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: nodes[0],
                to: nodes[1],
            },
        );

        // Run for timeout period (8 missed pulses at ~5τ interval = 40τ ≈ 4s at default τ)
        // Using 30s to provide ample margin
        sim.run_for(Duration::from_secs(30));

        // Node 0 should have removed node 1 from neighbors (timed out)
        let node0 = sim.node(&nodes[0]).unwrap();
        assert_eq!(
            node0.neighbor_count(),
            0,
            "Node 0 should have removed timed-out neighbor"
        );

        // Node 1 should have removed node 0 from neighbors (timed out)
        let node1 = sim.node(&nodes[1]).unwrap();
        assert_eq!(
            node1.neighbor_count(),
            0,
            "Node 1 should have removed timed-out neighbor"
        );
    }

    /// Scenario 1.2: Discovery Phase Timing
    /// Setup: 1 node boots, neighbors appear at t=2τ
    /// Run: 10τ
    /// Expect: Node waits until 3τ before selecting parent (discovery phase)
    #[test]
    fn test_discovery_phase_timing() {
        use crate::event::ScenarioAction;

        // Create 2-node network but start partitioned (nodes can't see each other)
        let (mut sim, nodes) = ScenarioBuilder::new(2)
            .with_seed(42)
            .fully_connected()
            .build();

        // Immediately partition the nodes so they can't communicate
        sim.schedule_action(
            Timestamp::ZERO,
            ScenarioAction::Partition {
                groups: vec![vec![nodes[0]], vec![nodes[1]]],
            },
        );

        // Run for 2τ = 200ms (at default τ=100ms)
        // At this point, both nodes are still in discovery and haven't seen each other
        sim.run_for(Duration::from_millis(200));

        // Both nodes should still be roots (no parent selection yet)
        let node0 = sim.node(&nodes[0]).unwrap();
        let node1 = sim.node(&nodes[1]).unwrap();
        assert!(node0.is_root(), "Node 0 should still be root at t=2τ");
        assert!(node1.is_root(), "Node 1 should still be root at t=2τ");

        // Now heal partition - neighbors appear at t=2τ
        sim.schedule_action(sim.current_time(), ScenarioAction::HealPartition);

        // Run for just under 1τ more (100ms) - we're now at t=3τ
        // Discovery should end around 3τ from boot (300ms)
        sim.run_for(Duration::from_millis(100));

        // Run more to allow parent selection to complete (need pulse exchange)
        sim.run_for(Duration::from_secs(2));

        // Now tree should have formed
        let node0 = sim.node(&nodes[0]).unwrap();
        let node1 = sim.node(&nodes[1]).unwrap();

        // One should be root, one should be child
        let roots = [node0.is_root(), node1.is_root()];
        assert!(
            (roots[0] && !roots[1]) || (!roots[0] && roots[1]),
            "After discovery, one node should be root and one child"
        );
    }

    /// Scenario 2.6: Parent Selection Prefers Shallow
    /// Setup: 3 nodes A, B, C all in range. A boots first (root). B joins A. C boots.
    /// Run: 15τ
    /// Expect: C joins A (larger keyspace), not B.
    ///
    /// The "prefer shallow" behavior is in select_best_parent(), which is called
    /// when discovery ends. C must see both A and B during its discovery phase.
    /// We achieve this by adding C to the simulation after A-B form a tree.
    #[test]
    fn test_parent_selection_prefers_shallow() {
        use crate::topology::Link;

        // Create simulator with 2 nodes (A and B) that can see each other
        let mut sim = Simulator::new(42);
        let node_a = sim.add_node(1);
        let node_b = sim.add_node(2);

        // Connect A and B
        sim.topology_mut().add_link(node_a, node_b, Link::default());

        // Run to let A and B form a tree
        sim.run_for(Duration::from_secs(2));

        // Verify A-B tree formed
        let a_is_root = sim.node(&node_a).unwrap().is_root();
        let b_is_root = sim.node(&node_b).unwrap().is_root();
        assert!(
            (a_is_root && !b_is_root) || (!a_is_root && b_is_root),
            "One of A,B should be root, the other child"
        );

        let (root_node, _child_node) = if a_is_root {
            (node_a, node_b)
        } else {
            (node_b, node_a)
        };

        // Verify tree size is 2
        assert_eq!(
            sim.node(&root_node).unwrap().tree_size(),
            2,
            "Root should have tree_size=2"
        );

        // Now add C - it will start discovery and see both A and B
        let node_c = sim.add_node(3);

        // Connect C to both A and B
        sim.topology_mut().add_link(node_c, node_a, Link::default());
        sim.topology_mut().add_link(node_c, node_b, Link::default());

        // Run to let C complete discovery and join the tree
        // C's discovery is 3τ = 300ms, plus some time for pulse exchange
        sim.run_for(Duration::from_secs(2));

        // C should have joined the root (prefers larger keyspace)
        let c_node = sim.node(&node_c).unwrap();
        assert!(!c_node.is_root(), "C should have joined the larger tree");

        // Verify C's parent is the root node (larger keyspace)
        let c_parent = c_node.parent_id();
        assert_eq!(
            c_parent,
            Some(root_node),
            "C should join the root (larger keyspace), not the child"
        );

        // Verify tree size is now 3
        assert_eq!(
            sim.node(&root_node).unwrap().tree_size(),
            3,
            "Root should have tree_size=3"
        );
    }
}
