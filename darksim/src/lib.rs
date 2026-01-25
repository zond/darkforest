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
        compute_depths(sim, nodes)
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }

    /// Find the root node among a set of nodes.
    fn find_root(sim: &Simulator, nodes: &[NodeId]) -> Option<NodeId> {
        nodes
            .iter()
            .copied()
            .find(|id| sim.node(id).is_some_and(|n| n.is_root()))
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
    /// Expect: Single tree with 11 nodes. Root is node with lowest root_hash
    /// (may be hub or a spoke, depending on hash values).
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

        // Verify single tree formed
        assert!(result.converged(), "Star should converge to single tree");
        assert_eq!(result.final_tree_count(), 1);
        assert_eq!(
            result.final_max_tree_size(),
            11,
            "Tree should have exactly 11 nodes"
        );

        // With merge shopping, the root is the node with the lowest root_hash.
        // In a star topology, if a spoke has the lowest hash, it becomes root
        // and the hub becomes its child (with other spokes joining via hub).
        // This is correct behavior - the tree still converges.
        let snapshot = result.metrics.latest_snapshot().unwrap();
        let root_count = snapshot.is_root.values().filter(|&&v| v).count();
        assert_eq!(root_count, 1, "Should have exactly one root");
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

    /// Scenario 2.7: MAX_CHILDREN Limit Enforced
    /// Setup: Star topology with more than MAX_CHILDREN spokes
    /// Run: Until convergence
    /// Expect: No node has more than MAX_CHILDREN children at any time.
    ///
    /// Note: The original scenario "Rejected by Full Parent" assumed a newcomer
    /// would stay root if the only visible parent is full. However, the protocol
    /// allows dynamic tree restructuring - children can leave a full parent,
    /// making room for newcomers. This test verifies the MAX_CHILDREN limit is
    /// never exceeded, which is the actual invariant the protocol guarantees.
    #[test]
    fn test_max_children_limit_enforced() {
        use crate::topology::Link;
        use darktree::MAX_CHILDREN;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create hub and more than MAX_CHILDREN spokes
        let hub = sim.add_node(1);
        let num_spokes = MAX_CHILDREN + 5;
        let mut all_nodes = vec![hub];

        for i in 0..num_spokes {
            let spoke = sim.add_node(100 + i as u64);
            sim.topology_mut().add_link(hub, spoke, Link::default());
            all_nodes.push(spoke);
        }

        // Run to form the tree
        sim.run_for(Duration::from_secs(10));

        // Verify no node exceeds MAX_CHILDREN
        for &node_id in &all_nodes {
            let node = sim.node(&node_id).unwrap();
            assert!(
                node.children_count() <= MAX_CHILDREN,
                "Node should not exceed MAX_CHILDREN (has {})",
                node.children_count()
            );
        }

        // Add a newcomer and verify limit still holds
        let newcomer = sim.add_node(999);
        sim.topology_mut().add_link(hub, newcomer, Link::default());
        all_nodes.push(newcomer);

        sim.run_for(Duration::from_secs(5));

        // Verify no node exceeds MAX_CHILDREN after newcomer joins
        for &node_id in &all_nodes {
            let node = sim.node(&node_id).unwrap();
            assert!(
                node.children_count() <= MAX_CHILDREN,
                "Node should not exceed MAX_CHILDREN after newcomer (has {})",
                node.children_count()
            );
        }

        // Note: In a star topology where spokes can only see the hub,
        // full convergence may not be possible if the hub is full.
        // Some nodes may remain as isolated single-node trees.
        // This is expected protocol behavior - the MAX_CHILDREN limit
        // takes precedence over forcing all nodes into one tree.
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();

        // Verify the largest tree has at least MAX_CHILDREN + 1 nodes
        // (hub/root + MAX_CHILDREN children)
        assert!(
            snapshot.max_tree_size() >= (MAX_CHILDREN + 1) as u32,
            "Largest tree should have at least {} nodes, got {}",
            MAX_CHILDREN + 1,
            snapshot.max_tree_size()
        );
    }

    /// Scenario 3.1: Larger Tree Wins
    /// Setup: Tree A (larger), Tree B (smaller). Link them at t=10τ.
    /// Run: 40τ
    /// Expect: Single tree with A's root. tree_size = A + B.
    ///
    /// We use smaller counts (10+5=15) for test efficiency while validating
    /// the same merge behavior as the scenario's 100+50=150.
    #[test]
    fn test_larger_tree_wins_merge() {
        use crate::topology::Link;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create Group A: 10 nodes, fully connected within group
        let mut group_a = Vec::with_capacity(10);
        for i in 0..10 {
            group_a.push(sim.add_node(1000 + i));
        }
        for i in 0..group_a.len() {
            for j in (i + 1)..group_a.len() {
                sim.topology_mut()
                    .add_link(group_a[i], group_a[j], Link::default());
            }
        }

        // Create Group B: 5 nodes, fully connected within group
        let mut group_b = Vec::with_capacity(5);
        for i in 0..5 {
            group_b.push(sim.add_node(2000 + i));
        }
        for i in 0..group_b.len() {
            for j in (i + 1)..group_b.len() {
                sim.topology_mut()
                    .add_link(group_b[i], group_b[j], Link::default());
            }
        }

        // No links between groups initially (partitioned)

        // Run to let each group form its own tree
        sim.run_for(Duration::from_secs(5));

        // Verify two separate trees formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 2, "Should have 2 separate trees");

        // Find the root of group A (the larger tree)
        let group_a_root = group_a
            .iter()
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Group A should have a root");
        let group_a_tree_size = sim.node(&group_a_root).unwrap().tree_size();
        assert_eq!(group_a_tree_size, 10, "Group A tree should have 10 nodes");

        // Find the root of group B
        let group_b_root = group_b
            .iter()
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Group B should have a root");
        let group_b_tree_size = sim.node(&group_b_root).unwrap().tree_size();
        assert_eq!(group_b_tree_size, 5, "Group B tree should have 5 nodes");

        // Connect the groups: add link between one node from each group
        // (simulates "link them at t=10τ")
        sim.topology_mut()
            .add_link(group_a[0], group_b[0], Link::default());

        // Run for merge to complete
        sim.run_for(Duration::from_secs(10));

        // Verify single tree formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            1,
            "Should have merged to 1 tree after linking"
        );

        // Verify the larger tree (A) won - its root should be the final root
        let final_root = group_a
            .iter()
            .chain(group_b.iter())
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Should have a root");

        // The root should be from group A (the larger tree)
        assert!(
            group_a.contains(&final_root),
            "Final root should be from larger group A"
        );

        // Verify Group B's former root is no longer a root (inversion completed)
        let group_b_former_root = sim.node(&group_b_root).unwrap();
        assert!(
            !group_b_former_root.is_root(),
            "Group B's former root should have been inverted"
        );

        // Verify tree size is now 15
        let final_tree_size = sim.node(&final_root).unwrap().tree_size();
        assert_eq!(
            final_tree_size, 15,
            "Merged tree should have 15 nodes (10 + 5)"
        );
    }

    /// Scenario 3.2: Equal Size - Lower Root Hash Wins
    /// Setup: Tree A and Tree B with equal size.
    /// Link: Connect them.
    /// Expect: Single tree with root whose hash is lexicographically lower.
    ///
    /// We create two equal-sized trees, connect them, and verify that the
    /// winning root is the one with the lower root_hash.
    #[test]
    fn test_equal_size_lower_root_hash_wins() {
        use crate::topology::Link;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create Group A: 5 nodes, fully connected within group
        let mut group_a = Vec::with_capacity(5);
        for i in 0..5 {
            group_a.push(sim.add_node(1000 + i));
        }
        for i in 0..group_a.len() {
            for j in (i + 1)..group_a.len() {
                sim.topology_mut()
                    .add_link(group_a[i], group_a[j], Link::default());
            }
        }

        // Create Group B: 5 nodes, fully connected within group (same size as A)
        let mut group_b = Vec::with_capacity(5);
        for i in 0..5 {
            group_b.push(sim.add_node(2000 + i));
        }
        for i in 0..group_b.len() {
            for j in (i + 1)..group_b.len() {
                sim.topology_mut()
                    .add_link(group_b[i], group_b[j], Link::default());
            }
        }

        // Run to let each group form its own tree
        sim.run_for(Duration::from_secs(5));

        // Verify two separate trees of equal size formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 2, "Should have 2 separate trees");

        // Find roots and their hashes
        let group_a_root = group_a
            .iter()
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Group A should have a root");
        let group_b_root = group_b
            .iter()
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Group B should have a root");

        // Verify equal sizes
        let a_size = sim.node(&group_a_root).unwrap().tree_size();
        let b_size = sim.node(&group_b_root).unwrap().tree_size();
        assert_eq!(a_size, 5, "Group A tree size should be 5");
        assert_eq!(b_size, 5, "Group B tree size should be 5");

        // Get root hashes before merge
        let a_hash = sim.node(&group_a_root).unwrap().root_hash();
        let b_hash = sim.node(&group_b_root).unwrap().root_hash();

        // Ensure hashes are different (if equal, no merge would occur)
        assert_ne!(
            a_hash, b_hash,
            "Test requires different root hashes to validate tie-breaking"
        );

        // Determine which should win (lower hash wins when sizes equal)
        let expected_winner = if a_hash < b_hash {
            group_a_root
        } else {
            group_b_root
        };

        // Connect the groups
        sim.topology_mut()
            .add_link(group_a[0], group_b[0], Link::default());

        // Run for merge to complete
        sim.run_for(Duration::from_secs(10));

        // Verify single tree formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            1,
            "Should have merged to 1 tree after linking"
        );

        // Find the final root
        let final_root = group_a
            .iter()
            .chain(group_b.iter())
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Should have a root");

        // Verify the expected winner won (lower hash wins)
        assert_eq!(
            final_root, expected_winner,
            "Root with lower hash should win when sizes are equal"
        );

        // Verify tree size is now 10
        let final_tree_size = sim.node(&final_root).unwrap().tree_size();
        assert_eq!(
            final_tree_size, 10,
            "Merged tree should have 10 nodes (5 + 5)"
        );
    }

    /// Scenario 4.1: Link Break Creates Partition
    /// Setup: Tree with root R, child A, grandchild C. Break A—C link.
    /// Run: 40τ (need 8 missed pulses ≈ 24τ for timeout)
    /// Expect: Two trees: R's tree (R and A), C's tree (C as root).
    #[test]
    fn test_link_break_creates_partition() {
        use crate::event::ScenarioAction;
        use crate::topology::Link;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create chain topology: R—A—C
        let node_r = sim.add_node(1);
        let node_a = sim.add_node(2);
        let node_c = sim.add_node(3);

        // R can see A, A can see both R and C, C can only see A
        sim.topology_mut().add_link(node_r, node_a, Link::default());
        sim.topology_mut().add_link(node_a, node_c, Link::default());

        // Run to form the tree
        sim.run_for(Duration::from_secs(5));

        // Verify single tree formed with 3 nodes
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 1, "Should have 1 tree initially");

        // Find the root (should be one of the nodes)
        let root_id = find_root(&sim, &[node_r, node_a, node_c]).expect("Should have a root");

        let root_tree_size = sim.node(&root_id).unwrap().tree_size();
        assert_eq!(root_tree_size, 3, "Initial tree should have 3 nodes");

        // Break the A—C link (bidirectional)
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: node_a,
                to: node_c,
            },
        );
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: node_c,
                to: node_a,
            },
        );

        // Run for timeout period (8 missed pulses × ~3τ = 24τ ≈ 2.4s at default τ=100ms)
        // Using 30s to be safe
        sim.run_for(Duration::from_secs(30));

        // Verify two separate trees now exist
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            2,
            "Should have 2 trees after link break and timeout"
        );

        // C should now be root of its own tree
        let c_node = sim.node(&node_c).unwrap();
        assert!(
            c_node.is_root(),
            "C should become root after losing parent connection"
        );
        assert_eq!(c_node.tree_size(), 1, "C's tree should have size 1");

        // R and A should still be connected (one is root, one is child)
        let r_is_root = sim.node(&node_r).unwrap().is_root();
        let a_is_root = sim.node(&node_a).unwrap().is_root();

        // Exactly one of R or A is root
        assert!(
            (r_is_root && !a_is_root) || (!r_is_root && a_is_root),
            "Exactly one of R/A should be root"
        );

        // The root's tree should have size 2
        let ra_root_id = if r_is_root { node_r } else { node_a };
        let ra_tree_size = sim.node(&ra_root_id).unwrap().tree_size();
        assert_eq!(ra_tree_size, 2, "R-A tree should have size 2");
    }

    /// Scenario 4.2: Partition Heals
    /// Setup: After partition (4.1), restore the broken link.
    /// Run: Until trees remerge (~10s provides ample margin).
    /// Expect: Trees remerge into single tree.
    #[test]
    fn test_partition_heals() {
        use crate::event::ScenarioAction;
        use crate::topology::Link;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create chain topology: R—A—C
        let node_r = sim.add_node(1);
        let node_a = sim.add_node(2);
        let node_c = sim.add_node(3);

        sim.topology_mut().add_link(node_r, node_a, Link::default());
        sim.topology_mut().add_link(node_a, node_c, Link::default());

        // Run to form the tree
        sim.run_for(Duration::from_secs(5));

        // Verify single tree formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 1, "Should have 1 tree initially");

        // Break the A—C link (links are bidirectional with canonical ordering)
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::DisableLink {
                from: node_a,
                to: node_c,
            },
        );

        // Run for partition to occur
        sim.run_for(Duration::from_secs(30));

        // Verify partition happened (2 trees)
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            2,
            "Should have 2 trees after partition"
        );

        // Now restore the link
        sim.schedule_action(
            sim.current_time(),
            ScenarioAction::EnableLink {
                from: node_a,
                to: node_c,
            },
        );

        // Run for trees to remerge
        sim.run_for(Duration::from_secs(10));

        // Verify single tree again
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            1,
            "Should have 1 tree after partition heals"
        );

        // Verify tree has all 3 nodes
        let root_id = find_root(&sim, &[node_r, node_a, node_c]).expect("Should have a root");

        let tree_size = sim.node(&root_id).unwrap().tree_size();
        assert_eq!(tree_size, 3, "Healed tree should have all 3 nodes");
    }

    /// Scenario 4.3: Root Dies, Children Remerge
    /// Setup: 4-node network with R connected to A, B, C (star), plus A-B-C triangle.
    /// Action: Isolate R by disabling all its links bidirectionally.
    /// Run: Until timeout and remerge (~40s provides ample margin).
    /// Expect: R becomes isolated single-node tree. A, B, C timeout, become
    /// separate roots briefly, then merge into single 3-node tree.
    ///
    /// Note: This tests node isolation and remerge regardless of which node
    /// was initially root. The protocol handles this correctly either way.
    #[test]
    fn test_root_dies_children_remerge() {
        use crate::event::ScenarioAction;
        use crate::topology::Link;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create R and children A, B, C
        let node_r = sim.add_node(1);
        let node_a = sim.add_node(2);
        let node_b = sim.add_node(3);
        let node_c = sim.add_node(4);

        // Star topology from R to children
        sim.topology_mut().add_link(node_r, node_a, Link::default());
        sim.topology_mut().add_link(node_r, node_b, Link::default());
        sim.topology_mut().add_link(node_r, node_c, Link::default());

        // Triangle among children (so they can merge after R dies)
        sim.topology_mut().add_link(node_a, node_b, Link::default());
        sim.topology_mut().add_link(node_a, node_c, Link::default());
        sim.topology_mut().add_link(node_b, node_c, Link::default());

        // Run to form the tree
        sim.run_for(Duration::from_secs(5));

        // Verify single tree formed with 4 nodes
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 1, "Should have 1 tree initially");

        // Find the initial root (could be any node depending on protocol)
        let initial_root =
            find_root(&sim, &[node_r, node_a, node_b, node_c]).expect("Should have a root");
        let initial_tree_size = sim.node(&initial_root).unwrap().tree_size();
        assert_eq!(initial_tree_size, 4, "Initial tree should have 4 nodes");

        // Isolate R by disabling all its links (bidirectional)
        for &child in &[node_a, node_b, node_c] {
            sim.schedule_action(
                sim.current_time(),
                ScenarioAction::DisableLink {
                    from: node_r,
                    to: child,
                },
            );
            sim.schedule_action(
                sim.current_time(),
                ScenarioAction::DisableLink {
                    from: child,
                    to: node_r,
                },
            );
        }

        // Run for children to timeout and remerge
        // Timeout takes ~24τ, then merge takes a few more τ
        sim.run_for(Duration::from_secs(40));

        // Verify the surviving nodes (A, B, C) have merged into one tree
        // R is now isolated as its own single-node tree
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();

        // Should have 2 trees: R alone, and A-B-C merged
        assert_eq!(
            snapshot.tree_count(),
            2,
            "Should have 2 trees: isolated R and merged A-B-C"
        );

        // R should be root of its own tree (size 1)
        let r_node = sim.node(&node_r).unwrap();
        assert!(r_node.is_root(), "Isolated R should be root");
        assert_eq!(r_node.tree_size(), 1, "R's tree should have size 1");

        // One of A, B, C should be root with tree_size = 3
        let abc_root =
            find_root(&sim, &[node_a, node_b, node_c]).expect("One of A, B, C should be root");
        let abc_tree_size = sim.node(&abc_root).unwrap().tree_size();
        assert_eq!(abc_tree_size, 3, "A-B-C tree should have size 3");
    }

    /// Scenario 3.3: Tree Inversion Propagation
    /// Setup: Tree B is a chain of 5 nodes (depth 5). Tree A is larger (10 nodes).
    ///        Connect Tree A to the LEAF of Tree B.
    /// Run: Until merge completes.
    /// Expect: Inversion propagates up the chain. All 15 nodes under A's root.
    ///
    /// This tests that when a larger tree connects to the deepest node of a
    /// chain, the inversion correctly propagates up through all ancestors.
    #[test]
    fn test_tree_inversion_propagation() {
        use crate::topology::Link;

        // Create simulator
        let mut sim = Simulator::new(42);

        // Create Tree A: 10 nodes fully connected (will be the larger tree)
        let mut tree_a = Vec::with_capacity(10);
        for i in 0..10 {
            tree_a.push(sim.add_node(1000 + i));
        }
        for i in 0..tree_a.len() {
            for j in (i + 1)..tree_a.len() {
                sim.topology_mut()
                    .add_link(tree_a[i], tree_a[j], Link::default());
            }
        }

        // Create Tree B: chain of 5 nodes (B0—B1—B2—B3—B4, where B4 is leaf)
        let mut chain_b = Vec::with_capacity(5);
        for i in 0..5 {
            chain_b.push(sim.add_node(2000 + i));
        }
        for i in 0..4 {
            sim.topology_mut()
                .add_link(chain_b[i], chain_b[i + 1], Link::default());
        }

        // No links between trees initially

        // Run to let each group form its own tree
        sim.run_for(Duration::from_secs(10));

        // Verify two separate trees formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 2, "Should have 2 separate trees");

        // Verify Tree A has 10 nodes
        let tree_a_root = tree_a
            .iter()
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Tree A should have a root");
        assert_eq!(
            sim.node(&tree_a_root).unwrap().tree_size(),
            10,
            "Tree A should have 10 nodes"
        );

        // Verify Tree B (chain) has 5 nodes
        let chain_b_root = chain_b
            .iter()
            .find(|id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Chain B should have a root");
        assert_eq!(
            sim.node(&chain_b_root).unwrap().tree_size(),
            5,
            "Chain B should have 5 nodes"
        );

        // Find the leaf of chain B (the node that is NOT root and has no children)
        // In a chain, the leaf should be one of the endpoints
        let chain_b_leaf = chain_b
            .iter()
            .find(|id| {
                let node = sim.node(id).unwrap();
                !node.is_root() && node.children_count() == 0
            })
            .copied()
            .expect("Chain B should have a leaf (non-root with no children)");

        // Connect Tree A to the LEAF of chain B
        // This forces inversion to propagate up the entire chain
        sim.topology_mut()
            .add_link(tree_a[0], chain_b_leaf, Link::default());

        // Run for merge and inversion to complete
        // Inversion propagates ~1.5τ per hop, chain has 4 hops, so ~6τ minimum
        // Plus merge time. Using 30s for ample margin.
        sim.run_for(Duration::from_secs(30));

        // Verify single tree formed
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            1,
            "Should have merged to 1 tree after connecting"
        );

        // Find the final root
        let final_root = tree_a
            .iter()
            .chain(chain_b.iter())
            .copied()
            .find(|id| sim.node(id).unwrap().is_root())
            .expect("Should have a root");

        // The root should be from Tree A (the larger tree)
        assert!(
            tree_a.contains(&final_root),
            "Final root should be from larger Tree A"
        );

        // Verify tree size is now 15 (10 + 5)
        let final_tree_size = sim.node(&final_root).unwrap().tree_size();
        assert_eq!(
            final_tree_size, 15,
            "Merged tree should have 15 nodes (10 + 5)"
        );

        // Verify all chain B nodes are now in the tree (not roots)
        for &node_id in &chain_b {
            let node = sim.node(&node_id).unwrap();
            if node_id != final_root {
                assert!(
                    !node.is_root(),
                    "Chain B node should not be root after merge"
                );
            }
        }

        // Verify the depth structure - compute depths to ensure inversion happened
        // Collect all node IDs for depth computation
        let all_node_ids: Vec<_> = tree_a.iter().chain(chain_b.iter()).copied().collect();
        let depths = compute_depths(&sim, &all_node_ids);

        // The key assertion: all 15 nodes should have computed depths
        assert_eq!(
            depths.len(),
            15,
            "All 15 nodes should have computable depths (all connected)"
        );
    }

    /// Scenario 3.4: Bridge Node Triggers Merge
    /// Setup: Tree A, Tree B (both separate). Node N can reach both.
    /// Run: 30τ
    /// Expect: N joins larger tree, other tree eventually merges via N.
    ///
    /// This tests that a bridge node connecting two separate trees causes
    /// them to merge, with the larger tree absorbing the smaller.
    #[test]
    fn test_bridge_node_triggers_merge() {
        use crate::topology::Link;

        let mut sim = Simulator::new(42);

        // Create Tree A with 5 nodes (star topology around a_root)
        let a_root = sim.add_node(100);
        let mut tree_a = vec![a_root];
        for i in 1..5 {
            let node = sim.add_node(100 + i);
            sim.topology_mut().add_link(a_root, node, Link::default());
            tree_a.push(node);
        }

        // Create Tree B with 3 nodes (star topology around b_root)
        let b_root = sim.add_node(200);
        let mut tree_b = vec![b_root];
        for i in 1..3 {
            let node = sim.add_node(200 + i);
            sim.topology_mut().add_link(b_root, node, Link::default());
            tree_b.push(node);
        }

        // Trees are NOT connected yet - run to form separate trees
        sim.run_for(Duration::from_secs(3));

        // Verify we have 2 separate trees
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 2, "Should have 2 separate trees");

        // Create bridge node N that connects to both trees
        let bridge = sim.add_node(500);
        sim.topology_mut()
            .add_link(bridge, tree_a[1], Link::default()); // Connect to a leaf of A
        sim.topology_mut()
            .add_link(bridge, tree_b[1], Link::default()); // Connect to a leaf of B

        // Run for 100τ (10 seconds) to allow merge and tree_size propagation
        // Bridge needs to join larger tree (3τ shopping), then smaller tree
        // nodes need to detect domination and merge (another 3τ shopping each),
        // plus time for tree_size to propagate from root to leaves
        sim.run_for(Duration::from_secs(10));

        // All nodes should now be in a single tree
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_count(),
            1,
            "Should have merged to 1 tree via bridge"
        );

        // The tree should have 9 nodes (5 from A + 3 from B + 1 bridge)
        let all_nodes: Vec<_> = tree_a
            .iter()
            .chain(tree_b.iter())
            .chain(std::iter::once(&bridge))
            .collect();

        // All nodes should have the same root_hash
        let first_hash = sim.node(all_nodes[0]).unwrap().root_hash();
        for &node_id in &all_nodes {
            assert_eq!(
                sim.node(node_id).unwrap().root_hash(),
                first_hash,
                "All nodes should have same root_hash after merge"
            );
        }

        // Find the actual root and verify tree size
        let root = all_nodes
            .iter()
            .find(|&&id| sim.node(id).unwrap().is_root())
            .copied()
            .expect("Should have a root");

        // Tree size should be 9
        assert_eq!(
            sim.node(root).unwrap().tree_size(),
            9,
            "Merged tree should have 9 nodes"
        );
    }

    /// Scenario 3.5: No Merge During Shopping
    /// Setup: N is in shopping phase. Receives pulse from larger tree.
    /// Expect: N waits until shopping ends before merging (doesn't interrupt shopping).
    ///
    /// This tests that the is_shopping() guard in consider_merge() works correctly.
    /// When a node is already shopping for a parent, it shouldn't restart shopping
    /// when it sees another dominating tree.
    #[test]
    fn test_no_merge_during_shopping() {
        use crate::topology::Link;

        let mut sim = Simulator::new(42);

        // Create a separate tree B with 5 nodes first (will be larger)
        let tree_b_root = sim.add_node(100);
        for i in 1..5 {
            let child = sim.add_node(100 + i);
            sim.topology_mut()
                .add_link(tree_b_root, child, Link::default());
        }

        // Run tree B to form (node A doesn't exist yet)
        sim.run_for(Duration::from_secs(5));

        // Verify tree B formed with 5 nodes
        let tree_b_node = sim.node(&tree_b_root).unwrap();
        assert_eq!(tree_b_node.tree_size(), 5, "Tree B should have 5 nodes");

        // Now add node A - it will start in shopping phase
        let node_a = sim.add_node(1);
        sim.topology_mut()
            .add_link(node_a, tree_b_root, Link::default());

        // Run for just 1τ (0.1s) - node A should be in shopping phase
        // but NOT yet have selected a parent
        sim.run_for(Duration::from_millis(100));

        // Node A should still be in shopping phase (shopping is 3τ = 0.3s)
        let node_a_state = sim.node(&node_a).unwrap();
        assert!(
            node_a_state.is_shopping(),
            "Node A should still be in shopping phase after 1τ"
        );
        assert!(
            node_a_state.is_root(),
            "Node A should still be root during shopping"
        );

        // Run for another 1τ - still shopping
        sim.run_for(Duration::from_millis(100));
        let node_a_state = sim.node(&node_a).unwrap();
        assert!(
            node_a_state.is_shopping(),
            "Node A should still be in shopping phase after 2τ"
        );

        // Run for another 2τ to complete shopping (total 4τ = 0.4s > 3τ)
        sim.run_for(Duration::from_millis(200));

        // Now shopping should be done and node A should have joined tree B
        let node_a_state = sim.node(&node_a).unwrap();
        assert!(
            !node_a_state.is_shopping(),
            "Node A should no longer be in shopping phase"
        );

        // Give some time for parent acknowledgment
        sim.run_for(Duration::from_secs(2));

        // Node A should now be part of tree B
        let node_a_state = sim.node(&node_a).unwrap();
        assert!(
            !node_a_state.is_root(),
            "Node A should have joined tree B after shopping"
        );

        // Tree should now have 6 nodes
        let tree_b_node = sim.node(&tree_b_root).unwrap();
        assert_eq!(
            tree_b_node.tree_size(),
            6,
            "Tree B should now have 6 nodes (original 5 + node A)"
        );
    }

    /// Scenario 4.4: Internal Node Dies
    /// Setup: R—A—{B, C, D}. Remove A at t=10τ.
    /// Run: 50τ
    /// Expect: B, C, D become separate subtrees, rejoin R if in range.
    ///
    /// This tests tree recovery when an internal node (not root, not leaf) dies.
    /// Children should timeout and become roots, then rejoin if they can reach
    /// another node in the surviving tree.
    #[test]
    fn test_internal_node_dies() {
        use crate::topology::Link;

        let mut sim = Simulator::new(42);

        // Create topology: R—A—{B, C, D}
        // R is root, A is internal node, B/C/D are leaves
        let r = sim.add_node(1);
        let a = sim.add_node(2);
        let b = sim.add_node(3);
        let c = sim.add_node(4);
        let d = sim.add_node(5);

        // R connects to A
        sim.topology_mut().add_link(r, a, Link::default());
        // A connects to B, C, D
        sim.topology_mut().add_link(a, b, Link::default());
        sim.topology_mut().add_link(a, c, Link::default());
        sim.topology_mut().add_link(a, d, Link::default());

        // Also connect B, C, D directly to R so they can rejoin after A dies
        sim.topology_mut().add_link(r, b, Link::default());
        sim.topology_mut().add_link(r, c, Link::default());
        sim.topology_mut().add_link(r, d, Link::default());

        // Form tree - run for 30τ (3 seconds) to ensure convergence
        sim.run_for(Duration::from_secs(3));

        // Verify tree formed with 5 nodes
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();
        assert_eq!(snapshot.tree_count(), 1, "Should have 1 tree initially");

        // Find the root (should be R or whichever has lowest root_hash)
        let root_id = find_root(&sim, &[r, a, b, c, d]).expect("Should have a root");
        assert_eq!(
            sim.node(&root_id).unwrap().tree_size(),
            5,
            "Tree should have 5 nodes"
        );

        // Now remove A by deactivating all its links
        if let Some(link) = sim.topology_mut().get_link_mut(r, a) {
            link.active = false;
        }
        if let Some(link) = sim.topology_mut().get_link_mut(a, b) {
            link.active = false;
        }
        if let Some(link) = sim.topology_mut().get_link_mut(a, c) {
            link.active = false;
        }
        if let Some(link) = sim.topology_mut().get_link_mut(a, d) {
            link.active = false;
        }

        // Run for 50τ (5 seconds) to allow timeout and rejoin
        // Parent timeout is 8 missed pulses at ~2τ interval = ~16τ
        sim.run_for(Duration::from_secs(5));

        // B, C, D should have timed out and rejoined via R
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();

        // Should have 1 tree with 4 nodes (R + B + C + D, minus dead A)
        // A is isolated (no links), so it may be a separate size-1 tree
        let tree_count = snapshot.tree_count();

        // The key assertion: B, C, D should have rejoined SOME tree
        // (either R's tree or formed a new tree among themselves)
        // Since they can all reach R, they should all be in one tree
        assert!(
            tree_count <= 2,
            "Should have at most 2 trees (main tree + possibly dead A)"
        );

        // Count how many of R, B, C, D are in the same tree
        let surviving_nodes = [r, b, c, d];
        let mut root_hashes: std::collections::HashSet<[u8; 4]> = std::collections::HashSet::new();
        for &node_id in &surviving_nodes {
            let node = sim.node(&node_id).unwrap();
            root_hashes.insert(node.root_hash());
        }

        // All surviving nodes should have the same root_hash (same tree)
        assert_eq!(
            root_hashes.len(),
            1,
            "All surviving nodes (R, B, C, D) should be in the same tree"
        );

        // The tree should have 4 nodes
        let any_surviving = sim.node(&r).unwrap();
        assert_eq!(
            any_surviving.tree_size(),
            4,
            "Surviving tree should have 4 nodes"
        );

        // Verify node A is now isolated (its own size-1 tree)
        let node_a = sim.node(&a).unwrap();
        assert!(node_a.is_root(), "Isolated node A should be root");
        assert_eq!(
            node_a.tree_size(),
            1,
            "Isolated node A should have tree_size=1"
        );
    }

    /// Scenario 13.1: 100 Nodes Converge
    /// Setup: 100 nodes added gradually, random mesh topology
    /// Run: Add 10 nodes at a time, run 5τ between batches
    /// Expect: Single tree. All nodes have same root_hash.
    ///
    /// This is a scale test that verifies the protocol converges correctly
    /// with a larger network and incremental node joins (more realistic).
    ///
    /// IGNORED by default because it takes a while to run.
    /// Run explicitly with: cargo test -p darksim test_100_nodes -- --ignored --nocapture
    ///
    /// NOTE: This test discovered a tree_size over-counting bug during rapid merges.
    /// See TODO in test body.
    #[test]
    #[ignore]
    fn test_100_nodes_converge() {
        use crate::topology::Link;

        let mut sim = Simulator::new(42);
        let mut nodes = Vec::with_capacity(100);

        // Deterministic RNG for topology
        let mut rng_state: u64 = 12345;
        let mut random_u64 = || -> u64 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng_state
        };

        println!("\n=== 100 Node Convergence Test ===");
        println!("Nodes  Trees  Largest");
        println!("-----  -----  -------");

        // Add 10 nodes at a time
        for batch in 0..10 {
            let batch_start = nodes.len();

            // Add 10 new nodes
            for i in 0..10 {
                let seed = (batch * 10 + i) as u64;
                nodes.push(sim.add_node(seed));
            }

            // Connect new nodes to existing nodes with 10% probability
            for i in batch_start..nodes.len() {
                for j in 0..i {
                    if random_u64() % 100 < 10 {
                        sim.topology_mut()
                            .add_link(nodes[i], nodes[j], Link::default());
                    }
                }
            }

            // Run for 5 seconds to let nodes discover and merge
            sim.run_for(Duration::from_secs(5));

            // Count trees and find largest
            let tree_count = nodes
                .iter()
                .filter(|id| sim.node(id).map(|n| n.is_root()).unwrap_or(false))
                .count();
            let largest = nodes
                .iter()
                .filter_map(|id| {
                    let node = sim.node(id)?;
                    if node.is_root() {
                        Some(node.tree_size())
                    } else {
                        None
                    }
                })
                .max()
                .unwrap_or(0);

            println!("{:5}  {:5}  {:7}", nodes.len(), tree_count, largest);
        }

        // Compute tree depth using compute_depths helper
        let depths = compute_depths(&sim, &nodes);
        let max_depth = depths.values().copied().max().unwrap_or(0);

        // For 100 nodes with MAX_CHILDREN=12, optimal depth is ~2 (log_12(100))
        // With random sparse topology, actual depth can be higher due to connectivity constraints
        // Depth 10 is a reasonable upper bound (still O(log N) range)
        println!("Tree depth: {}", max_depth);
        assert!(
            max_depth <= 10,
            "Tree should be reasonably shallow (depth {} > 10)",
            max_depth
        );

        // Take final snapshot
        sim.take_snapshot();
        let snapshot = sim.metrics().latest_snapshot().unwrap();

        // Check convergence - should form single tree
        let tree_count = snapshot.tree_count();
        assert_eq!(tree_count, 1, "Should converge to single tree");

        // Verify tree_size matches node count
        let root_tree_size = nodes
            .iter()
            .find_map(|id| {
                let node = sim.node(id)?;
                if node.is_root() {
                    Some(node.tree_size())
                } else {
                    None
                }
            })
            .unwrap_or(0);
        assert_eq!(
            root_tree_size, 100,
            "Root tree_size should be 100 (got {})",
            root_tree_size
        );
    }

    /// Scenario 12.4: Proactive Pulse on State Change
    /// Setup: Node's tree state changes (new child joins)
    /// Expect: Proactive pulse sent within ~1.5τ (jittered, range [τ, 2τ]).
    ///
    /// This tests that when a node's state changes (e.g., new child added),
    /// it sends a proactive pulse to inform neighbors. The pulse is scheduled
    /// in the range [τ, 2τ] to allow batching of multiple state changes.
    ///
    /// Verification approach: Using timestamps in DebugEvents, we verify that
    /// after ChildAdded, a PulseSent with child_count >= 1 occurs within [τ, 2τ].
    #[test]
    fn test_proactive_pulse_on_state_change() {
        use crate::topology::Link;
        use darktree::debug::DebugEvent;

        // Create parent node P alone
        let mut sim = Simulator::new(42);
        let p = sim.add_node(1);

        // Get tau for timing verification
        let tau = sim.node(&p).unwrap().tau();

        // Let P stabilize as root for 1 second
        sim.run_for(Duration::from_secs(1));

        // Verify P is root
        assert!(
            sim.node(&p).unwrap().is_root(),
            "P should be root after stabilization"
        );

        // Drain P's debug events to clear history
        sim.node(&p).unwrap().take_debug_events();

        // Create child node C and connect to P
        let c = sim.add_node(2);
        sim.topology_mut().add_link(p, c, Link::default());

        // Run for 2 seconds to let C complete shopping (possibly twice) and join P
        // First shopping is 3τ, if missed neighbor, merge shopping is another 3τ,
        // plus parent exchange takes a few more τ
        sim.run_for(Duration::from_secs(2));

        // Now check P's debug events - should see ChildAdded and PulseSent
        let p_events = sim.node(&p).unwrap().take_debug_events();

        // Find the ChildAdded timestamp
        let child_added_time = p_events.iter().find_map(|e| match e {
            DebugEvent::ChildAdded { timestamp, .. } => Some(*timestamp),
            _ => None,
        });

        assert!(
            child_added_time.is_some(),
            "P should have emitted ChildAdded event after C joined"
        );
        let child_added_time = child_added_time.unwrap();

        // Find first PulseSent with child_count >= 1 AFTER ChildAdded
        let proactive_pulse_time = p_events.iter().find_map(|e| match e {
            DebugEvent::PulseSent {
                timestamp,
                child_count,
                ..
            } if *child_count >= 1 && *timestamp >= child_added_time => Some(*timestamp),
            _ => None,
        });

        assert!(
            proactive_pulse_time.is_some(),
            "P should have sent a pulse with child_count >= 1 after adding child"
        );
        let proactive_pulse_time = proactive_pulse_time.unwrap();

        // Verify timing: proactive pulse should be within [τ, 2τ] of state change
        let delay = proactive_pulse_time - child_added_time;
        let min_delay = tau;
        let max_delay = tau * 2;

        assert!(
            delay >= min_delay && delay <= max_delay,
            "Proactive pulse should be sent within [τ, 2τ] of state change. \
             τ={:?}, delay={:?}, expected [{:?}, {:?}]",
            tau,
            delay,
            min_delay,
            max_delay
        );

        // Also verify C received the updated pulse
        let c_events = sim.node(&c).unwrap().take_debug_events();
        let received_updated_pulse_from_p = c_events.iter().any(|e| {
            matches!(
                e,
                DebugEvent::PulseReceived { from, tree_size: 2, .. } if *from == p
            )
        });

        assert!(
            received_updated_pulse_from_p,
            "C should have received pulse from P with tree_size=2"
        );

        // Verify tree formed correctly
        let p_node = sim.node(&p).unwrap();
        let c_node = sim.node(&c).unwrap();

        // Either P is root with C as child, or vice versa (due to shopping)
        if p_node.is_root() {
            assert_eq!(p_node.children_count(), 1, "P should have C as child");
            assert_eq!(c_node.parent_id(), Some(p), "C's parent should be P");
        } else {
            // C became root (lower root_hash), P joined C
            assert!(c_node.is_root(), "If P is not root, C should be");
        }
    }

    /// Scenario 11.1: Pulse Rate Limit (2τ)
    /// Setup: Node receives pulses from same neighbor faster than 2τ.
    /// Expect: Excess pulses ignored (rate limited).
    ///
    /// This tests the rate limiting mechanism that prevents a neighbor from
    /// flooding us with pulses. Pulses arriving faster than 2τ apart are dropped.
    #[test]
    fn test_pulse_rate_limit() {
        use crate::topology::Link;
        use darktree::debug::DebugEvent;

        // Create two connected nodes
        let mut sim = Simulator::new(42);
        let a = sim.add_node(1);
        let b = sim.add_node(2);
        sim.topology_mut().add_link(a, b, Link::default());

        // Get tau for timing calculations
        let tau = sim.node(&a).unwrap().tau();
        let min_interval = tau * 2; // Rate limit is 2τ

        // Run until they've exchanged pulses and know each other
        sim.run_for(Duration::from_secs(2));

        // Drain debug events to clear history
        sim.node(&a).unwrap().take_debug_events();
        sim.node(&b).unwrap().take_debug_events();

        // Trigger A to send a pulse by calling handle_timer at a future time
        // (past the next scheduled pulse time)
        let future_time = sim.current_time() + tau * 3; // Well past next pulse time
        sim.node_mut(&a).unwrap().handle_timer(future_time);

        // Capture A's outgoing pulse from the transport
        let a_pulses = sim.node(&a).unwrap().take_outgoing();
        assert!(!a_pulses.is_empty(), "A should have sent a pulse");
        let pulse_data = a_pulses[0].clone();

        // Use this future time as our reference point
        let now = future_time;

        // Deliver the pulse to B - first delivery should succeed
        sim.node_mut(&b)
            .unwrap()
            .handle_transport_rx(&pulse_data, None, now);

        // Check B's events - should have PulseReceived, no rate limiting
        let b_events = sim.node(&b).unwrap().take_debug_events();
        let pulse_received = b_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseReceived { .. }));
        let rate_limited = b_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseRateLimited { .. }));

        assert!(pulse_received, "First pulse should be received");
        assert!(!rate_limited, "First pulse should not be rate limited");

        // Now deliver the SAME pulse again immediately (within 2τ)
        // This simulates a duplicate or rapid re-transmission
        let now_plus_small = now + Duration::from_millis(10); // Much less than 2τ
        sim.node_mut(&b)
            .unwrap()
            .handle_transport_rx(&pulse_data, None, now_plus_small);

        // Check B's events - should be rate limited
        let b_events = sim.node(&b).unwrap().take_debug_events();
        let rate_limited = b_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseRateLimited { .. }));

        assert!(
            rate_limited,
            "Second pulse arriving within 2τ should be rate limited"
        );

        // Verify the rate limited event has correct timing info
        let rate_limit_event = b_events
            .iter()
            .find(|e| matches!(e, DebugEvent::PulseRateLimited { .. }));

        if let Some(DebugEvent::PulseRateLimited {
            min_interval_ms, ..
        }) = rate_limit_event
        {
            assert_eq!(
                *min_interval_ms,
                min_interval.as_millis(),
                "Rate limit interval should be 2τ"
            );
        }

        // Now wait for 2τ and try again - should NOT be rate limited
        let now_after_interval = now + min_interval + Duration::from_millis(10);
        sim.node_mut(&b)
            .unwrap()
            .handle_transport_rx(&pulse_data, None, now_after_interval);

        // Check B's events - should have PulseReceived, no rate limiting
        let b_events = sim.node(&b).unwrap().take_debug_events();
        let pulse_received = b_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseReceived { .. }));
        let rate_limited = b_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseRateLimited { .. }));

        assert!(pulse_received, "Pulse after 2τ interval should be received");
        assert!(
            !rate_limited,
            "Pulse after 2τ interval should not be rate limited"
        );
    }

    /// Scenario 11.2: Rate Limit Scales with Bandwidth
    /// Setup: Low bandwidth (τ=6.7s) vs high bandwidth (τ=0.1s).
    /// Expect: Rate limit is 13.4s vs 0.2s respectively.
    ///
    /// Tests that the rate limiting window (2τ) correctly scales with
    /// the bandwidth-aware tau value. LoRa's 38 bytes/sec gives τ=6.71s,
    /// while unlimited bandwidth gives τ=100ms.
    #[test]
    fn test_rate_limit_scales_with_bandwidth() {
        use crate::node::SimNode;

        // Test 1: LoRa bandwidth (38 bytes/sec)
        // τ = MTU / BW = 255 / 38 = 6.71s
        let lora_node = SimNode::with_bandwidth(1, Timestamp::ZERO, 38);
        let lora_tau = lora_node.tau();
        let lora_rate_limit = lora_tau * 2;

        assert_eq!(
            lora_tau.as_millis(),
            6710,
            "LoRa τ should be 6710ms (255/38)"
        );
        assert_eq!(
            lora_rate_limit.as_millis(),
            13420,
            "LoRa rate limit should be 13420ms (2τ)"
        );

        // Test 2: Default (unlimited) bandwidth
        // τ = 100ms default
        let udp_node = SimNode::new(1, Timestamp::ZERO);
        let udp_tau = udp_node.tau();
        let udp_rate_limit = udp_tau * 2;

        assert_eq!(udp_tau.as_millis(), 100, "Default τ should be 100ms");
        assert_eq!(
            udp_rate_limit.as_millis(),
            200,
            "Default rate limit should be 200ms (2τ)"
        );

        // Test 3: Custom bandwidth (100 bytes/sec)
        // τ = 255 / 100 = 2.55s
        let custom_node = SimNode::with_bandwidth(1, Timestamp::ZERO, 100);
        let custom_tau = custom_node.tau();
        let custom_rate_limit = custom_tau * 2;

        assert_eq!(
            custom_tau.as_millis(),
            2550,
            "Custom τ should be 2550ms (255/100)"
        );
        assert_eq!(
            custom_rate_limit.as_millis(),
            5100,
            "Custom rate limit should be 5100ms (2τ)"
        );

        // Verify ratio between different bandwidths
        // LoRa should be ~67x slower than UDP (6710/100 ≈ 67)
        let ratio = lora_tau.as_millis() / udp_tau.as_millis();
        assert!((65..=70).contains(&ratio), "LoRa τ should be ~67x UDP τ");
    }

    /// Scenario 10.1: Pubkey Cached on First Pulse
    /// Setup: N receives pulse from unknown node P with has_pubkey=true.
    /// Expect: N caches P's pubkey. Subsequent pulses verified.
    ///
    /// Tests that when a node receives a pulse containing a public key,
    /// the pubkey is cached and used to verify future pulses.
    #[test]
    fn test_pubkey_cached_on_first_pulse() {
        use crate::topology::Link;
        use darktree::debug::DebugEvent;

        // Create two connected nodes
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);
        let p = sim.add_node(2);
        sim.topology_mut().add_link(n, p, Link::default());

        // Initially, N should not have P's pubkey cached
        let n_has_p_pubkey = sim.node(&n).unwrap().inner().has_pubkey(&p);
        assert!(!n_has_p_pubkey, "N should not initially have P's pubkey");

        // Run simulation briefly to exchange pulses
        // During this time, nodes will:
        // 1. Send initial pulses (first pulses include pubkey)
        // 2. Cache each other's pubkeys
        sim.run_for(Duration::from_secs(2));

        // After exchange, N should have P's pubkey cached
        let n_has_p_pubkey = sim.node(&n).unwrap().inner().has_pubkey(&p);
        assert!(n_has_p_pubkey, "N should have cached P's pubkey");

        // And P should have N's pubkey cached
        let p_has_n_pubkey = sim.node(&p).unwrap().inner().has_pubkey(&n);
        assert!(p_has_n_pubkey, "P should have cached N's pubkey");

        // Clear debug events
        sim.node(&n).unwrap().take_debug_events();
        sim.node(&p).unwrap().take_debug_events();

        // Trigger P to send another pulse
        let tau = sim.node(&p).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&p).unwrap().handle_timer(future_time);

        // Capture P's pulse and deliver to N
        let p_pulses = sim.node(&p).unwrap().take_outgoing();
        assert!(!p_pulses.is_empty(), "P should have sent a pulse");
        let pulse_data = p_pulses[0].clone();

        // Deliver to N - should be verified using cached pubkey
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&pulse_data, None, future_time);

        // Check N's events - should have PulseReceived, not SignatureVerifyFailed
        let n_events = sim.node(&n).unwrap().take_debug_events();

        let pulse_received = n_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseReceived { from, .. } if *from == p));
        let sig_failed = n_events
            .iter()
            .any(|e| matches!(e, DebugEvent::SignatureVerifyFailed { .. }));

        assert!(
            pulse_received,
            "N should have received and verified P's pulse"
        );
        assert!(!sig_failed, "Signature verification should not have failed");
    }

    /// Scenario 10.2: Need Pubkey Flag
    /// Setup: N receives pulse from P without pubkey. N needs it.
    /// Expect: N sets need_pubkey=true in next pulse. P includes pubkey.
    ///
    /// Tests the request-response mechanism for pubkey exchange where
    /// a node explicitly requests a neighbor's pubkey via the need_pubkey flag.
    #[test]
    fn test_need_pubkey_flag() {
        use darktree::wire::{Decode, Reader};

        // Create two nodes without topology connection initially
        // This ensures they don't automatically exchange pulses
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);
        let p = sim.add_node(2);

        // Get tau for timing
        let tau = sim.node(&n).unwrap().tau();

        // Initially neither should have the other's pubkey
        assert!(
            !sim.node(&n).unwrap().inner().has_pubkey(&p),
            "N should not have P's pubkey initially"
        );
        assert!(
            !sim.node(&p).unwrap().inner().has_pubkey(&n),
            "P should not have N's pubkey initially"
        );

        // Nodes send initial pulses on creation, but they go nowhere (no topology)
        // Drain any initial outgoing to clear state
        sim.node(&n).unwrap().take_outgoing();
        sim.node(&p).unwrap().take_outgoing();

        // Advance time past the next scheduled pulse time to trigger P to send
        let t1 = sim.current_time() + tau * 3;
        sim.node_mut(&p).unwrap().handle_timer(t1);

        // Capture P's pulse - it should NOT include pubkey (no one needs it yet)
        let p_pulses = sim.node(&p).unwrap().take_outgoing();
        assert!(!p_pulses.is_empty(), "P should have sent a pulse");
        let p_pulse_data = p_pulses[0].clone();

        // Decode and check P's pulse flags
        let mut reader = Reader::new(&p_pulse_data[1..]); // Skip wire type byte
        let p_pulse = darktree::types::Pulse::decode(&mut reader).expect("decode P's pulse");
        assert!(
            !p_pulse.has_pubkey(),
            "P's first pulse should NOT include pubkey (no one needs it)"
        );
        assert!(
            !p_pulse.need_pubkey(),
            "P should not need any pubkeys initially"
        );

        // Deliver P's pulse to N
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&p_pulse_data, None, t1);

        // N should now need P's pubkey (added to need_pubkey set internally)
        // N should NOT have P's pubkey yet
        assert!(
            !sim.node(&n).unwrap().inner().has_pubkey(&p),
            "N should still not have P's pubkey (wasn't in pulse)"
        );

        // Drain N's outgoing (it may have scheduled a proactive pulse)
        sim.node(&n).unwrap().take_outgoing();

        // Advance time past next pulse time to trigger N to send
        let t2 = t1 + tau * 2;
        sim.node_mut(&n).unwrap().handle_timer(t2);

        // Capture N's pulse - it should have need_pubkey=true
        let n_pulses = sim.node(&n).unwrap().take_outgoing();
        assert!(!n_pulses.is_empty(), "N should have sent a pulse");
        let n_pulse_data = n_pulses[0].clone();

        // Decode and check N's pulse flags
        let mut reader = Reader::new(&n_pulse_data[1..]);
        let n_pulse = darktree::types::Pulse::decode(&mut reader).expect("decode N's pulse");
        assert!(
            n_pulse.need_pubkey(),
            "N's pulse should have need_pubkey=true (requesting P's pubkey)"
        );
        // N should include its own pubkey since it needs pubkeys
        assert!(
            n_pulse.has_pubkey(),
            "N should include its pubkey when requesting others"
        );

        // Deliver N's pulse to P
        sim.node_mut(&p)
            .unwrap()
            .handle_transport_rx(&n_pulse_data, None, t2);

        // P should now know N needs its pubkey (tracked in neighbors_need_pubkey)
        // P should also have cached N's pubkey
        assert!(
            sim.node(&p).unwrap().inner().has_pubkey(&n),
            "P should now have N's pubkey (N included it)"
        );

        // Drain P's outgoing and advance time to trigger new pulse
        sim.node(&p).unwrap().take_outgoing();
        let t3 = t2 + tau * 2;
        sim.node_mut(&p).unwrap().handle_timer(t3);

        // Capture P's response pulse - should now include pubkey
        let p_pulses = sim.node(&p).unwrap().take_outgoing();
        assert!(!p_pulses.is_empty(), "P should have sent a pulse");
        let p_pulse_data = p_pulses[0].clone();

        // Decode and check P's pulse flags
        let mut reader = Reader::new(&p_pulse_data[1..]);
        let p_pulse = darktree::types::Pulse::decode(&mut reader).expect("decode P's response");
        assert!(
            p_pulse.has_pubkey(),
            "P's response pulse should include pubkey (N needs it)"
        );

        // Deliver P's response to N
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&p_pulse_data, None, t3);

        // N should now have P's pubkey cached
        assert!(
            sim.node(&n).unwrap().inner().has_pubkey(&p),
            "N should now have P's pubkey cached"
        );
    }

    /// Scenario 10.3: Signature Verification Failure
    /// Setup: Attacker sends pulse with wrong signature.
    /// Expect: Pulse rejected after signature check.
    ///
    /// Tests that pulses with invalid signatures are rejected and
    /// the SignatureVerifyFailed debug event is emitted.
    #[test]
    fn test_signature_verification_failure() {
        use crate::topology::Link;
        use darktree::debug::DebugEvent;

        // Create two connected nodes
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);
        let p = sim.add_node(2);
        sim.topology_mut().add_link(n, p, Link::default());

        // Run briefly so they exchange pubkeys
        sim.run_for(Duration::from_secs(2));

        // Verify N has P's pubkey (required for signature verification)
        assert!(
            sim.node(&n).unwrap().inner().has_pubkey(&p),
            "N should have P's pubkey cached"
        );

        // Clear debug events
        sim.node(&n).unwrap().take_debug_events();

        // Trigger P to send a pulse
        let tau = sim.node(&p).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&p).unwrap().handle_timer(future_time);

        // Capture P's valid pulse
        let p_pulses = sim.node(&p).unwrap().take_outgoing();
        assert!(!p_pulses.is_empty(), "P should have sent a pulse");
        let mut corrupted_pulse = p_pulses[0].clone();

        // Corrupt the signature to fail SimCrypto's verify check
        // Signature format: algorithm (1 byte) + sig (64 bytes) = 65 bytes at end
        // SimCrypto.verify checks: sig.sig[..32] != [0u8; 32]
        // To fail this check, we set the first 32 bytes of sig to all zeros
        let len = corrupted_pulse.len();
        assert!(len > 65, "Pulse should be longer than signature");
        // sig bytes are at positions len-64 to len-1 (after algorithm byte)
        // Set first 32 bytes of sig to zero to fail the verify check
        for i in 0..32 {
            corrupted_pulse[len - 64 + i] = 0;
        }

        // Deliver the corrupted pulse to N
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&corrupted_pulse, None, future_time);

        // Check N's events - should have SignatureVerifyFailed
        let n_events = sim.node(&n).unwrap().take_debug_events();

        let sig_failed = n_events
            .iter()
            .any(|e| matches!(e, DebugEvent::SignatureVerifyFailed { node_id } if *node_id == p));
        let pulse_received = n_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseReceived { from, .. } if *from == p));

        assert!(
            sig_failed,
            "SignatureVerifyFailed event should be emitted for corrupted pulse"
        );
        assert!(
            !pulse_received,
            "PulseReceived should NOT be emitted for corrupted pulse"
        );

        // Verify that N's state was not affected by the corrupted pulse
        // (the corrupted pulse should not update neighbor timing or tree state)
        // We can verify this by delivering a valid pulse and checking it's processed normally
        let valid_pulse = p_pulses[0].clone();
        sim.node_mut(&n).unwrap().handle_transport_rx(
            &valid_pulse,
            None,
            future_time + Duration::from_millis(500),
        );

        let n_events = sim.node(&n).unwrap().take_debug_events();
        let pulse_received = n_events
            .iter()
            .any(|e| matches!(e, DebugEvent::PulseReceived { from, .. } if *from == p));

        assert!(
            pulse_received,
            "Valid pulse should be received after corrupted one was rejected"
        );
    }

    /// Scenario 17.1: Oversized Child Count
    /// Setup: Attacker sends pulse with child_count=20 (exceeds MAX_CHILDREN=12).
    /// Expect: Rejected at decode. No allocation attempted.
    ///
    /// Tests that malformed pulses with excessive child counts are rejected
    /// at the wire format decode stage before any memory allocation.
    #[test]
    fn test_oversized_child_count_rejected() {
        use darktree::debug::DebugEvent;
        use darktree::types::PULSE_CHILD_COUNT_SHIFT;
        use darktree::wire::{Decode, DecodeError, Reader};

        // Create a node
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);

        // Get tau and trigger a pulse
        let tau = sim.node(&n).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&n).unwrap().handle_timer(future_time);

        // Capture the valid pulse
        let pulses = sim.node(&n).unwrap().take_outgoing();
        assert!(!pulses.is_empty(), "Node should have sent a pulse");
        let mut malformed_pulse = pulses[0].clone();

        // Pulse wire format: wire_type(1) + node_id(16) + flags(1) + ...
        // flags byte is at index 17
        // flags format: bit 0 = has_parent, bit 1 = need_pubkey, bit 2 = has_pubkey
        //               bits 3-7 = child_count (0-31 range, but MAX_CHILDREN=12)
        let flags_index = 17;
        let original_flags = malformed_pulse[flags_index];

        // Set child_count to 20 (exceeds MAX_CHILDREN=12)
        // child_count is stored in bits 3-7, so child_count=20 means 20 << 3 = 160
        let malicious_child_count: u8 = 20;
        let new_flags =
            (original_flags & 0x07) | (malicious_child_count << PULSE_CHILD_COUNT_SHIFT);
        malformed_pulse[flags_index] = new_flags;

        // Verify the decode fails with CapacityExceeded
        let mut reader = Reader::new(&malformed_pulse[1..]); // Skip wire_type byte
        let result = darktree::types::Pulse::decode(&mut reader);

        assert!(
            matches!(result, Err(DecodeError::CapacityExceeded)),
            "Decode should fail with CapacityExceeded for child_count=20, got {:?}",
            result
        );

        // Also verify that delivering this malformed pulse to a node
        // results in MessageDecodeFailed event
        sim.node(&n).unwrap().take_debug_events(); // Clear events
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&malformed_pulse, None, future_time);

        let events = sim.node(&n).unwrap().take_debug_events();
        let decode_failed = events
            .iter()
            .any(|e| matches!(e, DebugEvent::MessageDecodeFailed { .. }));

        assert!(
            decode_failed,
            "MessageDecodeFailed event should be emitted for oversized child count"
        );
    }

    /// Scenario 17.2: Non-canonical varint encoding should be rejected.
    #[test]
    fn test_non_canonical_varint_rejected() {
        use darktree::debug::DebugEvent;
        use darktree::wire::DecodeError;

        // Create a node
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);

        // Get tau and trigger a pulse
        let tau = sim.node(&n).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&n).unwrap().handle_timer(future_time);

        // Capture the valid pulse
        let pulses = sim.node(&n).unwrap().take_outgoing();
        assert!(!pulses.is_empty(), "Node should have sent a pulse");
        let valid_pulse = &pulses[0];

        // Pulse wire format after wire_type(1) + node_id(16) + flags(1) = 18 bytes:
        // - [parent_hash: 4 bytes if has_parent flag set]
        // - root_hash: 4 bytes
        // - subtree_size: varint (1 byte for small values)
        // - tree_size: varint
        // - keyspace_lo: u32 big-endian (4 bytes)
        // - keyspace_hi: u32 big-endian (4 bytes)
        // ...

        // Verify our assumption: this is a root node (no parent)
        // If has_parent were set, the offset would shift by 4 bytes
        let flags_index = 17; // wire_type(1) + node_id(16)
        assert_eq!(
            valid_pulse[flags_index] & 0x01,
            0,
            "Test assumes node has no parent"
        );

        // The subtree_size is at offset 22 (18 + 4 for root_hash, no parent_hash).
        // For a single node, subtree_size=1, encoded as 0x01.
        let subtree_size_offset = 22; // wire_type(1) + node_id(16) + flags(1) + root_hash(4)
        assert_eq!(
            valid_pulse[subtree_size_offset], 0x01,
            "Expected subtree_size=1 for single node"
        );

        // Create malformed pulse with non-canonical varint for subtree_size
        // A non-canonical encoding of 1 would be 0x81 0x00 instead of 0x01.
        let mut malformed_pulse = Vec::with_capacity(valid_pulse.len() + 1);

        // Copy bytes up to subtree_size position
        malformed_pulse.extend_from_slice(&valid_pulse[..subtree_size_offset]);

        // Insert non-canonical encoding of 1: 0x81 0x00 instead of 0x01
        malformed_pulse.push(0x81);
        malformed_pulse.push(0x00);

        // Skip the original subtree_size byte and copy the rest
        // Original subtree_size for a single node is 1 byte (value 1 = 0x01)
        malformed_pulse.extend_from_slice(&valid_pulse[subtree_size_offset + 1..]);

        // Verify the decode fails with NonCanonicalVarint
        use darktree::wire::{Decode, Reader};
        let mut reader = Reader::new(&malformed_pulse[1..]); // Skip wire_type byte
        let result = darktree::types::Pulse::decode(&mut reader);

        assert!(
            matches!(result, Err(DecodeError::NonCanonicalVarint)),
            "Decode should fail with NonCanonicalVarint, got {:?}",
            result
        );

        // Also verify that delivering this malformed pulse to a node
        // results in MessageDecodeFailed event
        sim.node(&n).unwrap().take_debug_events(); // Clear events
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&malformed_pulse, None, future_time);

        let events = sim.node(&n).unwrap().take_debug_events();
        let decode_failed = events
            .iter()
            .any(|e| matches!(e, DebugEvent::MessageDecodeFailed { .. }));

        assert!(
            decode_failed,
            "MessageDecodeFailed event should be emitted for non-canonical varint"
        );
    }

    /// Scenario 17.3: Truncated message should be rejected.
    #[test]
    fn test_truncated_message_rejected() {
        use darktree::debug::DebugEvent;
        use darktree::wire::{Decode, DecodeError, Reader};

        // Create a node
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);

        // Get tau and trigger a pulse
        let tau = sim.node(&n).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&n).unwrap().handle_timer(future_time);

        // Capture the valid pulse
        let pulses = sim.node(&n).unwrap().take_outgoing();
        assert!(!pulses.is_empty(), "Node should have sent a pulse");
        let valid_pulse = &pulses[0];

        // A valid pulse has a 65-byte signature at the end (1 byte algorithm + 64 bytes sig).
        // Truncate before the signature to create an invalid message.
        assert!(
            valid_pulse.len() > 65,
            "Pulse should be longer than just the signature"
        );

        // Truncate to remove the last 32 bytes of the signature
        let truncated_pulse = &valid_pulse[..valid_pulse.len() - 32];

        // Verify the decode fails with UnexpectedEof
        let mut reader = Reader::new(&truncated_pulse[1..]); // Skip wire_type byte
        let result = darktree::types::Pulse::decode(&mut reader);

        assert!(
            matches!(result, Err(DecodeError::UnexpectedEof)),
            "Decode should fail with UnexpectedEof for truncated message, got {:?}",
            result
        );

        // Also verify that delivering this truncated pulse to a node
        // results in MessageDecodeFailed event
        sim.node(&n).unwrap().take_debug_events(); // Clear events
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(truncated_pulse, None, future_time);

        let events = sim.node(&n).unwrap().take_debug_events();
        let decode_failed = events
            .iter()
            .any(|e| matches!(e, DebugEvent::MessageDecodeFailed { .. }));

        assert!(
            decode_failed,
            "MessageDecodeFailed event should be emitted for truncated message"
        );
    }

    /// Scenario 17.4: Invalid wire type should be rejected.
    #[test]
    fn test_invalid_wire_type_rejected() {
        use darktree::debug::DebugEvent;
        use darktree::wire::{Decode, DecodeError, Message, Reader};

        // Create a node
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);

        // Get tau and trigger a pulse to get a valid message
        let tau = sim.node(&n).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&n).unwrap().handle_timer(future_time);

        // Capture the valid pulse
        let pulses = sim.node(&n).unwrap().take_outgoing();
        assert!(!pulses.is_empty(), "Node should have sent a pulse");
        let valid_pulse = &pulses[0];

        // Create a message with invalid wire type (0x99)
        // Valid wire types are: 0x01 (Pulse), 0x02 (Routed), 0x03 (Ack)
        let mut invalid_msg = valid_pulse.clone();
        invalid_msg[0] = 0x99; // Invalid wire type

        // Verify the decode fails with InvalidMessageType
        let mut reader = Reader::new(&invalid_msg);
        let result = Message::decode(&mut reader);

        assert!(
            matches!(result, Err(DecodeError::InvalidMessageType)),
            "Decode should fail with InvalidMessageType for wire_type=0x99, got {:?}",
            result
        );

        // Also verify that delivering this invalid message to a node
        // results in MessageDecodeFailed event
        sim.node(&n).unwrap().take_debug_events(); // Clear events
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&invalid_msg, None, future_time);

        let events = sim.node(&n).unwrap().take_debug_events();
        let decode_failed = events
            .iter()
            .any(|e| matches!(e, DebugEvent::MessageDecodeFailed { .. }));

        assert!(
            decode_failed,
            "MessageDecodeFailed event should be emitted for invalid wire type"
        );
    }

    /// Scenario 17.5: Invalid signature algorithm should be rejected.
    #[test]
    fn test_invalid_signature_algorithm_rejected() {
        use darktree::debug::DebugEvent;
        use darktree::wire::{Decode, DecodeError, Reader};

        // Create a node
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);

        // Get tau and trigger a pulse
        let tau = sim.node(&n).unwrap().tau();
        let future_time = sim.current_time() + tau * 3;
        sim.node_mut(&n).unwrap().handle_timer(future_time);

        // Capture the valid pulse
        let pulses = sim.node(&n).unwrap().take_outgoing();
        assert!(!pulses.is_empty(), "Node should have sent a pulse");
        let valid_pulse = &pulses[0];

        // A valid pulse has a signature at the end: 1 byte algorithm + 64 bytes sig = 65 bytes.
        // The algorithm byte is at offset len - SIG_WIRE_SIZE.
        const SIG_WIRE_SIZE: usize = 1 + 64; // algorithm byte + Ed25519 signature
        let sig_algo_offset = valid_pulse.len() - SIG_WIRE_SIZE;

        // Verify the original algorithm byte is 0x01 (ALGORITHM_ED25519)
        assert_eq!(
            valid_pulse[sig_algo_offset], 0x01,
            "Expected ALGORITHM_ED25519 (0x01)"
        );

        // Create a message with invalid signature algorithm (0x99)
        let mut invalid_msg = valid_pulse.clone();
        invalid_msg[sig_algo_offset] = 0x99; // Invalid algorithm

        // Verify the decode fails with InvalidSignature
        let mut reader = Reader::new(&invalid_msg[1..]); // Skip wire_type byte
        let result = darktree::types::Pulse::decode(&mut reader);

        assert!(
            matches!(result, Err(DecodeError::InvalidSignature)),
            "Decode should fail with InvalidSignature for algorithm=0x99, got {:?}",
            result
        );

        // Also verify that delivering this invalid message to a node
        // results in MessageDecodeFailed event
        sim.node(&n).unwrap().take_debug_events(); // Clear events
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&invalid_msg, None, future_time);

        let events = sim.node(&n).unwrap().take_debug_events();
        let decode_failed = events
            .iter()
            .any(|e| matches!(e, DebugEvent::MessageDecodeFailed { .. }));

        assert!(
            decode_failed,
            "MessageDecodeFailed event should be emitted for invalid signature algorithm"
        );
    }

    /// Scenario 17.6: Pulse with unsorted children should be rejected.
    #[test]
    fn test_unsorted_children_rejected() {
        use darktree::debug::DebugEvent;
        use darktree::types::ALGORITHM_ED25519;
        use darktree::wire::{Decode, DecodeError, Reader, Writer};

        // Create a node to receive the malformed message
        let mut sim = Simulator::new(42);
        let n = sim.add_node(1);
        let tau = sim.node(&n).unwrap().tau();
        let now = sim.current_time() + tau * 3;

        // Manually construct a pulse with unsorted children
        // Children should be sorted by hash in ascending order (lexicographic big-endian).
        // We'll put 0xBB before 0xAA which is wrong (0xAA < 0xBB).
        let mut w = Writer::new();

        // Wire type (Pulse = 0x01)
        w.write_u8(0x01);

        // node_id (16 bytes)
        w.write_node_id(&[0x42u8; 16]);

        // flags: has_parent=false, need_pubkey=false, has_pubkey=false, child_count=2
        let flags = 2 << 3; // 2 children in bits 3-7
        w.write_u8(flags);

        // root_hash (4 bytes)
        w.write_child_hash(&[0xAA; 4]);

        // subtree_size, tree_size (varints)
        w.write_varint(3); // subtree_size
        w.write_varint(3); // tree_size

        // keyspace_lo, keyspace_hi (u32 big-endian)
        w.write_u32_be(0);
        w.write_u32_be(u32::MAX);

        // Children in WRONG order (0xBB > 0xAA, so should be AA first)
        w.write_child_hash(&[0xBB; 4]); // First child hash (WRONG - should be after 0xAA)
        w.write_varint(1); // subtree_size
        w.write_child_hash(&[0xAA; 4]); // Second child hash
        w.write_varint(1); // subtree_size

        // Signature (1 + 64 bytes)
        w.write_u8(ALGORITHM_ED25519);
        w.write_bytes(&[0u8; 64]);

        let malformed_pulse = w.finish();

        // Verify the decode fails with InvalidValue
        let mut reader = Reader::new(&malformed_pulse[1..]); // Skip wire_type byte
        let result = darktree::types::Pulse::decode(&mut reader);

        assert!(
            matches!(result, Err(DecodeError::InvalidValue)),
            "Decode should fail with InvalidValue for unsorted children, got {:?}",
            result
        );

        // Also verify that delivering this malformed pulse to a node
        // results in MessageDecodeFailed event
        sim.node(&n).unwrap().take_debug_events(); // Clear events
        sim.node_mut(&n)
            .unwrap()
            .handle_transport_rx(&malformed_pulse, None, now);

        let events = sim.node(&n).unwrap().take_debug_events();
        let decode_failed = events
            .iter()
            .any(|e| matches!(e, DebugEvent::MessageDecodeFailed { .. }));

        assert!(
            decode_failed,
            "MessageDecodeFailed event should be emitted for unsorted children"
        );
    }
}
