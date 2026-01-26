//! Scenario builder for setting up and running simulations.

use darktree::{Duration, NodeId, Timestamp};

use crate::event::ScenarioAction;
use crate::metrics::SimulationResult;
use crate::sim::Simulator;
use crate::topology::Topology;

/// Type of topology to generate.
#[derive(Debug, Clone)]
enum TopologyType {
    /// Fully connected topology.
    FullyConnected,
    /// Chain topology (each node connected only to neighbors).
    Chain,
    /// Star topology (first node is hub).
    Star,
    /// Random geometric topology with specified radius.
    RandomGeometric { radius: f64 },
    /// Random geometric topology with adaptive radius.
    RandomGeometricAdaptive,
    /// Custom topology provided by user.
    Custom(Topology),
}

/// Builder for simulation scenarios.
pub struct ScenarioBuilder {
    /// Number of nodes to create.
    num_nodes: usize,
    /// RNG seed for determinism.
    seed: u64,
    /// Topology type to generate (must be explicitly specified).
    topology_type: Option<TopologyType>,
    /// Global packet loss rate.
    loss_rate: f64,
    /// Link delay.
    delay: Duration,
    /// Bandwidth limit (None = unlimited).
    bandwidth: Option<u32>,
    /// Scheduled actions.
    actions: Vec<(Timestamp, ScenarioAction)>,
    /// Snapshot interval.
    snapshot_interval: Option<Duration>,
}

impl Default for ScenarioBuilder {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ScenarioBuilder {
    /// Create a new scenario with the specified number of nodes.
    ///
    /// Note: You MUST specify a topology before calling build().
    /// Use `.fully_connected()`, `.chain_topology()`, `.star_topology()`,
    /// or `.topology(custom_topology)`.
    pub fn new(num_nodes: usize) -> Self {
        Self {
            num_nodes,
            seed: 42,
            topology_type: None, // Must be explicitly specified
            loss_rate: 0.0,
            delay: Duration::from_millis(1),
            bandwidth: None,
            actions: Vec::new(),
            snapshot_interval: None,
        }
    }

    /// Set the RNG seed for deterministic simulation.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set a custom network topology.
    pub fn topology(mut self, topo: Topology) -> Self {
        self.topology_type = Some(TopologyType::Custom(topo));
        self
    }

    /// Use fully connected topology.
    pub fn fully_connected(mut self) -> Self {
        self.topology_type = Some(TopologyType::FullyConnected);
        self
    }

    /// Use chain topology (each node connected only to neighbors).
    pub fn chain_topology(mut self) -> Self {
        self.topology_type = Some(TopologyType::Chain);
        self
    }

    /// Use star topology (first node is hub).
    pub fn star_topology(mut self) -> Self {
        self.topology_type = Some(TopologyType::Star);
        self
    }

    /// Use random geometric topology with specified radius.
    ///
    /// Nodes are placed at deterministic positions in a unit square.
    /// Two nodes are connected if their distance is <= radius.
    /// Connectivity is guaranteed by adding minimal MST edges if needed.
    pub fn random_geometric(mut self, radius: f64) -> Self {
        self.topology_type = Some(TopologyType::RandomGeometric { radius });
        self
    }

    /// Use random geometric topology with adaptive radius.
    ///
    /// The radius is computed to give approximately 5 neighbors per node,
    /// clamped to [0.15, 0.70]. Connectivity is guaranteed.
    pub fn random_geometric_adaptive(mut self) -> Self {
        self.topology_type = Some(TopologyType::RandomGeometricAdaptive);
        self
    }

    /// Set global packet loss rate.
    pub fn with_loss_rate(mut self, rate: f64) -> Self {
        self.loss_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set link delay.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Set bandwidth limit for LoRa simulation.
    pub fn with_bandwidth(mut self, bw: u32) -> Self {
        self.bandwidth = Some(bw);
        self
    }

    /// Set snapshot interval for metrics collection.
    pub fn with_snapshot_interval(mut self, interval: Duration) -> Self {
        self.snapshot_interval = Some(interval);
        self
    }

    /// Schedule a network partition at the specified time.
    pub fn partition_at(mut self, time: Timestamp, groups: Vec<Vec<usize>>) -> Self {
        // Store as indices, will convert to NodeIds during build
        self.actions.push((
            time,
            ScenarioAction::Partition {
                groups: groups
                    .into_iter()
                    .map(|g| g.into_iter().map(|i| [i as u8; 16]).collect())
                    .collect(),
            },
        ));
        self
    }

    /// Schedule partition healing at the specified time.
    pub fn heal_at(mut self, time: Timestamp) -> Self {
        self.actions.push((time, ScenarioAction::HealPartition));
        self
    }

    /// Schedule a snapshot at the specified time.
    pub fn snapshot_at(mut self, time: Timestamp) -> Self {
        self.actions.push((time, ScenarioAction::TakeSnapshot));
        self
    }

    /// Build the simulator with all nodes and topology.
    pub fn build(self) -> (Simulator, Vec<NodeId>) {
        let mut sim = Simulator::new(self.seed);

        // Set snapshot interval if specified
        if let Some(interval) = self.snapshot_interval {
            sim = sim.with_snapshot_interval(interval);
        }

        // Predict node IDs deterministically (matches SimCrypto.generate_keypair behavior)
        let predicted_node_ids: Vec<NodeId> = (0..self.num_nodes)
            .map(|i| predict_node_id(self.seed.wrapping_add(i as u64 * 1000)))
            .collect();

        // Build topology with predicted node IDs
        let mut topo = match self.topology_type {
            Some(TopologyType::FullyConnected) => Topology::fully_connected(&predicted_node_ids),
            Some(TopologyType::Chain) => Topology::chain(&predicted_node_ids),
            Some(TopologyType::Star) => Topology::star(&predicted_node_ids),
            Some(TopologyType::RandomGeometric { radius }) => {
                Topology::random_geometric(&predicted_node_ids, self.seed, radius)
            }
            Some(TopologyType::RandomGeometricAdaptive) => {
                Topology::random_geometric_adaptive(&predicted_node_ids, self.seed)
            }
            Some(TopologyType::Custom(t)) => t,
            None => panic!(
                "Topology must be explicitly specified. \
                Use .fully_connected(), .chain_topology(), .star_topology(), \
                .random_geometric(), .random_geometric_adaptive(), or .topology()"
            ),
        };

        // Apply global settings
        if self.loss_rate > 0.0 {
            topo.set_global_loss_rate(self.loss_rate);
        }

        // Update topology with custom delay
        for i in 0..predicted_node_ids.len() {
            for j in (i + 1)..predicted_node_ids.len() {
                if let Some(link) = topo.get_link_mut(predicted_node_ids[i], predicted_node_ids[j])
                {
                    link.delay = self.delay;
                }
            }
        }

        // Set topology BEFORE adding nodes
        sim = sim.with_topology(topo);

        // Now create nodes (they will use the correct topology)
        let mut node_ids = Vec::with_capacity(self.num_nodes);
        for (i, &predicted_id) in predicted_node_ids.iter().enumerate().take(self.num_nodes) {
            let node_seed = self.seed.wrapping_add(i as u64 * 1000);
            let node_id = if let Some(bw) = self.bandwidth {
                sim.add_node_with_bandwidth(node_seed, bw)
            } else {
                sim.add_node(node_seed)
            };
            // Verify prediction matches actual
            debug_assert_eq!(
                node_id, predicted_id,
                "Node ID prediction mismatch for node {}: predicted {:?} vs actual {:?}",
                i, predicted_id, node_id
            );
            node_ids.push(node_id);
        }

        // Schedule actions (convert indices to actual NodeIds)
        for (time, action) in self.actions {
            let converted_action = match action {
                ScenarioAction::Partition { groups } => {
                    let converted_groups: Vec<Vec<NodeId>> = groups
                        .into_iter()
                        .map(|g| {
                            g.into_iter()
                                .filter_map(|placeholder| {
                                    let idx = placeholder[0] as usize;
                                    node_ids.get(idx).copied()
                                })
                                .collect()
                        })
                        .collect();
                    ScenarioAction::Partition {
                        groups: converted_groups,
                    }
                }
                other => other,
            };
            sim.schedule_action(time, converted_action);
        }

        (sim, node_ids)
    }

    /// Build and run the simulation for the specified duration.
    pub fn run_for(self, duration: Duration) -> SimulationResult {
        let (mut sim, _) = self.build();
        sim.run_for(duration)
    }

    /// Build and run until the specified time.
    pub fn run_until(self, time: Timestamp) -> SimulationResult {
        let (mut sim, _) = self.build();
        sim.run_until(time)
    }
}

/// Convenience function to create a simple N-node fully connected scenario.
pub fn simple_scenario(num_nodes: usize) -> ScenarioBuilder {
    ScenarioBuilder::new(num_nodes).fully_connected()
}

/// Convenience function for LoRa-like simulation (38 bytes/sec bandwidth).
pub fn lora_scenario(num_nodes: usize) -> ScenarioBuilder {
    ScenarioBuilder::new(num_nodes)
        .fully_connected()
        .with_bandwidth(38)
}

/// Predict a node's ID from its seed (matches FastTestCrypto deterministic keypair generation).
fn predict_node_id(node_seed: u64) -> NodeId {
    use darktree::traits::{test_impls::FastTestCrypto, Crypto};

    let mut crypto = FastTestCrypto::new(node_seed);
    let (pubkey, _secret) = crypto.generate_keypair();
    crypto.node_id_from_pubkey(&pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_builder_basic() {
        let (sim, nodes) = ScenarioBuilder::new(3)
            .with_seed(123)
            .fully_connected()
            .build();

        assert_eq!(nodes.len(), 3);
        assert_eq!(sim.node_ids().len(), 3);
    }

    #[test]
    fn test_scenario_run_for() {
        let result = simple_scenario(2).run_for(Duration::from_secs(1));

        assert!(result.end_time >= Timestamp::from_secs(1));
        assert!(!result.metrics.snapshots.is_empty());
    }

    #[test]
    fn test_scenario_with_loss() {
        let (sim, nodes) = ScenarioBuilder::new(2)
            .fully_connected()
            .with_loss_rate(0.5)
            .build();

        // With 50% loss, topology should still be connected but lossy
        let link = sim.topology().get_link(nodes[0], nodes[1]).unwrap();
        assert_eq!(link.loss_rate, 0.5);
    }

    #[test]
    fn test_scenario_partition() {
        let (mut sim, nodes) = ScenarioBuilder::new(4)
            .fully_connected()
            .partition_at(Timestamp::from_millis(500), vec![vec![0, 1], vec![2, 3]])
            .build();

        // Initially connected
        assert!(sim.topology().is_connected(nodes[0], nodes[2]));

        // Run past partition time
        sim.run_for(Duration::from_secs(1));

        // Should be partitioned
        assert!(!sim.topology().is_connected(nodes[0], nodes[2]));
        assert!(sim.topology().is_connected(nodes[0], nodes[1]));
        assert!(sim.topology().is_connected(nodes[2], nodes[3]));
    }
}
