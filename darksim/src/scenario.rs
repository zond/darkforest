//! Scenario builder for setting up and running simulations.

use darktree::{Duration, NodeId, Timestamp};

use crate::event::ScenarioAction;
use crate::metrics::SimulationResult;
use crate::sim::Simulator;
use crate::topology::Topology;

/// Type of topology to generate.
#[derive(Debug, Clone, Default)]
enum TopologyType {
    /// Fully connected (default).
    #[default]
    FullyConnected,
    /// Chain topology (each node connected only to neighbors).
    Chain,
    /// Star topology (first node is hub).
    Star,
    /// Custom topology provided by user.
    Custom(Topology),
}

/// Builder for simulation scenarios.
pub struct ScenarioBuilder {
    /// Number of nodes to create.
    num_nodes: usize,
    /// RNG seed for determinism.
    seed: u64,
    /// Topology type to generate.
    topology_type: TopologyType,
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
    pub fn new(num_nodes: usize) -> Self {
        Self {
            num_nodes,
            seed: 42,
            topology_type: TopologyType::FullyConnected,
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
        self.topology_type = TopologyType::Custom(topo);
        self
    }

    /// Use fully connected topology (default).
    pub fn fully_connected(mut self) -> Self {
        self.topology_type = TopologyType::FullyConnected;
        self
    }

    /// Use chain topology (each node connected only to neighbors).
    pub fn chain_topology(mut self) -> Self {
        self.topology_type = TopologyType::Chain;
        self
    }

    /// Use star topology (first node is hub).
    pub fn star_topology(mut self) -> Self {
        self.topology_type = TopologyType::Star;
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

        // First, we need to predict node IDs based on seeds
        // This is deterministic because SimCrypto.generate_keypair is deterministic
        let mut predicted_node_ids = Vec::with_capacity(self.num_nodes);
        for i in 0..self.num_nodes {
            let node_seed = self.seed.wrapping_add(i as u64 * 1000);
            let seed_byte = (node_seed & 0xFF) as u8;

            // SimCrypto generates secret, then pubkey = hash(secret), then node_id = hash(pubkey)[..16]
            let mut secret = [seed_byte; 32];
            secret[0] = seed_byte;
            secret[1] = seed_byte.wrapping_add(1);

            // Hash function (matches SimCrypto.hash)
            let hash_fn = |data: &[u8]| -> [u8; 32] {
                let mut hash = [0u8; 32];
                for (j, &byte) in data.iter().enumerate() {
                    hash[j % 32] ^= byte;
                    hash[(j + 1) % 32] = hash[(j + 1) % 32].wrapping_add(byte);
                }
                hash
            };

            // pubkey = hash(secret)
            let pubkey = hash_fn(&secret);
            // node_id = hash(pubkey)[..16]
            let pubkey_hash = hash_fn(&pubkey);
            let mut node_id = [0u8; 16];
            node_id.copy_from_slice(&pubkey_hash[..16]);
            predicted_node_ids.push(node_id);
        }

        // Build topology with predicted node IDs
        let mut topo = match self.topology_type {
            TopologyType::FullyConnected => Topology::fully_connected(&predicted_node_ids),
            TopologyType::Chain => Topology::chain(&predicted_node_ids),
            TopologyType::Star => Topology::star(&predicted_node_ids),
            TopologyType::Custom(t) => t,
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
    ScenarioBuilder::new(num_nodes)
}

/// Convenience function for LoRa-like simulation (38 bytes/sec bandwidth).
pub fn lora_scenario(num_nodes: usize) -> ScenarioBuilder {
    ScenarioBuilder::new(num_nodes).with_bandwidth(38)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_builder_basic() {
        let (sim, nodes) = ScenarioBuilder::new(3).with_seed(123).build();

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
        let (sim, nodes) = ScenarioBuilder::new(2).with_loss_rate(0.5).build();

        // With 50% loss, topology should still be connected but lossy
        let link = sim.topology().get_link(nodes[0], nodes[1]).unwrap();
        assert_eq!(link.loss_rate, 0.5);
    }

    #[test]
    fn test_scenario_partition() {
        let (mut sim, nodes) = ScenarioBuilder::new(4)
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
