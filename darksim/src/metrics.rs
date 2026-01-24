//! Metrics collection for simulation analysis.

use darktree::{NodeId, Timestamp};
use hashbrown::HashMap;

/// A snapshot of tree state at a point in time.
#[derive(Debug, Clone)]
pub struct TreeSnapshot {
    /// When this snapshot was taken.
    pub time: Timestamp,
    /// Root hash for each node.
    pub root_hashes: HashMap<NodeId, [u8; 4]>,
    /// Tree size as reported by each node.
    pub tree_sizes: HashMap<NodeId, u32>,
    /// Whether each node is root of its tree.
    pub is_root: HashMap<NodeId, bool>,
}

impl TreeSnapshot {
    /// Create a new empty snapshot.
    pub fn new(time: Timestamp) -> Self {
        Self {
            time,
            root_hashes: HashMap::new(),
            tree_sizes: HashMap::new(),
            is_root: HashMap::new(),
        }
    }

    /// Record a node's state.
    pub fn record_node(
        &mut self,
        node_id: NodeId,
        root_hash: [u8; 4],
        tree_size: u32,
        is_root: bool,
    ) {
        self.root_hashes.insert(node_id, root_hash);
        self.tree_sizes.insert(node_id, tree_size);
        self.is_root.insert(node_id, is_root);
    }

    /// Check if all nodes have the same root hash.
    pub fn all_same_tree(&self) -> bool {
        let hashes: Vec<_> = self.root_hashes.values().collect();
        if hashes.is_empty() {
            return true;
        }
        hashes.windows(2).all(|w| w[0] == w[1])
    }

    /// Count distinct trees (by root hash).
    pub fn tree_count(&self) -> usize {
        let mut unique_hashes: Vec<[u8; 4]> = self.root_hashes.values().copied().collect();
        unique_hashes.sort();
        unique_hashes.dedup();
        unique_hashes.len()
    }

    /// Get nodes that are roots.
    pub fn roots(&self) -> Vec<NodeId> {
        self.is_root
            .iter()
            .filter(|(_, &is_root)| is_root)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get the maximum tree size reported.
    pub fn max_tree_size(&self) -> u32 {
        self.tree_sizes.values().copied().max().unwrap_or(0)
    }
}

/// Simulation metrics collected over time.
#[derive(Debug, Clone)]
pub struct SimMetrics {
    /// Total messages sent.
    pub messages_sent: u64,
    /// Messages dropped due to loss rate or disconnection.
    pub messages_dropped: u64,
    /// Messages delivered successfully.
    pub messages_delivered: u64,
    /// Tree snapshots taken at intervals.
    pub snapshots: Vec<TreeSnapshot>,
}

impl Default for SimMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SimMetrics {
    /// Create new empty metrics.
    pub fn new() -> Self {
        Self {
            messages_sent: 0,
            messages_dropped: 0,
            messages_delivered: 0,
            snapshots: Vec::new(),
        }
    }

    /// Add a snapshot.
    pub fn add_snapshot(&mut self, snapshot: TreeSnapshot) {
        self.snapshots.push(snapshot);
    }

    /// Check if network converged to single tree by specified time.
    pub fn converged_by(&self, time: Timestamp) -> bool {
        self.snapshots
            .iter()
            .find(|s| s.time >= time)
            .is_some_and(|s| s.all_same_tree())
    }

    /// Find first time when network converged to single tree.
    pub fn convergence_time(&self) -> Option<Timestamp> {
        self.snapshots
            .iter()
            .find(|s| s.all_same_tree())
            .map(|s| s.time)
    }

    /// Get the latest snapshot.
    pub fn latest_snapshot(&self) -> Option<&TreeSnapshot> {
        self.snapshots.last()
    }
}

/// Result of running a simulation.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// Final simulation time.
    pub end_time: Timestamp,
    /// Collected metrics.
    pub metrics: SimMetrics,
    /// Whether simulation ended due to event queue exhaustion (vs time limit).
    pub queue_exhausted: bool,
}

impl SimulationResult {
    /// Check if network converged to a single tree.
    pub fn converged(&self) -> bool {
        self.metrics
            .latest_snapshot()
            .is_some_and(|s| s.all_same_tree())
    }

    /// Get the number of distinct trees at end.
    pub fn final_tree_count(&self) -> usize {
        self.metrics
            .latest_snapshot()
            .map(|s| s.tree_count())
            .unwrap_or(0)
    }

    /// Get the maximum tree size at end.
    pub fn final_max_tree_size(&self) -> u32 {
        self.metrics
            .latest_snapshot()
            .map(|s| s.max_tree_size())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_snapshot_all_same() {
        let mut snapshot = TreeSnapshot::new(Timestamp::ZERO);
        let hash = [1u8, 2, 3, 4];

        snapshot.record_node([0u8; 16], hash, 3, false);
        snapshot.record_node([1u8; 16], hash, 3, false);
        snapshot.record_node([2u8; 16], hash, 3, true);

        assert!(snapshot.all_same_tree());
        assert_eq!(snapshot.tree_count(), 1);
    }

    #[test]
    fn test_tree_snapshot_multiple_trees() {
        let mut snapshot = TreeSnapshot::new(Timestamp::ZERO);

        snapshot.record_node([0u8; 16], [1, 1, 1, 1], 2, true);
        snapshot.record_node([1u8; 16], [1, 1, 1, 1], 2, false);
        snapshot.record_node([2u8; 16], [2, 2, 2, 2], 1, true);

        assert!(!snapshot.all_same_tree());
        assert_eq!(snapshot.tree_count(), 2);
        assert_eq!(snapshot.roots().len(), 2);
    }

    #[test]
    fn test_convergence_time() {
        let mut metrics = SimMetrics::new();

        // First snapshot: 2 trees
        let mut s1 = TreeSnapshot::new(Timestamp::from_secs(10));
        s1.record_node([0u8; 16], [1, 1, 1, 1], 1, true);
        s1.record_node([1u8; 16], [2, 2, 2, 2], 1, true);
        metrics.add_snapshot(s1);

        // Second snapshot: still 2 trees
        let mut s2 = TreeSnapshot::new(Timestamp::from_secs(20));
        s2.record_node([0u8; 16], [1, 1, 1, 1], 2, true);
        s2.record_node([1u8; 16], [1, 1, 1, 1], 2, false);
        metrics.add_snapshot(s2);

        assert_eq!(metrics.convergence_time(), Some(Timestamp::from_secs(20)));
    }
}
