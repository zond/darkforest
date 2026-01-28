//! Network topology and link properties.

use darktree::{Duration, NodeId};
use hashbrown::HashMap;

/// Properties of a network link between two nodes.
#[derive(Debug, Clone)]
pub struct Link {
    /// Signal strength in dBm.
    pub rssi: i16,
    /// Packet loss rate (0.0 to 1.0).
    pub loss_rate: f64,
    /// Propagation delay.
    pub delay: Duration,
    /// Whether the link is currently active.
    pub active: bool,
}

impl Default for Link {
    fn default() -> Self {
        Self {
            rssi: -70,
            loss_rate: 0.0,
            delay: Duration::from_millis(1),
            active: true,
        }
    }
}

impl Link {
    /// Create a new link with default properties.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the RSSI value.
    pub fn with_rssi(mut self, rssi: i16) -> Self {
        self.rssi = rssi;
        self
    }

    /// Set the loss rate.
    pub fn with_loss_rate(mut self, rate: f64) -> Self {
        self.loss_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set the delay.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Set whether the link is active.
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }
}

/// Network topology defining connectivity between nodes.
#[derive(Debug, Clone)]
pub struct Topology {
    /// Links between pairs of nodes (bidirectional by default).
    links: HashMap<(NodeId, NodeId), Link>,
    /// Default link properties for new connections.
    default_link: Link,
}

impl Default for Topology {
    fn default() -> Self {
        Self::new()
    }
}

impl Topology {
    /// Create an empty topology.
    pub fn new() -> Self {
        Self {
            links: HashMap::new(),
            default_link: Link::default(),
        }
    }

    /// Set default link properties for new connections.
    pub fn with_default_link(mut self, link: Link) -> Self {
        self.default_link = link;
        self
    }

    /// Create a fully connected topology for the given nodes.
    pub fn fully_connected(nodes: &[NodeId]) -> Self {
        let mut topo = Self::new();
        for (i, &a) in nodes.iter().enumerate() {
            for &b in nodes.iter().skip(i + 1) {
                topo.add_link(a, b, Link::default());
            }
        }
        topo
    }

    /// Create a chain topology (each node connected only to neighbors).
    pub fn chain(nodes: &[NodeId]) -> Self {
        let mut topo = Self::new();
        for window in nodes.windows(2) {
            topo.add_link(window[0], window[1], Link::default());
        }
        topo
    }

    /// Create a star topology (first node is hub, connected to all others).
    pub fn star(nodes: &[NodeId]) -> Self {
        let mut topo = Self::new();
        if nodes.is_empty() {
            return topo;
        }
        let hub = nodes[0];
        for &spoke in nodes.iter().skip(1) {
            topo.add_link(hub, spoke, Link::default());
        }
        topo
    }

    /// Create a random geometric topology.
    ///
    /// Nodes are placed at deterministic positions in a unit square based on the seed.
    /// Two nodes are connected if their distance is <= radius.
    /// If the resulting graph is disconnected, minimal edges are added to ensure connectivity.
    ///
    /// # Arguments
    /// * `nodes` - The node IDs to include in the topology
    /// * `seed` - Seed for deterministic position generation
    /// * `radius` - Connection radius (nodes within this distance are connected)
    pub fn random_geometric(nodes: &[NodeId], seed: u64, radius: f64) -> Self {
        let mut topo = Self::new();
        if nodes.len() <= 1 {
            return topo;
        }

        // Generate deterministic positions
        let positions = generate_positions(nodes.len(), seed);

        // Compute all pairwise distances and add edges within radius
        let mut all_edges: Vec<(usize, usize, f64)> = Vec::new();
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                let dx = positions[i].0 - positions[j].0;
                let dy = positions[i].1 - positions[j].1;
                let dist = (dx * dx + dy * dy).sqrt();
                all_edges.push((i, j, dist));

                if dist <= radius {
                    topo.add_link(nodes[i], nodes[j], Link::default());
                }
            }
        }

        // Ensure connectivity using union-find and MST edges
        ensure_connectivity(&mut topo, nodes, &mut all_edges);

        topo
    }

    /// Create a random geometric topology with an adaptive radius.
    ///
    /// The radius is computed to give approximately 5 neighbors per node on average,
    /// clamped to [0.15, 0.70].
    pub fn random_geometric_adaptive(nodes: &[NodeId], seed: u64) -> Self {
        let radius = compute_adaptive_radius(nodes.len());
        Self::random_geometric(nodes, seed, radius)
    }

    /// Add a bidirectional link between two nodes.
    pub fn add_link(&mut self, a: NodeId, b: NodeId, link: Link) {
        // Store link with canonical ordering (lower NodeId first).
        let (lo, hi) = Self::canonical_pair(a, b);
        self.links.insert((lo, hi), link);
    }

    /// Get a link between two nodes.
    pub fn get_link(&self, a: NodeId, b: NodeId) -> Option<&Link> {
        let (lo, hi) = Self::canonical_pair(a, b);
        self.links.get(&(lo, hi))
    }

    /// Get a mutable link between two nodes.
    pub fn get_link_mut(&mut self, a: NodeId, b: NodeId) -> Option<&mut Link> {
        let (lo, hi) = Self::canonical_pair(a, b);
        self.links.get_mut(&(lo, hi))
    }

    /// Check if two nodes are connected (link exists and is active).
    pub fn is_connected(&self, a: NodeId, b: NodeId) -> bool {
        self.get_link(a, b).is_some_and(|link| link.active)
    }

    /// Get all nodes that a given node can reach (active links).
    pub fn neighbors(&self, node: NodeId) -> Vec<NodeId> {
        let mut result = Vec::new();
        for (&(a, b), link) in &self.links {
            if link.active {
                if a == node {
                    result.push(b);
                } else if b == node {
                    result.push(a);
                }
            }
        }
        result
    }

    /// Disable all links crossing between partition groups.
    pub fn partition(&mut self, groups: &[Vec<NodeId>]) {
        for (&(a, b), link) in self.links.iter_mut() {
            // Find which groups a and b belong to
            let a_group = groups.iter().position(|g| g.contains(&a));
            let b_group = groups.iter().position(|g| g.contains(&b));

            // Disable link if nodes are in different groups
            if a_group != b_group {
                link.active = false;
            }
        }
    }

    /// Re-enable all links (heal partitions).
    pub fn heal(&mut self) {
        for link in self.links.values_mut() {
            link.active = true;
        }
    }

    /// Set global loss rate for all links.
    pub fn set_global_loss_rate(&mut self, rate: f64) {
        let rate = rate.clamp(0.0, 1.0);
        for link in self.links.values_mut() {
            link.loss_rate = rate;
        }
    }

    /// Get default link properties.
    pub fn default_link(&self) -> &Link {
        &self.default_link
    }

    /// Canonical pair ordering for consistent link storage.
    fn canonical_pair(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
        if a < b {
            (a, b)
        } else {
            (b, a)
        }
    }
}

/// Generate deterministic positions in a unit square using an LCG.
fn generate_positions(count: usize, seed: u64) -> Vec<(f64, f64)> {
    let mut positions = Vec::with_capacity(count);
    let mut state = seed;

    for _ in 0..count {
        // LCG parameters (same as glibc)
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let x = ((state >> 16) & 0x7FFF) as f64 / 32767.0;

        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let y = ((state >> 16) & 0x7FFF) as f64 / 32767.0;

        positions.push((x, y));
    }

    positions
}

/// Compute adaptive radius for random geometric graph.
///
/// Formula: r = sqrt(k / ((n-1) * pi)) where k ≈ 5 (target neighbors)
/// Clamped to [0.15, 0.70] for reasonable connectivity.
pub(crate) fn compute_adaptive_radius(num_nodes: usize) -> f64 {
    if num_nodes <= 1 {
        return 0.5;
    }

    // Target ~5 neighbors per node on average
    let k = 5.0;
    let n = num_nodes as f64;
    let pi = core::f64::consts::PI;

    // r = sqrt(k / ((n-1) * pi))
    let r = (k / ((n - 1.0) * pi)).sqrt();

    // Clamp to reasonable range
    r.clamp(0.15, 0.70)
}

/// Ensure the topology is connected by adding minimal MST edges.
///
/// Uses union-find to track connected components and adds shortest edges
/// between components until fully connected.
fn ensure_connectivity(topo: &mut Topology, nodes: &[NodeId], edges: &mut [(usize, usize, f64)]) {
    if nodes.len() <= 1 {
        return;
    }

    // Sort edges by distance
    edges.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(core::cmp::Ordering::Equal));

    // Union-find data structure
    let mut parent: Vec<usize> = (0..nodes.len()).collect();
    let mut rank: Vec<usize> = vec![0; nodes.len()];

    // Find with path compression (iterative to avoid stack overflow)
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        let mut root = x;
        while parent[root] != root {
            root = parent[root];
        }
        // Path compression
        while parent[x] != root {
            let next = parent[x];
            parent[x] = root;
            x = next;
        }
        root
    }

    // Union by rank
    fn union(parent: &mut [usize], rank: &mut [usize], x: usize, y: usize) -> bool {
        let px = find(parent, x);
        let py = find(parent, y);
        if px == py {
            return false; // Already in same component
        }
        if rank[px] < rank[py] {
            parent[px] = py;
        } else if rank[px] > rank[py] {
            parent[py] = px;
        } else {
            parent[py] = px;
            rank[px] += 1;
        }
        true
    }

    // Check if all nodes are in the same component
    let is_fully_connected = |parent: &mut [usize], n: usize| -> bool {
        let root0 = find(parent, 0);
        (1..n).all(|k| find(parent, k) == root0)
    };

    // First, process existing edges (already added to topology)
    for &(i, j, _) in edges.iter() {
        if topo.is_connected(nodes[i], nodes[j]) {
            union(&mut parent, &mut rank, i, j);
        }
    }

    // Check if already connected after processing existing edges
    if is_fully_connected(&mut parent, nodes.len()) {
        return;
    }

    // Add MST edges to connect remaining components
    for &(i, j, _) in edges.iter() {
        if !topo.is_connected(nodes[i], nodes[j]) && union(&mut parent, &mut rank, i, j) {
            topo.add_link(nodes[i], nodes[j], Link::default());

            if is_fully_connected(&mut parent, nodes.len()) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nodes(count: usize) -> Vec<NodeId> {
        (0..count).map(|i| [i as u8; 16]).collect()
    }

    /// Assert that all nodes in the topology are connected (reachable from node 0).
    fn assert_topology_connected(topo: &Topology, nodes: &[NodeId], msg: &str) {
        let mut visited = vec![false; nodes.len()];
        let mut queue = vec![0usize];
        visited[0] = true;

        while let Some(current) = queue.pop() {
            for (i, node) in nodes.iter().enumerate() {
                if !visited[i] && topo.is_connected(nodes[current], *node) {
                    visited[i] = true;
                    queue.push(i);
                }
            }
        }

        assert!(visited.iter().all(|&v| v), "{}", msg);
    }

    #[test]
    fn test_fully_connected() {
        let nodes = make_nodes(3);
        let topo = Topology::fully_connected(&nodes);

        assert!(topo.is_connected(nodes[0], nodes[1]));
        assert!(topo.is_connected(nodes[0], nodes[2]));
        assert!(topo.is_connected(nodes[1], nodes[2]));
    }

    #[test]
    fn test_chain() {
        let nodes = make_nodes(4);
        let topo = Topology::chain(&nodes);

        assert!(topo.is_connected(nodes[0], nodes[1]));
        assert!(topo.is_connected(nodes[1], nodes[2]));
        assert!(topo.is_connected(nodes[2], nodes[3]));

        // Non-adjacent nodes should not be connected
        assert!(!topo.is_connected(nodes[0], nodes[2]));
        assert!(!topo.is_connected(nodes[0], nodes[3]));
    }

    #[test]
    fn test_star() {
        let nodes = make_nodes(4);
        let topo = Topology::star(&nodes);

        // Hub connected to all spokes
        assert!(topo.is_connected(nodes[0], nodes[1]));
        assert!(topo.is_connected(nodes[0], nodes[2]));
        assert!(topo.is_connected(nodes[0], nodes[3]));

        // Spokes not connected to each other
        assert!(!topo.is_connected(nodes[1], nodes[2]));
        assert!(!topo.is_connected(nodes[1], nodes[3]));
    }

    #[test]
    fn test_partition() {
        let nodes = make_nodes(4);
        let mut topo = Topology::fully_connected(&nodes);

        // Partition into two groups
        topo.partition(&[vec![nodes[0], nodes[1]], vec![nodes[2], nodes[3]]]);

        // Within-group connections active
        assert!(topo.is_connected(nodes[0], nodes[1]));
        assert!(topo.is_connected(nodes[2], nodes[3]));

        // Cross-group connections disabled
        assert!(!topo.is_connected(nodes[0], nodes[2]));
        assert!(!topo.is_connected(nodes[0], nodes[3]));
        assert!(!topo.is_connected(nodes[1], nodes[2]));
        assert!(!topo.is_connected(nodes[1], nodes[3]));

        // Heal should restore all
        topo.heal();
        assert!(topo.is_connected(nodes[0], nodes[2]));
    }

    #[test]
    fn test_neighbors() {
        let nodes = make_nodes(4);
        let topo = Topology::star(&nodes);

        let hub_neighbors = topo.neighbors(nodes[0]);
        assert_eq!(hub_neighbors.len(), 3);

        let spoke_neighbors = topo.neighbors(nodes[1]);
        assert_eq!(spoke_neighbors.len(), 1);
        assert_eq!(spoke_neighbors[0], nodes[0]);
    }

    #[test]
    fn test_random_geometric_connectivity() {
        let nodes = make_nodes(20);
        let topo = Topology::random_geometric(&nodes, 42, 0.3);

        assert_topology_connected(&topo, &nodes, "Random geometric graph should be connected");
    }

    #[test]
    fn test_random_geometric_deterministic() {
        // Same seed should produce identical topology
        let nodes = make_nodes(10);
        let topo1 = Topology::random_geometric(&nodes, 123, 0.4);
        let topo2 = Topology::random_geometric(&nodes, 123, 0.4);

        // Check all pairs have same connectivity
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                assert_eq!(
                    topo1.is_connected(nodes[i], nodes[j]),
                    topo2.is_connected(nodes[i], nodes[j]),
                    "Topologies with same seed should match"
                );
            }
        }
    }

    #[test]
    fn test_random_geometric_different_seeds() {
        // Different seeds should produce different topologies (with high probability)
        let nodes = make_nodes(10);
        let topo1 = Topology::random_geometric(&nodes, 42, 0.3);
        let topo2 = Topology::random_geometric(&nodes, 999, 0.3);

        // Count differing links
        let mut differences = 0;
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                if topo1.is_connected(nodes[i], nodes[j]) != topo2.is_connected(nodes[i], nodes[j])
                {
                    differences += 1;
                }
            }
        }

        // Should have at least some differences (very unlikely to be identical)
        assert!(
            differences > 0,
            "Different seeds should produce different topologies"
        );
    }

    #[test]
    fn test_random_geometric_adaptive() {
        let nodes = make_nodes(50);
        let topo = Topology::random_geometric_adaptive(&nodes, 42);

        assert_topology_connected(
            &topo,
            &nodes,
            "Adaptive random geometric graph should be connected",
        );

        // Count average neighbors
        let total_neighbors: usize = nodes.iter().map(|n| topo.neighbors(*n).len()).sum();
        let avg_neighbors = total_neighbors as f64 / nodes.len() as f64;

        // Should have reasonable connectivity (not too sparse, not fully connected)
        assert!(
            (3.0..=15.0).contains(&avg_neighbors),
            "Average neighbors ({}) should be reasonable",
            avg_neighbors
        );
    }

    #[test]
    fn test_compute_adaptive_radius() {
        // Very small network (2 nodes): should hit upper bound
        assert!((compute_adaptive_radius(2) - 0.70).abs() < 0.01);

        // Small network: within valid range
        let r5 = compute_adaptive_radius(5);
        assert!((0.15..=0.70).contains(&r5), "r5 = {}", r5);

        // Large network: radius should be smaller but above lower bound
        let r100 = compute_adaptive_radius(100);
        assert!((0.15..=0.70).contains(&r100), "r100 = {}", r100);
        assert!(r100 < r5, "Larger network should have smaller radius");

        // Very large network: should hit lower bound
        let r1000 = compute_adaptive_radius(1000);
        assert!((r1000 - 0.15).abs() < 0.01, "r1000 = {}", r1000);
    }

    #[test]
    fn test_random_geometric_sparse_radius() {
        // With very small radius, connectivity is ensured via MST edges
        let nodes = make_nodes(10);
        let topo = Topology::random_geometric(&nodes, 42, 0.01); // Very small radius

        assert_topology_connected(
            &topo,
            &nodes,
            "Even with tiny radius, graph should be connected via MST",
        );
    }
}
