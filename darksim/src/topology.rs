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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_nodes(count: usize) -> Vec<NodeId> {
        (0..count).map(|i| [i as u8; 16]).collect()
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
}
