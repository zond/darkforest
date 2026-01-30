//! Child management with pre-computed hashes.
//!
//! This module provides [`ChildrenStore`], a data structure that manages child nodes
//! with O(1) hash lookups and O(n) iteration in hash order.
//!
//! # Design Rationale
//!
//! Children need to be accessed by NodeId (when processing messages) and iterated
//! in hash order (for deterministic keyspace assignment and pulse building).
//!
//! Rather than storing children in a single map and recomputing hashes during sorting,
//! this structure pre-computes hashes at insertion time and maintains two indexes:
//! - `entries`: BTreeMap<IdHash, ChildEntry> - sorted by hash for iteration
//! - `by_node_id`: BTreeMap<NodeId, IdHash> - for O(log n) lookup by NodeId
//!
//! # Hash Collision
//!
//! The protocol prevents hash collisions: parents MUST NOT accept a child whose
//! hash matches an existing child's hash. See design.md "Hash Collision Handling".

use alloc::collections::BTreeMap;

use crate::types::{IdHash, NodeId, MAX_CHILDREN};

/// Entry for a single child node.
#[derive(Clone, Debug)]
pub struct ChildEntry {
    /// The child's NodeId.
    pub node_id: NodeId,
    /// Size of the child's subtree (including itself).
    pub subtree_size: u32,
    /// Lower bound of keyspace range (inclusive).
    pub keyspace_lo: u32,
    /// Upper bound of keyspace range (exclusive).
    pub keyspace_hi: u32,
}

/// Store for child nodes with pre-computed hashes.
///
/// Provides O(log n) lookup by NodeId and O(n) iteration in hash order.
/// Hash is computed once at insertion, not during iteration/sorting.
#[derive(Clone, Debug)]
pub struct ChildrenStore {
    /// Authoritative data, keyed by hash. Naturally sorted in hash order.
    entries: BTreeMap<IdHash, ChildEntry>,

    /// Index: NodeId -> hash (the key into entries).
    by_node_id: BTreeMap<NodeId, IdHash>,
}

impl Default for ChildrenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChildrenStore {
    /// Create an empty children store.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            by_node_id: BTreeMap::new(),
        }
    }

    /// Insert a child with pre-computed hash.
    ///
    /// Returns `true` if this is a new child, `false` if updating existing.
    /// If the hash collides with an existing child (different NodeId, same hash),
    /// this replaces the old child - but the protocol should prevent this.
    ///
    /// # Panics (debug only)
    ///
    /// Panics if inserting a new child would exceed MAX_CHILDREN. Callers should
    /// check capacity before inserting new children.
    pub fn insert(&mut self, hash: IdHash, node_id: NodeId, subtree_size: u32) -> bool {
        // Remove old entry if this NodeId already exists with a different hash.
        // This path is unreachable in normal operation: hash is derived from node_id
        // via crypto.hash(), so the same node_id always produces the same hash.
        // We handle it defensively in case of bugs elsewhere.
        if let Some(old_hash) = self.by_node_id.get(&node_id) {
            if *old_hash != hash {
                debug_assert!(
                    false,
                    "Hash changed for existing NodeId - this indicates a bug"
                );
                self.entries.remove(old_hash);
            }
        }

        let is_new = !self.by_node_id.contains_key(&node_id);

        // Defensive capacity check - callers should prevent this.
        // Uses runtime assert (not debug_assert) because the check is cheap
        // and exceeding MAX_CHILDREN would corrupt protocol invariants.
        assert!(
            !is_new || self.entries.len() < MAX_CHILDREN,
            "ChildrenStore exceeded MAX_CHILDREN"
        );

        let entry = ChildEntry {
            node_id,
            subtree_size,
            keyspace_lo: 0,
            keyspace_hi: 0,
        };

        self.entries.insert(hash, entry);
        self.by_node_id.insert(node_id, hash);

        is_new
    }

    /// Remove a child by NodeId.
    ///
    /// Returns the removed entry, or None if not found.
    pub fn remove(&mut self, node_id: &NodeId) -> Option<ChildEntry> {
        if let Some(hash) = self.by_node_id.remove(node_id) {
            self.entries.remove(&hash)
        } else {
            None
        }
    }

    /// Get a child entry by NodeId.
    pub fn get(&self, node_id: &NodeId) -> Option<&ChildEntry> {
        self.by_node_id
            .get(node_id)
            .and_then(|hash| self.entries.get(hash))
    }

    /// Get a mutable child entry by NodeId.
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut ChildEntry> {
        if let Some(hash) = self.by_node_id.get(node_id) {
            self.entries.get_mut(hash)
        } else {
            None
        }
    }

    /// Check if a child exists by NodeId.
    pub fn contains_key(&self, node_id: &NodeId) -> bool {
        self.by_node_id.contains_key(node_id)
    }

    /// Check if a hash already exists (for collision detection).
    pub fn contains_hash(&self, hash: &IdHash) -> bool {
        self.entries.contains_key(hash)
    }

    /// Get the hash for a NodeId.
    pub fn get_hash(&self, node_id: &NodeId) -> Option<&IdHash> {
        self.by_node_id.get(node_id)
    }

    /// Number of children.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entries in hash order (for pulse building, keyspace computation).
    ///
    /// Returns (hash, entry) pairs sorted by hash.
    pub fn iter_by_hash(&self) -> impl Iterator<Item = (&IdHash, &ChildEntry)> {
        self.entries.iter()
    }

    /// Iterate NodeIds (for compatibility with existing code).
    pub fn node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.by_node_id.keys()
    }

    /// Iterate subtree sizes (for summing total).
    pub fn subtree_sizes(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries.values().map(|e| e.subtree_size)
    }

    /// Update subtree size for a child.
    ///
    /// Returns true if the child existed and was updated.
    pub fn update_subtree_size(&mut self, node_id: &NodeId, subtree_size: u32) -> bool {
        if let Some(entry) = self.get_mut(node_id) {
            entry.subtree_size = subtree_size;
            true
        } else {
            false
        }
    }

    /// Set keyspace range for a child.
    pub fn set_range(&mut self, node_id: &NodeId, lo: u32, hi: u32) -> bool {
        if let Some(entry) = self.get_mut(node_id) {
            entry.keyspace_lo = lo;
            entry.keyspace_hi = hi;
            true
        } else {
            false
        }
    }

    /// Get keyspace range for a child.
    pub fn get_range(&self, node_id: &NodeId) -> Option<(u32, u32)> {
        self.get(node_id).map(|e| (e.keyspace_lo, e.keyspace_hi))
    }

    /// Clear all keyspace ranges (for testing).
    #[cfg(test)]
    pub fn clear_ranges(&mut self) {
        for entry in self.entries.values_mut() {
            entry.keyspace_lo = 0;
            entry.keyspace_hi = 0;
        }
    }

    /// Iterate entries with mutable access (for setting ranges).
    ///
    /// Note: Not currently used because `recompute_child_ranges` collects to a Vec
    /// to avoid borrow conflicts. Kept for potential future use.
    #[allow(dead_code)]
    pub fn iter_by_hash_mut(&mut self) -> impl Iterator<Item = (&IdHash, &mut ChildEntry)> {
        self.entries.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn make_hash(n: u8) -> IdHash {
        [n, 0, 0, 0]
    }

    fn make_node_id(n: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = n;
        id
    }

    #[test]
    fn test_insert_and_get() {
        let mut store = ChildrenStore::new();

        let hash = make_hash(1);
        let node_id = make_node_id(10);

        assert!(store.insert(hash, node_id, 5));
        assert!(!store.insert(hash, node_id, 6)); // Update, not new

        let entry = store.get(&node_id).unwrap();
        assert_eq!(entry.subtree_size, 6);
        assert_eq!(entry.node_id, node_id);
    }

    #[test]
    fn test_remove() {
        let mut store = ChildrenStore::new();

        let hash = make_hash(1);
        let node_id = make_node_id(10);

        store.insert(hash, node_id, 5);
        assert_eq!(store.len(), 1);

        let removed = store.remove(&node_id);
        assert!(removed.is_some());
        assert_eq!(store.len(), 0);
        assert!(store.get(&node_id).is_none());
    }

    #[test]
    fn test_iter_by_hash_order() {
        let mut store = ChildrenStore::new();

        // Insert in reverse hash order
        store.insert(make_hash(3), make_node_id(30), 1);
        store.insert(make_hash(1), make_node_id(10), 1);
        store.insert(make_hash(2), make_node_id(20), 1);

        // Should iterate in hash order
        let hashes: Vec<_> = store.iter_by_hash().map(|(h, _)| h[0]).collect();
        assert_eq!(hashes, vec![1, 2, 3]);
    }

    #[test]
    fn test_contains_hash() {
        let mut store = ChildrenStore::new();

        let hash = make_hash(1);
        let node_id = make_node_id(10);

        assert!(!store.contains_hash(&hash));
        store.insert(hash, node_id, 5);
        assert!(store.contains_hash(&hash));
    }

    #[test]
    fn test_ranges() {
        let mut store = ChildrenStore::new();

        let node_id = make_node_id(10);
        store.insert(make_hash(1), node_id, 5);

        assert_eq!(store.get_range(&node_id), Some((0, 0)));

        store.set_range(&node_id, 100, 200);
        assert_eq!(store.get_range(&node_id), Some((100, 200)));

        store.clear_ranges();
        assert_eq!(store.get_range(&node_id), Some((0, 0)));
    }
}
