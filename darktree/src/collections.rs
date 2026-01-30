//! Memory-efficient collections that shrink when underutilized.
//!
//! These wrappers track removals since the last addition. After a threshold
//! of consecutive removals (default 8), the underlying collection is shrunk
//! to reclaim memory. This is useful for queues and caches that see bursty
//! usage patterns - they grow during bursts, then shrink back when idle.

use alloc::collections::VecDeque;
use hashbrown::HashMap;

/// Threshold of removals before shrinking.
const SHRINK_THRESHOLD: u8 = 8;

/// A VecDeque that shrinks after consecutive removals without additions.
///
/// Useful for queues with bursty usage patterns (e.g., pending messages
/// during network churn that drain when things stabilize).
pub struct ShrinkingVecDeque<T> {
    inner: VecDeque<T>,
    removals_since_add: u8,
}

impl<T> ShrinkingVecDeque<T> {
    /// Create a new empty deque.
    pub fn new() -> Self {
        Self {
            inner: VecDeque::new(),
            removals_since_add: 0,
        }
    }

    /// Add to the back of the deque. Resets removal counter.
    ///
    /// The counter reset means items cycling through the queue (pop_front + push_back)
    /// won't trigger shrinking. This is intentional: if items are being recycled,
    /// the queue is actively in use and shouldn't shrink.
    pub fn push_back(&mut self, value: T) {
        self.removals_since_add = 0;
        self.inner.push_back(value);
    }

    /// Remove from the front. May trigger shrink after threshold removals.
    pub fn pop_front(&mut self) -> Option<T> {
        let result = self.inner.pop_front();
        if result.is_some() {
            self.removals_since_add = self.removals_since_add.saturating_add(1);
            self.maybe_shrink();
        }
        result
    }

    /// Check if shrink threshold reached and shrink if so.
    fn maybe_shrink(&mut self) {
        if self.removals_since_add >= SHRINK_THRESHOLD {
            self.inner.shrink_to_fit();
            self.removals_since_add = 0;
        }
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over elements.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    /// Retain elements matching predicate. Counts removals.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&T) -> bool,
    {
        let before = self.inner.len();
        self.inner.retain(|x| f(x));
        let removed = before - self.inner.len();
        if removed > 0 {
            // Saturate both the cast and addition to handle >255 removals
            let removed_u8 = removed.min(u8::MAX as usize) as u8;
            self.removals_since_add = self.removals_since_add.saturating_add(removed_u8);
            self.maybe_shrink();
        }
    }
}

impl<T> Default for ShrinkingVecDeque<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A HashMap that shrinks after consecutive removals without additions.
///
/// Useful for caches with bursty usage patterns (e.g., recently-forwarded
/// tracking during message bursts that empties when traffic subsides).
pub struct ShrinkingHashMap<K, V, S = hashbrown::DefaultHashBuilder> {
    inner: HashMap<K, V, S>,
    removals_since_add: u8,
}

impl<K, V> ShrinkingHashMap<K, V, hashbrown::DefaultHashBuilder> {
    /// Create a new empty map.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            removals_since_add: 0,
        }
    }
}

impl<K, V, S> ShrinkingHashMap<K, V, S>
where
    K: Eq + core::hash::Hash,
    S: core::hash::BuildHasher,
{
    /// Insert a key-value pair. Resets removal counter.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.removals_since_add = 0;
        self.inner.insert(key, value)
    }

    /// Remove a key. May trigger shrink after threshold removals.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let result = self.inner.remove(key);
        if result.is_some() {
            self.removals_since_add = self.removals_since_add.saturating_add(1);
            self.maybe_shrink();
        }
        result
    }

    /// Check if shrink threshold reached and shrink if so.
    fn maybe_shrink(&mut self) {
        if self.removals_since_add >= SHRINK_THRESHOLD {
            self.inner.shrink_to_fit();
            self.removals_since_add = 0;
        }
    }

    /// Get a reference to a value.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Get a mutable reference to a value.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Check if key exists.
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter()
    }

    /// Iterate over keys.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.inner.keys()
    }

    /// Iterate over values.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.inner.values()
    }

    /// Retain entries matching predicate. Counts removals.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let before = self.inner.len();
        self.inner.retain(|k, v| f(k, v));
        let removed = before - self.inner.len();
        if removed > 0 {
            // Saturate both the cast and addition to handle >255 removals
            let removed_u8 = removed.min(u8::MAX as usize) as u8;
            self.removals_since_add = self.removals_since_add.saturating_add(removed_u8);
            self.maybe_shrink();
        }
    }
}

impl<K, V, S> ShrinkingHashMap<K, V, S>
where
    K: Eq + core::hash::Hash + Copy,
    S: core::hash::BuildHasher,
{
    /// Remove the entry with the minimum value according to a key function.
    ///
    /// Useful for evicting the oldest entry when at capacity.
    /// Returns true if an entry was removed.
    pub fn remove_min_by_key<B, F>(&mut self, mut f: F) -> bool
    where
        B: Ord,
        F: FnMut(&V) -> B,
    {
        if let Some(key) = self.inner.iter().min_by_key(|(_, v)| f(v)).map(|(k, _)| *k) {
            self.inner.remove(&key);
            self.removals_since_add = self.removals_since_add.saturating_add(1);
            self.maybe_shrink();
            true
        } else {
            false
        }
    }
}

impl<K, V> Default for ShrinkingHashMap<K, V, hashbrown::DefaultHashBuilder> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shrinking_vecdeque_shrinks_after_removals() {
        let mut q = ShrinkingVecDeque::new();

        // Add many items to grow capacity
        for i in 0..100 {
            q.push_back(i);
        }

        // Remove all - should trigger shrink after 8 removals
        for _ in 0..100 {
            q.pop_front();
        }

        // Capacity should be reduced (shrink_to_fit on empty = 0 capacity)
        assert!(q.is_empty());
    }

    #[test]
    fn test_shrinking_hashmap_shrinks_after_removals() {
        let mut m = ShrinkingHashMap::new();

        // Add many items
        for i in 0..100 {
            m.insert(i, i * 2);
        }

        // Remove all
        for i in 0..100 {
            m.remove(&i);
        }

        assert!(m.is_empty());
    }

    #[test]
    fn test_addition_resets_counter() {
        let mut q = ShrinkingVecDeque::new();

        // Add items
        for i in 0..10 {
            q.push_back(i);
        }

        // Remove 7 (below threshold)
        for _ in 0..7 {
            q.pop_front();
        }

        // Add one more - resets counter
        q.push_back(100);

        // Remove remaining 4 - still below threshold since counter was reset
        for _ in 0..4 {
            q.pop_front();
        }

        // Queue is now empty
        assert_eq!(q.len(), 0);
    }
}
