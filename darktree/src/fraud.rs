//! Fraud detection for tree size verification.
//!
//! This module implements statistical detection of inflated tree sizes
//! based on PUBLISH traffic analysis using unique publisher tracking.

use hashbrown::HashSet;

use crate::config::NodeConfig;
use crate::node::Node;
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::NodeId;

/// Maximum unique publishers to track (memory bound).
const MAX_UNIQUE_PUBLISHERS: usize = 512;

/// Minimum interval between fraud detection resets (1 hour).
/// Prevents attackers from manipulating subtree_size to repeatedly reset
/// the detection window and delay fraud detection indefinitely.
const MIN_RESET_INTERVAL_SECS: u64 = 3600;

/// Fraud detection state.
///
/// Uses PUBLISH traffic to verify claimed tree sizes by tracking unique publishers.
/// See docs/design.md "Tree Size Verification" for the statistical model.
#[derive(Clone, Debug)]
pub struct FraudDetection {
    /// Set of unique node_ids that have published.
    unique_publishers: HashSet<NodeId>,
    /// Time when counting started (milliseconds).
    count_start: Timestamp,
    /// Subtree size when counting started.
    subtree_size_at_start: u32,
    /// Time of last reset (for rate limiting).
    last_reset: Timestamp,
}

impl Default for FraudDetection {
    fn default() -> Self {
        Self::new()
    }
}

impl FraudDetection {
    /// Create new fraud detection state.
    pub fn new() -> Self {
        Self {
            unique_publishers: HashSet::new(),
            count_start: Timestamp::ZERO,
            subtree_size_at_start: 1,
            last_reset: Timestamp::ZERO,
        }
    }

    /// Reset fraud detection counters.
    pub fn reset(&mut self, now: Timestamp, subtree_size: u32) {
        self.unique_publishers.clear();
        self.count_start = now;
        self.subtree_size_at_start = subtree_size;
        self.last_reset = now;
    }

    /// Check if enough time has passed since last reset (rate limiting).
    pub fn can_reset(&self, now: Timestamp) -> bool {
        let elapsed = now.saturating_sub(self.last_reset);
        elapsed.as_secs() >= MIN_RESET_INTERVAL_SECS
    }

    /// Record a received PUBLISH message from a specific node.
    pub fn on_publish_received(&mut self, publisher: &NodeId) {
        // Only track if we're under the memory limit
        if self.unique_publishers.len() < MAX_UNIQUE_PUBLISHERS {
            self.unique_publishers.insert(*publisher);
        }
    }

    /// Check if subtree size changed significantly (requires counter reset).
    pub fn should_reset(&self, new_subtree_size: u32) -> bool {
        let old = self.subtree_size_at_start;
        new_subtree_size > old * 2 || new_subtree_size < old / 2
    }

    /// Get count of unique publishers.
    pub fn unique_publisher_count(&self) -> usize {
        self.unique_publishers.len()
    }

    /// Get count start time.
    pub fn count_start(&self) -> Timestamp {
        self.count_start
    }

    /// Get subtree size at start.
    pub fn subtree_size_at_start(&self) -> u32 {
        self.subtree_size_at_start
    }
}

/// Confidence level for fraud detection.
const FRAUD_Z_THRESHOLD: f64 = 2.33; // 99% confidence

/// Minimum expected unique publishers for valid statistics.
const MIN_EXPECTED: f64 = 5.0;

impl<T, Cr, R, Clk, Cfg> Node<T, Cr, R, Clk, Cfg>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
    Cfg: NodeConfig,
{
    /// Check for tree size fraud based on unique publishers.
    ///
    /// Returns true if fraud is detected with high confidence.
    ///
    /// The model: After observation time t, we expect to see approximately
    /// subtree_size unique publishers (each node publishes once per 8 hours,
    /// so in t hours we expect subtree_size * (t/8) publishes, but we're
    /// counting unique publishers, not total publishes).
    ///
    /// For long observation periods, the expected unique publishers approaches
    /// the subtree_size. For shorter periods, it's a fraction based on how
    /// many nodes have published at least once.
    pub fn check_tree_size_fraud(&self, now: Timestamp) -> bool {
        let _join_ctx = match self.join_context() {
            Some(ctx) => ctx,
            None => return false,
        };

        let fd = self.fraud_detection();
        let elapsed = now.saturating_sub(fd.count_start());
        let t_hours = elapsed.as_secs() as f64 / 3600.0;

        // Minimum observation time: 8 hours for meaningful statistics
        if t_hours < 8.0 {
            return false;
        }

        // Expected unique publishers after 8+ hours is approximately subtree_size
        // (assuming each node publishes once per 8 hours)
        // For t >= 8 hours, we expect most nodes to have published at least once
        let expected = fd.subtree_size_at_start() as f64;

        // Need enough samples for valid statistics
        if expected < MIN_EXPECTED {
            return false;
        }

        let observed = fd.unique_publisher_count() as f64;

        // Z-score: how many standard deviations below expected
        // Model: unique publishers as binomial with p = 1 - (1-1/8)^t for t hours
        // For t >= 8, p approaches 1, so variance approaches subtree_size * p * (1-p)
        // Simplified: use Poisson approximation, variance ~ expected
        let z = (expected - observed) / libm::sqrt(expected);

        z > FRAUD_Z_THRESHOLD
    }

    /// Add a node to the distrusted set.
    pub fn add_distrust(&mut self, node: NodeId, now: Timestamp) {
        // insert_distrusted handles capacity eviction
        self.insert_distrusted(node, now);
    }

    /// Leave current tree and rejoin as independent node.
    pub fn leave_and_rejoin(&mut self, now: Timestamp) {
        // Reset fraud detection
        let subtree_size = self.subtree_size();
        self.fraud_detection_mut().reset(now, subtree_size);

        // Clear join context
        self.set_join_context(None);

        // Become root of own subtree
        self.set_parent(None);
        self.set_parent_rejection_count(0);
        let my_hash = self.compute_node_hash(self.node_id());
        self.set_root_hash(my_hash);
        self.set_tree_size(self.subtree_size());
        self.set_keyspace_range(0, u32::MAX);
    }

    /// Handle potential fraud detection and response.
    pub fn handle_fraud_check(&mut self, now: Timestamp) {
        // Reset counters if subtree size changed significantly (2x either way)
        // Rate-limited to prevent attackers from manipulating subtree_size
        // to repeatedly reset the detection window.
        let current_subtree = self.subtree_size();
        if self.fraud_detection().should_reset(current_subtree)
            && self.fraud_detection().can_reset(now)
        {
            self.fraud_detection_mut().reset(now, current_subtree);
        }

        if self.check_tree_size_fraud(now) {
            // Add the parent we joined through to distrusted
            if let Some(ctx) = self.join_context().as_ref().copied() {
                let observed = self.fraud_detection().unique_publisher_count() as u32;
                let expected = self.fraud_detection().subtree_size_at_start();

                self.add_distrust(ctx.parent_at_join, now);

                // Emit event to notify application
                self.push_event(crate::types::Event::FraudDetected {
                    parent: ctx.parent_at_join,
                    observed,
                    expected,
                });
            }

            // Leave and rejoin
            self.leave_and_rejoin(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;

    #[test]
    fn test_fraud_detection_reset() {
        let mut fd = FraudDetection::new();

        // Initial state
        assert_eq!(fd.unique_publisher_count(), 0);

        // Receive some publishes
        let node1 = [1u8; 16];
        let node2 = [2u8; 16];
        fd.on_publish_received(&node1);
        fd.on_publish_received(&node2);
        fd.on_publish_received(&node1); // Duplicate - should not increase count
        assert_eq!(fd.unique_publisher_count(), 2);

        // Reset
        fd.reset(Timestamp::from_secs(100), 10);
        assert_eq!(fd.unique_publisher_count(), 0);
        assert_eq!(fd.count_start(), Timestamp::from_secs(100));
        assert_eq!(fd.subtree_size_at_start(), 10);
    }

    #[test]
    fn test_should_reset() {
        let mut fd = FraudDetection::new();
        fd.reset(Timestamp::ZERO, 10);

        // Small change - no reset
        assert!(!fd.should_reset(15));
        assert!(!fd.should_reset(8));

        // Large change - reset
        assert!(fd.should_reset(21)); // > 2x
        assert!(fd.should_reset(4)); // < 0.5x
    }

    #[test]
    fn test_unique_publishers_deduplication() {
        let mut fd = FraudDetection::new();

        let node = [42u8; 16];

        // Same node publishing multiple times should only count once
        for _ in 0..10 {
            fd.on_publish_received(&node);
        }

        assert_eq!(fd.unique_publisher_count(), 1);
    }

    #[test]
    fn test_reset_rate_limiting() {
        let mut fd = FraudDetection::new();
        fd.reset(Timestamp::from_secs(1000), 10);

        // Immediately after reset, can_reset should be false
        assert!(!fd.can_reset(Timestamp::from_secs(1000)));
        assert!(!fd.can_reset(Timestamp::from_secs(1000 + 1800))); // 30 min later

        // After MIN_RESET_INTERVAL_SECS (1 hour), can_reset should be true
        assert!(fd.can_reset(Timestamp::from_secs(1000 + 3600))); // Exactly 1 hour
        assert!(fd.can_reset(Timestamp::from_secs(1000 + 7200))); // 2 hours later
    }

    #[test]
    fn test_reset_rate_limiting_boundary() {
        let mut fd = FraudDetection::new();
        fd.reset(Timestamp::from_secs(10000), 10);

        // One second before the interval - should not allow reset
        assert!(!fd.can_reset(Timestamp::from_secs(10000 + 3599)));

        // Exactly at the interval - should allow reset
        assert!(fd.can_reset(Timestamp::from_secs(10000 + 3600)));
    }

    #[test]
    fn test_reset_rate_limiting_initial_state() {
        // New FraudDetection has last_reset = ZERO
        let fd = FraudDetection::new();

        // Any reasonable timestamp should allow initial reset
        // (since elapsed from ZERO will exceed 1 hour for any real timestamp)
        assert!(fd.can_reset(Timestamp::from_secs(3600))); // 1 hour from epoch
        assert!(fd.can_reset(Timestamp::from_secs(1000000))); // Much later
    }

    #[test]
    fn test_reset_rate_limiting_clock_skew() {
        let mut fd = FraudDetection::new();
        fd.reset(Timestamp::from_secs(10000), 10);

        // If clock goes backwards (now < last_reset), saturating_sub returns ZERO
        // which means elapsed.as_secs() = 0, so can_reset returns false
        // This is safe behavior - don't allow reset if time seems wrong
        assert!(!fd.can_reset(Timestamp::from_secs(5000))); // Time went backwards
        assert!(!fd.can_reset(Timestamp::from_secs(0))); // Time at zero
    }
}
