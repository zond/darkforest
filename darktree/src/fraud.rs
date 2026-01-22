//! Fraud detection for tree size verification.
//!
//! This module implements statistical detection of inflated tree sizes
//! based on PUBLISH traffic analysis.

use crate::node::Node;
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{NodeId, MAX_DISTRUSTED};

/// Fraud detection state.
///
/// Uses PUBLISH traffic to verify claimed tree sizes.
/// See docs/design.md "Tree Size Verification" for the statistical model.
#[derive(Clone, Debug)]
pub struct FraudDetection {
    /// Number of PUBLISH messages received since count_start.
    publish_count: u32,
    /// Time when counting started (milliseconds).
    count_start: Timestamp,
    /// Subtree size when counting started.
    subtree_size_at_start: u32,
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
            publish_count: 0,
            count_start: Timestamp::ZERO,
            subtree_size_at_start: 1,
        }
    }

    /// Reset fraud detection counters.
    pub fn reset(&mut self, now: Timestamp, subtree_size: u32) {
        self.publish_count = 0;
        self.count_start = now;
        self.subtree_size_at_start = subtree_size;
    }

    /// Record a received PUBLISH message.
    pub fn on_publish_received(&mut self) {
        self.publish_count += 1;
    }

    /// Check if subtree size changed significantly (requires counter reset).
    pub fn should_reset(&self, new_subtree_size: u32) -> bool {
        let old = self.subtree_size_at_start;
        new_subtree_size > old * 2 || new_subtree_size < old / 2
    }

    /// Get current publish count.
    pub fn publish_count(&self) -> u32 {
        self.publish_count
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

/// Minimum expected PUBLISH count for valid statistics.
const MIN_EXPECTED: f64 = 5.0;

impl<T, Cr, R, Clk> Node<T, Cr, R, Clk>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
{
    /// Check for tree size fraud based on PUBLISH traffic.
    ///
    /// Returns true if fraud is detected with high confidence.
    pub fn check_tree_size_fraud(&self, now: Timestamp) -> bool {
        let _join_ctx = match self.join_context() {
            Some(ctx) => ctx,
            None => return false,
        };

        let fd = self.fraud_detection();
        let elapsed = now.saturating_sub(fd.count_start());
        let t_hours = elapsed.as_secs() as f64 / 3600.0;

        // Expected PUBLISH per 8 hours = 3 × subtree_size
        // So expected for t hours = 3 × S × (t / 8)
        let expected = 3.0 * fd.subtree_size_at_start() as f64 * t_hours / 8.0;

        // Need enough samples for valid statistics
        if expected < MIN_EXPECTED {
            return false;
        }

        let observed = fd.publish_count() as f64;

        // Z-score: how many standard deviations below expected
        // For Poisson distribution, variance = expected, so std_dev = sqrt(expected)
        let z = (expected - observed) / expected.sqrt();

        z > FRAUD_Z_THRESHOLD
    }

    /// Add a node to the distrusted set.
    pub fn add_distrust(&mut self, node: NodeId, now: Timestamp) {
        // Evict oldest if at capacity
        while self.distrusted().len() >= MAX_DISTRUSTED {
            if let Some(oldest) = self
                .distrusted()
                .iter()
                .min_by_key(|(_, &time)| time)
                .map(|(id, _)| *id)
            {
                self.distrusted_mut().remove(&oldest);
            } else {
                break;
            }
        }
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
        self.set_root_id(*self.node_id());
        self.set_tree_size(self.subtree_size());
        self.set_tree_addr(Vec::new());
    }

    /// Handle potential fraud detection and response.
    pub fn handle_fraud_check(&mut self, now: Timestamp) {
        if self.check_tree_size_fraud(now) {
            // Add the parent we joined through to distrusted
            if let Some(ctx) = self.join_context().clone() {
                self.add_distrust(ctx.parent_at_join, now);
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
        assert_eq!(fd.publish_count(), 0);

        // Receive some publishes
        fd.on_publish_received();
        fd.on_publish_received();
        assert_eq!(fd.publish_count(), 2);

        // Reset
        fd.reset(Timestamp::from_secs(100), 10);
        assert_eq!(fd.publish_count(), 0);
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
}
