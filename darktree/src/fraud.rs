//! Fraud detection for tree size verification.
//!
//! This module implements statistical detection of inflated tree sizes
//! based on PUBLISH traffic analysis using HyperLogLog cardinality estimation.
//!
//! ## HyperLogLog Overview
//!
//! HyperLogLog (HLL) is a probabilistic algorithm that estimates the cardinality
//! (unique count) of a set using fixed memory. Key properties:
//! - **Fixed memory:** 256 bytes regardless of set size
//! - **Supports billions of items** with same memory footprint
//! - **~6.5% standard error** for 256 registers
//!
//! For fraud detection, 6.5% error is acceptable since we're detecting 2× or
//! larger fraud, not subtle differences.

use core::hash::Hasher;

use siphasher::sip::SipHasher24;

use crate::config::NodeConfig;
use crate::node::Node;
use crate::time::Timestamp;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::NodeId;

/// Number of HyperLogLog registers (256 = ~6.5% standard error).
const HLL_REGISTERS: usize = 256;

/// Minimum interval between fraud detection resets (1 hour).
/// Prevents attackers from manipulating subtree_size to repeatedly reset
/// the detection window and delay fraud detection indefinitely.
const MIN_RESET_INTERVAL_SECS: u64 = 3600;

/// Secret key size for SipHash.
pub(crate) const HLL_SECRET_KEY_SIZE: usize = 16;

/// HyperLogLog secret key type.
pub(crate) type HllSecretKey = [u8; HLL_SECRET_KEY_SIZE];

/// Fraud detection state using HyperLogLog.
///
/// Uses PUBLISH traffic to verify claimed tree sizes by estimating unique publishers.
/// See docs/design.md "Tree Size Verification" for the statistical model.
#[derive(Clone, Debug)]
pub(crate) struct FraudDetection {
    /// HyperLogLog registers for cardinality estimation.
    /// Each register stores the maximum leading zeros seen (0-64, fits in u8).
    hll_registers: [u8; HLL_REGISTERS],
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
            hll_registers: [0u8; HLL_REGISTERS],
            count_start: Timestamp::ZERO,
            subtree_size_at_start: 1,
            last_reset: Timestamp::ZERO,
        }
    }

    /// Reset fraud detection counters.
    pub fn reset(&mut self, now: Timestamp, subtree_size: u32) {
        self.hll_registers = [0u8; HLL_REGISTERS];
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
    ///
    /// Uses keyed SipHash to prevent adversarial bucket manipulation.
    pub fn add_publisher(&mut self, publisher: &NodeId, secret_key: &HllSecretKey) {
        // Create SipHasher with the secret key (k0 from bytes 0-7, k1 from bytes 8-15)
        // unwrap() is safe: HllSecretKey is [u8; 16], so slices are exactly 8 bytes
        let k0 = u64::from_le_bytes(secret_key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(secret_key[8..16].try_into().unwrap());
        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(publisher);
        let hash = hasher.finish();

        // Use lower 8 bits for bucket index (256 buckets)
        let bucket = (hash as usize) & (HLL_REGISTERS - 1);

        // Count leading zeros in upper 56 bits, +1 for rank (so rank is always >= 1)
        // Shift right 8 to get 56-bit value in lower bits, then count leading zeros
        // and subtract 8 (since we're working with 56 bits in a 64-bit container)
        let upper_bits = hash >> 8;
        let leading_zeros = if upper_bits == 0 {
            56 // All 56 bits are zero
        } else {
            (upper_bits.leading_zeros() as u8).saturating_sub(8)
        };
        let rank = leading_zeros + 1;

        // Update register if this is a new maximum
        if rank > self.hll_registers[bucket] {
            self.hll_registers[bucket] = rank;
        }
    }

    /// Estimate the cardinality (unique count) using HyperLogLog formula.
    pub fn estimate_cardinality(&self) -> f64 {
        let m = HLL_REGISTERS as f64;
        // Bias correction factor for 256 registers
        let alpha = 0.7213 / (1.0 + 1.079 / m);

        // Harmonic mean of 2^(-register)
        let sum: f64 = self
            .hll_registers
            .iter()
            .map(|&r| libm::pow(2.0, -(r as f64)))
            .sum();

        let estimate = alpha * m * m / sum;

        // Small range correction using linear counting
        let zeros = self.hll_registers.iter().filter(|&&r| r == 0).count();
        if estimate < 2.5 * m && zeros > 0 {
            return m * libm::log(m / zeros as f64);
        }

        estimate
    }

    /// Check if subtree size changed significantly (requires counter reset).
    pub fn should_reset(&self, new_subtree_size: u32) -> bool {
        let old = self.subtree_size_at_start;
        // Use saturating_mul to avoid overflow when old > u32::MAX / 2
        new_subtree_size > old.saturating_mul(2) || new_subtree_size < old / 2
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

/// HyperLogLog standard error for 256 registers (~6.5%).
const HLL_STD_ERROR: f64 = 0.065;

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

        // Use HyperLogLog estimate instead of exact count
        let observed = fd.estimate_cardinality();

        // Combined variance accounts for both:
        // 1. Poisson variance of expected arrivals: Var(Poisson) = λ = expected
        // 2. HLL estimation error: ~6.5% std error for 256 registers
        let poisson_variance = expected;
        let hll_variance = (HLL_STD_ERROR * observed) * (HLL_STD_ERROR * observed);
        let combined_std = libm::sqrt(poisson_variance + hll_variance);

        let z = (expected - observed) / combined_std;

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
                let observed = self.fraud_detection().estimate_cardinality() as u32;
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

    /// Test secret key for deterministic tests.
    const TEST_KEY: HllSecretKey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[test]
    fn test_fraud_detection_reset() {
        let mut fd = FraudDetection::new();

        // Initial state - empty HLL should estimate ~0
        assert!(fd.estimate_cardinality() < 1.0);

        // Add some publishers
        let node1 = [1u8; 16];
        let node2 = [2u8; 16];
        fd.add_publisher(&node1, &TEST_KEY);
        fd.add_publisher(&node2, &TEST_KEY);
        fd.add_publisher(&node1, &TEST_KEY); // Duplicate - HLL handles naturally

        // Should estimate approximately 2
        let estimate = fd.estimate_cardinality();
        assert!(
            estimate > 1.0 && estimate < 4.0,
            "estimate was {}",
            estimate
        );

        // Reset
        fd.reset(Timestamp::from_secs(100), 10);
        assert!(fd.estimate_cardinality() < 1.0);
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
    fn test_hll_duplicate_handling() {
        let mut fd = FraudDetection::new();
        let node = [42u8; 16];

        // Same node publishing multiple times - HLL naturally deduplicates
        // (same hash goes to same bucket, max doesn't change)
        for _ in 0..100 {
            fd.add_publisher(&node, &TEST_KEY);
        }

        // Should estimate approximately 1
        let estimate = fd.estimate_cardinality();
        assert!(
            estimate > 0.5 && estimate < 3.0,
            "estimate was {}",
            estimate
        );
    }

    #[test]
    fn test_hll_many_unique_publishers() {
        let mut fd = FraudDetection::new();

        // Add 100 unique publishers
        for i in 0u8..100 {
            let mut node = [0u8; 16];
            node[0] = i;
            node[1] = (i as u16 * 7) as u8; // Add variation
            fd.add_publisher(&node, &TEST_KEY);
        }

        // HLL with 256 registers has ~6.5% std error
        // For 100 publishers, expect estimate within ~80-120 (generous bounds for test)
        let estimate = fd.estimate_cardinality();
        assert!(
            estimate > 70.0 && estimate < 140.0,
            "estimate was {} for 100 unique publishers",
            estimate
        );
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

    #[test]
    fn test_estimate_cardinality_empty() {
        let fd = FraudDetection::new();
        // Empty HLL uses linear counting and should estimate near 0
        let estimate = fd.estimate_cardinality();
        assert!(estimate < 1.0, "empty HLL estimated {}", estimate);
    }

    #[test]
    fn test_estimate_cardinality_small_range_correction() {
        let mut fd = FraudDetection::new();

        // Add just a few publishers - should trigger linear counting correction
        for i in 0u8..5 {
            let mut node = [i; 16];
            node[0] = i;
            fd.add_publisher(&node, &TEST_KEY);
        }

        let estimate = fd.estimate_cardinality();
        // With linear counting for small ranges, estimate should be reasonable
        assert!(
            estimate > 2.0 && estimate < 15.0,
            "estimate was {}",
            estimate
        );
    }
}
