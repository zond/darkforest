//! Time types for the darktree protocol.
//!
//! These types provide explicit time handling without relying on
//! platform-specific clocks. All time values are passed explicitly,
//! enabling deterministic simulation.

use core::ops::{Add, AddAssign, Mul, Sub, SubAssign};

/// Protocol timestamp in milliseconds.
///
/// Wraps a u64 to enforce explicit unit conversions and prevent
/// mixing milliseconds with seconds or other units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Zero timestamp (epoch).
    pub const ZERO: Timestamp = Timestamp(0);

    /// Maximum timestamp.
    pub const MAX: Timestamp = Timestamp(u64::MAX);

    /// Create a timestamp from milliseconds.
    #[inline]
    pub const fn from_millis(ms: u64) -> Self {
        Timestamp(ms)
    }

    /// Create a timestamp from seconds.
    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Timestamp(secs.saturating_mul(1000))
    }

    /// Get the timestamp as milliseconds.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Get the timestamp as seconds (truncated).
    #[inline]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    /// Saturating addition of a duration.
    #[inline]
    pub const fn saturating_add(self, duration: Duration) -> Self {
        Timestamp(self.0.saturating_add(duration.0))
    }

    /// Saturating subtraction of another timestamp, returning a duration.
    #[inline]
    pub const fn saturating_sub(self, other: Timestamp) -> Duration {
        Duration(self.0.saturating_sub(other.0))
    }

    /// Checked subtraction of another timestamp.
    #[inline]
    pub const fn checked_sub(self, other: Timestamp) -> Option<Duration> {
        match self.0.checked_sub(other.0) {
            Some(d) => Some(Duration(d)),
            None => None,
        }
    }

    /// Checked addition of a duration.
    #[inline]
    pub const fn checked_add(self, duration: Duration) -> Option<Timestamp> {
        match self.0.checked_add(duration.0) {
            Some(t) => Some(Timestamp(t)),
            None => None,
        }
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    #[inline]
    fn add(self, rhs: Duration) -> Timestamp {
        Timestamp(self.0 + rhs.0)
    }
}

impl AddAssign<Duration> for Timestamp {
    #[inline]
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0;
    }
}

impl Sub for Timestamp {
    type Output = Duration;

    #[inline]
    fn sub(self, rhs: Timestamp) -> Duration {
        Duration(self.0 - rhs.0)
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Timestamp;

    #[inline]
    fn sub(self, rhs: Duration) -> Timestamp {
        Timestamp(self.0 - rhs.0)
    }
}

/// Duration in milliseconds.
///
/// Represents a time span, not a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(u64);

impl Duration {
    /// Zero duration.
    pub const ZERO: Duration = Duration(0);

    /// Maximum duration.
    pub const MAX: Duration = Duration(u64::MAX);

    /// Create a duration from milliseconds.
    #[inline]
    pub const fn from_millis(ms: u64) -> Self {
        Duration(ms)
    }

    /// Create a duration from seconds.
    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Duration(secs.saturating_mul(1000))
    }

    /// Create a duration from hours.
    #[inline]
    pub const fn from_hours(hours: u64) -> Self {
        Duration(hours.saturating_mul(3600 * 1000))
    }

    /// Get the duration as milliseconds.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Get the duration as seconds (truncated).
    #[inline]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    /// Saturating addition.
    #[inline]
    pub const fn saturating_add(self, other: Duration) -> Self {
        Duration(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction.
    #[inline]
    pub const fn saturating_sub(self, other: Duration) -> Self {
        Duration(self.0.saturating_sub(other.0))
    }

    /// Saturating multiplication.
    #[inline]
    pub const fn saturating_mul(self, n: u64) -> Self {
        Duration(self.0.saturating_mul(n))
    }

    /// Checked addition.
    #[inline]
    pub const fn checked_add(self, other: Duration) -> Option<Duration> {
        match self.0.checked_add(other.0) {
            Some(d) => Some(Duration(d)),
            None => None,
        }
    }

    /// Checked subtraction.
    #[inline]
    pub const fn checked_sub(self, other: Duration) -> Option<Duration> {
        match self.0.checked_sub(other.0) {
            Some(d) => Some(Duration(d)),
            None => None,
        }
    }
}

impl Add for Duration {
    type Output = Duration;

    #[inline]
    fn add(self, rhs: Duration) -> Duration {
        Duration(self.0 + rhs.0)
    }
}

impl AddAssign for Duration {
    #[inline]
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0;
    }
}

impl Sub for Duration {
    type Output = Duration;

    #[inline]
    fn sub(self, rhs: Duration) -> Duration {
        Duration(self.0 - rhs.0)
    }
}

impl SubAssign for Duration {
    #[inline]
    fn sub_assign(&mut self, rhs: Duration) {
        self.0 -= rhs.0;
    }
}

impl Mul<u64> for Duration {
    type Output = Duration;

    #[inline]
    fn mul(self, rhs: u64) -> Duration {
        Duration(self.0 * rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_creation() {
        let t1 = Timestamp::from_millis(1500);
        assert_eq!(t1.as_millis(), 1500);
        assert_eq!(t1.as_secs(), 1);

        let t2 = Timestamp::from_secs(5);
        assert_eq!(t2.as_millis(), 5000);
        assert_eq!(t2.as_secs(), 5);
    }

    #[test]
    fn test_duration_creation() {
        let d1 = Duration::from_millis(2500);
        assert_eq!(d1.as_millis(), 2500);
        assert_eq!(d1.as_secs(), 2);

        let d2 = Duration::from_secs(10);
        assert_eq!(d2.as_millis(), 10000);

        let d3 = Duration::from_hours(1);
        assert_eq!(d3.as_millis(), 3600 * 1000);
    }

    #[test]
    fn test_timestamp_arithmetic() {
        let t1 = Timestamp::from_secs(10);
        let d = Duration::from_secs(5);

        let t2 = t1 + d;
        assert_eq!(t2.as_secs(), 15);

        let t3 = Timestamp::from_secs(20);
        let diff = t3 - t1;
        assert_eq!(diff.as_secs(), 10);
    }

    #[test]
    fn test_duration_arithmetic() {
        let d1 = Duration::from_secs(5);
        let d2 = Duration::from_secs(3);

        assert_eq!((d1 + d2).as_secs(), 8);
        assert_eq!((d1 - d2).as_secs(), 2);
    }

    #[test]
    fn test_saturating_operations() {
        let t = Timestamp::MAX;
        let d = Duration::from_secs(1);
        assert_eq!(t.saturating_add(d), Timestamp::MAX);

        let t1 = Timestamp::from_secs(5);
        let t2 = Timestamp::from_secs(10);
        assert_eq!(t1.saturating_sub(t2), Duration::ZERO);
    }

    #[test]
    fn test_ordering() {
        let t1 = Timestamp::from_secs(5);
        let t2 = Timestamp::from_secs(10);
        assert!(t1 < t2);

        let d1 = Duration::from_secs(3);
        let d2 = Duration::from_secs(7);
        assert!(d1 < d2);
    }
}
