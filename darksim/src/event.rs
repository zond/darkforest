//! Event types and priority queue for discrete event simulation.

use std::cmp::Ordering;

use darktree::{NodeId, Timestamp};

/// Unique sequence number for deterministic event ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Scenario actions that can be scheduled during simulation.
#[derive(Debug, Clone)]
pub enum ScenarioAction {
    /// Partition the network into isolated groups.
    Partition { groups: Vec<Vec<NodeId>> },
    /// Heal all partitions (restore full connectivity).
    HealPartition,
    /// Disable a specific link.
    DisableLink { from: NodeId, to: NodeId },
    /// Enable a specific link.
    EnableLink { from: NodeId, to: NodeId },
    /// Set loss rate on a link.
    SetLossRate { from: NodeId, to: NodeId, rate: f64 },
    /// Take a tree snapshot for metrics.
    TakeSnapshot,
}

/// Events in the discrete event simulation.
#[derive(Debug, Clone)]
pub enum Event {
    /// Deliver a message to a node.
    MessageDelivery {
        to: NodeId,
        data: Vec<u8>,
        rssi: Option<i16>,
        from: NodeId,
    },
    /// Fire timer for a node.
    TimerFire { node: NodeId },
    /// Application sends data from one node to another.
    AppSend {
        from: NodeId,
        to: NodeId,
        payload: Vec<u8>,
    },
    /// Execute a scenario action.
    ScenarioAction(ScenarioAction),
}

/// A scheduled event with timestamp and sequence number for ordering.
#[derive(Debug, Clone)]
pub struct ScheduledEvent {
    /// When the event should occur.
    pub time: Timestamp,
    /// Sequence number for deterministic ordering of same-time events.
    pub seq: SequenceNumber,
    /// The event to process.
    pub event: Event,
}

impl ScheduledEvent {
    pub fn new(time: Timestamp, seq: SequenceNumber, event: Event) -> Self {
        Self { time, seq, event }
    }
}

// Implement ordering for min-heap (BinaryHeap is max-heap, so we reverse).
impl PartialEq for ScheduledEvent {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.seq == other.seq
    }
}

impl Eq for ScheduledEvent {}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (BinaryHeap is max-heap).
        // First compare by time, then by sequence number.
        match other.time.as_millis().cmp(&self.time.as_millis()) {
            Ordering::Equal => other.seq.cmp(&self.seq),
            ord => ord,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_ordering() {
        let e1 = ScheduledEvent::new(
            Timestamp::from_secs(10),
            SequenceNumber::new(1),
            Event::TimerFire { node: [0u8; 16] },
        );
        let e2 = ScheduledEvent::new(
            Timestamp::from_secs(5),
            SequenceNumber::new(2),
            Event::TimerFire { node: [0u8; 16] },
        );

        // e2 has earlier time, so it should be "greater" in min-heap terms
        assert!(e2 > e1);
    }

    #[test]
    fn test_same_time_sequence_ordering() {
        let e1 = ScheduledEvent::new(
            Timestamp::from_secs(10),
            SequenceNumber::new(1),
            Event::TimerFire { node: [0u8; 16] },
        );
        let e2 = ScheduledEvent::new(
            Timestamp::from_secs(10),
            SequenceNumber::new(2),
            Event::TimerFire { node: [0u8; 16] },
        );

        // Same time, e1 has lower sequence, so e1 should be processed first
        assert!(e1 > e2);
    }
}
