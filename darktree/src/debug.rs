//! Debug events for protocol tracing.
//!
//! Enabled in test builds. These events help trace protocol flow
//! during simulation and testing.

use crate::time::Timestamp;
use crate::types::NodeId;

/// Trait for receiving debug events from a node.
/// Implemented by test harnesses to collect/print events.
pub trait DebugEmitter: Send {
    /// Called when a debug event is emitted.
    fn emit(&mut self, event: DebugEvent);
}

/// Debug events emitted by the node for protocol tracing.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// Shopping phase started (first boot or merge).
    ShoppingStarted {
        timestamp: Timestamp,
        deadline: Timestamp,
    },
    /// Shopping phase ended, calling select_best_parent.
    ShoppingEnded {
        timestamp: Timestamp,
        neighbor_count: usize,
    },
    /// select_best_parent found candidates.
    SelectBestParent {
        candidate_count: usize,
        best_tree_size: u32,
        best_root_hash: [u8; 4],
        dominated: bool,
    },
    /// Pending parent set (trying to join a tree).
    PendingParentSet { parent_id: NodeId },
    /// Parent acknowledged us, join complete.
    ParentAcknowledged {
        parent_id: NodeId,
        new_root_hash: [u8; 4],
        new_tree_size: u32,
    },
    /// Pending parent gave up after too many attempts.
    PendingParentTimeout { parent_id: NodeId, attempts: u8 },
    /// Received pulse from a node.
    PulseReceived {
        timestamp: Timestamp,
        from: NodeId,
        tree_size: u32,
        root_hash: [u8; 4],
        has_pubkey: bool,
        need_pubkey: bool,
    },
    /// Pubkey cached for a node.
    PubkeyCached { node_id: NodeId },
    /// Signature verification failed.
    SignatureVerifyFailed { node_id: NodeId },
    /// consider_merge evaluated.
    ConsiderMerge {
        from: NodeId,
        dominated: bool,
        reason: &'static str,
    },
    /// Child added to our tree.
    ChildAdded {
        timestamp: Timestamp,
        child_id: NodeId,
        subtree_size: u32,
    },
    /// Pulse sent.
    PulseSent {
        timestamp: Timestamp,
        tree_size: u32,
        root_hash: [u8; 4],
        child_count: u8,
        has_pubkey: bool,
        need_pubkey: bool,
    },
    /// Neighbor timing updated.
    NeighborTimingUpdated {
        node_id: NodeId,
        tree_size: u32,
        root_hash: [u8; 4],
    },
    /// Pulse rate-limited (arrived too fast).
    PulseRateLimited {
        from: NodeId,
        now: Timestamp,
        last_seen: Timestamp,
        min_interval_ms: u64,
    },
    /// Message decode failed.
    MessageDecodeFailed { data_len: usize },
    /// Routed message sent (PUBLISH, LOOKUP, etc.)
    RoutedSent {
        msg_type: u8,
        dest_addr: u32,
        ttl: u8,
    },
    /// Routed message forwarded DOWN to a child/shortcut.
    RoutedForwardedDown {
        msg_type: u8,
        dest_addr: u32,
        next_hop: NodeId,
        ttl: u8,
        my_keyspace: (u32, u32),
    },
    /// Routed message forwarded UP to parent (no child owns dest).
    RoutedForwardedUp {
        msg_type: u8,
        dest_addr: u32,
        next_hop: NodeId,
        ttl: u8,
        my_keyspace: (u32, u32),
    },
    /// Routed message delivered locally (we own the keyspace).
    RoutedDelivered {
        msg_type: u8,
        dest_addr: u32,
        from: NodeId,
    },
    /// Routed message dropped (no route found).
    RoutedDropped {
        msg_type: u8,
        dest_addr: u32,
        reason: &'static str,
    },
    /// PUBLISH stored in location_store.
    PublishStored {
        owner: NodeId,
        replica_index: u8,
        dest_addr: u32,
        keyspace_lo: u32,
        keyspace_hi: u32,
        own_hi: u32,
    },
    /// Location publish started.
    LocationPublishStarted { node_id: NodeId, seq: u32 },
    /// Location entry removed (rebalance or expiry).
    LocationRemoved {
        owner: NodeId,
        replica_index: u8,
        reason: &'static str,
    },
    /// Duplicate routed message detected (already in recently_forwarded).
    RoutedDuplicate {
        msg_type: u8,
        dest_addr: u32,
        original_ttl: u8,
        stored_ttl: u8,
        action: &'static str,
    },
    /// Bounce-back scheduled for delayed forward.
    BounceBackScheduled {
        msg_type: u8,
        dest_addr: u32,
        seen_count: u8,
        delay_ms: u64,
    },
    /// Delayed forward executed after bounce-back.
    DelayedForwardExecuted {
        msg_type: u8,
        dest_addr: u32,
        ttl: u8,
        has_route: bool,
    },
}
