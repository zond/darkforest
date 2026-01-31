//! Debug events for protocol tracing.
//!
//! Enabled in test builds. These events help trace protocol flow
//! during simulation and testing.

use crate::time::Timestamp;
use crate::types::NodeId;

/// Trait for types that can emit debug events.
/// Implement this to make a type usable with the `emit_debug!` macro.
#[cfg(feature = "debug")]
pub trait HasDebugEmitter {
    /// Returns a reference to the debug emitter cell.
    fn debug_emitter(&self) -> &core::cell::RefCell<Option<alloc::boxed::Box<dyn DebugEmitter>>>;

    /// Check if a debug emitter is set.
    /// Use this to guard expensive computations (like hashing) that are only
    /// needed for debug events.
    /// Uses try_borrow to avoid panics if already borrowed (returns false).
    fn has_emitter(&self) -> bool {
        self.debug_emitter().try_borrow().is_ok_and(|e| e.is_some())
    }
}

/// Emit a debug event. When the "debug" feature is disabled, this expands to nothing,
/// so the event expression is never evaluated (zero overhead).
///
/// If no debug emitter is set, silently does nothing.
///
/// Usage: `emit_debug!(node, DebugEvent::Variant { ... })`
#[cfg(feature = "debug")]
macro_rules! emit_debug {
    ($node:expr, $event:expr) => {
        if let Some(emitter) = crate::debug::HasDebugEmitter::debug_emitter($node)
            .borrow_mut()
            .as_mut()
        {
            emitter.emit($event);
        }
    };
}

/// No-op version when debug feature is disabled.
#[cfg(not(feature = "debug"))]
macro_rules! emit_debug {
    ($node:expr, $event:expr) => {};
}

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
    /// Pending parent cleared (reason describes why).
    PendingParentCleared { reason: &'static str },
    /// Pending parent pulse count incremented.
    PendingParentPulseCount { parent_id: NodeId, count: u8 },
    /// Received pulse from a node.
    PulseReceived {
        timestamp: Timestamp,
        from: NodeId,
        tree_size: u32,
        root_hash: [u8; 4],
        keyspace_lo: u32,
        keyspace_hi: u32,
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
    /// payload_hash identifies the content for tracing across rebalances.
    RoutedSent {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        ttl: u32,
    },
    /// Routed message forwarded to next hop.
    /// `direction` is "up" (to parent) or "down" (to child/shortcut).
    RoutedForwarded {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        next_hop: NodeId,
        ttl: u32,
        my_keyspace: (u32, u32),
        direction: &'static str,
    },
    /// Routed message delivered locally (we own the keyspace).
    RoutedDelivered {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        from: NodeId,
    },
    /// Routed message dropped (send failed).
    RoutedDropped {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        error: crate::types::Error,
    },
    /// PUBLISH stored in location_store.
    PublishStored {
        payload_hash: [u8; 4],
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
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        original_hops: u32,
        stored_hops: u32,
        action: &'static str,
    },
    /// Message handled opportunistically (not designated forwarder but owns keyspace).
    RoutedOpportunistic {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
    },
    /// Bounce-back scheduled for delayed forward.
    BounceBackScheduled {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        seen_count: u8,
        delay_ms: u64,
    },
    /// Delayed forward executed after bounce-back.
    DelayedForwardExecuted {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
        ttl: u32,
        has_route: bool,
    },
    /// Outgoing queue rejected a routed message (queue full).
    OutgoingQueueFull {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
    },
    /// Message received from transport.
    /// payload_hash is Some if the message is a Routed message.
    TransportReceived {
        data_len: usize,
        payload_hash: Option<[u8; 4]>,
    },
    /// App incoming channel full, DATA message dropped.
    AppIncomingFull { from: NodeId, payload_len: usize },
    /// Event queue full, event dropped.
    EventQueueFull { event_type: &'static str },
    /// Routed message queued because no route available (root with no matching child).
    RoutedQueued {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
    },
    /// Queued routed message retried after neighbor pulse.
    RoutedRetried {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
    },
    /// Message evicted from pending_routed queue (queue full).
    RoutedEvicted {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
    },
    /// Message expired from pending_routed queue (320τ timeout).
    RoutedExpired {
        payload_hash: [u8; 4],
        msg_type: u8,
        dest_addr: u32,
    },
    /// Pending retry scheduled.
    PendingRetryScheduled { time_ms: u64, queue_len: usize },
    /// Pending retry tick fired.
    PendingRetryTick { queue_len: usize },
    /// Routing decision made: shows which neighbor was selected and why.
    /// believed_keyspace is what we think the selected neighbor owns (from their last pulse).
    RoutingDecision {
        dest_addr: u32,
        selected: NodeId,
        believed_keyspace: (u32, u32),
        is_parent_fallback: bool,
    },
}
