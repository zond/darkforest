//! Debug events for protocol tracing.
//!
//! Enabled via the `debug` feature. These events help trace protocol flow
//! during simulation and testing.

use crate::time::Timestamp;
use crate::traits::ChannelMutex;
use crate::types::NodeId;
use embassy_sync::channel::Channel;

/// Queue size for debug events.
pub const DEBUG_QUEUE_SIZE: usize = 256;

/// Debug event channel type.
pub type DebugChannel = Channel<ChannelMutex, DebugEvent, DEBUG_QUEUE_SIZE>;

/// Debug events emitted by the node for protocol tracing.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// Discovery phase started.
    DiscoveryStarted { deadline: Timestamp },
    /// Discovery phase ended, calling select_best_parent.
    DiscoveryEnded { neighbor_count: usize },
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
    ChildAdded { child_id: NodeId, subtree_size: u32 },
    /// Pulse sent.
    PulseSent {
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
}
