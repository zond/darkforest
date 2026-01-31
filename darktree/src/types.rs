//! Core types and constants for the darktree protocol.

use alloc::vec::Vec;
use core::fmt;

use crate::time::{Duration, Timestamp};

// Protocol limits (not configurable via NodeConfig)
pub const MAX_CHILDREN: usize = 12; // Guarantees worst-case Pulse fits in 252 bytes
pub const MAX_PACKET_SIZE: usize = 255;
/// Recently forwarded entries expire after 320τ to allow for slow multi-hop ACKs.
/// On LoRa (τ=6.7s) this is ~35 minutes; on UDP (τ=100ms) this is 32 seconds.
pub(crate) const RECENTLY_FORWARDED_TTL_MULTIPLIER: u64 = 320;

// Protocol constants
pub const K_REPLICAS: usize = 3;

// Timing constants
/// Maximum retransmission attempts before giving up. With exponential backoff
/// (1τ, 2τ, 4τ, 8τ, 16τ, 32τ, 64τ, 128τ), total wait is ~255τ before abandoning.
pub const MAX_RETRIES: u8 = 8;
pub const LOCATION_REFRESH: Duration = Duration::from_hours(8);
pub const LOCATION_TTL: Duration = Duration::from_hours(12);
pub const DISTRUST_TTL: Duration = Duration::from_hours(24);

// Bandwidth budget: Pulse traffic should use at most 1/PULSE_BW_DIVISOR of available bandwidth.
// With divisor=5, pulse is limited to 20% of bandwidth, leaving 80% for application data.
pub(crate) const PULSE_BW_DIVISOR: u32 = 5;

/// Minimum tau value in milliseconds (floor for high-bandwidth transports).
/// tau = max(MTU/bandwidth, MIN_TAU_MS).
pub(crate) const MIN_TAU_MS: u64 = 100;

// Routed message types (0-3 valid; 4-15 rejected at parse time)
// Note: ACK is a separate top-level message type (wire_type 0x03), not a Routed subtype
pub const MSG_PUBLISH: u8 = 0;
pub const MSG_LOOKUP: u8 = 1;
pub const MSG_FOUND: u8 = 2;
pub const MSG_DATA: u8 = 3;

// Algorithm identifiers
pub const ALGORITHM_ED25519: u8 = 0x01;

// Domain separation prefixes (internal for signing)
pub(crate) const DOMAIN_PULSE: &[u8] = b"PULSE:";
pub(crate) const DOMAIN_ROUTE: &[u8] = b"ROUTE:";
pub(crate) const DOMAIN_LOC: &[u8] = b"LOC:";
pub(crate) const DOMAIN_BCAST: &[u8] = b"BCAST:";

// Broadcast payload type identifiers
/// Application data broadcast.
pub const BCAST_PAYLOAD_DATA: u8 = 0x00;
/// Backup publish for DHT redundancy.
pub const BCAST_PAYLOAD_BACKUP: u8 = 0x01;

/// Message priority levels for transport scheduling.
///
/// Higher-priority messages (lower numeric value) are sent before lower-priority ones.
/// This ensures protocol traffic (tree maintenance, DHT operations) works even under
/// heavy application load.
///
/// Priority ordering (highest to lowest):
/// 1. Ack - Reliability; enables retransmission
/// 2. BroadcastProtocol - DHT backup protocol (BACKUP_PUBLISH), Pulse
/// 3. RoutedPublish - DHT PUBLISH operations
/// 4. RoutedFound - DHT FOUND responses
/// 5. RoutedLookup - DHT LOOKUP queries
/// 6. BroadcastData - Application broadcast
/// 7. RoutedData - Application unicast
///
/// Note: Pulse uses BroadcastProtocol priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Priority {
    /// Explicit ACKs for link-layer reliability.
    Ack = 0,
    /// Protocol-level broadcast (Pulse, BACKUP_PUBLISH).
    BroadcastProtocol = 1,
    /// DHT PUBLISH operations (highest routed protocol priority).
    RoutedPublish = 2,
    /// DHT FOUND responses.
    RoutedFound = 3,
    /// DHT LOOKUP queries.
    RoutedLookup = 4,
    /// Application-level broadcast data.
    BroadcastData = 5,
    /// Application-level routed data.
    RoutedData = 6,
}

impl Priority {
    /// Returns true if this is a protocol-level priority.
    ///
    /// Useful for metrics and monitoring to categorize traffic.
    #[allow(dead_code)] // Public API for library consumers
    pub fn is_protocol(&self) -> bool {
        matches!(
            self,
            Priority::Ack
                | Priority::BroadcastProtocol
                | Priority::RoutedPublish
                | Priority::RoutedFound
                | Priority::RoutedLookup
        )
    }
}

/// Incoming message wrapper for lazy decoding.
///
/// Wraps raw bytes received from the transport layer. Use with
/// `Message::decode_from_slice(&incoming.data)` to parse when ready.
#[derive(Debug, Clone)]
pub struct Incoming {
    /// Raw message bytes.
    pub data: Vec<u8>,
    /// Signal strength in dBm (if available from transport).
    pub rssi: Option<i16>,
}

impl Incoming {
    /// Create a new incoming message wrapper.
    pub fn new(data: Vec<u8>, rssi: Option<i16>) -> Self {
        Self { data, rssi }
    }
}

/// Pre-encoded message for retransmission.
///
/// Used when we have already-encoded bytes and need to send them with a
/// specific priority (e.g., retransmitting cached messages).
#[derive(Debug, Clone)]
pub struct PreEncoded {
    /// Pre-encoded message bytes.
    pub data: Vec<u8>,
    /// Priority for this message.
    pub priority: Priority,
}

impl PreEncoded {
    /// Create a new pre-encoded message.
    pub fn new(data: Vec<u8>, priority: Priority) -> Self {
        Self { data, priority }
    }
}

/// 16-byte node identifier derived from public key hash.
pub type NodeId = [u8; 16];

/// 32-byte Ed25519 public key.
pub type PublicKey = [u8; 32];

/// 32-byte Ed25519 secret key (seed).
pub type SecretKey = [u8; 32];

/// 4-byte truncated hash for node identification and verification.
/// Used for all nodes (self, parent, children, neighbors).
pub type IdHash = [u8; 4];

/// Children list in pulse messages: (4-byte hash, subtree_size).
pub type ChildrenList = Vec<(IdHash, u32)>;

/// Payload type for routed messages.
pub type Payload = Vec<u8>;

/// Cryptographic signature with algorithm identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// Algorithm identifier (0x01 = Ed25519).
    pub algorithm: u8,
    /// Algorithm-specific signature data (64 bytes for Ed25519).
    pub sig: [u8; 64],
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            algorithm: ALGORITHM_ED25519,
            sig: [0u8; 64],
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("algorithm", &self.algorithm)
            .field(
                "sig",
                &format_args!("[{:02x}{:02x}...]", self.sig[0], self.sig[1]),
            )
            .finish()
    }
}

// Pulse flags byte layout:
// - bit 0: has_parent
// - bit 1: need_pubkey
// - bit 2: has_pubkey
// - bit 3: unstable (shopping for parent)
// - bits 4-7: child_count (0-12, max MAX_CHILDREN)
pub(crate) const PULSE_FLAG_HAS_PARENT: u8 = 0x01;
pub(crate) const PULSE_FLAG_NEED_PUBKEY: u8 = 0x02;
pub(crate) const PULSE_FLAG_HAS_PUBKEY: u8 = 0x04;
pub(crate) const PULSE_FLAG_UNSTABLE: u8 = 0x08;
pub(crate) const PULSE_CHILD_COUNT_SHIFT: u8 = 4;

/// Periodic broadcast message for tree maintenance.
///
/// Uses keyspace-based addressing where each node owns a range [keyspace_lo, keyspace_hi).
#[derive(Clone, Debug)]
pub struct Pulse {
    /// Node's unique identifier.
    pub node_id: NodeId,
    /// Packed flags byte (has_parent, need_pubkey, has_pubkey, unstable, child_count).
    pub flags: u8,
    /// Truncated hash of parent (None if root).
    pub parent_hash: Option<IdHash>,
    /// Truncated hash of root node.
    pub root_hash: IdHash,
    /// Distance from root (0 = root). No protocol limit; bounded by TTL and physics.
    pub depth: u32,
    /// Maximum depth in subtree rooted at this node. No protocol limit.
    pub max_depth: u32,
    /// Size of subtree rooted at this node.
    pub subtree_size: u32,
    /// Total size of the tree.
    pub tree_size: u32,
    /// Start of owned keyspace range.
    pub keyspace_lo: u32,
    /// End of owned keyspace range (exclusive).
    pub keyspace_hi: u32,
    /// Optional public key (included when neighbors need it).
    pub pubkey: Option<PublicKey>,
    /// List of (4-byte hash, subtree_size) for each child, sorted by hash.
    pub children: ChildrenList,
    /// Ed25519 signature over all fields.
    pub signature: Signature,
}

impl Pulse {
    /// Check if this pulse indicates the node has a parent.
    pub fn has_parent(&self) -> bool {
        self.flags & PULSE_FLAG_HAS_PARENT != 0
    }

    /// Check if this node needs public keys from neighbors.
    pub fn need_pubkey(&self) -> bool {
        self.flags & PULSE_FLAG_NEED_PUBKEY != 0
    }

    /// Check if this pulse includes a public key.
    pub fn has_pubkey(&self) -> bool {
        self.flags & PULSE_FLAG_HAS_PUBKEY != 0
    }

    /// Check if this node is unstable (shopping for parent).
    pub fn is_unstable(&self) -> bool {
        self.flags & PULSE_FLAG_UNSTABLE != 0
    }

    /// Get the child count from flags.
    pub fn child_count(&self) -> u8 {
        self.flags >> PULSE_CHILD_COUNT_SHIFT
    }

    /// Build flags byte from components.
    pub fn build_flags(
        has_parent: bool,
        need_pubkey: bool,
        has_pubkey: bool,
        unstable: bool,
        child_count: u8,
    ) -> u8 {
        let mut flags = 0u8;
        if has_parent {
            flags |= PULSE_FLAG_HAS_PARENT;
        }
        if need_pubkey {
            flags |= PULSE_FLAG_NEED_PUBKEY;
        }
        if has_pubkey {
            flags |= PULSE_FLAG_HAS_PUBKEY;
        }
        if unstable {
            flags |= PULSE_FLAG_UNSTABLE;
        }
        flags |= (child_count.min(16)) << PULSE_CHILD_COUNT_SHIFT;
        flags
    }
}

impl Default for Pulse {
    fn default() -> Self {
        Self {
            node_id: [0u8; 16],
            flags: 0,
            parent_hash: None,
            root_hash: [0u8; 4],
            depth: 0,
            max_depth: 0,
            subtree_size: 1,
            tree_size: 1,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: Vec::new(),
            signature: Signature::default(),
        }
    }
}

// Routed flags_and_type byte layout:
// - bits 0-3: msg_type (0-15)
// - bit 4: has_dest_hash
// - bit 5: has_src_addr
// - bit 6: has_src_pubkey
// - bit 7: reserved
pub(crate) const ROUTED_MSG_TYPE_MASK: u8 = 0x0F;
pub(crate) const ROUTED_FLAG_HAS_DEST_HASH: u8 = 0x10;
pub(crate) const ROUTED_FLAG_HAS_SRC_ADDR: u8 = 0x20;
pub(crate) const ROUTED_FLAG_HAS_SRC_PUBKEY: u8 = 0x40;

/// Unicast routed message using keyspace addressing.
#[derive(Clone, Debug)]
pub struct Routed {
    /// Combined flags and message type byte.
    pub flags_and_type: u8,
    /// Truncated hash of intended next-hop forwarder (prevents amplification attacks).
    /// None until route is computed; always Some when encoded to wire.
    pub next_hop: Option<IdHash>,
    /// Destination keyspace address (u32).
    pub dest_addr: u32,
    /// Optional 4-byte hash of recipient for verification.
    pub dest_hash: Option<IdHash>,
    /// Optional source keyspace address (for replies).
    pub src_addr: Option<u32>,
    /// Source node identifier.
    pub src_node_id: NodeId,
    /// Optional source public key.
    pub src_pubkey: Option<PublicKey>,
    /// Time-to-live hop counter. Uses varint encoding on wire.
    pub ttl: u32,
    /// Actual hop count (increments at each hop, unlike TTL which decrements).
    /// Used for duplicate detection: same hops = retransmission, different = bounce-back.
    /// Not signed - varies at each hop like TTL.
    pub hops: u32,
    /// Type-specific payload.
    pub payload: Payload,
    /// Ed25519 signature (covers all fields except ttl and hops).
    pub signature: Signature,
}

impl Routed {
    /// Get the message type.
    pub fn msg_type(&self) -> u8 {
        self.flags_and_type & ROUTED_MSG_TYPE_MASK
    }

    /// Check if dest_hash is present.
    pub fn has_dest_hash(&self) -> bool {
        self.flags_and_type & ROUTED_FLAG_HAS_DEST_HASH != 0
    }

    /// Check if src_addr is present.
    pub fn has_src_addr(&self) -> bool {
        self.flags_and_type & ROUTED_FLAG_HAS_SRC_ADDR != 0
    }

    /// Check if src_pubkey is present.
    pub fn has_src_pubkey(&self) -> bool {
        self.flags_and_type & ROUTED_FLAG_HAS_SRC_PUBKEY != 0
    }

    /// Build flags_and_type byte from components.
    pub fn build_flags_and_type(
        msg_type: u8,
        has_dest_hash: bool,
        has_src_addr: bool,
        has_src_pubkey: bool,
    ) -> u8 {
        let mut flags = msg_type & ROUTED_MSG_TYPE_MASK;
        if has_dest_hash {
            flags |= ROUTED_FLAG_HAS_DEST_HASH;
        }
        if has_src_addr {
            flags |= ROUTED_FLAG_HAS_SRC_ADDR;
        }
        if has_src_pubkey {
            flags |= ROUTED_FLAG_HAS_SRC_PUBKEY;
        }
        flags
    }
}

// Manual impl to document that TTL=0 is intentional (real messages use create_routed())
#[allow(clippy::derivable_impls)]
impl Default for Routed {
    fn default() -> Self {
        Self {
            flags_and_type: 0,
            next_hop: None,
            dest_addr: 0,
            dest_hash: None,
            src_addr: None,
            src_node_id: [0u8; 16],
            src_pubkey: None,
            // TTL is computed dynamically from max(255, max_depth * 3) when creating messages.
            // Default to 0; real messages set TTL via create_routed().
            ttl: 0,
            hops: 0,
            payload: Vec::new(),
            signature: Signature::default(),
        }
    }
}

/// Maximum number of destinations in a Broadcast message.
pub const MAX_BROADCAST_DESTINATIONS: usize = 16;

/// Broadcast message for multi-destination delivery (e.g., backup publishing).
///
/// Unlike Routed messages which target a single keyspace address, Broadcast
/// messages are sent to a small set of specific neighbors identified by their
/// 4-byte child hashes.
#[derive(Clone, Debug, Default)]
pub struct Broadcast {
    /// Source node identifier.
    pub src_node_id: NodeId,
    /// Truncated hashes of designated recipients (max 16).
    pub destinations: Vec<IdHash>,
    /// Payload (first byte indicates type: DATA=0x00, BACKUP_PUBLISH=0x01).
    pub payload: Payload,
    /// Ed25519 signature over "BCAST:" || src_node_id || dest_count || destinations || payload.
    pub signature: Signature,
}

/// Location entry stored in the DHT.
#[derive(Clone, Debug)]
pub struct LocationEntry {
    /// Node whose location this is.
    pub node_id: NodeId,
    /// Node's public key.
    pub pubkey: PublicKey,
    /// Keyspace address (center of node's keyspace range).
    pub keyspace_addr: u32,
    /// Sequence number for replay protection.
    pub seq: u32,
    /// Replica index (0, 1, or 2).
    pub replica_index: u8,
    /// Signature over "LOC:" || node_id || keyspace_addr || seq.
    pub signature: Signature,
    /// Local timestamp when entry was received (for expiry).
    pub received_at: Timestamp,
    /// Hops when received (for rebalance, not transmitted).
    pub hops: u32,
}

/// Transport queue metrics for monitoring.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransportMetrics {
    /// Protocol messages successfully queued (Pulse, PUBLISH, LOOKUP, FOUND).
    pub protocol_sent: u64,
    /// Protocol messages dropped (queue full).
    pub protocol_dropped: u64,
    /// Protocol messages received (Pulse, PUBLISH, LOOKUP, FOUND).
    pub protocol_received: u64,
    /// Application messages successfully queued (DATA).
    pub app_sent: u64,
    /// Application messages dropped (queue full).
    pub app_dropped: u64,
    /// Application messages received (DATA).
    pub app_received: u64,
}

impl TransportMetrics {
    /// Create new zeroed metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total messages sent (protocol + app).
    pub fn total_sent(&self) -> u64 {
        self.protocol_sent + self.app_sent
    }

    /// Total messages dropped (protocol + app).
    pub fn total_dropped(&self) -> u64 {
        self.protocol_dropped + self.app_dropped
    }

    /// Total messages received (protocol + app).
    pub fn total_received(&self) -> u64 {
        self.protocol_received + self.app_received
    }
}

/// Events emitted by the node for application handling.
///
/// Note: Data received from other nodes is delivered via the `incoming()` channel
/// rather than as events. Use `node.incoming().receive().await` to receive data.
#[derive(Clone, Debug)]
pub enum Event {
    /// Lookup completed successfully.
    LookupComplete { node_id: NodeId, keyspace_addr: u32 },
    /// Lookup failed (all replicas exhausted).
    LookupFailed { node_id: NodeId },
    /// Tree structure changed.
    TreeChanged { new_root: IdHash, new_size: u32 },
    /// Fraud detected: parent claimed inflated tree size.
    FraudDetected {
        /// The parent node that was distrusted.
        parent: NodeId,
        /// Observed unique publishers.
        observed: u32,
        /// Expected unique publishers based on claimed subtree size.
        expected: u32,
    },
}

/// Error type for node operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Message exceeds MTU.
    MessageTooLarge,
    /// Outgoing queue is full.
    QueueFull,
    /// No route to destination.
    NoRoute,
    /// Lookup in progress.
    LookupPending,
    /// Too many pending operations.
    TooManyPending,
    /// Invalid message format.
    InvalidMessage,
    /// Signature verification failed.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MessageTooLarge => write!(f, "message too large"),
            Error::QueueFull => write!(f, "outgoing queue full"),
            Error::NoRoute => write!(f, "no route to destination"),
            Error::LookupPending => write!(f, "lookup already pending"),
            Error::TooManyPending => write!(f, "too many pending operations"),
            Error::InvalidMessage => write!(f, "invalid message format"),
            Error::InvalidSignature => write!(f, "invalid signature"),
        }
    }
}
