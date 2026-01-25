//! Core types and constants for the darktree protocol.

use alloc::vec::Vec;
use core::fmt;

use crate::time::{Duration, Timestamp};

// Protocol limits (not configurable via NodeConfig)
#[allow(dead_code)] // Reserved for future depth validation
pub(crate) const MAX_TREE_DEPTH: usize = 127; // TTL 255 / 2 for round-trip
pub const MAX_CHILDREN: usize = 12; // Guarantees worst-case Pulse fits in 252 bytes
pub const MAX_PACKET_SIZE: usize = 255;
/// Recently forwarded entries expire after 300τ to allow for slow multi-hop ACKs.
/// On LoRa (τ=6.7s) this is ~33 minutes; on UDP (τ=100ms) this is 30 seconds.
pub(crate) const RECENTLY_FORWARDED_TTL_MULTIPLIER: u64 = 300;

// Protocol constants
pub const K_REPLICAS: usize = 3;
pub const DEFAULT_TTL: u8 = 255; // Max hops

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

/// 16-byte node identifier derived from public key hash.
pub type NodeId = [u8; 16];

/// 32-byte Ed25519 public key.
pub type PublicKey = [u8; 32];

/// 32-byte Ed25519 secret key (seed).
pub type SecretKey = [u8; 32];

/// 4-byte truncated hash for child identification and verification.
pub type ChildHash = [u8; 4];

/// Children list in pulse messages: (4-byte hash, subtree_size).
pub type ChildrenList = Vec<(ChildHash, u32)>;

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
// - bits 3-7: child_count (0-12, max MAX_CHILDREN)
pub(crate) const PULSE_FLAG_HAS_PARENT: u8 = 0x01;
pub(crate) const PULSE_FLAG_NEED_PUBKEY: u8 = 0x02;
pub(crate) const PULSE_FLAG_HAS_PUBKEY: u8 = 0x04;
pub(crate) const PULSE_CHILD_COUNT_SHIFT: u8 = 3;

/// Periodic broadcast message for tree maintenance.
///
/// Uses keyspace-based addressing where each node owns a range [keyspace_lo, keyspace_hi).
#[derive(Clone, Debug)]
pub struct Pulse {
    /// Node's unique identifier.
    pub node_id: NodeId,
    /// Packed flags byte (has_parent, need_pubkey, has_pubkey, child_count).
    pub flags: u8,
    /// Truncated hash of parent (None if root).
    pub parent_hash: Option<ChildHash>,
    /// Truncated hash of root node.
    pub root_hash: ChildHash,
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

    /// Get the child count from flags.
    pub fn child_count(&self) -> u8 {
        self.flags >> PULSE_CHILD_COUNT_SHIFT
    }

    /// Build flags byte from components.
    pub fn build_flags(
        has_parent: bool,
        need_pubkey: bool,
        has_pubkey: bool,
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
    /// Destination keyspace address (u32).
    pub dest_addr: u32,
    /// Optional 4-byte hash of recipient for verification.
    pub dest_hash: Option<ChildHash>,
    /// Optional source keyspace address (for replies).
    pub src_addr: Option<u32>,
    /// Source node identifier.
    pub src_node_id: NodeId,
    /// Optional source public key.
    pub src_pubkey: Option<PublicKey>,
    /// Time-to-live hop counter.
    pub ttl: u8,
    /// Type-specific payload.
    pub payload: Payload,
    /// Ed25519 signature (covers all fields except ttl).
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

impl Default for Routed {
    fn default() -> Self {
        Self {
            flags_and_type: 0,
            dest_addr: 0,
            dest_hash: None,
            src_addr: None,
            src_node_id: [0u8; 16],
            src_pubkey: None,
            ttl: DEFAULT_TTL,
            payload: Vec::new(),
            signature: Signature::default(),
        }
    }
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
    TreeChanged { new_root: ChildHash, new_size: u32 },
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
