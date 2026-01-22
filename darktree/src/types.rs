//! Core types and constants for the darktree protocol.

use core::fmt;

// Memory bounds (kept as soft limits for validation)
pub const MAX_TREE_DEPTH: usize = 127; // TTL 255 / 2 for round-trip
pub const MAX_CHILDREN: usize = 16; // 4-bit nibble encoding limit
pub const MAX_NEIGHBORS: usize = 128;
pub const MAX_PUBKEY_CACHE: usize = 128;
pub const MAX_LOCATION_STORE: usize = 256;
pub const MAX_LOCATION_CACHE: usize = 64;
pub const MAX_PENDING_LOOKUPS: usize = 16;
pub const MAX_DISTRUSTED: usize = 64;
pub const MAX_PACKET_SIZE: usize = 255;
pub const MAX_PENDING_REQUESTS: usize = 16;
pub const MAX_PENDING_DATA: usize = 16;
pub const MAX_PENDING_PUBKEY: usize = 16; // Messages awaiting pubkey verification

// Protocol constants
pub const K_REPLICAS: usize = 3;
pub const DEFAULT_TTL: u8 = 255; // Max hops

// Timing constants (in seconds)
pub const MIN_PULSE_INTERVAL_SECS: u64 = 8;
pub const DEFAULT_PULSE_INTERVAL_SECS: u64 = 30;
pub const LOOKUP_TIMEOUT_SECS: u64 = 30;
pub const REQUEST_TIMEOUT_SECS: u64 = 30;
pub const MAX_RETRIES: u8 = 3;
pub const LOCATION_REFRESH_HOURS: u64 = 8;
pub const LOCATION_TTL_HOURS: u64 = 12;
pub const DISTRUST_TTL_HOURS: u64 = 24;
pub const REPUBLISH_JITTER_MS: u64 = 5000;

// Message types (0-3 valid; 4-255 dropped silently)
pub const MSG_PUBLISH: u8 = 0;
pub const MSG_LOOKUP: u8 = 1;
pub const MSG_FOUND: u8 = 2;
pub const MSG_DATA: u8 = 3;

// Algorithm identifiers
pub const ALGORITHM_ED25519: u8 = 0x01;

// Domain separation prefixes
pub const DOMAIN_PULSE: &[u8] = b"PULSE:";
pub const DOMAIN_ROUTE: &[u8] = b"ROUTE:";
pub const DOMAIN_LOC: &[u8] = b"LOC:";

/// 16-byte node identifier derived from public key hash.
pub type NodeId = [u8; 16];

/// 32-byte Ed25519 public key.
pub type PublicKey = [u8; 32];

/// 32-byte Ed25519 secret key (seed).
pub type SecretKey = [u8; 32];

/// Tree address type - path from root to node.
pub type TreeAddr = Vec<u8>;

/// Child prefix type for pulse messages.
pub type ChildPrefix = Vec<u8>;

/// Children list in pulse messages.
pub type ChildrenList = Vec<(ChildPrefix, u32)>;

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

/// Periodic broadcast message for tree maintenance.
#[derive(Clone, Debug)]
pub struct Pulse {
    /// Node's unique identifier.
    pub node_id: NodeId,
    /// Parent's node ID (None if root).
    pub parent_id: Option<NodeId>,
    /// Root of the tree this node belongs to.
    pub root_id: NodeId,
    /// Size of subtree rooted at this node.
    pub subtree_size: u32,
    /// Total size of the tree.
    pub tree_size: u32,
    /// Path from root to this node.
    pub tree_addr: TreeAddr,
    /// Whether this node needs public keys from neighbors.
    pub need_pubkey: bool,
    /// Optional public key (included when neighbors need it).
    pub pubkey: Option<PublicKey>,
    /// Prefix length for children identification.
    pub child_prefix_len: u8,
    /// List of (prefix, subtree_size) for each child.
    pub children: ChildrenList,
    /// Ed25519 signature over all fields.
    pub signature: Signature,
}

impl Default for Pulse {
    fn default() -> Self {
        Self {
            node_id: [0u8; 16],
            parent_id: None,
            root_id: [0u8; 16],
            subtree_size: 1,
            tree_size: 1,
            tree_addr: Vec::new(),
            need_pubkey: false,
            pubkey: None,
            child_prefix_len: 0,
            children: Vec::new(),
            signature: Signature::default(),
        }
    }
}

/// Unicast routed message.
#[derive(Clone, Debug)]
pub struct Routed {
    /// Destination tree address.
    pub dest_addr: TreeAddr,
    /// Specific destination node ID (None for keyspace routing).
    pub dest_node_id: Option<NodeId>,
    /// Source tree address (for replies, optional for one-way messages like PUBLISH).
    pub src_addr: Option<TreeAddr>,
    /// Source node identifier.
    pub src_node_id: NodeId,
    /// Message type (PUBLISH, LOOKUP, FOUND, DATA).
    pub msg_type: u8,
    /// Time-to-live hop counter.
    pub ttl: u8,
    /// Type-specific payload.
    pub payload: Payload,
    /// Ed25519 signature (covers all fields except ttl).
    pub signature: Signature,
}

impl Default for Routed {
    fn default() -> Self {
        Self {
            dest_addr: Vec::new(),
            dest_node_id: None,
            src_addr: None,
            src_node_id: [0u8; 16],
            msg_type: 0,
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
    /// Current tree address.
    pub tree_addr: TreeAddr,
    /// Sequence number for replay protection (varint encoded on wire).
    pub seq: u32,
    /// Signature over "LOC:" || node_id || tree_addr || seq.
    pub signature: Signature,
    /// Local timestamp when entry was received (for expiry).
    pub received_at_secs: u64,
}

/// Events emitted by the node for application handling.
#[derive(Clone, Debug)]
pub enum Event {
    /// Data received from another node.
    DataReceived { from: NodeId, data: Payload },
    /// Lookup completed successfully.
    LookupComplete {
        node_id: NodeId,
        tree_addr: TreeAddr,
    },
    /// Lookup failed (all replicas exhausted).
    LookupFailed { node_id: NodeId },
    /// Tree structure changed.
    TreeChanged { new_root: NodeId, new_size: u32 },
}

/// Error type for node operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<T> {
    /// Transport error.
    Transport(T),
    /// Message exceeds MTU.
    MessageTooLarge,
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

impl<T: fmt::Debug> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "transport error: {:?}", e),
            Error::MessageTooLarge => write!(f, "message too large"),
            Error::NoRoute => write!(f, "no route to destination"),
            Error::LookupPending => write!(f, "lookup already pending"),
            Error::TooManyPending => write!(f, "too many pending operations"),
            Error::InvalidMessage => write!(f, "invalid message format"),
            Error::InvalidSignature => write!(f, "invalid signature"),
        }
    }
}
