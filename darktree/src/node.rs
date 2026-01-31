//! Node implementation - the main protocol state machine.
//!
//! The Node struct holds all protocol state and provides an async `run()` method
//! that drives the protocol. It is fully event-driven:
//! - Incoming transport messages trigger protocol handling
//! - Application sends via outgoing channel trigger routing/lookup
//! - Internal timers trigger Pulse broadcasts
//!
//! # Example (node creation and state)
//!
//! ```
//! use darktree::{Node, DefaultConfig};
//! use darktree::traits::test_impls::{MockTransport, FastTestCrypto, MockRandom, MockClock};
//!
//! let node = Node::<_, _, _, _, DefaultConfig>::new(
//!     MockTransport::new(),
//!     FastTestCrypto::new(0),
//!     MockRandom::new(),
//!     MockClock::new(),
//! );
//!
//! // Query node state
//! let node_id = node.node_id();
//! let pubkey = node.pubkey();
//! let tau = node.tau(); // Bandwidth-aware time unit
//!
//! assert!(node.is_root());
//! assert_eq!(node.tree_size(), 1);
//! ```
//!
//! # Example (async integration)
//!
//! ```text
//! let node = Node::new(transport, crypto, random, clock);
//!
//! // Spawn the node's run loop
//! spawn(async move {
//!     node.run().await;
//! });
//!
//! // Send data to another node
//! node.outgoing().send(OutgoingData { target, payload }).await;
//!
//! // Receive data from other nodes
//! let data = node.incoming().receive().await;
//! ```

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::marker::PhantomData;
use hashbrown::HashMap;

use crate::children::ChildrenStore;
use crate::collections::{ShrinkingHashMap, ShrinkingVecDeque};
use crate::config::{DefaultConfig, NodeConfig};
use crate::fraud::{FraudDetection, HllSecretKey};
use crate::time::{Duration, Timestamp};
use crate::traits::{Clock, Crypto, DynamicChannel, IncomingData, OutgoingData, Random, Transport};
use crate::tree::FastDivisor;
use crate::types::{
    Event, IdHash, LocationEntry, NodeId, PublicKey, Routed, SecretKey, TransportMetrics,
    RECENTLY_FORWARDED_TTL_MULTIPLIER,
};

/// Timing, signal, and tree information for a neighbor.
#[derive(Clone, Debug)]
pub(crate) struct NeighborTiming {
    /// Last time we received a Pulse from this neighbor.
    pub last_seen: Timestamp,
    /// Last observed signal strength in dBm (if available).
    pub rssi: Option<i16>,
    /// Root hash of the neighbor's tree.
    pub root_hash: IdHash,
    /// Size of the neighbor's tree.
    pub tree_size: u32,
    /// Neighbor's keyspace range (lo, hi).
    pub keyspace_range: (u32, u32),
    /// Number of children the neighbor has.
    pub children_count: u8,
    /// Neighbor's depth in tree (0 = root).
    pub depth: u8,
    /// Maximum depth in neighbor's subtree.
    pub max_depth: u8,
    /// Whether neighbor is shopping for parent.
    pub unstable: bool,
}

/// Pending lookup state.
#[derive(Clone, Debug)]
pub(crate) struct PendingLookup {
    /// Current replica index being tried (0, 1, or 2).
    pub replica_index: usize,
    /// When the lookup started.
    #[allow(dead_code)] // Reserved for future debugging/metrics
    pub started_at: Timestamp,
    /// When current replica query was sent.
    pub last_query_at: Timestamp,
}

/// Context for fraud detection when joining a tree.
#[derive(Clone, Copy, Debug)]
pub(crate) struct JoinContext {
    /// Parent node when we joined.
    pub parent_at_join: NodeId,
    /// Time when we joined.
    #[allow(dead_code)] // Reserved for fraud detection timing
    pub join_time: Timestamp,
}

// Type aliases for collections
// Uses ShrinkingHashMap for collections that drain during normal operation.
pub(crate) type NeighborTimingMap = ShrinkingHashMap<NodeId, NeighborTiming>;
/// Pubkey cache: node_id -> (pubkey, last_used).
/// Not shrinking - entries only evicted when full, not naturally removed.
pub(crate) type PubkeyCache = HashMap<NodeId, (PublicKey, Timestamp)>;
pub(crate) type NeedPubkeySet = BTreeSet<NodeId>;
pub(crate) type NeighborsNeedPubkeySet = BTreeSet<NodeId>;
/// Location store: (node_id, replica_index) -> LocationEntry.
/// Keyed by both node_id AND replica_index to allow storing multiple replicas
/// for the same publisher when a node temporarily owns multiple replica addresses
/// during tree formation.
pub(crate) type LocationStore = ShrinkingHashMap<(NodeId, u8), LocationEntry>;
/// Location cache: node_id -> (keyspace_addr, last_used).
pub(crate) type LocationCache = ShrinkingHashMap<NodeId, (u32, Timestamp)>;
pub(crate) type PendingLookupMap = ShrinkingHashMap<NodeId, PendingLookup>;
pub(crate) type PendingDataMap = ShrinkingHashMap<NodeId, Vec<u8>>;
pub(crate) type DistrustedMap = ShrinkingHashMap<NodeId, Timestamp>;
/// Messages awaiting pubkey for a specific node_id (keyed by the node whose pubkey is needed).
pub(crate) type PendingPubkeyMap = ShrinkingHashMap<NodeId, VecDeque<Routed>>;

/// 4-byte hash used for ACK identification.
pub(crate) type AckHash = [u8; 4];

/// Pending ACK entry for link-layer reliability.
///
/// Tracks a message awaiting acknowledgment with exponential backoff retry.
#[derive(Clone, Debug)]
pub(crate) struct PendingAck {
    /// Original encoded message bytes for retransmission.
    pub original_bytes: Vec<u8>,
    /// Priority for retransmission.
    pub priority: crate::types::Priority,
    /// Number of retries attempted so far.
    pub retries: u8,
    /// Timestamp when next retry should occur.
    pub next_retry_at: Timestamp,
    /// TTL value when message was sent (for implicit ACK verification).
    pub sent_ttl: u8,
}

/// Map of pending ACKs keyed by message hash.
pub(crate) type PendingAckMap = ShrinkingHashMap<AckHash, PendingAck>;

/// Map of recently forwarded message hashes for duplicate detection.
/// Stores (timestamp, hops, seen_count) to distinguish retransmissions from alternate paths
/// and track bounce-back occurrences for exponential backoff.
/// hops is u32 because it's a varint on the wire.
/// Uses ShrinkingHashMap to reclaim memory when traffic subsides.
pub(crate) type RecentlyForwardedMap = ShrinkingHashMap<AckHash, (Timestamp, u32, u8)>;

/// Backup entry for DHT redundancy.
///
/// Stores a location entry received via BACKUP_PUBLISH, along with metadata
/// about which storage node we're backing up for.
#[derive(Clone, Debug)]
pub(crate) struct BackupEntry {
    /// The location entry being backed up.
    pub entry: LocationEntry,
    /// Child hash of the storage node we're backing up for.
    pub backed_up_for: IdHash,
    /// When this backup was received.
    pub received_at: Timestamp,
}

/// Backup store: (node_id, replica_index) -> BackupEntry.
/// Keyed the same as LocationStore to allow efficient lookup and deduplication.
pub(crate) type BackupStore = ShrinkingHashMap<(NodeId, u8), BackupEntry>;

/// Delayed forward entry for bounce-back dampening.
///
/// When a message bounces back during tree restructuring, it's queued here
/// with exponential backoff to give the tree time to stabilize.
#[derive(Clone, Debug)]
pub(crate) struct DelayedForward {
    /// The message to forward (with TTL already decremented once).
    pub msg: Routed,
    /// Number of times this message has bounced back.
    /// Used to calculate backoff even if recently_forwarded entry is evicted.
    pub seen_count: u8,
    /// When the delayed forward should fire.
    pub scheduled_time: Timestamp,
}

/// A routed message waiting for a neighbor to claim its dest_addr.
///
/// Used by root nodes when `best_next_hop()` returns None and there's no parent.
/// Messages are retried when a neighbor pulses with an updated keyspace range.
#[derive(Clone, Debug)]
pub(crate) struct PendingRouted {
    /// The routed message waiting to be sent.
    pub msg: Routed,
    /// When the message was queued.
    pub queued_at: Timestamp,
}

/// Map of delayed forwards keyed by ack_hash.
/// At most one delayed forward per message hash (newer bounces extend the delay).
/// Uses ShrinkingHashMap to reclaim memory when bounce-back traffic ends.
pub(crate) type DelayedForwardMap = ShrinkingHashMap<AckHash, DelayedForward>;

/// The main protocol node.
///
/// Generic over:
/// - `T`: Transport implementation
/// - `Cr`: Crypto implementation
/// - `R`: Random number generator
/// - `Clk`: Clock/timer implementation
/// - `Cfg`: Memory configuration (defaults to `DefaultConfig`)
///
/// The node is fully event-driven. Call `run()` to start the main loop.
pub struct Node<T, Cr, R, Clk, Cfg: NodeConfig = DefaultConfig> {
    // Dependencies (injected)
    transport: T,
    crypto: Cr,
    random: R,
    clock: Clk,

    // Config phantom
    _config: PhantomData<Cfg>,

    // Application-level channels (sizes from Cfg at construction time)
    app_incoming: DynamicChannel<IncomingData>,
    app_outgoing: DynamicChannel<OutgoingData>,
    events: DynamicChannel<Event>,

    // Identity
    node_id: NodeId,
    pubkey: PublicKey,
    secret: SecretKey,

    // Tree position (keyspace-based)
    parent: Option<NodeId>,
    pending_parent: Option<(NodeId, u8)>, // (candidate, pulses_waited)
    parent_rejection_count: u8,           // consecutive pulses from parent not including us
    root_hash: IdHash,
    tree_size: u32,
    subtree_size: u32,
    keyspace_lo: u32,
    keyspace_hi: u32,
    depth: u8,     // Distance from root (0 = root)
    max_depth: u8, // Max depth in subtree rooted at this node

    // Neighbors
    children: ChildrenStore,
    neighbor_times: NeighborTimingMap,

    // Caches
    pubkey_cache: PubkeyCache,
    need_pubkey: NeedPubkeySet,
    neighbors_need_pubkey: NeighborsNeedPubkeySet,
    location_store: LocationStore,
    location_cache: LocationCache,
    backup_store: BackupStore,

    // Pending operations
    pending_lookups: PendingLookupMap,
    /// Data waiting for lookup completion. Implicitly bounded by MAX_PENDING_LOOKUPS
    /// since entries are only added when a lookup is initiated, and removed when
    /// the lookup completes or times out.
    pending_data: PendingDataMap,
    pending_pubkey: PendingPubkeyMap,

    // Fraud detection
    join_context: Option<JoinContext>,
    distrusted: DistrustedMap,
    fraud_detection: FraudDetection,
    hll_secret_key: HllSecretKey,

    // Link-layer reliability
    pending_acks: PendingAckMap,
    recently_forwarded: RecentlyForwardedMap,
    delayed_forwards: DelayedForwardMap,

    // Pending routed messages (root nodes only)
    // Uses ShrinkingVecDeque to reclaim memory when churn subsides.
    pending_routed: ShrinkingVecDeque<PendingRouted>,

    // Scheduling
    last_pulse: Option<Timestamp>,
    last_pulse_size: usize,
    next_publish: Option<Timestamp>,
    next_rebalance: Option<Timestamp>,
    next_pending_retry: Option<Timestamp>,
    location_seq: u32,
    proactive_pulse_pending: Option<Timestamp>,
    shopping_deadline: Option<Timestamp>,

    // Metrics
    metrics: TransportMetrics,

    // Cached computations (avoid u64 division on 32-bit MCUs)
    cached_tau_ms: u64,
    /// Cached fast divisor for bandwidth (bw is constant for node lifetime).
    cached_bw_divisor: Option<FastDivisor>,

    // Debug emitter callback (only with "debug" feature)
    #[cfg(feature = "debug")]
    debug_emitter: core::cell::RefCell<Option<alloc::boxed::Box<dyn crate::debug::DebugEmitter>>>,
}

#[cfg(feature = "debug")]
impl<T, Cr, R, Clk, Cfg: NodeConfig> crate::debug::HasDebugEmitter for Node<T, Cr, R, Clk, Cfg> {
    fn debug_emitter(
        &self,
    ) -> &core::cell::RefCell<Option<alloc::boxed::Box<dyn crate::debug::DebugEmitter>>> {
        &self.debug_emitter
    }
}

impl<T, Cr, R, Clk, Cfg> Node<T, Cr, R, Clk, Cfg>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
    Cfg: NodeConfig,
{
    /// Create a new node with a fresh identity.
    pub fn new(transport: T, mut crypto: Cr, random: R, clock: Clk) -> Self {
        let (pubkey, secret) = crypto.generate_keypair();
        let node_id = crypto.node_id_from_pubkey(&pubkey);

        Self::with_identity(transport, crypto, random, clock, node_id, pubkey, secret)
    }

    /// Create a node with an existing identity.
    pub fn with_identity(
        transport: T,
        crypto: Cr,
        random: R,
        clock: Clk,
        node_id: NodeId,
        pubkey: PublicKey,
        secret: SecretKey,
    ) -> Self {
        // Compute root_hash from our node_id (we are initially root of our own tree)
        let root_hash = Self::compute_id_hash_static(&crypto, &node_id);

        // Cache tau and FastDivisor(bw) to avoid u64 division on 32-bit MCUs at runtime.
        // Note: tau is computed once at initialization. If transport bandwidth
        // changes dynamically, create a new Node instance.
        let (cached_tau_ms, cached_bw_divisor) = match transport.bw() {
            Some(bw) if bw > 0 => {
                let ms = (transport.mtu() as u64 * 1000) / bw as u64;
                (
                    ms.max(crate::types::MIN_TAU_MS),
                    Some(FastDivisor::new(bw as u64)),
                )
            }
            _ => (crate::types::MIN_TAU_MS, None),
        };

        // Derive HLL secret key from identity for deterministic behavior.
        // Hash(secret || "hll_key") ensures uniqueness per identity.
        let hll_secret_key = {
            let mut data = [0u8; 39]; // 32 + 7
            data[..32].copy_from_slice(&secret);
            data[32..].copy_from_slice(b"hll_key");
            let hash = crypto.hash(&data);
            let mut key = [0u8; 16];
            key.copy_from_slice(&hash[..16]);
            key
        };

        Self {
            transport,
            crypto,
            random,
            clock,

            _config: PhantomData,

            app_incoming: DynamicChannel::new(Cfg::APP_QUEUE_SIZE),
            app_outgoing: DynamicChannel::new(Cfg::APP_QUEUE_SIZE),
            events: DynamicChannel::new(Cfg::EVENT_QUEUE_SIZE),

            node_id,
            pubkey,
            secret,

            parent: None,
            pending_parent: None,
            parent_rejection_count: 0,
            root_hash,
            tree_size: 1,
            subtree_size: 1,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            depth: 0,
            max_depth: 0,

            children: ChildrenStore::new(),
            neighbor_times: ShrinkingHashMap::with_max_capacity(Cfg::MAX_NEIGHBORS),

            pubkey_cache: HashMap::new(),
            need_pubkey: BTreeSet::new(),
            neighbors_need_pubkey: BTreeSet::new(),
            location_store: ShrinkingHashMap::with_max_capacity(Cfg::MAX_LOCATION_STORE),
            location_cache: ShrinkingHashMap::with_max_capacity(Cfg::MAX_LOCATION_CACHE),
            backup_store: ShrinkingHashMap::with_max_capacity(Cfg::MAX_BACKUP_STORE),

            pending_lookups: ShrinkingHashMap::with_max_capacity(Cfg::MAX_PENDING_LOOKUPS),
            pending_data: ShrinkingHashMap::with_max_capacity(Cfg::MAX_PENDING_DATA),
            pending_pubkey: ShrinkingHashMap::with_max_capacity(Cfg::MAX_PENDING_PUBKEY_NODES),

            join_context: None,
            distrusted: ShrinkingHashMap::with_max_capacity(Cfg::MAX_DISTRUSTED),
            fraud_detection: FraudDetection::new(),
            hll_secret_key,

            pending_acks: ShrinkingHashMap::with_max_capacity(Cfg::MAX_PENDING_ACKS),
            recently_forwarded: ShrinkingHashMap::with_max_capacity(Cfg::MAX_RECENTLY_FORWARDED),
            delayed_forwards: ShrinkingHashMap::with_max_capacity(Cfg::MAX_DELAYED_FORWARDS),

            pending_routed: ShrinkingVecDeque::with_max_capacity(Cfg::MAX_PENDING_ROUTED),

            last_pulse: None,
            last_pulse_size: 0,
            next_publish: None,
            next_rebalance: None,
            next_pending_retry: None,
            location_seq: 0,
            proactive_pulse_pending: None,
            shopping_deadline: None,

            metrics: TransportMetrics::new(),

            cached_tau_ms,
            cached_bw_divisor,

            #[cfg(feature = "debug")]
            debug_emitter: core::cell::RefCell::new(None),
        }
    }

    /// Compute the 4-byte hash of a node_id.
    fn compute_id_hash_static(crypto: &Cr, node_id: &NodeId) -> IdHash {
        let hash = crypto.hash(node_id);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Compute the 4-byte hash of a node_id.
    pub(crate) fn compute_id_hash(&self, node_id: &NodeId) -> IdHash {
        Self::compute_id_hash_static(&self.crypto, node_id)
    }

    /// Get this node's identity.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get this node's public key.
    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    /// Get current keyspace range.
    pub fn keyspace_range(&self) -> (u32, u32) {
        (self.keyspace_lo, self.keyspace_hi)
    }

    /// Get this node's keyspace address (center of owned slice).
    ///
    /// Returns the midpoint of the slice this node actually owns, not the full
    /// keyspace range. The owned slice is 1/subtree_size of the total range.
    pub fn my_address(&self) -> u32 {
        debug_assert!(self.subtree_size > 0, "subtree_size must be at least 1");
        let lo = self.keyspace_lo as u64;
        let hi = self.keyspace_hi as u64;
        let range = hi - lo;
        let own_slice_size = range / (self.subtree_size as u64);
        // Midpoint of owned slice: lo + own_slice_size / 2
        (lo + own_slice_size / 2) as u32
    }

    /// Check if this node owns a keyspace location.
    ///
    /// A node only owns its own slice of keyspace, not the ranges delegated to children.
    /// The node's own slice is 1/subtree_size of the total range, starting at keyspace_lo.
    pub fn owns_key(&self, key: u32) -> bool {
        debug_assert!(self.subtree_size > 0, "subtree_size must be at least 1");
        let lo = self.keyspace_lo as u64;
        let hi = self.keyspace_hi as u64;
        let range = hi - lo;
        let own_slice_size = range / (self.subtree_size as u64);
        let own_hi = lo + own_slice_size;

        (key as u64) >= lo && (key as u64) < own_hi
    }

    /// Get current tree size.
    pub fn tree_size(&self) -> u32 {
        self.tree_size
    }

    /// Get current subtree size.
    pub fn subtree_size(&self) -> u32 {
        self.subtree_size
    }

    /// Get the root hash.
    pub fn root_hash(&self) -> &IdHash {
        &self.root_hash
    }

    /// Check if this node is the root.
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Get the parent node ID, if any.
    pub fn parent_id(&self) -> Option<NodeId> {
        self.parent
    }

    /// Get the number of children.
    pub fn children_count(&self) -> usize {
        self.children.len()
    }

    /// Get the number of known neighbors.
    pub fn neighbor_count(&self) -> usize {
        self.neighbor_times.len()
    }

    /// Channel for receiving data from other nodes.
    ///
    /// Application reads DATA messages from here.
    pub fn incoming(&self) -> &DynamicChannel<IncomingData> {
        &self.app_incoming
    }

    /// Channel for sending data to other nodes.
    ///
    /// Application sends DATA messages here. The node handles
    /// routing/lookup automatically.
    pub fn outgoing(&self) -> &DynamicChannel<OutgoingData> {
        &self.app_outgoing
    }

    /// Channel for protocol events.
    ///
    /// Application receives events like TreeChanged, LookupComplete, etc.
    pub fn events(&self) -> &DynamicChannel<Event> {
        &self.events
    }

    /// Set the debug emitter callback (only with "debug" feature).
    #[cfg(feature = "debug")]
    pub fn set_debug_emitter(&self, emitter: alloc::boxed::Box<dyn crate::debug::DebugEmitter>) {
        *self.debug_emitter.borrow_mut() = Some(emitter);
    }

    /// Get the transport reference.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Get tau: the bandwidth-aware time unit.
    /// tau = MTU / bandwidth (with MIN_TAU_MS floor)
    /// Cached at initialization to avoid u64 division on 32-bit MCUs.
    pub fn tau(&self) -> Duration {
        Duration::from_millis(self.cached_tau_ms)
    }

    /// Lookup timeout: τ × (3 + 3 × max_tree_depth)
    /// Scales with tree depth to allow round-trip propagation.
    /// For LoRa (τ=6.7s, depth=10): ~4 minutes
    /// For UDP (τ=0.1s, depth=10): ~3.3 seconds
    pub(crate) fn lookup_timeout(&self) -> Duration {
        let multiplier = 3 + 3 * self.max_depth as u64;
        self.tau() * multiplier
    }

    /// Get the crypto reference.
    pub fn crypto(&self) -> &Cr {
        &self.crypto
    }

    /// Get the current timestamp from the clock.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Get a reference to the clock.
    /// Useful for simulation where the clock time needs to be updated externally.
    pub fn clock(&self) -> &Clk {
        &self.clock
    }

    /// Get transport metrics for monitoring.
    ///
    /// Returns counters for sent/dropped/received messages, split by
    /// protocol (Pulse, PUBLISH, LOOKUP, FOUND) and application (DATA).
    pub fn metrics(&self) -> &TransportMetrics {
        &self.metrics
    }

    /// Initialize the node for operation.
    ///
    /// This sends the first pulse and starts the discovery phase.
    /// Call this before using `handle_timer` and `handle_transport_rx` for
    /// simulation or testing. The async `run()` method calls this automatically.
    pub fn initialize(&mut self, now: Timestamp) {
        // Send first pulse immediately
        self.send_pulse(now);

        // Start shopping phase if orphan (no parent, no children)
        // Shopping lasts 3τ to collect neighbor Pulses before selecting parent
        if self.parent.is_none() && self.children.is_empty() {
            self.start_shopping(now);
        }
    }

    /// Run the node's main loop.
    ///
    /// This is fully event-driven and runs forever. It handles:
    /// - Incoming transport messages (protocol handling)
    /// - Outgoing application data (routing/lookup)
    /// - Periodic Pulse broadcasts
    /// - Timeouts and maintenance
    ///
    /// Call this from an async task/executor.
    pub async fn run(&mut self) -> ! {
        use embassy_futures::select::{select3, Either3};

        // Initialize (sends first pulse, starts discovery)
        let now = self.clock.now();
        self.initialize(now);

        loop {
            // Calculate when we need to wake for timer work
            let next_pulse_time = self.next_pulse_time();
            let next_timeout = self.next_timeout_time();
            let mut timer_wake = match (next_pulse_time, next_timeout) {
                (Some(p), Some(t)) => p.min(t),
                (Some(p), None) => p,
                (None, Some(t)) => t,
                (None, None) => self.clock.now() + Duration::from_secs(60),
            };
            // Include discovery deadline in timer wake
            if let Some(deadline) = self.shopping_deadline {
                timer_wake = timer_wake.min(deadline);
            }
            // Include scheduled work (rebalance, pending retry)
            if let Some(t) = self.next_rebalance {
                timer_wake = timer_wake.min(t);
            }
            if let Some(t) = self.next_pending_retry {
                timer_wake = timer_wake.min(t);
            }

            // Wait for: incoming message, outgoing app data, or timer
            let result = select3(
                self.transport.incoming().receive(),
                self.app_outgoing.receive(),
                self.clock.sleep_until(timer_wake),
            )
            .await;

            match result {
                Either3::First(msg) => {
                    let now = self.clock.now();
                    self.handle_transport_rx(&msg.data, msg.rssi, now);
                }
                Either3::Second(data) => {
                    let now = self.clock.now();
                    self.handle_app_send(data, now);
                }
                Either3::Third(()) => {
                    let now = self.clock.now();
                    self.handle_timer(now);
                }
            }
        }
    }

    /// Calculate next pulse time.
    ///
    /// Returns None if no pulse has been sent yet (send immediately).
    /// With bandwidth limits, interval is extended to keep pulse within budget.
    /// Proactive pulses are batched (1-2τ delay) but still respect bandwidth budget.
    fn next_pulse_time(&self) -> Option<Timestamp> {
        use crate::types::PULSE_BW_DIVISOR;

        let last = self.last_pulse?;

        // Minimum interval between pulses is 2*tau
        let min_interval = self.tau() * 2;
        let interval = match &self.cached_bw_divisor {
            Some(divisor) => {
                // Interval to stay within pulse bandwidth budget.
                // Uses cached FastDivisor to avoid u64 software division on 32-bit MCUs.
                // secs = pulse_size * divisor / bw
                let numerator = self.last_pulse_size as u64 * PULSE_BW_DIVISOR as u64;
                let secs = divisor.div(numerator);
                Duration::from_secs(secs).max(min_interval)
            }
            None => min_interval,
        };

        let budget_time = last + interval;

        // Proactive pulse can trigger early, but must still respect bandwidth budget.
        // Use max to ensure we don't send before budget_time.
        let next = match self.proactive_pulse_pending {
            Some(proactive) => budget_time.max(proactive),
            None => budget_time,
        };
        Some(next)
    }

    /// Calculate next timeout time based on pending operations.
    ///
    /// Returns the earliest of: neighbor timeouts, pending ACK retries,
    /// pending lookup timeouts, and delayed forward times.
    fn next_timeout_time(&self) -> Option<Timestamp> {
        let now = self.clock.now();

        // Get next neighbor timeout
        let (_, neighbor_timeout) = self.check_neighbor_timeouts(now);

        // Get next ACK timeout
        let (_, ack_timeout) = self.check_ack_timeouts(now);

        // Get next lookup timeout
        let (_, lookup_timeout) = self.check_lookup_timeouts(now);

        // Get next delayed forward time
        let delayed_forward_timeout = self.next_delayed_forward_time();

        // Return minimum of all timeouts
        [
            neighbor_timeout,
            ack_timeout,
            lookup_timeout,
            delayed_forward_timeout,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Handle incoming transport message.
    ///
    /// Call this to process a message received from the transport layer.
    /// For simulation, call this directly instead of using `run()`.
    pub fn handle_transport_rx(&mut self, data: &[u8], rssi: Option<i16>, now: Timestamp) {
        use crate::traits::Ackable;
        use crate::types::MSG_DATA;
        use crate::wire::{Decode, Message};

        let msg = match Message::decode_from_slice(data) {
            Ok(m) => m,
            Err(_e) => {
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::MessageDecodeFailed {
                        data_len: data.len(),
                    }
                );
                return;
            }
        };

        // Emit TransportReceived with payload_hash if it's a Routed or Broadcast message
        emit_debug!(self, {
            let payload_hash = match &msg {
                Message::Routed(r) => Some(r.payload_hash(self.crypto())),
                Message::Broadcast(b) => Some(b.payload_hash(self.crypto())),
                _ => None,
            };
            crate::debug::DebugEvent::TransportReceived {
                data_len: data.len(),
                payload_hash,
            }
        });

        match msg {
            Message::Pulse(pulse) => {
                self.record_protocol_received();
                self.handle_pulse(pulse, rssi, now);
            }
            Message::Routed(routed) => {
                if routed.msg_type() == MSG_DATA {
                    self.record_app_received();
                } else {
                    self.record_protocol_received();
                }

                // Implicit ACK: overhearing a Routed message clears pending ACK
                // Only clear if TTL matches what we expect (sent_ttl - 1).
                // This prevents false positives from messages arriving via alternate paths.
                let received_hash = routed.ack_hash(self.crypto());
                let received_ttl = routed.ttl;
                if let Some(pending) = self.pending_acks.get(&received_hash) {
                    if received_ttl == pending.sent_ttl.saturating_sub(1) {
                        // TTL matches: this is the message we sent, forwarded by next hop
                        self.pending_acks.remove(&received_hash);
                    }
                }

                self.handle_routed(routed, now);
            }
            Message::Ack(ack) => {
                self.record_protocol_received();
                // Explicit ACK: sender received duplicate and is confirming receipt
                self.pending_acks.remove(&ack.hash);
            }
            Message::Broadcast(broadcast) => {
                self.record_protocol_received();
                self.handle_broadcast(broadcast, now);
            }
        }
    }

    /// Handle an incoming Broadcast message.
    ///
    /// Verifies the sender is a known neighbor, checks if we are a designated recipient,
    /// verifies the signature, and dispatches based on payload type.
    fn handle_broadcast(&mut self, broadcast: crate::types::Broadcast, now: Timestamp) {
        // Step 1: Verify we are a designated recipient
        let my_hash = self.compute_id_hash(self.node_id());
        if !broadcast.destinations.contains(&my_hash) {
            return; // Not for us
        }

        // Step 2: Verify sender is a known neighbor
        if !self.neighbor_times.contains_key(&broadcast.src_node_id) {
            return; // Unknown sender
        }

        // Step 3: Verify Broadcast signature
        let pubkey = match self.pubkey_cache.get(&broadcast.src_node_id) {
            Some((pk, _)) => *pk,
            None => return, // No pubkey available, can't verify
        };

        let sign_data = crate::wire::broadcast_sign_data(&broadcast);
        if !self
            .crypto
            .verify(&pubkey, sign_data.as_slice(), &broadcast.signature)
        {
            return; // Invalid signature
        }

        // Dispatch based on payload type (first byte)
        if broadcast.payload.is_empty() {
            return;
        }

        match broadcast.payload[0] {
            crate::types::BCAST_PAYLOAD_DATA => {
                // Application data broadcast - deliver to app
                let payload = broadcast.payload[1..].to_vec();
                self.push_incoming_data(broadcast.src_node_id, payload);
            }
            crate::types::BCAST_PAYLOAD_BACKUP => {
                // BACKUP_PUBLISH - decode and handle the location entry
                self.handle_backup_publish(&broadcast, pubkey, now);
            }
            _ => {
                // Unknown payload type, ignore
            }
        }
    }

    /// Handle BACKUP_PUBLISH payload from a verified Broadcast.
    ///
    /// Steps 4-8 of the 8-step verification chain:
    /// 4. Verify sender owns keyspace for entry
    /// 5. Verify LOC: signature on entry
    /// 6. Check seq (only store if newer)
    /// 7. Check per-neighbor limit
    /// 8. Evict oldest if at capacity
    fn handle_backup_publish(
        &mut self,
        broadcast: &crate::types::Broadcast,
        _sender_pubkey: crate::types::PublicKey,
        now: Timestamp,
    ) {
        use crate::wire::{location_sign_data, Decode, Reader};

        // Decode LocationEntry from payload (skip the first byte which is BCAST_PAYLOAD_BACKUP)
        let payload = &broadcast.payload[1..];
        let mut reader = Reader::new(payload);
        let entry = match LocationEntry::decode(&mut reader) {
            Ok(e) => e,
            Err(_) => return, // Invalid payload
        };

        // Step 4: Verify sender owns keyspace for entry
        // The sender should be the storage node for this entry's keyspace address
        // We verify this by checking if the sender's keyspace range contains entry.keyspace_addr
        let sender_timing = match self.neighbor_times.get(&broadcast.src_node_id) {
            Some(t) => t,
            None => return,
        };
        let (sender_lo, sender_hi) = sender_timing.keyspace_range;
        if entry.keyspace_addr < sender_lo || entry.keyspace_addr >= sender_hi {
            return; // Sender doesn't own this keyspace
        }

        // Step 5: Verify LOC: signature on entry
        let loc_sign_data = location_sign_data(&entry.node_id, entry.keyspace_addr, entry.seq);
        if !self
            .crypto
            .verify(&entry.pubkey, loc_sign_data.as_slice(), &entry.signature)
        {
            return; // Invalid location signature
        }

        // Compute sender's child hash for tracking
        let sender_hash = self.compute_id_hash(&broadcast.src_node_id);

        let key = (entry.node_id, entry.replica_index);

        // Step 6: Check seq (only store if newer)
        if let Some(existing) = self.backup_store.get(&key) {
            if existing.entry.seq >= entry.seq {
                return; // We have a newer or equal entry
            }
        }

        // Step 7: Check per-neighbor limit
        let count_from_sender = self
            .backup_store
            .values()
            .filter(|e| e.backed_up_for == sender_hash)
            .count();
        if count_from_sender >= Cfg::MAX_BACKUPS_PER_NEIGHBOR {
            // At limit for this neighbor - could evict oldest from this neighbor
            // but for simplicity, just reject
            return;
        }

        // Step 8: Evict oldest if at MAX_BACKUP_STORE
        if self.backup_store.len() >= Cfg::MAX_BACKUP_STORE && !self.backup_store.contains_key(&key)
        {
            // Find and remove oldest entry
            let oldest_key = self
                .backup_store
                .iter()
                .min_by_key(|(_, v)| v.received_at)
                .map(|(k, _)| *k);
            if let Some(k) = oldest_key {
                self.backup_store.remove(&k);
            }
        }

        // Store the backup entry
        let mut entry_with_timestamp = entry;
        entry_with_timestamp.received_at = now;
        self.backup_store.insert(
            key,
            BackupEntry {
                entry: entry_with_timestamp,
                backed_up_for: sender_hash,
                received_at: now,
            },
        );
    }

    /// Handle application send request.
    ///
    /// Call this to process an outgoing data request from the application.
    /// For simulation, call this directly instead of using `run()`.
    pub fn handle_app_send(&mut self, data: OutgoingData, now: Timestamp) {
        let OutgoingData { target, payload } = data;

        // Check if we have the target's location cached (marks as recently used)
        if let Some(addr) = self.get_location_cache(&target, now) {
            // Send directly
            let _ = self.send_data_to(target, addr, payload, now);
        } else {
            // Queue data and initiate lookup
            self.pending_data.insert(target, payload);
            self.start_lookup(target, now);
        }
    }

    /// Handle timer events (pulse, timeouts).
    ///
    /// Call this to process timer-driven events (pulse broadcasts, timeouts).
    /// For simulation, call this directly instead of using `run()`.
    pub fn handle_timer(&mut self, now: Timestamp) {
        // Check if discovery phase is complete
        if let Some(deadline) = self.shopping_deadline {
            if now >= deadline {
                self.shopping_deadline = None;

                emit_debug!(
                    self,
                    crate::debug::DebugEvent::ShoppingEnded {
                        timestamp: now,
                        neighbor_count: self.neighbor_times.len(),
                    }
                );

                self.select_best_parent(now);
            }
        }

        // Check if pulse is due
        if let Some(next_pulse) = self.next_pulse_time() {
            if now >= next_pulse {
                self.send_pulse(now);
            }
        }

        // Check if location publish is due
        if let Some(next_publish) = self.next_publish {
            if now >= next_publish {
                self.publish_location(now);
            }
        }

        // Check if rebalance is due (incremental, one entry at a time)
        if let Some(next_rebalance) = self.next_rebalance {
            if now >= next_rebalance {
                self.next_rebalance = None;
                if self.rebalance_one(now) {
                    // More work to do, schedule next rebalance in 2τ
                    self.next_rebalance = Some(now + self.tau() * 2);
                }
            }
        }

        // Process pending routed retry (incremental, one message at a time)
        if let Some(next_pending_retry) = self.next_pending_retry {
            if now >= next_pending_retry {
                self.next_pending_retry = None;
                emit_debug!(
                    self,
                    crate::debug::DebugEvent::PendingRetryTick {
                        queue_len: self.pending_routed.len(),
                    }
                );
                if self.retry_one_pending(now) {
                    // More messages to check, schedule next retry in 2τ
                    self.next_pending_retry = Some(now + self.tau() * 2);
                }
            }
        }

        // Handle various timeouts
        self.handle_timeouts(now);
        self.handle_neighbor_timeouts(now);
        self.handle_location_expiry(now);

        // Link-layer reliability maintenance
        self.handle_ack_timeouts(now);
        self.cleanup_recently_forwarded(now);

        // Bounce-back dampening: process delayed forwards
        self.handle_delayed_forwards(now);

        // Check for tree size fraud
        self.handle_fraud_check(now);
    }

    /// Check ACK timeouts, returning entries needing action and next timeout.
    ///
    /// Returns ((retransmit_list, give_up_list), next_timeout_time).
    /// Retransmit list contains (hash, bytes, priority, retries).
    #[allow(clippy::type_complexity)]
    fn check_ack_timeouts(
        &self,
        now: Timestamp,
    ) -> (
        (
            Vec<(AckHash, Vec<u8>, crate::types::Priority, u8)>,
            Vec<AckHash>,
        ),
        Option<Timestamp>,
    ) {
        use crate::types::MAX_RETRIES;

        let mut retransmit = Vec::new();
        let mut give_up = Vec::new();
        let mut next_timeout: Option<Timestamp> = None;

        for (&hash, pending) in self.pending_acks.iter() {
            if now >= pending.next_retry_at {
                if pending.retries < MAX_RETRIES {
                    retransmit.push((
                        hash,
                        pending.original_bytes.clone(),
                        pending.priority,
                        pending.retries,
                    ));
                } else {
                    give_up.push(hash);
                }
            } else {
                // Track earliest future timeout
                next_timeout = Some(match next_timeout {
                    Some(t) => t.min(pending.next_retry_at),
                    None => pending.next_retry_at,
                });
            }
        }

        ((retransmit, give_up), next_timeout)
    }

    /// Handle ACK timeouts - retransmit or give up on pending messages.
    ///
    /// Returns the next timeout time (if any pending ACKs remain).
    fn handle_ack_timeouts(&mut self, now: Timestamp) -> Option<Timestamp> {
        use crate::types::PreEncoded;

        let ((retransmit, give_up), next_timeout) = self.check_ack_timeouts(now);

        // Process retransmissions
        for (hash, bytes, priority, retries) in retransmit {
            // Calculate next retry time with exponential backoff and jitter
            let next_retry = now + self.retry_backoff(retries + 1);

            // Update pending entry
            if let Some(pending) = self.pending_acks.get_mut(&hash) {
                pending.retries = retries + 1;
                pending.next_retry_at = next_retry;
            }

            // Retransmit with original priority
            let msg = PreEncoded::new(bytes, priority);
            if self.transport().outgoing().try_send(msg) {
                self.record_protocol_sent();
            } else {
                self.record_protocol_dropped();
            }
        }

        // Remove entries that have exceeded MAX_RETRIES
        for hash in give_up {
            self.pending_acks.remove(&hash);
        }

        next_timeout
    }

    /// Clean up old entries from recently_forwarded.
    pub(crate) fn cleanup_recently_forwarded(&mut self, now: Timestamp) {
        let expiry = self.tau() * RECENTLY_FORWARDED_TTL_MULTIPLIER;
        self.recently_forwarded
            .retain(|_, &mut (timestamp, _, _)| now.saturating_sub(timestamp) < expiry);
    }

    /// Calculate retry backoff duration with exponential growth and jitter.
    ///
    /// Base: τ × 2^retries (capped at 128τ)
    /// Jitter: ±10%
    pub(crate) fn retry_backoff(&mut self, retries: u8) -> Duration {
        let tau = self.tau();

        // Exponential backoff: τ × 2^retries, capped at 128τ
        let multiplier = 1u64 << retries.min(7); // 2^retries, max 128
        let base_ms = tau.as_millis().saturating_mul(multiplier);

        // Add ±10% jitter
        let jitter_range = base_ms / 10; // 10% of base
        if jitter_range > 0 {
            let jitter = self.random_mut().gen_range(0, jitter_range * 2);
            let jittered = base_ms.saturating_sub(jitter_range).saturating_add(jitter);
            Duration::from_millis(jittered)
        } else {
            Duration::from_millis(base_ms)
        }
    }

    /// Start a lookup for a target node.
    pub(crate) fn start_lookup(&mut self, target: NodeId, now: Timestamp) {
        if self.pending_lookups.contains_key(&target) {
            return; // Already in progress
        }

        if self.pending_lookups.len() >= Cfg::MAX_PENDING_LOOKUPS {
            return; // Too many pending
        }

        let lookup = PendingLookup {
            replica_index: 0,
            started_at: now,
            last_query_at: now,
        };
        self.pending_lookups.insert(target, lookup);

        self.send_lookup(target, 0, now);
    }

    // --- Cache accessors ---
    //
    // Cache API usage:
    // - has_pubkey/has_location: Check existence without updating LRU timestamp (for quick checks)
    // - get_pubkey/get_location_cache: Get value AND update LRU timestamp (for actual usage)
    // - pubkey_cache()/location_cache(): Raw access for iteration or bulk operations
    //
    // Use get_* when the value will be used, has_* when just checking existence.

    /// Check if we have a public key cached for a node.
    /// Does not update the LRU timestamp (use `get_pubkey` when actually using the key).
    pub fn has_pubkey(&self, node_id: &NodeId) -> bool {
        self.pubkey_cache.contains_key(node_id)
    }

    /// Get a cached public key and mark it as recently used for LRU eviction.
    pub fn get_pubkey(&mut self, node_id: &NodeId, now: Timestamp) -> Option<PublicKey> {
        if let Some((pk, last_used)) = self.pubkey_cache.get_mut(node_id) {
            *last_used = now;
            Some(*pk)
        } else {
            None
        }
    }

    /// Get a cached location and mark it as recently used for LRU eviction.
    pub fn get_location_cache(&mut self, node_id: &NodeId, now: Timestamp) -> Option<u32> {
        if let Some((addr, last_used)) = self.location_cache.get_mut(node_id) {
            *last_used = now;
            Some(*addr)
        } else {
            None
        }
    }

    /// Push an event to the events channel.
    pub(crate) fn push_event(&mut self, event: Event) {
        let _ = self.events.try_send(event);
    }

    /// Push incoming data to the app_incoming channel.
    pub(crate) fn push_incoming_data(&mut self, from: NodeId, payload: Vec<u8>) {
        #[cfg(feature = "debug")]
        let payload_len = payload.len();
        if !self.app_incoming.try_send(IncomingData { from, payload }) {
            emit_debug!(
                self,
                crate::debug::DebugEvent::AppIncomingFull { from, payload_len }
            );
        }
    }

    // --- Internal accessors for other modules ---

    pub(crate) fn children(&self) -> &ChildrenStore {
        &self.children
    }

    pub(crate) fn children_mut(&mut self) -> &mut ChildrenStore {
        &mut self.children
    }

    pub(crate) fn neighbor_times(&self) -> &NeighborTimingMap {
        &self.neighbor_times
    }

    pub(crate) fn neighbor_times_mut(&mut self) -> &mut NeighborTimingMap {
        &mut self.neighbor_times
    }

    pub(crate) fn pubkey_cache(&self) -> &PubkeyCache {
        &self.pubkey_cache
    }

    pub(crate) fn pubkey_cache_mut(&mut self) -> &mut PubkeyCache {
        &mut self.pubkey_cache
    }

    pub(crate) fn need_pubkey(&self) -> &NeedPubkeySet {
        &self.need_pubkey
    }

    pub(crate) fn need_pubkey_mut(&mut self) -> &mut NeedPubkeySet {
        &mut self.need_pubkey
    }

    pub(crate) fn neighbors_need_pubkey(&self) -> &NeighborsNeedPubkeySet {
        &self.neighbors_need_pubkey
    }

    pub(crate) fn neighbors_need_pubkey_mut(&mut self) -> &mut NeighborsNeedPubkeySet {
        &mut self.neighbors_need_pubkey
    }

    pub(crate) fn location_store(&self) -> &LocationStore {
        &self.location_store
    }

    pub(crate) fn location_store_mut(&mut self) -> &mut LocationStore {
        &mut self.location_store
    }

    #[allow(dead_code)] // Reserved for future backup retrieval
    pub(crate) fn backup_store(&self) -> &BackupStore {
        &self.backup_store
    }

    #[allow(dead_code)] // Reserved for future backup management
    pub(crate) fn backup_store_mut(&mut self) -> &mut BackupStore {
        &mut self.backup_store
    }

    pub(crate) fn pending_lookups(&self) -> &PendingLookupMap {
        &self.pending_lookups
    }

    pub(crate) fn pending_lookups_mut(&mut self) -> &mut PendingLookupMap {
        &mut self.pending_lookups
    }

    pub(crate) fn pending_data_mut(&mut self) -> &mut PendingDataMap {
        &mut self.pending_data
    }

    pub(crate) fn queue_pending_pubkey(&mut self, needed_node_id: NodeId, msg: Routed) {
        // Limit number of distinct nodes to prevent unbounded growth
        if self.pending_pubkey.len() >= Cfg::MAX_PENDING_PUBKEY_NODES
            && !self.pending_pubkey.contains_key(&needed_node_id)
        {
            // Evict the node we haven't heard from in the longest time
            if let Some(oldest_key) = self
                .pending_pubkey
                .keys()
                .min_by_key(|id| {
                    self.neighbor_times
                        .get(*id)
                        .map(|t| t.last_seen)
                        .unwrap_or(crate::time::Timestamp::ZERO)
                })
                .copied()
            {
                self.pending_pubkey.remove(&oldest_key);
            }
        }

        if !self.pending_pubkey.contains_key(&needed_node_id) {
            self.pending_pubkey.insert(needed_node_id, VecDeque::new());
        }
        let queue = self.pending_pubkey.get_mut(&needed_node_id).unwrap();
        if queue.len() >= Cfg::MAX_MSGS_PER_PENDING_PUBKEY {
            queue.pop_front();
        }
        queue.push_back(msg);
    }

    pub(crate) fn take_pending_pubkey(&mut self, node_id: &NodeId) -> Option<VecDeque<Routed>> {
        self.pending_pubkey.remove(node_id)
    }

    pub(crate) fn distrusted(&self) -> &DistrustedMap {
        &self.distrusted
    }

    #[cfg(test)]
    pub(crate) fn pending_acks(&self) -> &PendingAckMap {
        &self.pending_acks
    }

    pub(crate) fn pending_acks_mut(&mut self) -> &mut PendingAckMap {
        &mut self.pending_acks
    }

    pub(crate) fn recently_forwarded(&self) -> &RecentlyForwardedMap {
        &self.recently_forwarded
    }

    pub(crate) fn recently_forwarded_mut(&mut self) -> &mut RecentlyForwardedMap {
        &mut self.recently_forwarded
    }

    pub(crate) fn delayed_forwards(&self) -> &DelayedForwardMap {
        &self.delayed_forwards
    }

    pub(crate) fn delayed_forwards_mut(&mut self) -> &mut DelayedForwardMap {
        &mut self.delayed_forwards
    }

    pub(crate) fn pending_routed(&self) -> &ShrinkingVecDeque<PendingRouted> {
        &self.pending_routed
    }

    pub(crate) fn pending_routed_mut(&mut self) -> &mut ShrinkingVecDeque<PendingRouted> {
        &mut self.pending_routed
    }

    pub(crate) fn fraud_detection(&self) -> &FraudDetection {
        &self.fraud_detection
    }

    pub(crate) fn fraud_detection_mut(&mut self) -> &mut FraudDetection {
        &mut self.fraud_detection
    }

    pub(crate) fn hll_secret_key(&self) -> &HllSecretKey {
        &self.hll_secret_key
    }

    pub(crate) fn join_context(&self) -> &Option<JoinContext> {
        &self.join_context
    }

    pub(crate) fn set_join_context(&mut self, ctx: Option<JoinContext>) {
        self.join_context = ctx;
    }

    pub(crate) fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    pub(crate) fn set_parent(&mut self, parent: Option<NodeId>) {
        self.parent = parent;
    }

    pub(crate) fn pending_parent(&self) -> Option<(NodeId, u8)> {
        self.pending_parent
    }

    pub(crate) fn set_pending_parent(&mut self, pending: Option<(NodeId, u8)>) {
        self.pending_parent = pending;
    }

    pub(crate) fn parent_rejection_count(&self) -> u8 {
        self.parent_rejection_count
    }

    pub(crate) fn set_parent_rejection_count(&mut self, count: u8) {
        self.parent_rejection_count = count;
    }

    pub(crate) fn set_root_hash(&mut self, root: IdHash) {
        self.root_hash = root;
    }

    pub(crate) fn set_tree_size(&mut self, size: u32) {
        self.tree_size = size;
    }

    pub(crate) fn set_subtree_size(&mut self, size: u32) {
        self.subtree_size = size;
    }

    pub(crate) fn keyspace_lo(&self) -> u32 {
        self.keyspace_lo
    }

    pub(crate) fn keyspace_hi(&self) -> u32 {
        self.keyspace_hi
    }

    pub(crate) fn set_keyspace_range(&mut self, lo: u32, hi: u32) {
        self.keyspace_lo = lo;
        self.keyspace_hi = hi;
    }

    pub(crate) fn depth(&self) -> u8 {
        self.depth
    }

    pub(crate) fn set_depth(&mut self, depth: u8) {
        self.depth = depth;
    }

    pub(crate) fn max_depth(&self) -> u8 {
        self.max_depth
    }

    pub(crate) fn set_max_depth(&mut self, max_depth: u8) {
        self.max_depth = max_depth;
    }

    /// Clear shopping state after parent selection is complete.
    pub(crate) fn clear_shopping(&mut self) {
        self.shopping_deadline = None;
    }

    pub(crate) fn next_location_seq(&mut self) -> u32 {
        self.location_seq = self.location_seq.wrapping_add(1);
        self.location_seq
    }

    pub(crate) fn set_next_publish(&mut self, time: Option<Timestamp>) {
        self.next_publish = time;
    }

    /// Trigger incremental rebalance. Runs one entry now, schedules more if needed.
    pub(crate) fn trigger_rebalance(&mut self, now: Timestamp) {
        if self.rebalance_one(now) {
            // More work to do, schedule next rebalance in 2τ
            self.next_rebalance = Some(now + self.tau() * 2);
        }
    }

    pub(crate) fn set_last_pulse(&mut self, time: Option<Timestamp>) {
        self.last_pulse = time;
    }

    pub(crate) fn set_last_pulse_size(&mut self, size: usize) {
        self.last_pulse_size = size;
    }

    pub(crate) fn proactive_pulse_pending(&self) -> Option<Timestamp> {
        self.proactive_pulse_pending
    }

    pub(crate) fn set_proactive_pulse_pending(&mut self, time: Option<Timestamp>) {
        self.proactive_pulse_pending = time;
    }

    /// Schedule a pending routed retry at the given time.
    ///
    /// If a retry is already scheduled, use the earlier of the two times.
    /// Called when routing conditions may have changed (e.g., neighbor pulsed)
    /// or when a message is queued.
    pub(crate) fn schedule_pending_retry(&mut self, time: Timestamp) {
        if self.pending_routed.is_empty() {
            return;
        }

        // Only update if no retry is scheduled or the new time is earlier
        let should_schedule = self
            .next_pending_retry
            .map_or(true, |existing| time < existing);
        if !should_schedule {
            return;
        }

        self.next_pending_retry = Some(time);
        emit_debug!(
            self,
            crate::debug::DebugEvent::PendingRetryScheduled {
                time_ms: time.as_millis(),
                queue_len: self.pending_routed.len(),
            }
        );
    }

    /// Check if node is in shopping phase (first boot or merge).
    pub fn is_shopping(&self) -> bool {
        self.shopping_deadline.is_some()
    }

    /// Start shopping phase with fixed duration of 3τ.
    ///
    /// During shopping, current state (parent, root_hash, depth) is preserved and used
    /// for candidate filtering. We only become root if shopping finds no valid candidates.
    pub(crate) fn start_shopping(&mut self, now: Timestamp) {
        let deadline = now + self.tau() * 3;
        self.shopping_deadline = Some(deadline);

        emit_debug!(
            self,
            crate::debug::DebugEvent::ShoppingStarted {
                timestamp: now,
                deadline,
            }
        );
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub(crate) fn random_mut(&mut self) -> &mut R {
        &mut self.random
    }

    // Metrics tracking methods

    pub(crate) fn record_protocol_sent(&mut self) {
        self.metrics.protocol_sent += 1;
    }

    pub(crate) fn record_protocol_dropped(&mut self) {
        self.metrics.protocol_dropped += 1;
    }

    pub(crate) fn record_protocol_received(&mut self) {
        self.metrics.protocol_received += 1;
    }

    pub(crate) fn record_app_sent(&mut self) {
        self.metrics.app_sent += 1;
    }

    pub(crate) fn record_app_dropped(&mut self) {
        self.metrics.app_dropped += 1;
    }

    pub(crate) fn record_app_received(&mut self) {
        self.metrics.app_received += 1;
    }

    // --- Bounded insertion helpers ---
    //
    // These helpers implement LRU (Least Recently Used) eviction for bounded collections.
    // When a collection reaches its maximum size and a new entry needs to be inserted,
    // the entry with the oldest timestamp is evicted. The O(n) iteration cost is acceptable
    // because eviction only occurs when the cache is full, which is infrequent in practice.

    /// Evict the oldest entry from a map based on a timestamp extraction function.
    /// Returns the evicted key-value pair, or None if the map was empty.
    fn evict_oldest_by<K, V, F>(map: &mut HashMap<K, V>, get_timestamp: F) -> Option<(K, V)>
    where
        K: Eq + core::hash::Hash + Copy,
        F: Fn(&V) -> Timestamp,
    {
        let oldest_key = map
            .iter()
            .min_by_key(|(_, v)| get_timestamp(v))
            .map(|(k, _)| *k)?;
        map.remove(&oldest_key).map(|v| (oldest_key, v))
    }

    pub(crate) fn insert_pubkey_cache(
        &mut self,
        node_id: NodeId,
        pubkey: PublicKey,
        now: Timestamp,
    ) {
        if self.pubkey_cache.len() >= Cfg::MAX_PUBKEY_CACHE
            && !self.pubkey_cache.contains_key(&node_id)
        {
            Self::evict_oldest_by(&mut self.pubkey_cache, |(_, last_used)| *last_used);
        }
        self.pubkey_cache.insert(node_id, (pubkey, now));
    }

    pub(crate) fn insert_location_store(
        &mut self,
        node_id: NodeId,
        replica_index: u8,
        entry: LocationEntry,
    ) {
        let key = (node_id, replica_index);
        if self.location_store.len() >= Cfg::MAX_LOCATION_STORE
            && !self.location_store.contains_key(&key)
        {
            // Evict oldest entry and emit debug event
            let _evicted = self.location_store.remove_min_by_key(|e| e.received_at);
            emit_debug!(self, {
                let (evicted_key, _) =
                    _evicted.expect("eviction should succeed when over capacity");
                crate::debug::DebugEvent::LocationRemoved {
                    owner: evicted_key.0,
                    replica_index: evicted_key.1,
                    reason: "capacity",
                }
            });
        }
        self.location_store.insert(key, entry);
    }

    pub(crate) fn insert_location_cache(&mut self, node_id: NodeId, addr: u32, now: Timestamp) {
        if self.location_cache.len() >= Cfg::MAX_LOCATION_CACHE
            && !self.location_cache.contains_key(&node_id)
        {
            self.location_cache
                .remove_min_by_key(|(_, last_used)| *last_used);
        }
        self.location_cache.insert(node_id, (addr, now));
    }

    pub(crate) fn insert_neighbor_time(&mut self, node_id: NodeId, timing: NeighborTiming) {
        if self.neighbor_times.len() >= Cfg::MAX_NEIGHBORS
            && !self.neighbor_times.contains_key(&node_id)
        {
            self.neighbor_times.remove_min_by_key(|t| t.last_seen);
        }
        self.neighbor_times.insert(node_id, timing);
    }

    pub(crate) fn insert_distrusted(&mut self, node_id: NodeId, timestamp: Timestamp) {
        if self.distrusted.len() >= Cfg::MAX_DISTRUSTED && !self.distrusted.contains_key(&node_id) {
            self.distrusted.remove_min_by_key(|&ts| ts);
        }
        self.distrusted.insert(node_id, timestamp);
    }

    /// Insert a pending ACK entry with bounded eviction.
    ///
    /// Evicts the entry with the oldest `next_retry_at` when at capacity.
    pub(crate) fn insert_pending_ack(
        &mut self,
        hash: AckHash,
        original_bytes: Vec<u8>,
        priority: crate::types::Priority,
        sent_ttl: u8,
        now: Timestamp,
    ) {
        if self.pending_acks.len() >= Cfg::MAX_PENDING_ACKS
            && !self.pending_acks.contains_key(&hash)
        {
            self.pending_acks.remove_min_by_key(|pa| pa.next_retry_at);
        }

        let pending = PendingAck {
            original_bytes,
            priority,
            retries: 0,
            next_retry_at: now + self.tau(),
            sent_ttl,
        };
        self.pending_acks.insert(hash, pending);
    }

    /// Insert a recently forwarded entry with bounded eviction.
    ///
    /// Evicts the oldest entry by timestamp when at capacity.
    /// Stores timestamp, hops, and seen_count to distinguish retransmissions from alternate paths
    /// and track bounce-back occurrences.
    pub(crate) fn insert_recently_forwarded(&mut self, hash: AckHash, hops: u32, now: Timestamp) {
        if self.recently_forwarded.len() >= Cfg::MAX_RECENTLY_FORWARDED
            && !self.recently_forwarded.contains_key(&hash)
        {
            self.recently_forwarded.remove_min_by_key(|&(ts, _, _)| ts);
        }
        self.recently_forwarded.insert(hash, (now, hops, 1));
    }

    // =========================================================================
    // Test support methods
    // =========================================================================
    //
    // These methods expose internal state for testing via the simulator.
    // Only available when the `test-support` feature is enabled.

    /// Access the location store for testing DHT operations.
    #[cfg(feature = "test-support")]
    pub fn test_location_store(&self) -> &LocationStore {
        &self.location_store
    }

    /// Access pending lookups for testing DHT operations.
    #[cfg(feature = "test-support")]
    #[allow(private_interfaces)]
    pub fn test_pending_lookups(&self) -> &PendingLookupMap {
        &self.pending_lookups
    }

    /// Access the app incoming channel for testing data delivery.
    #[cfg(feature = "test-support")]
    pub fn test_app_incoming(&self) -> &DynamicChannel<IncomingData> {
        &self.app_incoming
    }

    /// Access the location cache for testing DHT operations.
    #[cfg(feature = "test-support")]
    pub fn test_location_cache(&self) -> &LocationCache {
        &self.location_cache
    }

    /// Access pending ACKs for testing reliability mechanisms.
    #[cfg(feature = "test-support")]
    #[allow(private_interfaces)]
    pub fn test_pending_acks(&self) -> &PendingAckMap {
        &self.pending_acks
    }

    /// Compute keyspace address for a node's replica (for testing).
    #[cfg(feature = "test-support")]
    pub fn test_replica_addr(&self, node_id: &NodeId, replica: u8) -> u32 {
        self.replica_addr(node_id, replica)
    }

    /// Trigger a location publish (for testing DHT).
    #[cfg(feature = "test-support")]
    pub fn test_publish_location(&mut self, now: Timestamp) {
        self.publish_location(now);
    }
}
