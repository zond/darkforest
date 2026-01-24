//! Node implementation - the main protocol state machine.
//!
//! The Node struct holds all protocol state and provides an async `run()` method
//! that drives the protocol. It is fully event-driven:
//! - Incoming transport messages trigger protocol handling
//! - Application sends via outgoing channel trigger routing/lookup
//! - Internal timers trigger Pulse broadcasts
//!
//! # Usage
//!
//! ```ignore
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

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::marker::PhantomData;
use hashbrown::HashMap;

use embassy_sync::channel::Channel;

use crate::config::{DefaultConfig, NodeConfig};
use crate::fraud::{FraudDetection, HllSecretKey};
use crate::time::{Duration, Timestamp};
use crate::traits::{
    AppInChannel, AppOutChannel, Clock, Crypto, EventChannel, IncomingData, OutgoingData, Random,
    Transport,
};
use crate::types::{
    ChildHash, Event, LocationEntry, NodeId, PublicKey, Routed, SecretKey, TransportMetrics,
    RECENTLY_FORWARDED_TTL_MULTIPLIER,
};

/// Timing, signal, and tree information for a neighbor.
#[derive(Clone, Debug)]
pub struct NeighborTiming {
    /// Last time we received a Pulse from this neighbor.
    pub last_seen: Timestamp,
    /// Previous Pulse time (for interval estimation).
    pub prev_seen: Option<Timestamp>,
    /// Last observed signal strength in dBm (if available).
    pub rssi: Option<i16>,
    /// Root hash of the neighbor's tree.
    pub root_hash: ChildHash,
    /// Size of the neighbor's tree.
    pub tree_size: u32,
    /// Neighbor's keyspace range (lo, hi).
    pub keyspace_range: (u32, u32),
    /// Number of children the neighbor has.
    pub children_count: u8,
}

/// Pending lookup state.
#[derive(Clone, Debug)]
pub struct PendingLookup {
    /// Current replica index being tried (0, 1, or 2).
    pub replica_index: usize,
    /// When the lookup started.
    pub started_at: Timestamp,
    /// When current replica query was sent.
    pub last_query_at: Timestamp,
}

/// Context for fraud detection when joining a tree.
#[derive(Clone, Copy, Debug)]
pub struct JoinContext {
    /// Parent node when we joined.
    pub parent_at_join: NodeId,
    /// Time when we joined.
    pub join_time: Timestamp,
}

// Type aliases for collections
pub type ChildMap = BTreeMap<NodeId, u32>;
/// Child ranges: child_id -> (keyspace_lo, keyspace_hi).
pub type ChildRanges = HashMap<NodeId, (u32, u32)>;
/// Shortcuts: shortcut_id -> (keyspace_lo, keyspace_hi).
pub type ShortcutMap = HashMap<NodeId, (u32, u32)>;
pub type NeighborTimingMap = HashMap<NodeId, NeighborTiming>;
/// Pubkey cache: node_id -> (pubkey, last_used).
pub type PubkeyCache = HashMap<NodeId, (PublicKey, Timestamp)>;
pub type NeedPubkeySet = BTreeSet<NodeId>;
pub type NeighborsNeedPubkeySet = BTreeSet<NodeId>;
pub type LocationStore = HashMap<NodeId, LocationEntry>;
/// Location cache: node_id -> (keyspace_addr, last_used).
pub type LocationCache = HashMap<NodeId, (u32, Timestamp)>;
pub type PendingLookupMap = HashMap<NodeId, PendingLookup>;
pub type PendingDataMap = HashMap<NodeId, Vec<u8>>;
pub type DistrustedMap = HashMap<NodeId, Timestamp>;
/// Messages awaiting pubkey for a specific node_id (keyed by the node whose pubkey is needed).
pub type PendingPubkeyMap = HashMap<NodeId, VecDeque<Routed>>;

/// 8-byte hash used for ACK identification.
pub type AckHash = [u8; 8];

/// Pending ACK entry for link-layer reliability.
///
/// Tracks a message awaiting acknowledgment with exponential backoff retry.
#[derive(Clone, Debug)]
pub struct PendingAck {
    /// Original encoded message bytes for retransmission.
    pub original_bytes: Vec<u8>,
    /// Number of retries attempted so far.
    pub retries: u8,
    /// Timestamp when next retry should occur.
    pub next_retry_at: Timestamp,
}

/// Map of pending ACKs keyed by message hash.
pub type PendingAckMap = HashMap<AckHash, PendingAck>;

/// Map of recently forwarded message hashes for duplicate detection.
pub type RecentlyForwardedMap = HashMap<AckHash, Timestamp>;

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

    // Application-level channels
    app_incoming: AppInChannel,
    app_outgoing: AppOutChannel,
    events: EventChannel,

    // Identity
    node_id: NodeId,
    pubkey: PublicKey,
    secret: SecretKey,

    // Tree position (keyspace-based)
    parent: Option<NodeId>,
    pending_parent: Option<(NodeId, u8)>, // (candidate, pulses_waited)
    parent_rejection_count: u8,           // consecutive pulses from parent not including us
    root_hash: ChildHash,
    tree_size: u32,
    subtree_size: u32,
    keyspace_lo: u32,
    keyspace_hi: u32,

    // Neighbors
    children: ChildMap,
    child_ranges: ChildRanges,
    shortcuts: ShortcutMap,
    neighbor_times: NeighborTimingMap,

    // Caches
    pubkey_cache: PubkeyCache,
    need_pubkey: NeedPubkeySet,
    neighbors_need_pubkey: NeighborsNeedPubkeySet,
    location_store: LocationStore,
    location_cache: LocationCache,

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

    // Scheduling
    last_pulse: Option<Timestamp>,
    last_pulse_size: usize,
    next_publish: Option<Timestamp>,
    location_seq: u32,
    proactive_pulse_pending: Option<Timestamp>,
    discovery_deadline: Option<Timestamp>,

    // Metrics
    metrics: TransportMetrics,

    // Cached computations (avoid u64 division on 32-bit MCUs)
    cached_tau_ms: u64,

    // Debug events channel (only with "debug" feature)
    #[cfg(feature = "debug")]
    debug_channel: crate::debug::DebugChannel,
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
        let root_hash = Self::compute_node_hash_static(&crypto, &node_id);

        // Cache tau to avoid u64 division on 32-bit MCUs at runtime.
        // Note: tau is computed once at initialization. If transport bandwidth
        // changes dynamically, create a new Node instance.
        let cached_tau_ms = match transport.bw() {
            Some(bw) if bw > 0 => {
                let ms = (transport.mtu() as u64 * 1000) / bw as u64;
                ms.max(crate::types::MIN_TAU_MS)
            }
            _ => crate::types::MIN_TAU_MS,
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

            app_incoming: Channel::new(),
            app_outgoing: Channel::new(),
            events: Channel::new(),

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

            children: BTreeMap::new(),
            child_ranges: HashMap::new(),
            shortcuts: HashMap::new(),
            neighbor_times: HashMap::new(),

            pubkey_cache: HashMap::new(),
            need_pubkey: BTreeSet::new(),
            neighbors_need_pubkey: BTreeSet::new(),
            location_store: HashMap::new(),
            location_cache: HashMap::new(),

            pending_lookups: HashMap::new(),
            pending_data: HashMap::new(),
            pending_pubkey: HashMap::new(),

            join_context: None,
            distrusted: HashMap::new(),
            fraud_detection: FraudDetection::new(),
            hll_secret_key,

            pending_acks: HashMap::new(),
            recently_forwarded: HashMap::new(),

            last_pulse: None,
            last_pulse_size: 0,
            next_publish: None,
            location_seq: 0,
            proactive_pulse_pending: None,
            discovery_deadline: None,

            metrics: TransportMetrics::new(),

            cached_tau_ms,

            #[cfg(feature = "debug")]
            debug_channel: embassy_sync::channel::Channel::new(),
        }
    }

    /// Compute the 4-byte hash of a node_id.
    fn compute_node_hash_static(crypto: &Cr, node_id: &NodeId) -> ChildHash {
        let hash = crypto.hash(node_id);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Compute the 4-byte hash of a node_id.
    pub fn compute_node_hash(&self, node_id: &NodeId) -> ChildHash {
        Self::compute_node_hash_static(&self.crypto, node_id)
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

    /// Get this node's keyspace address (center of range).
    /// Uses overflow-safe calculation.
    pub fn my_address(&self) -> u32 {
        (self.keyspace_lo / 2) + (self.keyspace_hi / 2)
    }

    /// Check if this node owns a keyspace location.
    ///
    /// Uses half-open interval [keyspace_lo, keyspace_hi). The keyspace is
    /// [0, u32::MAX), so u32::MAX is not a valid address.
    pub fn owns_key(&self, key: u32) -> bool {
        key >= self.keyspace_lo && key < self.keyspace_hi
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
    pub fn root_hash(&self) -> &ChildHash {
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

    /// Channel for receiving data from other nodes.
    ///
    /// Application reads DATA messages from here.
    pub fn incoming(&self) -> &AppInChannel {
        &self.app_incoming
    }

    /// Channel for sending data to other nodes.
    ///
    /// Application sends DATA messages here. The node handles
    /// routing/lookup automatically.
    pub fn outgoing(&self) -> &AppOutChannel {
        &self.app_outgoing
    }

    /// Channel for protocol events.
    ///
    /// Application receives events like TreeChanged, LookupComplete, etc.
    pub fn events(&self) -> &EventChannel {
        &self.events
    }

    /// Channel for debug events (only with "debug" feature).
    ///
    /// Simulator/test can receive detailed protocol trace events.
    #[cfg(feature = "debug")]
    pub fn debug_channel(&self) -> &crate::debug::DebugChannel {
        &self.debug_channel
    }

    /// Emit a debug event (only with "debug" feature).
    #[cfg(feature = "debug")]
    pub(crate) fn emit_debug(&self, event: crate::debug::DebugEvent) {
        let _ = self.debug_channel.try_send(event);
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

    /// Lookup timeout: 32τ per replica
    /// For LoRa (τ=6.7s): ~3.5 minutes
    /// For UDP (τ=0.1s): ~3 seconds
    pub fn lookup_timeout(&self) -> Duration {
        self.tau() * 32
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

        // Start discovery phase if orphan (no parent, no children)
        // Discovery lasts 3τ to collect neighbor Pulses before selecting parent
        if self.parent.is_none() && self.children.is_empty() {
            let discovery_duration = self.tau() * 3;
            let deadline = now + discovery_duration;
            self.discovery_deadline = Some(deadline);

            #[cfg(feature = "debug")]
            self.emit_debug(crate::debug::DebugEvent::DiscoveryStarted { deadline });
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
            if let Some(deadline) = self.discovery_deadline {
                timer_wake = timer_wake.min(deadline);
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
        let interval = match self.transport.bw() {
            Some(bw) if bw > 0 => {
                // Interval to stay within pulse bandwidth budget.
                // Single division for better integer accuracy:
                // secs = pulse_size / (bw / divisor) = pulse_size * divisor / bw
                let secs = (self.last_pulse_size as u64 * PULSE_BW_DIVISOR as u64) / (bw as u64);
                Duration::from_secs(secs).max(min_interval)
            }
            _ => min_interval,
        };

        let budget_time = last + interval;

        // Proactive pulse can trigger early, but must still respect bandwidth budget.
        // Use max to ensure we don't send before budget_time.
        match self.proactive_pulse_pending {
            Some(proactive) => Some(budget_time.max(proactive)),
            None => Some(budget_time),
        }
    }

    /// Calculate next timeout time (lookups, neighbors, locations).
    fn next_timeout_time(&self) -> Option<Timestamp> {
        // For now, check timeouts every 10 seconds
        // A more sophisticated implementation would track exact timeout times
        Some(self.clock.now() + Duration::from_secs(10))
    }

    /// Handle incoming transport message.
    ///
    /// Call this to process a message received from the transport layer.
    /// For simulation, call this directly instead of using `run()`.
    pub fn handle_transport_rx(&mut self, data: &[u8], rssi: Option<i16>, now: Timestamp) {
        use crate::types::MSG_DATA;
        use crate::wire::{Decode, Message};

        let msg = match Message::decode_from_slice(data) {
            Ok(m) => m,
            Err(_e) => {
                #[cfg(feature = "debug")]
                self.emit_debug(crate::debug::DebugEvent::MessageDecodeFailed {
                    data_len: data.len(),
                });
                return;
            }
        };

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
                // This is cheap (just a hash lookup) so we do it BEFORE signature verification.
                let received_hash = self.compute_ack_hash(&routed);
                self.pending_acks.remove(&received_hash);

                self.handle_routed(routed, now);
            }
            Message::Ack(ack) => {
                self.record_protocol_received();
                // Explicit ACK: sender received duplicate and is confirming receipt
                self.pending_acks.remove(&ack.hash);
            }
        }
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
        if let Some(deadline) = self.discovery_deadline {
            if now >= deadline {
                self.discovery_deadline = None;

                #[cfg(feature = "debug")]
                self.emit_debug(crate::debug::DebugEvent::DiscoveryEnded {
                    neighbor_count: self.neighbor_times.len(),
                });

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

        // Handle various timeouts
        self.handle_timeouts(now);
        self.handle_neighbor_timeouts(now);
        self.handle_location_expiry(now);

        // Link-layer reliability maintenance
        self.handle_ack_timeouts(now);
        self.cleanup_recently_forwarded(now);

        // Check for tree size fraud
        self.handle_fraud_check(now);
    }

    /// Handle ACK timeouts - retransmit or give up on pending messages.
    fn handle_ack_timeouts(&mut self, now: Timestamp) {
        use crate::types::MAX_RETRIES;

        // Collect entries that need action to avoid borrow issues
        let mut retransmit = Vec::new();
        let mut give_up = Vec::new();

        for (&hash, pending) in self.pending_acks.iter() {
            if now >= pending.next_retry_at {
                if pending.retries < MAX_RETRIES {
                    retransmit.push((hash, pending.original_bytes.clone(), pending.retries));
                } else {
                    give_up.push(hash);
                }
            }
        }

        // Process retransmissions
        for (hash, bytes, retries) in retransmit {
            // Calculate next retry time with exponential backoff and jitter
            let next_retry = now + self.retry_backoff(retries + 1);

            // Update pending entry
            if let Some(pending) = self.pending_acks.get_mut(&hash) {
                pending.retries = retries + 1;
                pending.next_retry_at = next_retry;
            }

            // Retransmit
            let result = self.transport().protocol_outgoing().try_send(bytes);
            if result.is_ok() {
                self.record_protocol_sent();
            } else {
                self.record_protocol_dropped();
            }
        }

        // Remove entries that have exceeded MAX_RETRIES
        for hash in give_up {
            self.pending_acks.remove(&hash);
        }
    }

    /// Clean up old entries from recently_forwarded.
    pub(crate) fn cleanup_recently_forwarded(&mut self, now: Timestamp) {
        let ttl = self.tau() * RECENTLY_FORWARDED_TTL_MULTIPLIER;
        self.recently_forwarded
            .retain(|_, &mut timestamp| now.saturating_sub(timestamp) < ttl);
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
        let _ = self.app_incoming.try_send(IncomingData { from, payload });
    }

    // --- Internal accessors for other modules ---

    pub(crate) fn children(&self) -> &ChildMap {
        &self.children
    }

    pub(crate) fn children_mut(&mut self) -> &mut ChildMap {
        &mut self.children
    }

    pub(crate) fn child_ranges(&self) -> &ChildRanges {
        &self.child_ranges
    }

    pub(crate) fn child_ranges_mut(&mut self) -> &mut ChildRanges {
        &mut self.child_ranges
    }

    pub(crate) fn shortcuts(&self) -> &ShortcutMap {
        &self.shortcuts
    }

    pub(crate) fn shortcuts_mut(&mut self) -> &mut ShortcutMap {
        &mut self.shortcuts
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

        let queue = self.pending_pubkey.entry(needed_node_id).or_default();
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

    pub(crate) fn set_root_hash(&mut self, root: ChildHash) {
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

    pub(crate) fn next_location_seq(&mut self) -> u32 {
        self.location_seq = self.location_seq.wrapping_add(1);
        self.location_seq
    }

    pub(crate) fn set_next_publish(&mut self, time: Option<Timestamp>) {
        self.next_publish = time;
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

    /// Check if node is in discovery phase.
    pub(crate) fn is_in_discovery(&self) -> bool {
        self.discovery_deadline.is_some()
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
    /// Returns true if an entry was evicted.
    fn evict_oldest_by<V, F>(map: &mut HashMap<NodeId, V>, get_timestamp: F) -> bool
    where
        F: Fn(&V) -> Timestamp,
    {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, v)| get_timestamp(v))
            .map(|(k, _)| *k)
        {
            map.remove(&oldest_key);
            true
        } else {
            false
        }
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

    pub(crate) fn insert_location_store(&mut self, node_id: NodeId, entry: LocationEntry) {
        if self.location_store.len() >= Cfg::MAX_LOCATION_STORE
            && !self.location_store.contains_key(&node_id)
        {
            Self::evict_oldest_by(&mut self.location_store, |e| e.received_at);
        }
        self.location_store.insert(node_id, entry);
    }

    pub(crate) fn insert_location_cache(&mut self, node_id: NodeId, addr: u32, now: Timestamp) {
        if self.location_cache.len() >= Cfg::MAX_LOCATION_CACHE
            && !self.location_cache.contains_key(&node_id)
        {
            Self::evict_oldest_by(&mut self.location_cache, |(_, last_used)| *last_used);
        }
        self.location_cache.insert(node_id, (addr, now));
    }

    pub(crate) fn insert_neighbor_time(&mut self, node_id: NodeId, timing: NeighborTiming) {
        if self.neighbor_times.len() >= Cfg::MAX_NEIGHBORS
            && !self.neighbor_times.contains_key(&node_id)
        {
            Self::evict_oldest_by(&mut self.neighbor_times, |t| t.last_seen);
        }
        self.neighbor_times.insert(node_id, timing);
    }

    pub(crate) fn insert_distrusted(&mut self, node_id: NodeId, timestamp: Timestamp) {
        if self.distrusted.len() >= Cfg::MAX_DISTRUSTED && !self.distrusted.contains_key(&node_id) {
            Self::evict_oldest_by(&mut self.distrusted, |&ts| ts);
        }
        self.distrusted.insert(node_id, timestamp);
    }

    pub(crate) fn insert_shortcut(&mut self, node_id: NodeId, keyspace: (u32, u32)) {
        if self.shortcuts.len() >= Cfg::MAX_SHORTCUTS && !self.shortcuts.contains_key(&node_id) {
            // Shortcuts use a different eviction strategy: cross-reference with neighbor_times.
            // Unlike other caches, shortcuts don't store timestamps. Instead, when we receive
            // a pulse, we update neighbor_times.last_seen. So we evict the shortcut whose
            // corresponding neighbor was heard from least recently.
            if let Some(oldest_key) = self
                .shortcuts
                .keys()
                .min_by_key(|id| {
                    self.neighbor_times
                        .get(*id)
                        .map(|t| t.last_seen)
                        .unwrap_or(crate::time::Timestamp::ZERO)
                })
                .copied()
            {
                self.shortcuts.remove(&oldest_key);
            }
        }
        self.shortcuts.insert(node_id, keyspace);
    }

    /// Evict the oldest entry from an AckHash-keyed map based on a timestamp extraction function.
    fn evict_oldest_ack_by<V, F>(map: &mut HashMap<AckHash, V>, get_timestamp: F) -> bool
    where
        F: Fn(&V) -> Timestamp,
    {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, v)| get_timestamp(v))
            .map(|(k, _)| *k)
        {
            map.remove(&oldest_key);
            true
        } else {
            false
        }
    }

    /// Insert a pending ACK entry with bounded eviction.
    ///
    /// Evicts the entry with the oldest `next_retry_at` when at capacity.
    pub(crate) fn insert_pending_ack(
        &mut self,
        hash: AckHash,
        original_bytes: Vec<u8>,
        now: Timestamp,
    ) {
        if self.pending_acks.len() >= Cfg::MAX_PENDING_ACKS
            && !self.pending_acks.contains_key(&hash)
        {
            Self::evict_oldest_ack_by(&mut self.pending_acks, |pa| pa.next_retry_at);
        }

        let pending = PendingAck {
            original_bytes,
            retries: 0,
            next_retry_at: now + self.tau(),
        };
        self.pending_acks.insert(hash, pending);
    }

    /// Insert a recently forwarded entry with bounded eviction.
    ///
    /// Evicts the oldest entry by timestamp when at capacity.
    pub(crate) fn insert_recently_forwarded(&mut self, hash: AckHash, now: Timestamp) {
        if self.recently_forwarded.len() >= Cfg::MAX_RECENTLY_FORWARDED
            && !self.recently_forwarded.contains_key(&hash)
        {
            Self::evict_oldest_ack_by(&mut self.recently_forwarded, |&ts| ts);
        }
        self.recently_forwarded.insert(hash, now);
    }
}
