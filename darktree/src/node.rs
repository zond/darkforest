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

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use embassy_sync::channel::Channel;

use crate::fraud::FraudDetection;
use crate::time::{Duration, Timestamp};
use crate::traits::{
    AppInChannel, AppOutChannel, Clock, Crypto, EventChannel, IncomingData, OutgoingData, Random,
    Transport,
};
use crate::types::{
    Event, LocationEntry, NodeId, PublicKey, Routed, SecretKey, TransportMetrics, TreeAddr,
    MAX_DISTRUSTED, MAX_LOCATION_CACHE, MAX_LOCATION_STORE, MAX_NEIGHBORS, MAX_PENDING_DATA,
    MAX_PENDING_LOOKUPS, MAX_PENDING_PUBKEY, MAX_PUBKEY_CACHE, MIN_PULSE_INTERVAL,
};

/// Timing and signal information for a neighbor.
#[derive(Clone, Copy, Debug)]
pub struct NeighborTiming {
    /// Last time we received a Pulse from this neighbor.
    pub last_seen: Timestamp,
    /// Previous Pulse time (for interval estimation).
    pub prev_seen: Option<Timestamp>,
    /// Last observed signal strength in dBm (if available).
    pub rssi: Option<i16>,
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

/// Pending request state (for request-response patterns).
#[derive(Clone, Debug)]
pub struct PendingRequest {
    /// Data to send.
    pub data: Vec<u8>,
    /// When the request was sent.
    pub sent_at: Timestamp,
    /// Number of retries so far.
    pub retries: u8,
}

/// Context for fraud detection when joining a tree.
#[derive(Clone, Debug)]
pub struct JoinContext {
    /// Parent node when we joined.
    pub parent_at_join: NodeId,
    /// Time when we joined.
    pub join_time: Timestamp,
}

// Type aliases for collections
pub type ChildMap = BTreeMap<NodeId, u32>;
pub type ShortcutSet = BTreeSet<NodeId>;
pub type NeighborTimingMap = HashMap<NodeId, NeighborTiming>;
pub type PubkeyCache = HashMap<NodeId, PublicKey>;
pub type NeedPubkeySet = BTreeSet<NodeId>;
pub type NeighborsNeedPubkeySet = BTreeSet<NodeId>;
pub type LocationStore = HashMap<NodeId, LocationEntry>;
pub type LocationCache = HashMap<NodeId, TreeAddr>;
pub type PendingLookupMap = HashMap<NodeId, PendingLookup>;
pub type PendingRequestMap = HashMap<NodeId, PendingRequest>;
pub type PendingDataMap = HashMap<NodeId, Vec<u8>>;
pub type DistrustedMap = HashMap<NodeId, Timestamp>;
/// Messages awaiting pubkey for a specific node_id (keyed by the node whose pubkey is needed).
pub type PendingPubkeyMap = HashMap<NodeId, VecDeque<Routed>>;

/// The main protocol node.
///
/// Generic over:
/// - `T`: Transport implementation
/// - `Cr`: Crypto implementation
/// - `R`: Random number generator
/// - `Clk`: Clock/timer implementation
///
/// The node is fully event-driven. Call `run()` to start the main loop.
pub struct Node<T, Cr, R, Clk> {
    // Dependencies (injected)
    transport: T,
    crypto: Cr,
    random: R,
    clock: Clk,

    // Application-level channels
    app_incoming: AppInChannel,
    app_outgoing: AppOutChannel,
    events: EventChannel,

    // Identity
    node_id: NodeId,
    pubkey: PublicKey,
    secret: SecretKey,

    // Tree position
    parent: Option<NodeId>,
    pending_parent: Option<(NodeId, u8)>, // (candidate, pulses_waited)
    root_id: NodeId,
    tree_size: u32,
    subtree_size: u32,
    tree_addr: TreeAddr,

    // Neighbors
    children: ChildMap,
    shortcuts: ShortcutSet,
    neighbor_times: NeighborTimingMap,

    // Caches
    pubkey_cache: PubkeyCache,
    need_pubkey: NeedPubkeySet,
    neighbors_need_pubkey: NeighborsNeedPubkeySet,
    location_store: LocationStore,
    location_cache: LocationCache,

    // Pending operations
    pending_lookups: PendingLookupMap,
    #[allow(dead_code)]
    pending_requests: PendingRequestMap,
    pending_data: PendingDataMap,
    pending_pubkey: PendingPubkeyMap,

    // Fraud detection
    join_context: Option<JoinContext>,
    distrusted: DistrustedMap,
    fraud_detection: FraudDetection,

    // Scheduling
    last_pulse: Option<Timestamp>,
    last_pulse_size: usize,
    next_publish: Option<Timestamp>,
    location_seq: u32,
    proactive_pulse_pending: Option<Timestamp>,

    // Metrics
    metrics: TransportMetrics,
}

impl<T, Cr, R, Clk> Node<T, Cr, R, Clk>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Clk: Clock,
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
        Self {
            transport,
            crypto,
            random,
            clock,

            app_incoming: Channel::new(),
            app_outgoing: Channel::new(),
            events: Channel::new(),

            node_id,
            pubkey,
            secret,

            parent: None,
            pending_parent: None,
            root_id: node_id,
            tree_size: 1,
            subtree_size: 1,
            tree_addr: Vec::new(),

            children: BTreeMap::new(),
            shortcuts: BTreeSet::new(),
            neighbor_times: HashMap::new(),

            pubkey_cache: HashMap::new(),
            need_pubkey: BTreeSet::new(),
            neighbors_need_pubkey: BTreeSet::new(),
            location_store: HashMap::new(),
            location_cache: HashMap::new(),

            pending_lookups: HashMap::new(),
            pending_requests: HashMap::new(),
            pending_data: HashMap::new(),
            pending_pubkey: HashMap::new(),

            join_context: None,
            distrusted: HashMap::new(),
            fraud_detection: FraudDetection::new(),

            last_pulse: None,
            last_pulse_size: 0,
            next_publish: None,
            location_seq: 0,
            proactive_pulse_pending: None,

            metrics: TransportMetrics::new(),
        }
    }

    /// Get this node's identity.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get this node's public key.
    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    /// Get current tree address.
    pub fn tree_addr(&self) -> &TreeAddr {
        &self.tree_addr
    }

    /// Get current tree size.
    pub fn tree_size(&self) -> u32 {
        self.tree_size
    }

    /// Get current subtree size.
    pub fn subtree_size(&self) -> u32 {
        self.subtree_size
    }

    /// Get the root node ID.
    pub fn root_id(&self) -> &NodeId {
        &self.root_id
    }

    /// Check if this node is the root.
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
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

    /// Get the transport reference.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Calculate tau: the bandwidth-aware time unit.
    /// tau = MTU / bandwidth (with MIN_TAU_MS floor)
    pub fn tau(&self) -> Duration {
        use crate::types::MIN_TAU_MS;
        match self.transport.bw() {
            Some(bw) if bw > 0 => {
                let ms = (self.transport.mtu() as u64 * 1000) / bw as u64;
                Duration::from_millis(ms.max(MIN_TAU_MS))
            }
            _ => Duration::from_millis(MIN_TAU_MS),
        }
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

    /// Get transport metrics for monitoring.
    ///
    /// Returns counters for sent/dropped/received messages, split by
    /// protocol (Pulse, PUBLISH, LOOKUP, FOUND) and application (DATA).
    pub fn metrics(&self) -> &TransportMetrics {
        &self.metrics
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

        // Send first pulse immediately
        let now = self.clock.now();
        self.send_pulse(now);

        loop {
            // Calculate when we need to wake for timer work
            let next_pulse_time = self.next_pulse_time();
            let next_timeout = self.next_timeout_time();
            let timer_wake = match (next_pulse_time, next_timeout) {
                (Some(p), Some(t)) => p.min(t),
                (Some(p), None) => p,
                (None, Some(t)) => t,
                (None, None) => self.clock.now() + Duration::from_secs(60),
            };

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
    /// Returns the earlier of regular scheduled pulse or proactive pulse.
    fn next_pulse_time(&self) -> Option<Timestamp> {
        use crate::types::PULSE_BW_DIVISOR;

        let last = self.last_pulse?;

        let interval = match self.transport.bw() {
            Some(bw) if bw > 0 => {
                // Interval to stay within pulse bandwidth budget.
                // Single division for better integer accuracy:
                // secs = pulse_size / (bw / divisor) = pulse_size * divisor / bw
                let secs = (self.last_pulse_size as u64 * PULSE_BW_DIVISOR as u64) / (bw as u64);
                Duration::from_secs(secs).max(MIN_PULSE_INTERVAL)
            }
            _ => MIN_PULSE_INTERVAL,
        };

        let regular_time = last + interval;

        // Return earlier of regular pulse or proactive pulse
        match self.proactive_pulse_pending {
            Some(proactive) => Some(regular_time.min(proactive)),
            None => Some(regular_time),
        }
    }

    /// Calculate next timeout time (lookups, neighbors, locations).
    fn next_timeout_time(&self) -> Option<Timestamp> {
        // For now, check timeouts every 10 seconds
        // A more sophisticated implementation would track exact timeout times
        Some(self.clock.now() + Duration::from_secs(10))
    }

    /// Handle incoming transport message.
    fn handle_transport_rx(&mut self, data: &[u8], rssi: Option<i16>, now: Timestamp) {
        use crate::types::MSG_DATA;
        use crate::wire::{Decode, Message};

        let msg = match Message::decode_from_slice(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        match msg {
            Message::Pulse(pulse) => {
                self.record_protocol_received();
                self.handle_pulse(pulse, rssi, now);
            }
            Message::Routed(routed) => {
                if routed.msg_type == MSG_DATA {
                    self.record_app_received();
                } else {
                    self.record_protocol_received();
                }
                self.handle_routed(routed, now);
            }
        }
    }

    /// Handle application send request.
    fn handle_app_send(&mut self, data: OutgoingData, now: Timestamp) {
        let OutgoingData { target, payload } = data;

        // Check if we have the target's location cached
        if let Some(addr) = self.location_cache.get(&target).cloned() {
            // Send directly
            let _ = self.send_data_to(target, addr, payload, now);
        } else {
            // Queue data and initiate lookup
            self.pending_data.insert(target, payload);
            self.start_lookup(target, now);
        }
    }

    /// Handle timer events (pulse, timeouts).
    fn handle_timer(&mut self, now: Timestamp) {
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

        // Check for tree size fraud
        self.handle_fraud_check(now);
    }

    /// Start a lookup for a target node.
    fn start_lookup(&mut self, target: NodeId, now: Timestamp) {
        if self.pending_lookups.contains_key(&target) {
            return; // Already in progress
        }

        if self.pending_lookups.len() >= MAX_PENDING_LOOKUPS {
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

    /// Check if we have a public key cached for a node.
    pub fn has_pubkey(&self, node_id: &NodeId) -> bool {
        self.pubkey_cache.contains_key(node_id)
    }

    /// Get a cached public key.
    pub fn get_pubkey(&self, node_id: &NodeId) -> Option<&PublicKey> {
        self.pubkey_cache.get(node_id)
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

    #[allow(dead_code)]
    pub(crate) fn shortcuts(&self) -> &ShortcutSet {
        &self.shortcuts
    }

    pub(crate) fn shortcuts_mut(&mut self) -> &mut ShortcutSet {
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

    #[allow(dead_code)]
    pub(crate) fn location_cache(&self) -> &LocationCache {
        &self.location_cache
    }

    #[allow(dead_code)]
    pub(crate) fn location_cache_mut(&mut self) -> &mut LocationCache {
        &mut self.location_cache
    }

    pub(crate) fn pending_lookups(&self) -> &PendingLookupMap {
        &self.pending_lookups
    }

    pub(crate) fn pending_lookups_mut(&mut self) -> &mut PendingLookupMap {
        &mut self.pending_lookups
    }

    #[allow(dead_code)]
    pub(crate) fn pending_data(&self) -> &PendingDataMap {
        &self.pending_data
    }

    pub(crate) fn pending_data_mut(&mut self) -> &mut PendingDataMap {
        &mut self.pending_data
    }

    pub(crate) fn queue_pending_pubkey(&mut self, needed_node_id: NodeId, msg: Routed) {
        use crate::types::MAX_PENDING_PUBKEY_NODES;

        // Limit number of distinct nodes to prevent unbounded growth
        if self.pending_pubkey.len() >= MAX_PENDING_PUBKEY_NODES
            && !self.pending_pubkey.contains_key(&needed_node_id)
        {
            // Evict an arbitrary entry (first key found)
            if let Some(key) = self.pending_pubkey.keys().next().copied() {
                self.pending_pubkey.remove(&key);
            }
        }

        let queue = self.pending_pubkey.entry(needed_node_id).or_default();
        if queue.len() >= MAX_PENDING_PUBKEY {
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

    pub(crate) fn distrusted_mut(&mut self) -> &mut DistrustedMap {
        &mut self.distrusted
    }

    pub(crate) fn fraud_detection(&self) -> &FraudDetection {
        &self.fraud_detection
    }

    pub(crate) fn fraud_detection_mut(&mut self) -> &mut FraudDetection {
        &mut self.fraud_detection
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

    pub(crate) fn set_root_id(&mut self, root: NodeId) {
        self.root_id = root;
    }

    pub(crate) fn set_tree_size(&mut self, size: u32) {
        self.tree_size = size;
    }

    pub(crate) fn set_subtree_size(&mut self, size: u32) {
        self.subtree_size = size;
    }

    pub(crate) fn set_tree_addr(&mut self, addr: TreeAddr) {
        self.tree_addr = addr;
    }

    #[allow(dead_code)]
    pub(crate) fn location_seq(&self) -> u32 {
        self.location_seq
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

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }

    #[allow(dead_code)]
    pub(crate) fn crypto_mut(&mut self) -> &mut Cr {
        &mut self.crypto
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

    pub(crate) fn insert_pubkey_cache(&mut self, node_id: NodeId, pubkey: PublicKey) {
        if self.pubkey_cache.len() >= MAX_PUBKEY_CACHE && !self.pubkey_cache.contains_key(&node_id)
        {
            if let Some(key) = self.pubkey_cache.keys().next().copied() {
                self.pubkey_cache.remove(&key);
            }
        }
        self.pubkey_cache.insert(node_id, pubkey);
    }

    pub(crate) fn insert_location_store(&mut self, node_id: NodeId, entry: LocationEntry) {
        if self.location_store.len() >= MAX_LOCATION_STORE
            && !self.location_store.contains_key(&node_id)
        {
            if let Some(oldest_key) = self
                .location_store
                .iter()
                .min_by_key(|(_, e)| e.received_at)
                .map(|(k, _)| *k)
            {
                self.location_store.remove(&oldest_key);
            }
        }
        self.location_store.insert(node_id, entry);
    }

    pub(crate) fn insert_location_cache(&mut self, node_id: NodeId, addr: TreeAddr) {
        if self.location_cache.len() >= MAX_LOCATION_CACHE
            && !self.location_cache.contains_key(&node_id)
        {
            if let Some(key) = self.location_cache.keys().next().copied() {
                self.location_cache.remove(&key);
            }
        }
        self.location_cache.insert(node_id, addr);
    }

    #[allow(dead_code)]
    pub(crate) fn insert_pending_lookup(&mut self, node_id: NodeId, lookup: PendingLookup) {
        if self.pending_lookups.len() >= MAX_PENDING_LOOKUPS
            && !self.pending_lookups.contains_key(&node_id)
        {
            if let Some(oldest_key) = self
                .pending_lookups
                .iter()
                .min_by_key(|(_, l)| l.started_at)
                .map(|(k, _)| *k)
            {
                self.pending_lookups.remove(&oldest_key);
            }
        }
        self.pending_lookups.insert(node_id, lookup);
    }

    pub(crate) fn insert_neighbor_time(&mut self, node_id: NodeId, timing: NeighborTiming) {
        if self.neighbor_times.len() >= MAX_NEIGHBORS && !self.neighbor_times.contains_key(&node_id)
        {
            if let Some(oldest_key) = self
                .neighbor_times
                .iter()
                .min_by_key(|(_, t)| t.last_seen)
                .map(|(k, _)| *k)
            {
                self.neighbor_times.remove(&oldest_key);
            }
        }
        self.neighbor_times.insert(node_id, timing);
    }

    #[allow(dead_code)]
    pub(crate) fn insert_pending_data(&mut self, node_id: NodeId, payload: Vec<u8>) {
        if self.pending_data.len() >= MAX_PENDING_DATA && !self.pending_data.contains_key(&node_id)
        {
            if let Some(key) = self.pending_data.keys().next().copied() {
                self.pending_data.remove(&key);
            }
        }
        self.pending_data.insert(node_id, payload);
    }

    pub(crate) fn insert_distrusted(&mut self, node_id: NodeId, timestamp: Timestamp) {
        if self.distrusted.len() >= MAX_DISTRUSTED && !self.distrusted.contains_key(&node_id) {
            if let Some(oldest_key) = self
                .distrusted
                .iter()
                .min_by_key(|(_, &ts)| ts)
                .map(|(k, _)| *k)
            {
                self.distrusted.remove(&oldest_key);
            }
        }
        self.distrusted.insert(node_id, timestamp);
    }
}
