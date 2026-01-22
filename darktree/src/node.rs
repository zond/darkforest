//! Node implementation - the main protocol state machine.
//!
//! The Node struct holds all protocol state and provides the public API for:
//! - Sending data to other nodes
//! - Looking up node locations
//! - Processing received messages
//! - Emitting events to the application

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::fraud::FraudDetection;
use crate::traits::{Clock, Crypto, Random, Transport};
use crate::types::{
    Error, Event, LocationEntry, NodeId, Payload, PublicKey, Routed, SecretKey, TreeAddr,
    DEFAULT_PULSE_INTERVAL_SECS, MAX_DISTRUSTED, MAX_LOCATION_CACHE, MAX_LOCATION_STORE,
    MAX_NEIGHBORS, MAX_PACKET_SIZE, MAX_PENDING_DATA, MAX_PENDING_LOOKUPS, MAX_PENDING_PUBKEY,
    MAX_PUBKEY_CACHE,
};
use crate::wire::{Decode, Message};

/// Timing information for a neighbor.
#[derive(Clone, Copy, Debug)]
pub struct NeighborTiming {
    /// Last time we received a Pulse from this neighbor (seconds).
    pub last_seen_secs: u64,
    /// Previous Pulse time (for interval estimation).
    pub prev_seen_secs: Option<u64>,
}

/// Pending lookup state.
#[derive(Clone, Debug)]
pub struct PendingLookup {
    /// Current replica index being tried (0, 1, or 2).
    pub replica_index: usize,
    /// When the lookup started (seconds).
    pub started_secs: u64,
    /// When current replica query was sent (seconds).
    pub last_query_secs: u64,
}

/// Pending request state (for request-response patterns).
#[derive(Clone, Debug)]
pub struct PendingRequest {
    /// Data to send.
    pub data: Payload,
    /// When the request was sent (seconds).
    pub sent_at_secs: u64,
    /// Number of retries so far.
    pub retries: u8,
}

/// Context for fraud detection when joining a tree.
#[derive(Clone, Debug)]
pub struct JoinContext {
    /// Parent node when we joined.
    pub parent_at_join: NodeId,
    /// Time when we joined (seconds).
    pub join_time_secs: u64,
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
pub type PendingDataMap = HashMap<NodeId, Payload>;
pub type DistrustedMap = HashMap<NodeId, u64>;
pub type EventQueue = VecDeque<Event>;
/// Messages awaiting pubkey for a specific node_id (keyed by the node whose pubkey is needed).
pub type PendingPubkeyMap = HashMap<NodeId, VecDeque<Routed>>;

/// The main protocol node.
///
/// Generic over:
/// - `T`: Transport implementation
/// - `Cr`: Crypto implementation
/// - `R`: Random number generator
/// - `Cl`: Clock implementation
pub struct Node<T, Cr, R, Cl> {
    // Dependencies (injected)
    transport: T,
    crypto: Cr,
    random: R,
    clock: Cl,

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
    neighbors_need_pubkey: NeighborsNeedPubkeySet, // Neighbors that signaled need_pubkey=true
    location_store: LocationStore,
    location_cache: LocationCache,

    // Pending operations
    pending_lookups: PendingLookupMap,
    #[allow(dead_code)] // Reserved for future request-response patterns
    pending_requests: PendingRequestMap,
    pending_data: PendingDataMap,
    pending_pubkey: PendingPubkeyMap, // Messages awaiting pubkey verification

    // Fraud detection
    join_context: Option<JoinContext>,
    distrusted: DistrustedMap,
    fraud_detection: FraudDetection,

    // Scheduling
    last_pulse_secs: Option<u64>,
    next_publish_secs: Option<u64>,
    location_seq: u32,

    // Event queue for application
    events: EventQueue,
}

impl<T, Cr, R, Cl> Node<T, Cr, R, Cl>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
    Cl: Clock,
{
    /// Create a new node with a fresh identity.
    pub fn new(transport: T, mut crypto: Cr, random: R, clock: Cl) -> Self {
        let (pubkey, secret) = crypto.generate_keypair();
        let node_id = crypto.node_id_from_pubkey(&pubkey);

        Self::with_identity(transport, crypto, random, clock, node_id, pubkey, secret)
    }

    /// Create a node with an existing identity.
    pub fn with_identity(
        transport: T,
        crypto: Cr,
        random: R,
        clock: Cl,
        node_id: NodeId,
        pubkey: PublicKey,
        secret: SecretKey,
    ) -> Self {
        Self {
            transport,
            crypto,
            random,
            clock,

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

            last_pulse_secs: None,
            next_publish_secs: None,
            location_seq: 0,

            events: VecDeque::new(),
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

    /// Get the transport reference.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Get the transport mutably.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Get the crypto reference.
    pub fn crypto(&self) -> &Cr {
        &self.crypto
    }

    /// Poll the node - call this regularly to process messages and timers.
    ///
    /// Returns events that the application should handle.
    pub fn poll(&mut self) -> Option<Event> {
        let now = self.clock.now_secs();

        // Process incoming messages
        let mut buf = [0u8; MAX_PACKET_SIZE];
        while let Some((len, rssi)) = self.transport.rx(&mut buf) {
            self.handle_rx(&buf[..len], rssi, now);
        }

        // Check if we should send a Pulse
        if self.should_send_pulse(now) {
            self.send_pulse(now);
        }

        // Check for location publish
        if self.should_publish_location(now) {
            self.publish_location(now);
        }

        // Handle timeouts
        self.handle_timeouts(now);

        // Return next event if any
        self.pop_event()
    }

    /// Pop the next event from the queue.
    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Queue an event for the application.
    pub(crate) fn push_event(&mut self, event: Event) {
        self.events.push_back(event);
    }

    /// Send data to a target node.
    ///
    /// If we have the target's location cached, sends immediately.
    /// Otherwise, initiates a lookup and queues the data.
    pub fn send(&mut self, target: NodeId, data: Payload) -> Result<(), Error<T::Error>> {
        let now = self.clock.now_secs();

        // Check if we have the location cached
        if let Some(addr) = self.location_cache.get(&target).cloned() {
            self.send_data_to(target, addr, data, now)
        } else {
            // Queue data and initiate lookup
            self.pending_data.insert(target, data);
            self.lookup(target)?;
            Ok(())
        }
    }

    /// Lookup a node's tree address.
    ///
    /// Result comes via Event::LookupComplete or Event::LookupFailed.
    pub fn lookup(&mut self, target: NodeId) -> Result<(), Error<T::Error>> {
        let now = self.clock.now_secs();

        // Check if lookup already pending
        if self.pending_lookups.contains_key(&target) {
            return Err(Error::LookupPending);
        }

        // Start lookup at replica 0
        let lookup = PendingLookup {
            replica_index: 0,
            started_secs: now,
            last_query_secs: now,
        };
        self.pending_lookups.insert(target, lookup);

        self.send_lookup(target, 0, now);
        Ok(())
    }

    /// Check if we have a public key cached for a node.
    pub fn has_pubkey(&self, node_id: &NodeId) -> bool {
        self.pubkey_cache.contains_key(node_id)
    }

    /// Get a cached public key.
    pub fn get_pubkey(&self, node_id: &NodeId) -> Option<&PublicKey> {
        self.pubkey_cache.get(node_id)
    }

    /// Handle a received message.
    fn handle_rx(&mut self, data: &[u8], _rssi: Option<i16>, now: u64) {
        // Decode message
        let msg = match Message::decode_from_slice(data) {
            Ok(m) => m,
            Err(_) => return, // Invalid message, ignore
        };

        match msg {
            Message::Pulse(pulse) => self.handle_pulse(pulse, now),
            Message::Routed(routed) => self.handle_routed(routed, now),
        }
    }

    /// Check if we should send a pulse now.
    fn should_send_pulse(&self, now: u64) -> bool {
        // Check transport backoff
        if self.transport.tx_backoff() > 0 {
            return false;
        }

        // Calculate pulse interval based on bandwidth
        let interval = self.pulse_interval();

        match self.last_pulse_secs {
            Some(last) => now >= last + interval,
            None => true, // First pulse
        }
    }

    /// Calculate pulse interval based on transport bandwidth.
    fn pulse_interval(&self) -> u64 {
        match self.transport.bandwidth() {
            Some(bw) => {
                // Pulse budget = 20% of effective bandwidth
                let pulse_size = 180u32; // Approximate average pulse size
                let pulse_budget_bps = (bw as f32 * 0.20) as u32;
                if pulse_budget_bps == 0 {
                    return DEFAULT_PULSE_INTERVAL_SECS;
                }
                let interval = pulse_size / pulse_budget_bps;
                interval.max(10) as u64 // Minimum 10 seconds
            }
            None => DEFAULT_PULSE_INTERVAL_SECS,
        }
    }

    /// Check if we should publish location now.
    fn should_publish_location(&self, now: u64) -> bool {
        match self.next_publish_secs {
            Some(next) => now >= next,
            None => true, // First publish
        }
    }

    /// Get the current time from the clock.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn now(&self) -> u64 {
        self.clock.now_secs()
    }

    /// Access children map.
    pub(crate) fn children(&self) -> &ChildMap {
        &self.children
    }

    /// Access children map mutably.
    pub(crate) fn children_mut(&mut self) -> &mut ChildMap {
        &mut self.children
    }

    /// Access shortcuts set.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn shortcuts(&self) -> &ShortcutSet {
        &self.shortcuts
    }

    /// Access shortcuts set mutably.
    pub(crate) fn shortcuts_mut(&mut self) -> &mut ShortcutSet {
        &mut self.shortcuts
    }

    /// Access neighbor timings.
    pub(crate) fn neighbor_times(&self) -> &NeighborTimingMap {
        &self.neighbor_times
    }

    /// Access neighbor timings mutably.
    pub(crate) fn neighbor_times_mut(&mut self) -> &mut NeighborTimingMap {
        &mut self.neighbor_times
    }

    /// Access pubkey cache.
    pub(crate) fn pubkey_cache(&self) -> &PubkeyCache {
        &self.pubkey_cache
    }

    /// Access pubkey cache mutably.
    pub(crate) fn pubkey_cache_mut(&mut self) -> &mut PubkeyCache {
        &mut self.pubkey_cache
    }

    /// Access need_pubkey set.
    pub(crate) fn need_pubkey(&self) -> &NeedPubkeySet {
        &self.need_pubkey
    }

    /// Access need_pubkey set mutably.
    pub(crate) fn need_pubkey_mut(&mut self) -> &mut NeedPubkeySet {
        &mut self.need_pubkey
    }

    /// Access neighbors_need_pubkey set (neighbors that signaled need_pubkey=true).
    pub(crate) fn neighbors_need_pubkey(&self) -> &NeighborsNeedPubkeySet {
        &self.neighbors_need_pubkey
    }

    /// Access neighbors_need_pubkey set mutably.
    pub(crate) fn neighbors_need_pubkey_mut(&mut self) -> &mut NeighborsNeedPubkeySet {
        &mut self.neighbors_need_pubkey
    }

    /// Access location store.
    pub(crate) fn location_store(&self) -> &LocationStore {
        &self.location_store
    }

    /// Access location store mutably.
    pub(crate) fn location_store_mut(&mut self) -> &mut LocationStore {
        &mut self.location_store
    }

    /// Access location cache.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn location_cache(&self) -> &LocationCache {
        &self.location_cache
    }

    /// Access location cache mutably.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn location_cache_mut(&mut self) -> &mut LocationCache {
        &mut self.location_cache
    }

    /// Access pending lookups.
    pub(crate) fn pending_lookups(&self) -> &PendingLookupMap {
        &self.pending_lookups
    }

    /// Access pending lookups mutably.
    pub(crate) fn pending_lookups_mut(&mut self) -> &mut PendingLookupMap {
        &mut self.pending_lookups
    }

    /// Access pending data.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn pending_data(&self) -> &PendingDataMap {
        &self.pending_data
    }

    /// Access pending data mutably.
    pub(crate) fn pending_data_mut(&mut self) -> &mut PendingDataMap {
        &mut self.pending_data
    }

    /// Queue a message awaiting pubkey for a node.
    /// Evicts oldest message if queue is full.
    pub(crate) fn queue_pending_pubkey(&mut self, needed_node_id: NodeId, msg: Routed) {
        let queue = self.pending_pubkey.entry(needed_node_id).or_default();

        // Evict oldest if at capacity
        if queue.len() >= MAX_PENDING_PUBKEY {
            queue.pop_front();
        }

        queue.push_back(msg);
    }

    /// Take all messages awaiting pubkey for a node.
    pub(crate) fn take_pending_pubkey(&mut self, node_id: &NodeId) -> Option<VecDeque<Routed>> {
        self.pending_pubkey.remove(node_id)
    }

    /// Access distrusted map.
    pub(crate) fn distrusted(&self) -> &DistrustedMap {
        &self.distrusted
    }

    /// Access distrusted map mutably.
    pub(crate) fn distrusted_mut(&mut self) -> &mut DistrustedMap {
        &mut self.distrusted
    }

    /// Access fraud detection state.
    pub(crate) fn fraud_detection(&self) -> &FraudDetection {
        &self.fraud_detection
    }

    /// Access fraud detection state mutably.
    pub(crate) fn fraud_detection_mut(&mut self) -> &mut FraudDetection {
        &mut self.fraud_detection
    }

    /// Access join context.
    pub(crate) fn join_context(&self) -> &Option<JoinContext> {
        &self.join_context
    }

    /// Set join context.
    pub(crate) fn set_join_context(&mut self, ctx: Option<JoinContext>) {
        self.join_context = ctx;
    }

    /// Get parent.
    pub(crate) fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    /// Set parent.
    pub(crate) fn set_parent(&mut self, parent: Option<NodeId>) {
        self.parent = parent;
    }

    /// Get pending parent.
    pub(crate) fn pending_parent(&self) -> Option<(NodeId, u8)> {
        self.pending_parent
    }

    /// Set pending parent.
    pub(crate) fn set_pending_parent(&mut self, pending: Option<(NodeId, u8)>) {
        self.pending_parent = pending;
    }

    /// Set root ID.
    pub(crate) fn set_root_id(&mut self, root: NodeId) {
        self.root_id = root;
    }

    /// Set tree size.
    pub(crate) fn set_tree_size(&mut self, size: u32) {
        self.tree_size = size;
    }

    /// Set subtree size.
    pub(crate) fn set_subtree_size(&mut self, size: u32) {
        self.subtree_size = size;
    }

    /// Set tree address.
    pub(crate) fn set_tree_addr(&mut self, addr: TreeAddr) {
        self.tree_addr = addr;
    }

    /// Get location sequence number.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn location_seq(&self) -> u32 {
        self.location_seq
    }

    /// Increment and return location sequence number.
    pub(crate) fn next_location_seq(&mut self) -> u32 {
        self.location_seq = self.location_seq.wrapping_add(1);
        self.location_seq
    }

    /// Set next publish time.
    pub(crate) fn set_next_publish_secs(&mut self, secs: Option<u64>) {
        self.next_publish_secs = secs;
    }

    /// Set last pulse time.
    pub(crate) fn set_last_pulse_secs(&mut self, secs: Option<u64>) {
        self.last_pulse_secs = secs;
    }

    /// Access secret key.
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Access crypto.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn crypto_mut(&mut self) -> &mut Cr {
        &mut self.crypto
    }

    /// Access random.
    pub(crate) fn random_mut(&mut self) -> &mut R {
        &mut self.random
    }

    // --- Bounded insertion helpers ---
    // These methods enforce MAX_* limits with eviction when full

    /// Insert into pubkey cache with bounds enforcement.
    pub(crate) fn insert_pubkey_cache(&mut self, node_id: NodeId, pubkey: PublicKey) {
        if self.pubkey_cache.len() >= MAX_PUBKEY_CACHE && !self.pubkey_cache.contains_key(&node_id)
        {
            // Evict first entry (arbitrary eviction policy)
            if let Some(key) = self.pubkey_cache.keys().next().copied() {
                self.pubkey_cache.remove(&key);
            }
        }
        self.pubkey_cache.insert(node_id, pubkey);
    }

    /// Insert into location store with bounds enforcement.
    pub(crate) fn insert_location_store(&mut self, node_id: NodeId, entry: LocationEntry) {
        if self.location_store.len() >= MAX_LOCATION_STORE
            && !self.location_store.contains_key(&node_id)
        {
            // Evict oldest entry by received_at_secs
            if let Some(oldest_key) = self
                .location_store
                .iter()
                .min_by_key(|(_, e)| e.received_at_secs)
                .map(|(k, _)| *k)
            {
                self.location_store.remove(&oldest_key);
            }
        }
        self.location_store.insert(node_id, entry);
    }

    /// Insert into location cache with bounds enforcement.
    pub(crate) fn insert_location_cache(&mut self, node_id: NodeId, addr: TreeAddr) {
        if self.location_cache.len() >= MAX_LOCATION_CACHE
            && !self.location_cache.contains_key(&node_id)
        {
            // Evict first entry (arbitrary eviction policy)
            if let Some(key) = self.location_cache.keys().next().copied() {
                self.location_cache.remove(&key);
            }
        }
        self.location_cache.insert(node_id, addr);
    }

    /// Insert into pending lookups with bounds enforcement.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn insert_pending_lookup(&mut self, node_id: NodeId, lookup: PendingLookup) {
        if self.pending_lookups.len() >= MAX_PENDING_LOOKUPS
            && !self.pending_lookups.contains_key(&node_id)
        {
            // Evict oldest by started_at
            if let Some(oldest_key) = self
                .pending_lookups
                .iter()
                .min_by_key(|(_, l)| l.started_secs)
                .map(|(k, _)| *k)
            {
                self.pending_lookups.remove(&oldest_key);
            }
        }
        self.pending_lookups.insert(node_id, lookup);
    }

    /// Insert into neighbor times with bounds enforcement.
    pub(crate) fn insert_neighbor_time(&mut self, node_id: NodeId, timing: NeighborTiming) {
        if self.neighbor_times.len() >= MAX_NEIGHBORS && !self.neighbor_times.contains_key(&node_id)
        {
            // Evict oldest by last_seen_secs
            if let Some(oldest_key) = self
                .neighbor_times
                .iter()
                .min_by_key(|(_, t)| t.last_seen_secs)
                .map(|(k, _)| *k)
            {
                self.neighbor_times.remove(&oldest_key);
            }
        }
        self.neighbor_times.insert(node_id, timing);
    }

    /// Insert into pending data with bounds enforcement.
    #[allow(dead_code)] // Part of internal API
    pub(crate) fn insert_pending_data(&mut self, node_id: NodeId, payload: Payload) {
        if self.pending_data.len() >= MAX_PENDING_DATA && !self.pending_data.contains_key(&node_id)
        {
            // Evict first entry (arbitrary eviction policy)
            if let Some(key) = self.pending_data.keys().next().copied() {
                self.pending_data.remove(&key);
            }
        }
        self.pending_data.insert(node_id, payload);
    }

    /// Insert into distrusted map with bounds enforcement.
    pub(crate) fn insert_distrusted(&mut self, node_id: NodeId, timestamp: u64) {
        if self.distrusted.len() >= MAX_DISTRUSTED && !self.distrusted.contains_key(&node_id) {
            // Evict oldest by distrust timestamp
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
