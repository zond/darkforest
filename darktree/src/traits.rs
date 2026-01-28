//! Core traits for transport, cryptography, time, and randomness abstraction.
//!
//! These traits allow the protocol to be used with different:
//! - Transport layers (LoRa, BLE, UDP, simulation)
//! - Cryptographic implementations (software, hardware accelerated)
//! - Time sources (real hardware time, simulated time)
//! - Random number generators

use alloc::vec::Vec;
use core::future::Future;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

use crate::time::Timestamp;
use crate::types::{
    Event, Incoming, NodeId, Payload, PreEncoded, Priority, PublicKey, SecretKey, Signature,
};

/// Queue size for transport channels.
pub(crate) const TRANSPORT_QUEUE_SIZE: usize = 8;

/// Queue size for application-level channels.
pub(crate) const APP_QUEUE_SIZE: usize = 8;

/// Queue size for event channel.
pub(crate) const EVENT_QUEUE_SIZE: usize = 16;

/// Mutex type used for channels.
pub(crate) type ChannelMutex = CriticalSectionRawMutex;

/// Incoming transport message channel type.
pub type TransportInChannel = Channel<ChannelMutex, Incoming, TRANSPORT_QUEUE_SIZE>;

/// Data received from another node (application level).
#[derive(Debug, Clone)]
pub struct IncomingData {
    /// Node that sent this data.
    pub from: NodeId,
    /// Payload data.
    pub payload: Payload,
}

/// Data to send to another node (application level).
#[derive(Debug, Clone)]
pub struct OutgoingData {
    /// Target node to send to.
    pub target: NodeId,
    /// Payload data.
    pub payload: Payload,
}

/// Application-level incoming data channel.
pub type AppInChannel = Channel<ChannelMutex, IncomingData, APP_QUEUE_SIZE>;

/// Application-level outgoing data channel.
pub type AppOutChannel = Channel<ChannelMutex, OutgoingData, APP_QUEUE_SIZE>;

/// Protocol event channel.
pub type EventChannel = Channel<ChannelMutex, Event, EVENT_QUEUE_SIZE>;

/// Trait for messages that can be sent via the priority queue.
pub trait Outgoing {
    /// Returns the priority of this message.
    fn priority(&self) -> Priority;

    /// Encodes the message to bytes.
    fn encode(&self) -> Vec<u8>;
}

/// Trait for messages that can be acknowledged.
///
/// Implemented by `Routed` and `Broadcast` - the message types that support
/// ACK-based reliability. The hash is computed from the message's signing data
/// (excluding TTL for Routed, so it's invariant across hops).
pub trait Ackable {
    /// Compute the 4-byte ACK hash using the provided crypto.
    ///
    /// The hash uniquely identifies this message for duplicate detection
    /// and acknowledgment tracking.
    fn ack_hash<C: Crypto>(&self, crypto: &C) -> [u8; 4];
}

impl Outgoing for PreEncoded {
    fn priority(&self) -> Priority {
        self.priority
    }

    fn encode(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// Priority queue for outgoing messages.
///
/// Messages are stored by priority and sequence number, ensuring:
/// - Higher priority messages are sent first
/// - Within the same priority, FIFO ordering is maintained
///
/// The queue has a configurable maximum size. When full, the lowest-priority
/// message is dropped to make room for new messages (unless the new message
/// is itself the lowest priority, in which case it's rejected).
///
/// # Design Choice: `alloc` + `BTreeMap`
///
/// This crate requires the `alloc` crate and uses `BTreeMap` for priority ordering.
/// This is a deliberate choice for our target platforms (ESP32-class devices with
/// 256KB+ RAM). Alternatives considered:
///
/// - **Multiple embassy Channels (one per priority)**: Simpler, but loses cross-priority
///   eviction (can't drop low-priority to make room for high-priority when full).
///   Also complicates async receive (must poll 5 channels).
///
/// - **`heapless` collections**: Would require compile-time capacity constants and
///   doesn't support priority ordering without manual sorting.
///
/// **Heap fragmentation** is not a practical concern because:
/// 1. Queue sizes are small (8-32 entries)
/// 2. Message rates are low (LoRa tau ≈ 6.7 seconds)
/// 3. Modern embedded allocators like `embedded-alloc` with TLSF handle this well
///    (O(1) alloc/free, 4-byte overhead per allocation, designed for real-time)
///
/// If you're integrating darktree, use `embedded-alloc::TlsfHeap` or your platform's
/// allocator (e.g., `esp-alloc` for ESP32). Avoid simple allocators like
/// `linked_list_allocator` or `wee_alloc` which fragment poorly.
///
/// # Interrupt Safety
///
/// This queue uses `CriticalSectionRawMutex` which disables interrupts during
/// lock operations. This provides the following safety guarantees:
///
/// - **ISR-safe for `try_send`**: Radio RX interrupt handlers can safely call
///   `incoming().try_send()` to deliver received messages.
/// - **Task-safe for all operations**: Any async task can call `try_send`,
///   `try_receive`, or `receive`.
/// - **No deadlock risk**: Critical sections are short (priority check + insert/remove).
///   Message encoding happens BEFORE acquiring the lock to minimize interrupt latency.
///
/// # Critical Section Duration
///
/// With queue sizes of 8-32 entries and BTreeMap O(log n) operations:
/// - `try_send`: ~5-15µs (priority check + optional eviction + insert)
/// - `try_receive`: ~2-5µs (pop_first)
///
/// **Note:** These estimates assume a fast allocator (TLSF, dlmalloc). With a slow
/// allocator like `linked_list_allocator`, BTreeMap operations can take 10-100×
/// longer due to heap fragmentation and O(n) free-list traversal.
///
/// # Usage Contract
///
/// - Radio ISR → `transport.incoming().try_send()` (delivers raw bytes)
/// - Protocol task → `transport.outgoing().try_send(msg)` (queues encoded messages)
/// - Transmit task → `transport.outgoing().receive()` (dequeues for transmission)
pub struct PriorityQueue {
    /// Storage: BTreeMap sorted by (priority, sequence) for automatic ordering.
    inner:
        embassy_sync::blocking_mutex::Mutex<ChannelMutex, core::cell::RefCell<PriorityQueueInner>>,
    /// Signal for async notification when items are added.
    signal: embassy_sync::signal::Signal<ChannelMutex, ()>,
}

struct PriorityQueueInner {
    items: alloc::collections::BTreeMap<(Priority, u64), Vec<u8>>,
    next_seq: u64,
    max_size: usize,
}

impl PriorityQueue {
    /// Create a new priority queue with the specified maximum size.
    pub const fn new(max_size: usize) -> Self {
        Self {
            inner: embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(
                PriorityQueueInner {
                    items: alloc::collections::BTreeMap::new(),
                    next_seq: 0,
                    max_size,
                },
            )),
            signal: embassy_sync::signal::Signal::new(),
        }
    }

    /// Try to send a message with the given priority.
    ///
    /// Returns true if the message was queued, false if rejected.
    /// When the queue is full:
    /// - If the new message has higher priority than the lowest in queue, drop lowest and accept
    /// - Otherwise, reject the new message
    ///
    /// # Optimization: Pre-check Before Encoding
    ///
    /// This method checks capacity/priority before calling `msg.encode()` to avoid
    /// unnecessary allocation when the message would be rejected. This requires two
    /// brief critical sections instead of one, but avoids wasting memory when the
    /// queue is full of higher-priority messages.
    ///
    /// # Race Window Between Critical Sections
    ///
    /// There is an intentional race window between the pre-check and insert:
    /// 1. Pre-check says "queue has room or we can evict"
    /// 2. Another context fills the queue with higher-priority messages
    /// 3. We encode (potentially expensive for cryptographic signing)
    /// 4. Re-check may now reject us (wasted encoding work)
    ///
    /// This is the correct tradeoff: the alternative (holding the lock during
    /// encoding) would block all other contexts from sending, which is worse
    /// for real-time systems. At LoRa message rates (~6.7s between messages),
    /// this race is extremely unlikely to occur in practice.
    pub fn try_send<T: Outgoing>(&self, msg: T) -> bool {
        let priority = msg.priority();

        // Quick pre-check: would this priority be accepted?
        // Avoids encoding (allocation) when we'd definitely be rejected.
        let dominated_by_higher = self.inner.lock(|cell| {
            let inner = cell.borrow();
            if inner.items.len() < inner.max_size {
                false // Queue has room, will accept
            } else if let Some((&lowest_key, _)) = inner.items.last_key_value() {
                priority >= lowest_key.0 // Would be rejected (same or lower priority)
            } else {
                true // max_size=0, always reject
            }
        });

        if dominated_by_higher {
            return false;
        }

        // Now encode (may allocate)
        let data = msg.encode();

        // Insert with re-check (queue state may have changed between checks)
        let success = self.inner.lock(|cell| {
            let mut inner = cell.borrow_mut();

            // Re-check: queue may have filled since pre-check
            if inner.items.len() >= inner.max_size {
                if let Some((&lowest_key, _)) = inner.items.last_key_value() {
                    if priority >= lowest_key.0 {
                        return false;
                    }
                    inner.items.pop_last();
                } else {
                    return false;
                }
            }

            let seq = inner.next_seq;
            inner.next_seq = inner.next_seq.wrapping_add(1);
            inner.items.insert((priority, seq), data);
            true
        });

        if success {
            self.signal.signal(());
        }
        success
    }

    /// Try to receive the highest-priority message without blocking.
    ///
    /// Returns the message data if available, None if queue is empty.
    pub fn try_receive(&self) -> Option<Vec<u8>> {
        self.inner.lock(|cell| {
            let mut inner = cell.borrow_mut();
            // First entry has lowest key = highest priority
            inner.items.pop_first().map(|(_, data)| data)
        })
    }

    /// Wait for and receive the highest-priority message.
    pub async fn receive(&self) -> Vec<u8> {
        loop {
            if let Some(data) = self.try_receive() {
                return data;
            }
            self.signal.wait().await;
        }
    }

    /// Returns the number of messages currently in the queue.
    pub fn len(&self) -> usize {
        self.inner.lock(|cell| cell.borrow().items.len())
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Transport trait for radio/network backends.
///
/// Provides two channels:
/// - `outgoing()`: Priority queue for all outgoing messages
/// - `incoming()`: Channel for received messages (decodable to protocol messages)
///
/// # Priority Model
///
/// The outgoing priority queue automatically orders messages by priority:
/// 1. Ack (highest) - Link-layer reliability
/// 2. BroadcastProtocol - DHT backup (BACKUP_PUBLISH)
/// 3. RoutedProtocol - DHT operations (PUBLISH, LOOKUP, FOUND)
/// 4. BroadcastData - Application broadcast
/// 5. RoutedData (lowest) - Application unicast
///
/// Pulse messages are sent directly (timer-driven) and bypass the queue.
///
/// # Usage Pattern
///
/// ```
/// use darktree::traits::test_impls::MockTransport;
/// use darktree::traits::{Transport, Outgoing};
/// use darktree::Priority;
///
/// // Simple wrapper for raw bytes with priority
/// struct PriorityMessage { priority: Priority, data: Vec<u8> }
/// impl Outgoing for PriorityMessage {
///     fn priority(&self) -> Priority { self.priority }
///     fn encode(&self) -> Vec<u8> { self.data.clone() }
/// }
///
/// let transport = MockTransport::new();
///
/// // Send messages with different priorities
/// transport.outgoing().try_send(PriorityMessage {
///     priority: Priority::RoutedData,
///     data: vec![1, 2, 3],
/// });
/// transport.outgoing().try_send(PriorityMessage {
///     priority: Priority::Ack,
///     data: vec![4, 5, 6],
/// });
///
/// // Receive returns highest priority first
/// assert_eq!(transport.outgoing().try_receive(), Some(vec![4, 5, 6])); // Ack first
/// assert_eq!(transport.outgoing().try_receive(), Some(vec![1, 2, 3])); // Then data
/// ```
pub trait Transport {
    /// Maximum transmission unit for this transport.
    ///
    /// Protocol MUST check message size before sending.
    /// - LoRa: 255 bytes
    /// - BLE extended advertising: 252 bytes
    /// - UDP: 512 bytes (safe across all paths)
    fn mtu(&self) -> usize;

    /// Available bandwidth in bytes per second, if known.
    ///
    /// Returns `None` for transports with effectively unlimited bandwidth (UDP, etc.)
    /// where protocol-level rate limiting isn't needed.
    ///
    /// Returns `Some(bytes_per_second)` for constrained transports (LoRa, BLE, etc.)
    /// where the Node should limit its transmission rate.
    fn bw(&self) -> Option<u32> {
        None
    }

    /// Priority queue for outgoing messages.
    ///
    /// Messages are automatically ordered by priority and sent highest-first.
    /// Within the same priority level, FIFO order is maintained.
    fn outgoing(&self) -> &PriorityQueue;

    /// Channel for incoming messages.
    ///
    /// - Radio ISR calls `incoming().try_send(msg)` when data received
    /// - Simulator calls `incoming().try_send(msg)` to deliver messages
    /// - Node calls `incoming().receive().await` to receive
    fn incoming(&self) -> &TransportInChannel;

    /// Check if the given RSSI indicates acceptable link quality.
    ///
    /// Returns `false` for RSSI values below the transport's reliability threshold.
    /// Returns `true` for acceptable values or when RSSI is not applicable.
    ///
    /// Default implementation accepts all RSSI values (no filtering).
    /// Radio transports should override with appropriate thresholds:
    /// - LoRa: -110 dBm (margin above -120 dBm noise floor)
    /// - WiFi: -80 dBm
    /// - Bluetooth: -90 dBm
    fn is_acceptable_rssi(&self, rssi: Option<i16>) -> bool {
        let _ = rssi;
        true
    }
}

/// Time source trait for real or simulated time.
///
/// Allows the protocol to work with:
/// - Real hardware time (embassy_time, std::time)
/// - Simulated time (controlled by simulator for deterministic testing)
///
/// # Example (testing with MockClock)
///
/// ```
/// use darktree::traits::test_impls::MockClock;
/// use darktree::{Clock, Duration, Timestamp};
///
/// let clock = MockClock::new();
/// assert_eq!(clock.now(), Timestamp::ZERO);
///
/// // Advance time manually
/// clock.advance(Duration::from_secs(10));
/// assert_eq!(clock.now(), Timestamp::from_secs(10));
///
/// // Set to specific time
/// clock.set(Timestamp::from_millis(5000));
/// assert_eq!(clock.now().as_millis(), 5000);
/// ```
///
/// # Example (embedded with embassy)
///
/// ```text
/// struct EmbassyClock;
///
/// impl Clock for EmbassyClock {
///     type SleepFuture<'a> = impl Future<Output = ()>;
///
///     fn now(&self) -> Timestamp {
///         Timestamp::from_millis(embassy_time::Instant::now().as_millis())
///     }
///
///     fn sleep_until(&self, time: Timestamp) -> Self::SleepFuture<'_> {
///         embassy_time::Timer::at(embassy_time::Instant::from_millis(time.as_millis()))
///     }
/// }
/// ```
pub trait Clock {
    /// Future type returned by sleep_until.
    type SleepFuture<'a>: Future<Output = ()>
    where
        Self: 'a;

    /// Get the current timestamp.
    fn now(&self) -> Timestamp;

    /// Sleep until the given timestamp.
    ///
    /// For simulation, this should complete when the simulator advances
    /// time past the given timestamp.
    fn sleep_until(&self, time: Timestamp) -> Self::SleepFuture<'_>;
}

/// Cryptographic operations trait.
///
/// Allows plugging in different implementations:
/// - Software (ed25519-dalek)
/// - Hardware accelerated (STM32 CRYP, nRF CryptoCell)
/// - HSM/secure element
pub trait Crypto {
    /// Returns the algorithm identifier.
    ///
    /// Currently defined:
    /// - `0x01` = Ed25519
    fn algorithm(&self) -> u8;

    /// Sign a message with the secret key.
    ///
    /// Returns a Signature containing the algorithm byte and 64-byte signature.
    fn sign(&self, secret: &SecretKey, message: &[u8]) -> Signature;

    /// Verify a signature against a message and public key.
    ///
    /// Returns `false` if:
    /// - Algorithm doesn't match
    /// - Signature is invalid
    /// - Public key is invalid
    fn verify(&self, pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool;

    /// Generate a new keypair.
    ///
    /// Returns (public_key, secret_key).
    fn generate_keypair(&mut self) -> (PublicKey, SecretKey);

    /// Hash data using SHA-256.
    ///
    /// Returns 32-byte hash.
    fn hash(&self, data: &[u8]) -> [u8; 32];

    /// Derive a NodeId from a public key.
    ///
    /// Default implementation: first 16 bytes of SHA-256(pubkey).
    fn node_id_from_pubkey(&self, pubkey: &PublicKey) -> NodeId {
        let hash = self.hash(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        id
    }

    /// Verify that a public key correctly derives to the claimed node ID.
    ///
    /// CRITICAL: Always verify this before trusting a pubkey!
    fn verify_pubkey_binding(&self, node_id: &NodeId, pubkey: &PublicKey) -> bool {
        self.node_id_from_pubkey(pubkey) == *node_id
    }
}

/// Random number generator trait.
///
/// Used for:
/// - Republish jitter
/// - Tiebreaking
pub trait Random {
    /// Generate a random u64 in the range [min, max).
    fn gen_range(&mut self, min: u64, max: u64) -> u64;

    /// Generate a random u32.
    fn gen_u32(&mut self) -> u32 {
        self.gen_range(0, u32::MAX as u64 + 1) as u32
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_impls {
    //! Mock implementations of traits for unit testing and doc tests.
    //!
    //! Available when running tests or with the `test-support` feature enabled.

    use core::cell::Cell;
    use core::future::{ready, Ready};

    use super::*;

    /// Default queue size for MockTransport.
    pub const MOCK_QUEUE_SIZE: usize = 16;

    /// Mock transport for testing using priority queue.
    pub struct MockTransport {
        mtu: usize,
        bw: Option<u32>,
        outgoing: PriorityQueue,
        incoming: TransportInChannel,
    }

    impl Default for MockTransport {
        fn default() -> Self {
            Self {
                mtu: 255,
                bw: None,
                outgoing: PriorityQueue::new(MOCK_QUEUE_SIZE),
                incoming: Channel::new(),
            }
        }
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_mtu(mtu: usize) -> Self {
            Self::with_mtu_and_bw(mtu, None)
        }

        /// Create a transport with specified bandwidth limit.
        pub fn with_bw(bw: u32) -> Self {
            Self::with_mtu_and_bw(255, Some(bw))
        }

        /// Create a transport with specified MTU and bandwidth.
        pub fn with_mtu_and_bw(mtu: usize, bw: Option<u32>) -> Self {
            Self {
                mtu,
                bw,
                outgoing: PriorityQueue::new(MOCK_QUEUE_SIZE),
                incoming: Channel::new(),
            }
        }

        /// Inject a message as if it was received (for testing).
        pub fn inject_rx(&self, data: Vec<u8>, rssi: Option<i16>) {
            let _ = self.incoming.try_send(Incoming::new(data, rssi));
        }

        /// Take all sent messages in priority order (for testing).
        pub fn take_sent(&self) -> Vec<Vec<u8>> {
            let mut msgs = Vec::new();
            while let Some(msg) = self.outgoing.try_receive() {
                msgs.push(msg);
            }
            msgs
        }
    }

    impl Transport for MockTransport {
        fn mtu(&self) -> usize {
            self.mtu
        }

        fn bw(&self) -> Option<u32> {
            self.bw
        }

        fn outgoing(&self) -> &PriorityQueue {
            &self.outgoing
        }

        fn incoming(&self) -> &TransportInChannel {
            &self.incoming
        }
    }

    /// Mock clock for testing (synchronous, time advances manually).
    pub struct MockClock {
        current: Cell<Timestamp>,
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self {
                current: Cell::new(Timestamp::ZERO),
            }
        }
    }

    impl MockClock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn at(time: Timestamp) -> Self {
            Self {
                current: Cell::new(time),
            }
        }

        /// Advance time to the given timestamp.
        pub fn set(&self, time: Timestamp) {
            self.current.set(time);
        }

        /// Advance time by the given duration.
        pub fn advance(&self, duration: crate::time::Duration) {
            self.current.set(self.current.get() + duration);
        }
    }

    impl Clock for MockClock {
        type SleepFuture<'a> = Ready<()>;

        fn now(&self) -> Timestamp {
            self.current.get()
        }

        fn sleep_until(&self, _time: Timestamp) -> Self::SleepFuture<'_> {
            // In synchronous tests, sleep completes immediately.
            // The test code should advance time manually.
            ready(())
        }
    }

    /// Fast crypto for simulation and tests.
    ///
    /// Uses a simple XOR-mixing hash for all operations. Not cryptographically
    /// secure, but fast and deterministic for testing. Different seeds produce
    /// unique node IDs.
    pub struct FastTestCrypto {
        seed: u64,
    }

    impl FastTestCrypto {
        /// Create a new FastTestCrypto with the given seed.
        pub fn new(seed: u64) -> Self {
            Self { seed }
        }

        /// Fast 256-bit hash using xxh3 (called twice for 256 bits).
        #[inline(always)]
        fn fast_hash(data: &[u8]) -> [u8; 32] {
            let h1 = xxhash_rust::xxh3::xxh3_128_with_seed(data, 0);
            let h2 = xxhash_rust::xxh3::xxh3_128_with_seed(data, 1);
            let mut hash = [0u8; 32];
            hash[..16].copy_from_slice(&h1.to_le_bytes());
            hash[16..].copy_from_slice(&h2.to_le_bytes());
            hash
        }
    }

    impl super::Crypto for FastTestCrypto {
        fn algorithm(&self) -> u8 {
            0x01 // Pretend to be Ed25519 for protocol compatibility
        }

        fn sign(&self, secret: &crate::SecretKey, message: &[u8]) -> crate::Signature {
            // Fast mock signature: hash(secret || message)
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(secret);
            let msg_hash = Self::fast_hash(message);
            combined[32..].copy_from_slice(&msg_hash);
            let hash = Self::fast_hash(&combined);

            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&hash);
            sig[32..].copy_from_slice(&hash);
            crate::Signature {
                algorithm: self.algorithm(),
                sig,
            }
        }

        fn verify(
            &self,
            _pubkey: &crate::PublicKey,
            _message: &[u8],
            sig: &crate::Signature,
        ) -> bool {
            // For simulation, just check algorithm matches and signature isn't all zeros
            sig.algorithm == self.algorithm() && sig.sig[..32] != [0u8; 32]
        }

        fn generate_keypair(&mut self) -> (crate::PublicKey, crate::SecretKey) {
            // Derive deterministic keypair from seed
            let secret = Self::fast_hash(&self.seed.to_le_bytes());
            self.seed = self.seed.wrapping_add(1);

            // Pubkey is hash of the secret
            let pubkey = Self::fast_hash(&secret);
            (pubkey, secret)
        }

        fn hash(&self, data: &[u8]) -> [u8; 32] {
            Self::fast_hash(data)
        }
    }

    /// Mock random for testing (deterministic).
    pub struct MockRandom {
        pub state: u64,
    }

    impl Default for MockRandom {
        fn default() -> Self {
            Self { state: 12345 }
        }
    }

    impl MockRandom {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_seed(seed: u64) -> Self {
            Self { state: seed }
        }
    }

    impl Random for MockRandom {
        fn gen_range(&mut self, min: u64, max: u64) -> u64 {
            // Simple LCG
            self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let range = max - min;
            if range == 0 {
                return min;
            }
            min + (self.state % range)
        }
    }
}
