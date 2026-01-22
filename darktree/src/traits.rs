//! Core traits for transport, cryptography, time, and randomness abstraction.
//!
//! These traits allow the protocol to be used with different:
//! - Transport layers (LoRa, BLE, UDP, simulation)
//! - Cryptographic implementations (software, hardware accelerated)
//! - Time sources (real hardware time, simulated time)
//! - Random number generators

use core::future::Future;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

use crate::time::Timestamp;
use crate::types::{Event, NodeId, Payload, PublicKey, SecretKey, Signature};

/// Queue size for transport channels.
pub const TRANSPORT_QUEUE_SIZE: usize = 8;

/// Queue size for application-level channels.
pub const APP_QUEUE_SIZE: usize = 8;

/// Queue size for event channel.
pub const EVENT_QUEUE_SIZE: usize = 16;

/// Mutex type used for channels.
pub type ChannelMutex = CriticalSectionRawMutex;

/// Received message with optional signal strength.
#[derive(Debug, Clone)]
pub struct Received {
    /// Message data.
    pub data: Vec<u8>,
    /// Signal strength in dBm (if available).
    pub rssi: Option<i16>,
}

/// Outgoing transport message channel type.
pub type TransportOutChannel = Channel<ChannelMutex, Vec<u8>, TRANSPORT_QUEUE_SIZE>;

/// Incoming transport message channel type.
pub type TransportInChannel = Channel<ChannelMutex, Received, TRANSPORT_QUEUE_SIZE>;

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

/// Transport trait for radio/network backends.
///
/// Provides channels for bidirectional communication with priority separation:
/// - `protocol_outgoing()`: High-priority protocol messages (Pulse, PUBLISH, LOOKUP, FOUND)
/// - `app_outgoing()`: Application data messages (DATA)
/// - `incoming()`: All received messages
///
/// # Priority Model
///
/// The transport implementation is responsible for scheduling between the two
/// outgoing queues. Protocol messages should be prioritized to ensure tree
/// maintenance and DHT operations work even under heavy application load.
///
/// # Usage Pattern
///
/// ```ignore
/// // Node sends protocol message (Pulse, LOOKUP, etc.)
/// transport.protocol_outgoing().try_send(data).ok();
///
/// // Node sends application data
/// transport.app_outgoing().try_send(data).ok();
///
/// // Node receives messages (async)
/// let msg = transport.incoming().receive().await;
///
/// // Radio task transmits - check protocol queue first
/// let data = transport.protocol_outgoing().try_receive()
///     .or_else(|_| transport.app_outgoing().try_receive());
/// ```
///
/// # Simulation
///
/// For simulation, the simulator reads from both outgoing queues:
///
/// ```ignore
/// // Simulator distributes messages between nodes
/// for queue in [node_a.transport().protocol_outgoing(), node_a.transport().app_outgoing()] {
///     while let Ok(msg) = queue.try_receive() {
///         node_b.transport().incoming().try_send(Received {
///             data: msg,
///             rssi: Some(-50),
///         }).ok();
///     }
/// }
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
    ///
    /// This allows the Node to budget bandwidth across message types (e.g., limiting
    /// Pulse overhead to 1/5 of available bandwidth) without knowing transport details.
    fn bw(&self) -> Option<u32> {
        None
    }

    /// Channel for outgoing protocol messages (Pulse, PUBLISH, LOOKUP, FOUND).
    ///
    /// Transport should prioritize this queue over `app_outgoing()` to ensure
    /// tree maintenance and DHT operations work under load.
    fn protocol_outgoing(&self) -> &TransportOutChannel;

    /// Channel for outgoing application data (DATA messages).
    ///
    /// Lower priority than protocol messages. May be delayed or dropped
    /// when protocol queue has pending messages.
    fn app_outgoing(&self) -> &TransportOutChannel;

    /// Channel for incoming messages.
    ///
    /// - Radio ISR calls `incoming().try_send(msg)` when data received
    /// - Simulator calls `incoming().try_send(msg)` to deliver messages
    /// - Node calls `incoming().receive().await` to receive
    fn incoming(&self) -> &TransportInChannel;
}

/// Time source trait for real or simulated time.
///
/// Allows the protocol to work with:
/// - Real hardware time (embassy_time, std::time)
/// - Simulated time (controlled by simulator for deterministic testing)
///
/// # Example (embedded with embassy)
///
/// ```ignore
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

#[cfg(test)]
pub mod test_impls {
    //! Test implementations of traits for unit testing.

    use super::*;
    use crate::types::ALGORITHM_ED25519;

    /// Mock transport for testing using embassy-sync channels.
    pub struct MockTransport {
        mtu: usize,
        bw: Option<u32>,
        protocol_outgoing: TransportOutChannel,
        app_outgoing: TransportOutChannel,
        incoming: TransportInChannel,
    }

    impl Default for MockTransport {
        fn default() -> Self {
            Self {
                mtu: 255,
                bw: None,
                protocol_outgoing: Channel::new(),
                app_outgoing: Channel::new(),
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
                protocol_outgoing: Channel::new(),
                app_outgoing: Channel::new(),
                incoming: Channel::new(),
            }
        }

        /// Inject a message as if it was received (for testing).
        pub fn inject_rx(&self, data: Vec<u8>, rssi: Option<i16>) {
            let _ = self.incoming.try_send(Received { data, rssi });
        }

        /// Take all sent messages from both queues (protocol first, for testing).
        pub fn take_sent(&self) -> Vec<Vec<u8>> {
            let mut msgs = Vec::new();
            while let Ok(msg) = self.protocol_outgoing.try_receive() {
                msgs.push(msg);
            }
            while let Ok(msg) = self.app_outgoing.try_receive() {
                msgs.push(msg);
            }
            msgs
        }

        /// Take only protocol messages (for testing).
        pub fn take_protocol_sent(&self) -> Vec<Vec<u8>> {
            let mut msgs = Vec::new();
            while let Ok(msg) = self.protocol_outgoing.try_receive() {
                msgs.push(msg);
            }
            msgs
        }

        /// Take only application messages (for testing).
        pub fn take_app_sent(&self) -> Vec<Vec<u8>> {
            let mut msgs = Vec::new();
            while let Ok(msg) = self.app_outgoing.try_receive() {
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

        fn protocol_outgoing(&self) -> &TransportOutChannel {
            &self.protocol_outgoing
        }

        fn app_outgoing(&self) -> &TransportOutChannel {
            &self.app_outgoing
        }

        fn incoming(&self) -> &TransportInChannel {
            &self.incoming
        }
    }

    /// Mock clock for testing (synchronous, time advances manually).
    pub struct MockClock {
        current: std::cell::Cell<Timestamp>,
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self {
                current: std::cell::Cell::new(Timestamp::ZERO),
            }
        }
    }

    impl MockClock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn at(time: Timestamp) -> Self {
            Self {
                current: std::cell::Cell::new(time),
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
        type SleepFuture<'a> = std::future::Ready<()>;

        fn now(&self) -> Timestamp {
            self.current.get()
        }

        fn sleep_until(&self, _time: Timestamp) -> Self::SleepFuture<'_> {
            // In synchronous tests, sleep completes immediately.
            // The test code should advance time manually.
            std::future::ready(())
        }
    }

    /// Mock crypto for testing (deterministic, NOT cryptographically secure).
    pub struct MockCrypto {
        pub next_keypair_seed: u8,
    }

    impl Default for MockCrypto {
        fn default() -> Self {
            Self {
                next_keypair_seed: 0,
            }
        }
    }

    impl MockCrypto {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Crypto for MockCrypto {
        fn algorithm(&self) -> u8 {
            ALGORITHM_ED25519
        }

        fn sign(&self, secret: &SecretKey, message: &[u8]) -> Signature {
            // Deterministic "signature" for testing: hash(secret || message)
            let mut sig = [0u8; 64];
            let hash = self.hash(&[secret.as_slice(), message].concat());
            sig[..32].copy_from_slice(&hash);
            sig[32..].copy_from_slice(&hash);
            Signature {
                algorithm: self.algorithm(),
                sig,
            }
        }

        fn verify(&self, pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool {
            if sig.algorithm != self.algorithm() {
                return false;
            }
            // For testing, we can't verify without the secret key,
            // so we just check the format
            let hash = self.hash(&[pubkey.as_slice(), message].concat());
            // In real impl this would verify the signature
            // For mock, just check non-zero
            sig.sig[..32] != [0u8; 32] && hash[0] == hash[0]
        }

        fn generate_keypair(&mut self) -> (PublicKey, SecretKey) {
            let seed = self.next_keypair_seed;
            self.next_keypair_seed = self.next_keypair_seed.wrapping_add(1);

            let mut secret = [seed; 32];
            secret[0] = seed;
            secret[1] = seed.wrapping_add(1);

            // "Public key" = hash of secret (deterministic)
            let pubkey = self.hash(&secret);

            (pubkey, secret)
        }

        fn hash(&self, data: &[u8]) -> [u8; 32] {
            // Simple non-cryptographic hash for testing
            let mut hash = [0u8; 32];
            for (i, &byte) in data.iter().enumerate() {
                hash[i % 32] ^= byte;
                hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(byte);
            }
            hash
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
