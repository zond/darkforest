//! Core traits for transport, cryptography, and randomness abstraction.
//!
//! These traits allow the protocol to be used with different:
//! - Transport layers (LoRa, BLE, UDP, etc.)
//! - Cryptographic implementations (software, hardware accelerated)
//! - Random number generators

use core::fmt::Debug;

use crate::types::{NodeId, PublicKey, SecretKey, Signature};

/// Transport trait for radio/network backends.
///
/// Designed around the most constrained transport (LoRa) where:
/// - All transmissions are broadcasts (no unicast at radio layer)
/// - Duty cycle limits may apply
/// - MTU is limited (255 bytes for LoRa)
///
/// # Implementation Notes
///
/// For async runtimes (Embassy, Tokio), wrap the transport in an adapter that
/// converts between the polling interface and async/await.
///
/// For interrupt-driven systems, use RX/TX queues:
/// - ISR pushes received packets to RX queue
/// - TX task drains TX queue respecting duty cycle
pub trait Transport {
    /// Transport-specific error type.
    type Error: Debug;

    /// Maximum transmission unit for this transport.
    ///
    /// Protocol MUST check message size before transmitting.
    /// - LoRa: 255 bytes
    /// - BLE extended advertising: 252 bytes
    /// - UDP: 512 bytes (safe across all paths)
    fn mtu(&self) -> usize;

    /// Effective bandwidth in bytes per second (accounting for duty cycle).
    ///
    /// Returns `None` for transports without bandwidth constraints.
    ///
    /// For LoRa: `raw_bps × duty_cycle` (e.g., 387 × 0.10 = 38 bytes/sec)
    /// For UDP/BLE: `None` (no regulatory limit)
    fn bandwidth(&self) -> Option<u32> {
        None
    }

    /// Milliseconds until transport is ready to send again.
    ///
    /// Returns 0 if ready now. Used for duty cycle management.
    fn tx_backoff(&self) -> u32 {
        0
    }

    /// Attempt to transmit data to all neighbors (broadcast).
    ///
    /// Returns:
    /// - `Ok(())` if transmission started/completed
    /// - `Err(WouldBlock)` if transport is busy (check `tx_backoff()`)
    /// - `Err(...)` for other transport errors
    ///
    /// For LoRa: This may block until TX completes (100s of ms).
    /// For UDP: Usually completes immediately (OS buffers).
    fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Attempt to receive a message.
    ///
    /// Returns:
    /// - `Some((len, rssi))` if a message was received (data written to buf)
    /// - `None` if no message available
    ///
    /// The `rssi` is signal strength in dBm (if available).
    fn rx(&mut self, buf: &mut [u8]) -> Option<(usize, Option<i16>)>;
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

/// Time source trait for getting current timestamps.
///
/// The protocol uses seconds as the time unit for simplicity.
/// Implementations should provide monotonically increasing values.
pub trait Clock {
    /// Get current time in seconds since some fixed epoch.
    ///
    /// The epoch can be arbitrary (boot time, UNIX epoch, etc.)
    /// as long as it's consistent within a session.
    fn now_secs(&self) -> u64;

    /// Get current time in milliseconds since some fixed epoch.
    fn now_millis(&self) -> u64 {
        self.now_secs() * 1000
    }
}

#[cfg(test)]
pub mod test_impls {
    //! Test implementations of traits for unit testing.

    use super::*;
    use crate::types::ALGORITHM_ED25519;
    use std::collections::VecDeque;

    /// Mock transport for testing.
    pub struct MockTransport {
        pub mtu: usize,
        pub rx_queue: VecDeque<(Vec<u8>, Option<i16>)>,
        pub tx_log: Vec<Vec<u8>>,
    }

    impl Default for MockTransport {
        fn default() -> Self {
            Self {
                mtu: 255,
                rx_queue: VecDeque::new(),
                tx_log: Vec::new(),
            }
        }
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn push_rx(&mut self, data: &[u8], rssi: Option<i16>) {
            self.rx_queue.push_back((data.to_vec(), rssi));
        }
    }

    #[derive(Debug)]
    pub struct MockTransportError;

    impl Transport for MockTransport {
        type Error = MockTransportError;

        fn mtu(&self) -> usize {
            self.mtu
        }

        fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.tx_log.push(data.to_vec());
            Ok(())
        }

        fn rx(&mut self, buf: &mut [u8]) -> Option<(usize, Option<i16>)> {
            if let Some((data, rssi)) = self.rx_queue.pop_front() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Some((len, rssi))
            } else {
                None
            }
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

    /// Mock clock for testing.
    pub struct MockClock {
        pub current_secs: u64,
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self { current_secs: 0 }
        }
    }

    impl MockClock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn advance(&mut self, secs: u64) {
            self.current_secs += secs;
        }
    }

    impl Clock for MockClock {
        fn now_secs(&self) -> u64 {
            self.current_secs
        }
    }
}
