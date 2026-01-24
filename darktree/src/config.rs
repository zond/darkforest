//! Compile-time configuration for memory bounds.
//!
//! The `NodeConfig` trait allows tuning memory usage for different MCU sizes.
//! Use `DefaultConfig` for 256KB+ RAM, `SmallConfig` for 64KB RAM.
//!
//! # Memory Footprint
//!
//! Approximate RAM usage per config (excluding stack and code):
//!
//! | Config | Bounded Collections | Suitable MCUs |
//! |--------|--------------------:|---------------|
//! | `DefaultConfig` | ~50-60 KB | STM32F4, nRF52840, ESP32, RP2040 |
//! | `SmallConfig` | ~15-20 KB | STM32F1, nRF52810, ATmega2560 |
//!
//! Memory formula (rough estimate):
//! - `MAX_NEIGHBORS * 80` bytes (neighbor timing + routing info)
//! - `MAX_PUBKEY_CACHE * 48` bytes (pubkey + metadata)
//! - `MAX_LOCATION_STORE * 100` bytes (DHT entries)
//! - `MAX_PENDING_ACKS * 300` bytes (retransmission buffers)
//! - `MAX_RECENTLY_FORWARDED * 16` bytes (hash + timestamp)
//!
//! # Example
//!
//! ```ignore
//! use darktree::{Node, DefaultConfig, SmallConfig};
//!
//! // For 256KB+ RAM devices (default)
//! let node = Node::<_, _, _, _, DefaultConfig>::new(transport, crypto, random, clock);
//!
//! // For 64KB RAM devices
//! let node = Node::<_, _, _, _, SmallConfig>::new(transport, crypto, random, clock);
//!
//! // Custom configuration
//! struct MyConfig;
//! impl NodeConfig for MyConfig {
//!     const MAX_NEIGHBORS: usize = 16;
//!     // ... other constants
//! }
//! ```

/// Configuration trait for compile-time memory tuning.
///
/// Implement this trait to define custom memory bounds for your target platform.
/// All bounds must be non-zero.
pub trait NodeConfig {
    /// Maximum tracked neighbors (affects routing table size).
    const MAX_NEIGHBORS: usize;

    /// Maximum cached public keys for signature verification.
    const MAX_PUBKEY_CACHE: usize;

    /// Maximum DHT location entries stored locally.
    const MAX_LOCATION_STORE: usize;

    /// Maximum cached location lookups.
    const MAX_LOCATION_CACHE: usize;

    /// Maximum concurrent pending lookups.
    const MAX_PENDING_LOOKUPS: usize;

    /// Maximum tracked distrusted nodes (fraud detection).
    const MAX_DISTRUSTED: usize;

    /// Maximum routing shortcuts.
    const MAX_SHORTCUTS: usize;

    /// Maximum pending outgoing data messages.
    const MAX_PENDING_DATA: usize;

    /// Maximum messages queued per node awaiting pubkey.
    const MAX_MSGS_PER_PENDING_PUBKEY: usize;

    /// Maximum distinct nodes with pending pubkey requests.
    const MAX_PENDING_PUBKEY_NODES: usize;

    /// Maximum pending ACKs awaiting confirmation.
    const MAX_PENDING_ACKS: usize;

    /// Maximum recently forwarded hashes for duplicate detection.
    const MAX_RECENTLY_FORWARDED: usize;
}

/// Default configuration for 256KB+ RAM devices.
///
/// Memory footprint: ~50-60KB for all bounded collections.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultConfig;

impl NodeConfig for DefaultConfig {
    const MAX_NEIGHBORS: usize = 128;
    const MAX_PUBKEY_CACHE: usize = 128;
    const MAX_LOCATION_STORE: usize = 256;
    const MAX_LOCATION_CACHE: usize = 64;
    const MAX_PENDING_LOOKUPS: usize = 16;
    const MAX_DISTRUSTED: usize = 64;
    const MAX_SHORTCUTS: usize = 64;
    const MAX_PENDING_DATA: usize = 16;
    const MAX_MSGS_PER_PENDING_PUBKEY: usize = 8;
    const MAX_PENDING_PUBKEY_NODES: usize = 16;
    const MAX_PENDING_ACKS: usize = 32;
    const MAX_RECENTLY_FORWARDED: usize = 256;
}

/// Small configuration for 64KB RAM devices.
///
/// Memory footprint: ~15-20KB for all bounded collections.
/// Suitable for constrained MCUs like STM32F1, nRF52810.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmallConfig;

impl NodeConfig for SmallConfig {
    const MAX_NEIGHBORS: usize = 16;
    const MAX_PUBKEY_CACHE: usize = 16;
    const MAX_LOCATION_STORE: usize = 32;
    const MAX_LOCATION_CACHE: usize = 8;
    const MAX_PENDING_LOOKUPS: usize = 4;
    const MAX_DISTRUSTED: usize = 8;
    const MAX_SHORTCUTS: usize = 8;
    const MAX_PENDING_DATA: usize = 4;
    const MAX_MSGS_PER_PENDING_PUBKEY: usize = 2;
    const MAX_PENDING_PUBKEY_NODES: usize = 4;
    const MAX_PENDING_ACKS: usize = 8;
    const MAX_RECENTLY_FORWARDED: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        assert_eq!(DefaultConfig::MAX_NEIGHBORS, 128);
        assert_eq!(DefaultConfig::MAX_PUBKEY_CACHE, 128);
        assert_eq!(DefaultConfig::MAX_LOCATION_STORE, 256);
        assert_eq!(DefaultConfig::MAX_LOCATION_CACHE, 64);
        assert_eq!(DefaultConfig::MAX_PENDING_LOOKUPS, 16);
        assert_eq!(DefaultConfig::MAX_DISTRUSTED, 64);
        assert_eq!(DefaultConfig::MAX_SHORTCUTS, 64);
        assert_eq!(DefaultConfig::MAX_PENDING_DATA, 16);
        assert_eq!(DefaultConfig::MAX_MSGS_PER_PENDING_PUBKEY, 8);
        assert_eq!(DefaultConfig::MAX_PENDING_PUBKEY_NODES, 16);
        assert_eq!(DefaultConfig::MAX_PENDING_ACKS, 32);
        assert_eq!(DefaultConfig::MAX_RECENTLY_FORWARDED, 256);
    }

    #[test]
    fn test_small_config_values() {
        assert_eq!(SmallConfig::MAX_NEIGHBORS, 16);
        assert_eq!(SmallConfig::MAX_PUBKEY_CACHE, 16);
        assert_eq!(SmallConfig::MAX_LOCATION_STORE, 32);
        assert_eq!(SmallConfig::MAX_LOCATION_CACHE, 8);
        assert_eq!(SmallConfig::MAX_PENDING_LOOKUPS, 4);
        assert_eq!(SmallConfig::MAX_DISTRUSTED, 8);
        assert_eq!(SmallConfig::MAX_SHORTCUTS, 8);
        assert_eq!(SmallConfig::MAX_PENDING_DATA, 4);
        assert_eq!(SmallConfig::MAX_MSGS_PER_PENDING_PUBKEY, 2);
        assert_eq!(SmallConfig::MAX_PENDING_PUBKEY_NODES, 4);
        assert_eq!(SmallConfig::MAX_PENDING_ACKS, 8);
        assert_eq!(SmallConfig::MAX_RECENTLY_FORWARDED, 32);
    }

    #[test]
    fn test_small_config_smaller_than_default() {
        assert!(SmallConfig::MAX_NEIGHBORS < DefaultConfig::MAX_NEIGHBORS);
        assert!(SmallConfig::MAX_PUBKEY_CACHE < DefaultConfig::MAX_PUBKEY_CACHE);
        assert!(SmallConfig::MAX_LOCATION_STORE < DefaultConfig::MAX_LOCATION_STORE);
        assert!(SmallConfig::MAX_LOCATION_CACHE < DefaultConfig::MAX_LOCATION_CACHE);
        assert!(SmallConfig::MAX_PENDING_LOOKUPS < DefaultConfig::MAX_PENDING_LOOKUPS);
        assert!(SmallConfig::MAX_DISTRUSTED < DefaultConfig::MAX_DISTRUSTED);
        assert!(SmallConfig::MAX_SHORTCUTS < DefaultConfig::MAX_SHORTCUTS);
        assert!(SmallConfig::MAX_PENDING_DATA < DefaultConfig::MAX_PENDING_DATA);
        assert!(SmallConfig::MAX_MSGS_PER_PENDING_PUBKEY < DefaultConfig::MAX_MSGS_PER_PENDING_PUBKEY);
        assert!(SmallConfig::MAX_PENDING_PUBKEY_NODES < DefaultConfig::MAX_PENDING_PUBKEY_NODES);
        assert!(SmallConfig::MAX_PENDING_ACKS < DefaultConfig::MAX_PENDING_ACKS);
        assert!(SmallConfig::MAX_RECENTLY_FORWARDED < DefaultConfig::MAX_RECENTLY_FORWARDED);
    }

    #[test]
    fn test_configs_are_nonzero() {
        // DefaultConfig
        assert!(DefaultConfig::MAX_NEIGHBORS > 0);
        assert!(DefaultConfig::MAX_PUBKEY_CACHE > 0);
        assert!(DefaultConfig::MAX_LOCATION_STORE > 0);
        assert!(DefaultConfig::MAX_LOCATION_CACHE > 0);
        assert!(DefaultConfig::MAX_PENDING_LOOKUPS > 0);
        assert!(DefaultConfig::MAX_DISTRUSTED > 0);
        assert!(DefaultConfig::MAX_SHORTCUTS > 0);
        assert!(DefaultConfig::MAX_PENDING_DATA > 0);
        assert!(DefaultConfig::MAX_MSGS_PER_PENDING_PUBKEY > 0);
        assert!(DefaultConfig::MAX_PENDING_PUBKEY_NODES > 0);
        assert!(DefaultConfig::MAX_PENDING_ACKS > 0);
        assert!(DefaultConfig::MAX_RECENTLY_FORWARDED > 0);

        // SmallConfig
        assert!(SmallConfig::MAX_NEIGHBORS > 0);
        assert!(SmallConfig::MAX_PUBKEY_CACHE > 0);
        assert!(SmallConfig::MAX_LOCATION_STORE > 0);
        assert!(SmallConfig::MAX_LOCATION_CACHE > 0);
        assert!(SmallConfig::MAX_PENDING_LOOKUPS > 0);
        assert!(SmallConfig::MAX_DISTRUSTED > 0);
        assert!(SmallConfig::MAX_SHORTCUTS > 0);
        assert!(SmallConfig::MAX_PENDING_DATA > 0);
        assert!(SmallConfig::MAX_MSGS_PER_PENDING_PUBKEY > 0);
        assert!(SmallConfig::MAX_PENDING_PUBKEY_NODES > 0);
        assert!(SmallConfig::MAX_PENDING_ACKS > 0);
        assert!(SmallConfig::MAX_RECENTLY_FORWARDED > 0);
    }
}
