//! Compile-time configuration for memory bounds.
//!
//! The `NodeConfig` trait allows tuning memory usage for different MCU sizes.
//! Use `DefaultConfig` for 256KB+ RAM, `SmallConfig` for 64KB RAM.
//!
//! # Memory Footprint
//!
//! Approximate RAM usage per config (excluding stack and code):
//!
//! | Config | Peak Memory | Idle Memory | Suitable MCUs |
//! |--------|------------:|------------:|---------------|
//! | `DefaultConfig` | ~300 KB | ~75 KB | STM32F4, nRF52840, ESP32 |
//! | `SmallConfig` | ~70 KB | ~15 KB | STM32F1, nRF52810, ATmega2560 |
//!
//! **Reclaimable memory:** Queues used during network churn (`pending_routed`,
//! `delayed_forwards`, `recently_forwarded`) use shrinking collections that
//! automatically reclaim memory after 8 consecutive removals without additions.
//! This allows generous limits without permanent memory cost.
//!
//! Memory formula (rough estimate):
//! - `MAX_NEIGHBORS * 80` bytes (neighbor timing + routing info)
//! - `MAX_PUBKEY_CACHE * 48` bytes (pubkey + metadata)
//! - `MAX_LOCATION_STORE * 100` bytes (DHT entries)
//! - `MAX_PENDING_ACKS * 300` bytes (retransmission buffers)
//! - `MAX_RECENTLY_FORWARDED * 20` bytes (hash + timestamp, reclaimable)
//! - `MAX_PENDING_ROUTED * 280` bytes (routed msg, reclaimable)
//! - `MAX_DELAYED_FORWARDS * 280` bytes (delayed msg, reclaimable)
//!
//! # Example
//!
//! ```
//! use darktree::{Node, DefaultConfig, SmallConfig, NodeConfig};
//! use darktree::traits::test_impls::{MockTransport, FastTestCrypto, MockRandom, MockClock};
//!
//! // For 256KB+ RAM devices (default)
//! let node = Node::<_, _, _, _, DefaultConfig>::new(
//!     MockTransport::new(), FastTestCrypto::new(0), MockRandom::new(), MockClock::new()
//! );
//! assert_eq!(node.tree_size(), 1);
//!
//! // For 64KB RAM devices
//! let node = Node::<_, _, _, _, SmallConfig>::new(
//!     MockTransport::new(), FastTestCrypto::new(0), MockRandom::new(), MockClock::new()
//! );
//! assert!(node.is_root());
//!
//! // Custom configuration
//! struct MyConfig;
//! impl NodeConfig for MyConfig {
//!     const MAX_NEIGHBORS: usize = 16;
//!     const MAX_PUBKEY_CACHE: usize = 16;
//!     const MAX_LOCATION_STORE: usize = 32;
//!     const MAX_LOCATION_CACHE: usize = 8;
//!     const MAX_PENDING_LOOKUPS: usize = 4;
//!     const MAX_DISTRUSTED: usize = 8;
//!     const MAX_PENDING_DATA: usize = 4;
//!     const MAX_MSGS_PER_PENDING_PUBKEY: usize = 2;
//!     const MAX_PENDING_PUBKEY_NODES: usize = 4;
//!     const MAX_PENDING_ACKS: usize = 8;
//!     const MAX_RECENTLY_FORWARDED: usize = 32;
//!     const MAX_BACKUP_STORE: usize = 64;
//!     const MAX_BACKUPS_PER_NEIGHBOR: usize = 16;
//!     const MAX_DELAYED_FORWARDS: usize = 16;
//!     const MAX_PENDING_ROUTED: usize = 16;
//!     const OUTGOING_QUEUE_SIZE: usize = 16;
//!     const INCOMING_QUEUE_SIZE: usize = 8;
//!     const APP_QUEUE_SIZE: usize = 8;
//!     const EVENT_QUEUE_SIZE: usize = 16;
//! }
//! let node = Node::<_, _, _, _, MyConfig>::new(
//!     MockTransport::new(), FastTestCrypto::new(0), MockRandom::new(), MockClock::new()
//! );
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

    /// Maximum DHT backup entries stored for broadcast backup recovery.
    /// Typically 2× MAX_LOCATION_STORE (backup entries from ~2 neighbors on average).
    const MAX_BACKUP_STORE: usize;

    /// Maximum backup entries stored for any single neighbor.
    /// Limits how much backup storage one neighbor can consume.
    const MAX_BACKUPS_PER_NEIGHBOR: usize;

    /// Maximum delayed forwards for bounce-back dampening.
    /// Messages that bounce back during tree restructuring are queued here.
    const MAX_DELAYED_FORWARDS: usize;

    /// Maximum pending routed messages awaiting neighbor keyspace updates.
    /// Only roots use this queue (non-roots have parent fallback).
    const MAX_PENDING_ROUTED: usize;

    // --- Queue sizes (used by Transport implementations) ---

    /// Transport outgoing queue size.
    /// Should handle: K_REPLICAS publish burst, pending ACK retransmits,
    /// delayed forwards, and backup restoration bursts.
    const OUTGOING_QUEUE_SIZE: usize;

    /// Transport incoming queue size.
    /// Should handle bursts from radio while main loop processes messages.
    const INCOMING_QUEUE_SIZE: usize;

    /// Application data channel size (incoming and outgoing).
    /// Should handle bursts of DATA messages.
    const APP_QUEUE_SIZE: usize;

    /// Event channel size.
    /// Events are informational; larger buffer prevents drops under load.
    const EVENT_QUEUE_SIZE: usize;
}

/// Default configuration for 256KB+ RAM devices.
///
/// Memory footprint: ~75KB idle, ~300KB peak (reclaimable queues shrink when idle).
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultConfig;

impl NodeConfig for DefaultConfig {
    const MAX_NEIGHBORS: usize = 128;
    const MAX_PUBKEY_CACHE: usize = 64;
    const MAX_LOCATION_STORE: usize = 256;
    const MAX_LOCATION_CACHE: usize = 64;
    const MAX_PENDING_LOOKUPS: usize = 16;
    const MAX_DISTRUSTED: usize = 64;
    const MAX_PENDING_DATA: usize = 16;
    const MAX_MSGS_PER_PENDING_PUBKEY: usize = 8;
    const MAX_PENDING_PUBKEY_NODES: usize = 16;
    const MAX_PENDING_ACKS: usize = 32;
    const MAX_RECENTLY_FORWARDED: usize = 512;
    const MAX_BACKUP_STORE: usize = 256;
    const MAX_BACKUPS_PER_NEIGHBOR: usize = 64;
    const MAX_DELAYED_FORWARDS: usize = 256;
    const MAX_PENDING_ROUTED: usize = 512;

    const OUTGOING_QUEUE_SIZE: usize = 32;
    const INCOMING_QUEUE_SIZE: usize = 16;
    const APP_QUEUE_SIZE: usize = 16;
    const EVENT_QUEUE_SIZE: usize = 32;
}

/// Small configuration for 64KB RAM devices.
///
/// Memory footprint: ~15KB idle, ~70KB peak (reclaimable queues shrink when idle).
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
    const MAX_PENDING_DATA: usize = 4;
    const MAX_MSGS_PER_PENDING_PUBKEY: usize = 2;
    const MAX_PENDING_PUBKEY_NODES: usize = 4;
    const MAX_PENDING_ACKS: usize = 8;
    const MAX_RECENTLY_FORWARDED: usize = 128;
    const MAX_BACKUP_STORE: usize = 64;
    const MAX_BACKUPS_PER_NEIGHBOR: usize = 16;
    const MAX_DELAYED_FORWARDS: usize = 64;
    const MAX_PENDING_ROUTED: usize = 128;

    const OUTGOING_QUEUE_SIZE: usize = 8;
    const INCOMING_QUEUE_SIZE: usize = 8;
    const APP_QUEUE_SIZE: usize = 8;
    const EVENT_QUEUE_SIZE: usize = 16;
}

// Compile-time assertions to catch invalid configurations.
// MAX_LOCATION_STORE must be > 0 for the DHT replication logic to work correctly.
const _: () = assert!(DefaultConfig::MAX_LOCATION_STORE > 0);
const _: () = assert!(SmallConfig::MAX_LOCATION_STORE > 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        assert_eq!(DefaultConfig::MAX_NEIGHBORS, 128);
        assert_eq!(DefaultConfig::MAX_PUBKEY_CACHE, 64);
        assert_eq!(DefaultConfig::MAX_LOCATION_STORE, 256);
        assert_eq!(DefaultConfig::MAX_LOCATION_CACHE, 64);
        assert_eq!(DefaultConfig::MAX_PENDING_LOOKUPS, 16);
        assert_eq!(DefaultConfig::MAX_DISTRUSTED, 64);
        assert_eq!(DefaultConfig::MAX_PENDING_DATA, 16);
        assert_eq!(DefaultConfig::MAX_MSGS_PER_PENDING_PUBKEY, 8);
        assert_eq!(DefaultConfig::MAX_PENDING_PUBKEY_NODES, 16);
        assert_eq!(DefaultConfig::MAX_PENDING_ACKS, 32);
        assert_eq!(DefaultConfig::MAX_RECENTLY_FORWARDED, 512);
        assert_eq!(DefaultConfig::MAX_BACKUP_STORE, 256);
        assert_eq!(DefaultConfig::MAX_BACKUPS_PER_NEIGHBOR, 64);
        assert_eq!(DefaultConfig::MAX_DELAYED_FORWARDS, 256);
        assert_eq!(DefaultConfig::MAX_PENDING_ROUTED, 512);
    }

    #[test]
    fn test_small_config_values() {
        assert_eq!(SmallConfig::MAX_NEIGHBORS, 16);
        assert_eq!(SmallConfig::MAX_PUBKEY_CACHE, 16);
        assert_eq!(SmallConfig::MAX_LOCATION_STORE, 32);
        assert_eq!(SmallConfig::MAX_LOCATION_CACHE, 8);
        assert_eq!(SmallConfig::MAX_PENDING_LOOKUPS, 4);
        assert_eq!(SmallConfig::MAX_DISTRUSTED, 8);
        assert_eq!(SmallConfig::MAX_PENDING_DATA, 4);
        assert_eq!(SmallConfig::MAX_MSGS_PER_PENDING_PUBKEY, 2);
        assert_eq!(SmallConfig::MAX_PENDING_PUBKEY_NODES, 4);
        assert_eq!(SmallConfig::MAX_PENDING_ACKS, 8);
        assert_eq!(SmallConfig::MAX_RECENTLY_FORWARDED, 128);
        assert_eq!(SmallConfig::MAX_BACKUP_STORE, 64);
        assert_eq!(SmallConfig::MAX_BACKUPS_PER_NEIGHBOR, 16);
        assert_eq!(SmallConfig::MAX_DELAYED_FORWARDS, 64);
        assert_eq!(SmallConfig::MAX_PENDING_ROUTED, 128);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_small_config_smaller_than_default() {
        assert!(SmallConfig::MAX_NEIGHBORS < DefaultConfig::MAX_NEIGHBORS);
        assert!(SmallConfig::MAX_PUBKEY_CACHE < DefaultConfig::MAX_PUBKEY_CACHE);
        assert!(SmallConfig::MAX_LOCATION_STORE < DefaultConfig::MAX_LOCATION_STORE);
        assert!(SmallConfig::MAX_LOCATION_CACHE < DefaultConfig::MAX_LOCATION_CACHE);
        assert!(SmallConfig::MAX_PENDING_LOOKUPS < DefaultConfig::MAX_PENDING_LOOKUPS);
        assert!(SmallConfig::MAX_DISTRUSTED < DefaultConfig::MAX_DISTRUSTED);
        assert!(SmallConfig::MAX_PENDING_DATA < DefaultConfig::MAX_PENDING_DATA);
        assert!(
            SmallConfig::MAX_MSGS_PER_PENDING_PUBKEY < DefaultConfig::MAX_MSGS_PER_PENDING_PUBKEY
        );
        assert!(SmallConfig::MAX_PENDING_PUBKEY_NODES < DefaultConfig::MAX_PENDING_PUBKEY_NODES);
        assert!(SmallConfig::MAX_PENDING_ACKS < DefaultConfig::MAX_PENDING_ACKS);
        assert!(SmallConfig::MAX_RECENTLY_FORWARDED < DefaultConfig::MAX_RECENTLY_FORWARDED);
        assert!(SmallConfig::MAX_BACKUP_STORE < DefaultConfig::MAX_BACKUP_STORE);
        assert!(SmallConfig::MAX_BACKUPS_PER_NEIGHBOR < DefaultConfig::MAX_BACKUPS_PER_NEIGHBOR);
        assert!(SmallConfig::MAX_DELAYED_FORWARDS < DefaultConfig::MAX_DELAYED_FORWARDS);
        assert!(SmallConfig::MAX_PENDING_ROUTED < DefaultConfig::MAX_PENDING_ROUTED);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_configs_are_nonzero() {
        // DefaultConfig
        assert!(DefaultConfig::MAX_NEIGHBORS > 0);
        assert!(DefaultConfig::MAX_PUBKEY_CACHE > 0);
        assert!(DefaultConfig::MAX_LOCATION_STORE > 0);
        assert!(DefaultConfig::MAX_LOCATION_CACHE > 0);
        assert!(DefaultConfig::MAX_PENDING_LOOKUPS > 0);
        assert!(DefaultConfig::MAX_DISTRUSTED > 0);
        assert!(DefaultConfig::MAX_PENDING_DATA > 0);
        assert!(DefaultConfig::MAX_MSGS_PER_PENDING_PUBKEY > 0);
        assert!(DefaultConfig::MAX_PENDING_PUBKEY_NODES > 0);
        assert!(DefaultConfig::MAX_PENDING_ACKS > 0);
        assert!(DefaultConfig::MAX_RECENTLY_FORWARDED > 0);
        assert!(DefaultConfig::MAX_BACKUP_STORE > 0);
        assert!(DefaultConfig::MAX_BACKUPS_PER_NEIGHBOR > 0);
        assert!(DefaultConfig::MAX_DELAYED_FORWARDS > 0);
        assert!(DefaultConfig::MAX_PENDING_ROUTED > 0);

        // SmallConfig
        assert!(SmallConfig::MAX_NEIGHBORS > 0);
        assert!(SmallConfig::MAX_PUBKEY_CACHE > 0);
        assert!(SmallConfig::MAX_LOCATION_STORE > 0);
        assert!(SmallConfig::MAX_LOCATION_CACHE > 0);
        assert!(SmallConfig::MAX_PENDING_LOOKUPS > 0);
        assert!(SmallConfig::MAX_DISTRUSTED > 0);
        assert!(SmallConfig::MAX_PENDING_DATA > 0);
        assert!(SmallConfig::MAX_MSGS_PER_PENDING_PUBKEY > 0);
        assert!(SmallConfig::MAX_PENDING_PUBKEY_NODES > 0);
        assert!(SmallConfig::MAX_PENDING_ACKS > 0);
        assert!(SmallConfig::MAX_RECENTLY_FORWARDED > 0);
        assert!(SmallConfig::MAX_BACKUP_STORE > 0);
        assert!(SmallConfig::MAX_BACKUPS_PER_NEIGHBOR > 0);
        assert!(SmallConfig::MAX_DELAYED_FORWARDS > 0);
        assert!(SmallConfig::MAX_PENDING_ROUTED > 0);
    }
}
