# Darkforest Rust Implementation Plan

## Overview

Implement the tree-based DHT protocol as a Rust library crate with transport abstraction via traits, enabling deployment on BLE, WiFi, or LoRa.

## Project Structure

```
darkforest/
├── Cargo.toml          # workspace root
├── README.md
├── CLAUDE.md
├── docs/
│   └── design.md       # (existing)
└── darktree/           # crate directory
    ├── Cargo.toml
    └── src/
        ├── lib.rs           # Public API exports
        ├── types.rs         # Core types (NodeId, Signature, Pulse, Routed, etc.)
        ├── wire.rs          # Serialization/deserialization
        ├── node.rs          # Main Node struct and protocol logic
        ├── tree.rs          # Tree formation, merging, timeouts
        ├── routing.rs       # Routing algorithm, keyspace
        ├── dht.rs           # PUBLISH/LOOKUP/FOUND, location storage
        ├── fraud.rs         # Tree size verification (FraudDetection)
        └── traits.rs        # Transport, Clock, Crypto, Random traits
```

## Transport Layer Research Summary

### LoRa (SX1262/SX127x)
- **Max payload:** 255 bytes (practical limit)
- **Send:** Blocking (`transmit_payload`) or non-blocking (`transmit_payload_busy` + poll)
- **Receive:** Poll-based (`poll_irq`) or interrupt-driven (DIO pins)
- **Key issue:** Non-blocking TX returns before transmission complete - calling TX again abandons first packet
- **Config:** Frequency, SF, bandwidth, coding rate must be set before TX/RX
- **Async:** Embassy/lora-rs ecosystem supports async/await

### BLE
- **Legacy advertising:** 29 bytes usable - **TOO SMALL** for Pulse (122-194 bytes)
- **Extended advertising:** 252 bytes - sufficient for Pulse
- **GATT connections:** 247+ bytes with MTU negotiation
- **Range:** 10-50m (much shorter than LoRa's multi-km)
- **Roles:** Central (scanner/receiver) vs Peripheral (advertiser/sender)
- **Key issue:** Must use extended advertising OR GATT, not legacy advertising

### UDP/IP
- **Safe max:** 512 bytes to avoid fragmentation across all paths
- **Broadcast:** 255.255.255.255 (local subnet only, not routable)
- **Multicast:** 224.0.0.x (better for mesh, can cross subnets with TTL)
- **Async:** Tokio (`tokio::net::UdpSocket`), needs `socket2` for multicast setup
- **Embedded:** `smoltcp` crate for no_std

### Key Constraints for Trait Design

| Transport | MTU | Send Semantics | Receive Model |
|-----------|-----|----------------|---------------|
| LoRa | 255 | Broadcast only, may be async | Poll or interrupt |
| BLE (extended) | 252 | Periodic advertising | Scanning |
| BLE (GATT) | 247+ | Connection required | Notification/indication |
| UDP | 512+ safe | Immediate return (OS buffers) | Blocking or async |

## Core Traits (`traits.rs`)

### Transport Trait

The key abstraction for radio/network backends. Designed around the most constrained transport (LoRa):

```rust
pub trait Transport {
    type Error: core::fmt::Debug;

    /// Maximum transmission unit for this transport
    fn mtu(&self) -> usize;

    /// Effective bandwidth in bytes per second (accounting for duty cycle).
    /// Returns None for transports without bandwidth constraints.
    ///
    /// For LoRa: raw_bps × duty_cycle (e.g., 387 × 0.10 = 38 bytes/sec)
    /// For UDP/BLE: None (no regulatory limit)
    fn bw(&self) -> Option<u32> {
        None
    }

    /// Milliseconds until transport is ready to send again.
    /// Returns 0 if ready now. Sync because it just checks state.
    fn tx_backoff(&self) -> u32 {
        0
    }

    /// Transmit data to all neighbors (async - awaits completion)
    /// For LoRa: awaits until TX done (can take 100s of ms)
    /// For UDP: usually completes immediately (OS buffers)
    async fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Receive a message (async - awaits until data available)
    /// Returns (data, rssi) where rssi is signal strength in dBm
    async fn rx(&mut self) -> (Vec<u8>, Option<i16>);
}
```

**Note:** Async trait methods require Rust 1.75+. For real hardware, implementations use interrupt-driven wakers. The Embassy ecosystem provides abstractions for this.

**Pulse Interval Calculation:**

Protocol computes exact Pulse interval from bandwidth:

```rust
fn pulse_interval(&self, pulse_size: usize) -> Duration {
    match self.transport.bw() {
        Some(bw) => {
            // Pulse budget = 20% of effective bandwidth
            let pulse_budget_bps = bw as f32 * 0.20;
            let interval_s = pulse_size as f32 / pulse_budget_bps;
            Duration::from_secs_f32(interval_s.max(10.0))
        }
        None => Duration::from_secs(10),  // Minimum interval (design spec)
    }
}
```

For LoRa at SF8, 10% duty cycle, 150-byte Pulse:
- Raw rate: 387 bytes/sec
- Effective bw: 387 × 0.10 = 38.7 bytes/sec
- Pulse budget: 38.7 × 0.20 = 7.74 bytes/sec
- Interval: 150 / 7.74 = 19.4s

**Duty Cycle Management:**

The transport itself tracks duty cycle state internally. Protocol layer just checks `tx_backoff()`:

```rust
// In Node::run() event loop
if self.transport.tx_backoff() == 0 {
    let pulse = self.build_pulse();
    self.transport.tx(&pulse).await?;  // Async TX
}
```

This keeps duty cycle logic encapsulated in the transport where it belongs.

**Design rationale:**
- **Broadcast-only send:** At LoRa level, all transmissions are broadcasts. BLE advertising is also broadcast. UDP can use multicast. No point exposing "send to specific neighbor" since the protocol handles routing.
- **Async TX and RX:** Both methods are async. `tx()` awaits until transmission completes (important for LoRa where TX takes 100s of ms). `rx()` awaits until data arrives. This enables efficient event loops without polling.
- **MTU exposed:** Protocol MUST check message size. BLE legacy (29 bytes) would require fragmenting Pulse messages, which we don't support - use extended advertising or GATT.
- **Sync `tx_backoff()`:** Just checks state (no I/O), so stays synchronous.

### Why no unicast/neighbor-specific send?

Even though UDP supports unicast and BLE GATT requires connections, the protocol doesn't need it:
1. **Pulse messages:** Always broadcast to all neighbors
2. **Routed messages:** Also broadcast at radio layer - only the intended recipient/forwarder processes them

The transport just needs to get bytes on the air. Routing is handled at protocol layer.

### RX/TX Queue Architecture

Transports should use queues to decouple interrupt handlers from protocol logic:

```rust
use embassy_sync::channel::Channel;
use heapless::Vec as HVec;

const RX_QUEUE_SIZE: usize = 4;
const TX_QUEUE_SIZE: usize = 4;
const MAX_PACKET_SIZE: usize = 255;

type Packet = HVec<u8, MAX_PACKET_SIZE>;

/// RX queue: ISR pushes received packets, protocol pops them
/// Tuple: (packet_data, rssi)
type RxQueue = Channel<CriticalSectionRawMutex, (Packet, Option<i16>), RX_QUEUE_SIZE>;

/// TX queue: Protocol pushes packets to send, TX task pops and transmits
type TxQueue = Channel<CriticalSectionRawMutex, Packet, TX_QUEUE_SIZE>;
```

**Why queues matter:**

1. **RX queue**: LoRa radios have single-packet FIFOs. If a second packet arrives before the first is processed, it's lost. The ISR should immediately copy the packet to the RX queue.

2. **TX queue**: Decouples "I want to send" from "radio is ready to send". Protocol logic can queue multiple messages; the transport drains them respecting duty cycle and half-duplex constraints.

**ISR pattern (LoRa):**
```rust
#[interrupt]
fn RADIO_IRQ() {
    // SAFETY: We're in interrupt context, using critical section for shared state
    critical_section::with(|_cs| {
        let status = unsafe { RADIO.as_mut().unwrap() }.read_irq_flags();

        if status.rx_done() {
            let mut buf = HVec::new();
            let len = unsafe { RADIO.as_mut().unwrap() }.read_packet_to_slice(&mut buf);
            let rssi = unsafe { RADIO.as_mut().unwrap() }.get_rssi();
            unsafe { RADIO.as_mut().unwrap() }.clear_irq_flags();

            // Non-blocking send - drops packet if queue full (acceptable)
            let _ = RX_QUEUE.try_send((buf, Some(rssi)));
        }

        if status.tx_done() {
            TX_DONE_SIGNAL.signal(());
        }
    });
}
```

### Transport Implementation Sketches

**LoRa (SX127x):**
```rust
use embassy_time::Instant;
use lora_modulation::BaseBandModulationParams;

struct Sx127xTransport {
    radio: LoRa<...>,
    modulation: BaseBandModulationParams,  // SF, BW, CR config
    duty_cycle_percent: u8,                 // 1 or 10 depending on band
    raw_bps: u32,                           // raw data rate (e.g., 387 for SF8)
    preamble_len: u16,                      // typically 8
    // Duty cycle tracking
    window_start: Instant,
    airtime_used_ms: u32,
    // Queues (shared with ISR)
    rx_queue: &'static RxQueue,
    tx_queue: &'static TxQueue,
    tx_done_signal: &'static Signal<CriticalSectionRawMutex, ()>,
}

const DUTY_CYCLE_WINDOW_MS: u64 = 60_000;

impl Transport for Sx127xTransport {
    type Error = sx127x_lora::Error;

    fn mtu(&self) -> usize { 255 }

    fn bw(&self) -> Option<u32> {
        Some(self.raw_bps * self.duty_cycle_percent as u32 / 100)
    }

    fn tx_backoff(&self) -> u32 {
        let elapsed_ms = self.window_start.elapsed().as_millis() as u64;
        if elapsed_ms >= DUTY_CYCLE_WINDOW_MS {
            return 0;
        }
        let budget_ms = DUTY_CYCLE_WINDOW_MS * self.duty_cycle_percent as u64 / 100;
        if (self.airtime_used_ms as u64) < budget_ms {
            0
        } else {
            (DUTY_CYCLE_WINDOW_MS - elapsed_ms) as u32
        }
    }

    async fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        // Reset duty cycle window if needed
        let elapsed_ms = self.window_start.elapsed().as_millis() as u64;
        if elapsed_ms >= DUTY_CYCLE_WINDOW_MS {
            self.window_start = Instant::now();
            self.airtime_used_ms = 0;
        }

        // Track airtime
        let airtime_us = self.modulation.time_on_air_us(
            self.preamble_len, data.len() as u16
        );
        self.airtime_used_ms += (airtime_us / 1000) as u32;

        // Start TX and await completion via interrupt
        self.radio.start_transmit(data)?;
        self.tx_done_signal.wait().await;

        // Re-enter RX mode after TX (half-duplex)
        self.radio.start_receive()?;
        Ok(())
    }

    async fn rx(&mut self) -> Result<(Packet, Option<i16>), Self::Error> {
        // Receive from queue (ISR populates this)
        let (packet, rssi) = self.rx_queue.receive().await;
        Ok((packet, rssi))
    }
}

/// Background task that drains TX queue respecting duty cycle
async fn tx_task(transport: &mut Sx127xTransport) {
    loop {
        // Wait for something to send
        let packet = transport.tx_queue.receive().await;

        // Wait for duty cycle budget
        while transport.tx_backoff() > 0 {
            Timer::after(Duration::from_millis(transport.tx_backoff() as u64)).await;
        }

        // Transmit
        let _ = transport.tx(&packet).await;
    }
}
```

**UDP Multicast + Peer Bridging (async with Tokio):**
```rust
use tokio::net::UdpSocket;

struct UdpTransport {
    socket: UdpSocket,
    multicast_addr: SocketAddr,
    peers: Vec<SocketAddr>,  // Internet bridge peers (optional)
}

impl Transport for UdpTransport {
    type Error = std::io::Error;

    fn mtu(&self) -> usize { 512 }

    // bw() defaults to None (no limit)
    // tx_backoff() defaults to 0 (no duty cycle)

    async fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        // Local multicast
        self.socket.send_to(data, &self.multicast_addr).await?;
        // Also send to internet bridge peers
        for peer in &self.peers {
            let _ = self.socket.send_to(data, peer).await;
        }
        Ok(())
    }

    async fn rx(&mut self) -> (Vec<u8>, Option<i16>) {
        let mut buf = [0u8; 512];
        let (n, _addr) = self.socket.recv_from(&mut buf).await.unwrap();
        (buf[..n].to_vec(), None)  // No RSSI for UDP
    }
}
```

**BLE Extended Advertising (conceptual - nrf-softdevice style):**
```rust
impl Transport for BleExtendedAdvTransport {
    type Error = BleError;

    fn mtu(&self) -> usize { 252 }  // Extended advertising limit

    // bw() defaults to None (no limit)
    // tx_backoff() defaults to 0 (no regulatory duty cycle)

    async fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut adv_data = vec![0x02, 0x01, 0x06];  // Flags
        adv_data.push((data.len() + 3) as u8);
        adv_data.push(0xFF);  // Manufacturer specific
        adv_data.extend_from_slice(&COMPANY_ID);
        adv_data.extend_from_slice(data);

        self.advertiser.set_adv_data(&adv_data).await?;
        Ok(())
    }

    async fn rx(&mut self) -> (Vec<u8>, Option<i16>) {
        loop {
            let scan_result = self.scanner.next().await;  // Async scan
            if let Some(mfr_data) = scan_result.find_manufacturer_data(COMPANY_ID) {
                return (mfr_data.to_vec(), Some(scan_result.rssi));
            }
        }
    }
}
```

### Crypto Trait

Abstraction for signing/verification (allows hardware crypto or testing):

```rust
pub trait Crypto {
    /// Returns the algorithm identifier (0x01 = Ed25519)
    fn algorithm(&self) -> u8;

    /// Sign message, returning full Signature (algorithm byte + 64-byte sig)
    fn sign(&self, secret: &SecretKey, message: &[u8]) -> Signature;

    /// Verify signature matches message and pubkey
    /// Returns false if algorithm doesn't match or signature invalid
    fn verify(&self, pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool;

    fn generate_keypair(&mut self) -> (PublicKey, SecretKey);
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

// Example Ed25519 implementation
impl Crypto for Ed25519Crypto {
    fn algorithm(&self) -> u8 { 0x01 }

    fn sign(&self, secret: &SecretKey, message: &[u8]) -> Signature {
        let sig = ed25519_dalek::sign(secret, message);
        Signature { algorithm: 0x01, sig }
    }

    fn verify(&self, pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool {
        if sig.algorithm != 0x01 { return false; }  // Wrong algorithm
        ed25519_dalek::verify(pubkey, message, &sig.sig)
    }
    // ...
}
```

### Random Trait

For jitter in republishing:

```rust
pub trait Random {
    fn gen_range(&mut self, min: u64, max: u64) -> u64;
}
```

## Core Types (`types.rs`)

```rust
pub type NodeId = [u8; 16];
pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 32];  // Ed25519 seed
pub type TreeAddr = Vec<u8>;

pub struct Signature {
    pub algorithm: u8,      // 0x01 = Ed25519
    pub sig: [u8; 64],
}

pub struct Pulse {
    pub node_id: NodeId,
    pub parent_id: Option<NodeId>,
    pub root_id: NodeId,
    pub subtree_size: u32,
    pub tree_size: u32,
    pub tree_addr: TreeAddr,
    pub need_pubkey: bool,
    pub pubkey: Option<PublicKey>,
    pub child_prefix_len: u8,
    pub children: Vec<(Vec<u8>, u32)>,  // (prefix, subtree_size)
    pub signature: Signature,
}

pub struct Routed {
    pub dest_addr: TreeAddr,
    pub dest_node_id: Option<NodeId>,
    pub src_addr: TreeAddr,
    pub src_node_id: NodeId,
    pub msg_type: u8,
    pub ttl: u8,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

// Message types
pub const MSG_PUBLISH: u8 = 0x01;
pub const MSG_LOOKUP: u8 = 0x02;
pub const MSG_FOUND: u8 = 0x03;
pub const MSG_DATA: u8 = 0x10;
```

## Node State (`node.rs`)

```rust
use embassy_time::Instant;

pub struct Node<T, Cr, R> {
    // Dependencies (injected)
    transport: T,
    crypto: Cr,
    random: R,

    // Identity
    node_id: NodeId,
    pubkey: PublicKey,
    secret: SecretKey,

    // Tree position
    parent: Option<NodeId>,
    pending_parent: Option<(NodeId, u8)>,  // (candidate, pulses_waited)
    root_id: NodeId,
    tree_size: u32,
    subtree_size: u32,
    tree_addr: TreeAddr,

    // Neighbors (children bounded by MAX_CHILDREN = 16)
    children: HashMap<NodeId, u32>,       // child -> subtree_size
    shortcuts: HashSet<NodeId>,
    neighbor_times: HashMap<NodeId, NeighborTiming>,

    // Caches (bounded)
    pubkey_cache: LruCache<NodeId, PublicKey>,
    need_pubkey: HashSet<NodeId>,
    location_store: HashMap<NodeId, LocationEntry>,
    location_cache: LruCache<NodeId, TreeAddr>,

    // Pending operations
    pending_lookups: HashMap<NodeId, PendingLookup>,
    pending_requests: HashMap<NodeId, PendingRequest>,

    // Fraud detection
    join_context: Option<JoinContext>,
    distrusted: HashMap<NodeId, Instant>,
    fraud_detection: FraudDetection,

    // Scheduling
    last_pulse: Option<Instant>,
    next_publish: Option<Instant>,
    location_seq: u64,

    // Event queue for application
    events: VecDeque<Event>,
}
```

## Public API (Async with Embassy)

The API is async-based, compatible with Embassy (embedded) and Tokio (std).

```rust
impl<T, Cr, R> Node<T, Cr, R>
where
    T: Transport,
    Cr: Crypto,
    R: Random,
{
    /// Create a new node with a fresh identity
    pub fn new(transport: T, crypto: Cr, random: R) -> Self;

    /// Create a node with an existing identity
    pub fn with_identity(
        transport: T, crypto: Cr, random: R,
        node_id: NodeId, pubkey: PublicKey, secret: SecretKey,
    ) -> Self;

    /// Run the node - processes messages and emits events.
    /// This is the main entry point. Runs forever.
    pub async fn run<F>(&mut self, mut on_event: F) -> !
    where
        F: FnMut(Event),
    {
        use embassy_futures::select::{select3, Either3};

        loop {
            match select3(
                self.transport.rx(),                    // async: waits for data
                Timer::after(self.next_pulse_delay()),  // pulse timer
                Timer::after(self.next_timeout()),      // pending op timeout
            ).await {
                Either3::First((data, rssi)) => {
                    self.handle_rx(&data, rssi);
                }
                Either3::Second(_) => {
                    if self.transport.tx_backoff() == 0 {
                        let pulse = self.build_pulse();
                        let _ = self.transport.tx(&pulse).await;  // async TX
                    }
                }
                Either3::Third(_) => {
                    self.handle_timeouts();
                }
            }

            // Emit generated events
            while let Some(event) = self.events.pop_front() {
                on_event(event);
            }
        }
    }

    /// Send data to a target node (non-blocking, queues for send)
    pub fn send(&mut self, target: NodeId, data: Vec<u8>) -> Result<(), Error<T::Error>>;

    /// Lookup a node's tree address (result comes via Event)
    pub fn lookup(&mut self, target: NodeId);

    /// Get this node's identity
    pub fn node_id(&self) -> &NodeId;
    pub fn pubkey(&self) -> &PublicKey;

    /// Get current tree position
    pub fn tree_addr(&self) -> &TreeAddr;
    pub fn tree_size(&self) -> u32;
}

pub enum Event {
    /// Data received from another node
    DataReceived { from: NodeId, data: Vec<u8> },

    /// Lookup completed successfully
    LookupComplete { node_id: NodeId, tree_addr: TreeAddr },

    /// Lookup failed (all replicas exhausted)
    LookupFailed { node_id: NodeId },

    /// Tree structure changed
    TreeChanged { new_root: NodeId, new_size: u32 },
}
```


## Wire Format (`wire.rs`)

Binary serialization for embedded efficiency:
- Varints for sizes (1-3 bytes)
- Length-prefixed vectors
- Optional fields encoded with presence byte

### Cursor-Based Decoding

Use a cursor (reader) that tracks position and returns references into the original buffer where possible. This avoids allocations for borrowed data.

```rust
#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEof,
    InvalidVarint,
    InvalidLength,
    InvalidSignature,
}

/// Zero-copy reader over a byte slice
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + len > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn read_varint(&mut self) -> Result<u32, DecodeError> {
        // Standard varint decoding (1-5 bytes for u32)
        let mut result: u32 = 0;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7F) as u32) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 35 {
                return Err(DecodeError::InvalidVarint);
            }
        }
    }

    /// Read length-prefixed bytes (returns reference, no allocation)
    pub fn read_len_prefixed(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_varint()? as usize;
        self.read_bytes(len)
    }
}

/// Writer for encoding
pub struct Writer {
    #[cfg(feature = "alloc")]
    buf: alloc::vec::Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    buf: heapless::Vec<u8, MAX_PACKET_SIZE>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Default::default() }
    }

    pub fn write_u8(&mut self, v: u8) { self.buf.push(v).ok(); }
    pub fn write_bytes(&mut self, v: &[u8]) { self.buf.extend_from_slice(v).ok(); }
    pub fn write_varint(&mut self, mut v: u32) {
        while v >= 0x80 {
            self.buf.push((v as u8) | 0x80).ok();
            v >>= 7;
        }
        self.buf.push(v as u8).ok();
    }
    pub fn write_len_prefixed(&mut self, v: &[u8]) {
        self.write_varint(v.len() as u32);
        self.write_bytes(v);
    }

    pub fn finish(self) -> impl AsRef<[u8]> { self.buf }
}

pub trait Encode {
    fn encode(&self, w: &mut Writer);
}

pub trait Decode<'a>: Sized {
    fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError>;
}

// Implement for Pulse, Routed, LocationEntry, etc.
```

**Note:** Decoded types that borrow from the buffer (like `&[u8]` for tree_addr) have a lifetime. For types that need to outlive the buffer, implement both a borrowed and an owned variant, or copy on decode.

## Implementation Order

1. **types.rs** - Core type definitions
2. **wire.rs** - Serialization (needed for everything else)
3. **traits.rs** - Transport, Crypto, Random traits
4. **node.rs** - Node struct with basic initialization
5. **tree.rs** - Pulse handling, tree formation, merging, parent selection
   - Parent selection must skip neighbors with `children.len() >= MAX_CHILDREN`
   - Parent ignores (doesn't add to children list) a child if:
     - Already at `MAX_CHILDREN`
     - Adding child would cause Pulse to exceed transport MTU
   - Joining node tracks "pending parent" state; if not acknowledged in parent's
     children list after 3 Pulses, tries another neighbor
   - This ensures Pulse messages always fit within MTU
6. **routing.rs** - Routing algorithm, keyspace calculations
7. **dht.rs** - PUBLISH/LOOKUP/FOUND handling
8. **fraud.rs** - Tree size verification
9. **lib.rs** - Public exports

**Note:** No Clock trait needed - use `embassy_time::Instant` directly.

## Dependencies

```toml
[dependencies]
embassy-futures = "0.1"    # Async combinators (select, join)
embassy-time = "0.3"       # Timer, Instant, Duration
embassy-sync = "0.6"       # Async channels and signals
heapless = "0.8"           # Static collections for no_std

[dev-dependencies]
ed25519-dalek = "2"        # For default crypto impl in tests
sha2 = "0.10"              # For default hash impl in tests
rand = "0.8"               # For default random impl in tests
tokio = { version = "1", features = ["rt", "macros"] }  # Async runtime for tests
```

Optional feature flags:
```toml
[features]
default = []
std = ["heapless/std"]
alloc = []                 # Enable alloc-based collections (Vec, HashMap)
default-crypto = ["ed25519-dalek", "sha2"]
```

**Note:** Embassy-time works on both embedded (HAL backends) and std (using tokio).

## Allocation Strategy

The library supports two allocation modes via feature flags:

**Default (no features): Static allocation with `heapless`**
- All collections use fixed-capacity `heapless` types
- Works on bare-metal with no allocator
- Maximum portability (Cortex-M0+, 16KB+ RAM)

**With `alloc` feature: Dynamic allocation**
- Uses `Vec`, `HashMap` from `alloc` crate
- More flexible sizing, simpler APIs
- Requires global allocator (fine for nRF52840, ESP32, STM32F4+)

```rust
// In types.rs
#[cfg(not(feature = "alloc"))]
pub type TreeAddr = heapless::Vec<u8, MAX_TREE_DEPTH>;

#[cfg(feature = "alloc")]
pub type TreeAddr = alloc::vec::Vec<u8>;

#[cfg(not(feature = "alloc"))]
pub type ChildMap = heapless::FnvIndexMap<NodeId, u32, MAX_CHILDREN>;

#[cfg(feature = "alloc")]
pub type ChildMap = alloc::collections::BTreeMap<NodeId, u32>;
```

**Memory bounds (heapless mode):**
```rust
const MAX_TREE_DEPTH: usize = 32;      // Supports trees up to 16^32 nodes
const MAX_CHILDREN: usize = 16;        // Per design spec
const MAX_NEIGHBORS: usize = 128;
const MAX_PUBKEY_CACHE: usize = 128;
const MAX_LOCATION_STORE: usize = 256;
const MAX_LOCATION_CACHE: usize = 64;
const MAX_PENDING_LOOKUPS: usize = 16;
const MAX_DISTRUSTED: usize = 64;
```

## Testing Strategy

1. **Unit tests** per module with mock traits
2. **Integration tests** with in-memory transport simulating multiple nodes
3. **Property tests** for wire format (encode/decode roundtrip)

Example test transport (uses channel for async simulation):
```rust
use embassy_sync::channel::{Channel, Receiver, Sender};

struct TestTransport {
    tx_channel: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 16>,
    rx_channel: Receiver<'static, CriticalSectionRawMutex, (Vec<u8>, Option<i16>), 16>,
}

impl Transport for TestTransport {
    type Error = Infallible;

    fn mtu(&self) -> usize { 255 }

    fn bw(&self) -> Option<u32> {
        Some(38)  // Simulate LoRa SF8 @ 10% duty cycle
    }

    async fn tx(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.tx_channel.send(data.to_vec()).await;
        Ok(())
    }

    async fn rx(&mut self) -> (Vec<u8>, Option<i16>) {
        self.rx_channel.receive().await
    }
}
```

Test harness connects multiple nodes by routing tx_channel outputs to other nodes' rx_channels.

## Verification

After implementation:
1. `cargo build` - compiles without errors
2. `cargo test` - all tests pass
3. `cargo clippy` - no warnings
4. Create a simple example that:
   - Creates two nodes with TestTransport
   - Connects them (feed Pulses between transports)
   - Node A sends data to Node B
   - Verify B receives the data

## Files to Create/Modify

| File | Action |
|------|--------|
| `Cargo.toml` | Create workspace manifest |
| `darktree/Cargo.toml` | Create crate manifest |
| `darktree/src/lib.rs` | Create |
| `darktree/src/types.rs` | Create |
| `darktree/src/wire.rs` | Create |
| `darktree/src/traits.rs` | Create |
| `darktree/src/node.rs` | Create |
| `darktree/src/tree.rs` | Create |
| `darktree/src/routing.rs` | Create |
| `darktree/src/dht.rs` | Create |
| `darktree/src/fraud.rs` | Create |
