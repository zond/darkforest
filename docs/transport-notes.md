# Transport Layer Notes

Research and implementation guidance for transport backends (LoRa, BLE, UDP).

## Transport Research Summary

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

### Key Constraints

| Transport | MTU | Send Semantics | Receive Model |
|-----------|-----|----------------|---------------|
| LoRa | 255 | Broadcast only, may be async | Poll or interrupt |
| BLE (extended) | 252 | Periodic advertising | Scanning |
| BLE (GATT) | 247+ | Connection required | Notification/indication |
| UDP | 512+ safe | Immediate return (OS buffers) | Blocking or async |

## Transport Trait

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

## Pulse Interval Calculation

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

## Duty Cycle Management

The transport itself tracks duty cycle state internally. Protocol layer just checks `tx_backoff()`:

```rust
// In Node::run() event loop
if self.transport.tx_backoff() == 0 {
    let pulse = self.build_pulse();
    self.transport.tx(&pulse).await?;  // Async TX
}
```

This keeps duty cycle logic encapsulated in the transport where it belongs.

## Design Rationale

- **Broadcast-only send:** At LoRa level, all transmissions are broadcasts. BLE advertising is also broadcast. UDP can use multicast. No point exposing "send to specific neighbor" since the protocol handles routing.
- **Async TX and RX:** Both methods are async. `tx()` awaits until transmission completes (important for LoRa where TX takes 100s of ms). `rx()` awaits until data arrives. This enables efficient event loops without polling.
- **MTU exposed:** Protocol MUST check message size. BLE legacy (29 bytes) would require fragmenting Pulse messages, which we don't support - use extended advertising or GATT.
- **Sync `tx_backoff()`:** Just checks state (no I/O), so stays synchronous.
- **No unicast:** Even though UDP supports unicast and BLE GATT requires connections, the protocol doesn't need it. Pulse messages are always broadcast, and Routed messages are also broadcast at radio layer - only the intended recipient/forwarder processes them.

## RX/TX Queue Architecture

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

## Transport Implementation Sketches

### LoRa (SX127x)

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

### UDP Multicast + Peer Bridging

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

### BLE Extended Advertising (Conceptual)

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

## Crypto Trait

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
```

## Random Trait

For jitter in republishing:

```rust
pub trait Random {
    fn gen_range(&mut self, min: u64, max: u64) -> u64;
}
```
