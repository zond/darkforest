//! Wire format serialization and deserialization.
//!
//! Uses cursor-based encoding with varints for sizes and keyspace-based addressing.
//!
//! ## Pulse Wire Format
//!
//! ```text
//! node_id (16) || flags (1) || [parent_hash (4)] || root_hash (4)
//! || subtree_size (varint) || tree_size (varint)
//! || keyspace_lo (4) || keyspace_hi (4)
//! || [pubkey (32)] || children (N × (hash(4) + subtree_size(varint)))
//! || signature (65)
//!
//! Flags byte:
//! - bit 0: has_parent (determines if parent_hash present)
//! - bit 1: need_pubkey
//! - bit 2: has_pubkey (determines if pubkey present)
//! - bits 3-7: child_count (0-16)
//!
//! Children are sorted by hash (lexicographic big-endian).
//! ```
//!
//! ## Routed Wire Format
//!
//! ```text
//! flags_and_type (1) || dest_addr (4) || [dest_hash (4)] || [src_addr (4)]
//! || src_node_id (16) || [src_pubkey (32)] || ttl (1)
//! || payload_len (varint) || payload || signature (65)
//!
//! flags_and_type byte:
//! - bits 0-3: msg_type
//! - bit 4: has_dest_hash
//! - bit 5: has_src_addr
//! - bit 6: has_src_pubkey
//! - bit 7: reserved
//! ```

use alloc::vec::Vec;

use crate::types::{
    ChildHash, ChildrenList, LocationEntry, Pulse, Routed, Signature, PULSE_CHILD_COUNT_SHIFT,
    PULSE_FLAG_HAS_PARENT, PULSE_FLAG_HAS_PUBKEY, ROUTED_FLAG_HAS_DEST_HASH,
    ROUTED_FLAG_HAS_SRC_ADDR, ROUTED_FLAG_HAS_SRC_PUBKEY,
};

/// Decoding error types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Unexpected end of buffer.
    UnexpectedEof,
    /// Invalid varint encoding.
    InvalidVarint,
    /// Non-canonical varint encoding (must use minimal bytes).
    NonCanonicalVarint,
    /// Invalid length value or trailing bytes.
    InvalidLength,
    /// Invalid signature format.
    InvalidSignature,
    /// Invalid message type.
    InvalidMessageType,
    /// Collection capacity exceeded.
    CapacityExceeded,
    /// Invalid flags.
    InvalidFlags,
    /// Semantic validation failed (e.g., children not sorted, invalid size relationships).
    InvalidValue,
}

/// Zero-copy reader over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a new reader over a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns true if there are no more bytes to read.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the current position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a fixed number of bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + len > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Read a u16 in big-endian format.
    pub fn read_u16_be(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a u32 in big-endian format.
    pub fn read_u32_be(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a u64 in big-endian format.
    pub fn read_u64_be(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a varint (1-5 bytes for u32) with canonical encoding validation.
    /// Rejects non-minimal encodings (e.g., 0x80 0x00 for 0).
    pub fn read_varint(&mut self) -> Result<u32, DecodeError> {
        let start_pos = self.pos;
        let mut result: u32 = 0;
        let mut shift = 0;
        let mut byte_count = 0;

        loop {
            let byte = self.read_u8()?;
            byte_count += 1;

            // Check for overflow before applying bits
            if shift == 28 && (byte & 0xF0) != 0 {
                return Err(DecodeError::InvalidVarint);
            }

            result |= ((byte & 0x7F) as u32) << shift;
            if byte & 0x80 == 0 {
                // Check for non-canonical encoding:
                // - If byte_count > 1 and result fits in fewer bytes, it's non-canonical
                // - Special case: 0x80 0x00 encodes 0 but should be 0x00
                let minimal_bytes = if result == 0 {
                    1
                } else {
                    // Calculate minimum bytes needed: ceil(bits_needed / 7)
                    let bits_needed = 32 - result.leading_zeros();
                    (bits_needed as usize).div_ceil(7).max(1)
                };

                if byte_count > minimal_bytes {
                    self.pos = start_pos; // Reset position for error recovery
                    return Err(DecodeError::NonCanonicalVarint);
                }

                return Ok(result);
            }
            shift += 7;
            if shift > 28 {
                return Err(DecodeError::InvalidVarint);
            }
        }
    }

    /// Read length-prefixed bytes (returns reference, no allocation).
    pub fn read_len_prefixed(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_varint()? as usize;
        self.read_bytes(len)
    }

    /// Read a NodeId (16 bytes).
    pub fn read_node_id(&mut self) -> Result<[u8; 16], DecodeError> {
        let bytes = self.read_bytes(16)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(bytes);
        Ok(id)
    }

    /// Read a 4-byte hash (ChildHash).
    pub fn read_child_hash(&mut self) -> Result<ChildHash, DecodeError> {
        let bytes = self.read_bytes(4)?;
        let mut hash = [0u8; 4];
        hash.copy_from_slice(bytes);
        Ok(hash)
    }

    /// Read a PublicKey (32 bytes).
    pub fn read_pubkey(&mut self) -> Result<[u8; 32], DecodeError> {
        let bytes = self.read_bytes(32)?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(bytes);
        Ok(pk)
    }

    /// Read a Signature (1 + 64 bytes).
    /// Validates that algorithm byte is ALGORITHM_ED25519 (0x01).
    pub fn read_signature(&mut self) -> Result<Signature, DecodeError> {
        let algorithm = self.read_u8()?;
        // Strict validation: only Ed25519 is supported
        if algorithm != crate::types::ALGORITHM_ED25519 {
            return Err(DecodeError::InvalidSignature);
        }
        let sig_bytes = self.read_bytes(64)?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(sig_bytes);
        Ok(Signature { algorithm, sig })
    }

    /// Read an optional NodeId (1 + 0 or 16 bytes).
    pub fn read_optional_node_id(&mut self) -> Result<Option<[u8; 16]>, DecodeError> {
        let present = self.read_u8()?;
        if present == 0 {
            Ok(None)
        } else {
            Ok(Some(self.read_node_id()?))
        }
    }

    /// Read an optional PublicKey (1 + 0 or 32 bytes).
    pub fn read_optional_pubkey(&mut self) -> Result<Option<[u8; 32]>, DecodeError> {
        let present = self.read_u8()?;
        if present == 0 {
            Ok(None)
        } else {
            Ok(Some(self.read_pubkey()?))
        }
    }
}

/// Writer for encoding messages.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create a new empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Returns the current length of written data.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns true if no data has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Write a single byte.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a slice of bytes.
    pub fn write_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Write a u16 in big-endian format.
    pub fn write_u16_be(&mut self, v: u16) {
        self.write_bytes(&v.to_be_bytes());
    }

    /// Write a u32 in big-endian format.
    pub fn write_u32_be(&mut self, v: u32) {
        self.write_bytes(&v.to_be_bytes());
    }

    /// Write a u64 in big-endian format.
    pub fn write_u64_be(&mut self, v: u64) {
        self.write_bytes(&v.to_be_bytes());
    }

    /// Write a varint (1-5 bytes for u32).
    pub fn write_varint(&mut self, mut v: u32) {
        while v >= 0x80 {
            self.buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }

    /// Write length-prefixed bytes.
    pub fn write_len_prefixed(&mut self, v: &[u8]) {
        self.write_varint(v.len() as u32);
        self.write_bytes(v);
    }

    /// Write a NodeId (16 bytes).
    pub fn write_node_id(&mut self, id: &[u8; 16]) {
        self.write_bytes(id);
    }

    /// Write a 4-byte hash (ChildHash).
    pub fn write_child_hash(&mut self, hash: &ChildHash) {
        self.write_bytes(hash);
    }

    /// Write a PublicKey (32 bytes).
    pub fn write_pubkey(&mut self, pk: &[u8; 32]) {
        self.write_bytes(pk);
    }

    /// Write a Signature (1 + 64 bytes).
    pub fn write_signature(&mut self, sig: &Signature) {
        self.write_u8(sig.algorithm);
        self.write_bytes(&sig.sig);
    }

    /// Write an optional NodeId (1 + 0 or 16 bytes).
    pub fn write_optional_node_id(&mut self, id: Option<&[u8; 16]>) {
        match id {
            None => self.write_u8(0),
            Some(id) => {
                self.write_u8(1);
                self.write_node_id(id);
            }
        }
    }

    /// Write an optional PublicKey (1 + 0 or 32 bytes).
    pub fn write_optional_pubkey(&mut self, pk: Option<&[u8; 32]>) {
        match pk {
            None => self.write_u8(0),
            Some(pk) => {
                self.write_u8(1);
                self.write_pubkey(pk);
            }
        }
    }

    /// Finish writing and return the buffer.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Get the buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Trait for types that can be encoded to wire format.
pub trait Encode {
    /// Encode this value to the writer.
    fn encode(&self, w: &mut Writer);

    /// Encode and return the bytes.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }
}

/// Trait for types that can be decoded from wire format.
pub trait Decode: Sized {
    /// Decode a value from the reader.
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Decode from a byte slice (strict: rejects trailing bytes).
    fn decode_from_slice(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let result = Self::decode(&mut r)?;
        // Strict validation: reject trailing bytes
        if !r.is_empty() {
            return Err(DecodeError::InvalidLength);
        }
        Ok(result)
    }
}

// Message type discriminators for the wire format
const WIRE_TYPE_PULSE: u8 = 0x01;
const WIRE_TYPE_ROUTED: u8 = 0x02;

/// Wrapper enum for encoding/decoding top-level messages.
#[derive(Clone, Debug)]
pub enum Message {
    Pulse(Pulse),
    Routed(Routed),
}

impl Encode for Pulse {
    fn encode(&self, w: &mut Writer) {
        w.write_node_id(&self.node_id);
        w.write_u8(self.flags);

        // parent_hash (conditional on has_parent flag)
        if self.flags & PULSE_FLAG_HAS_PARENT != 0 {
            if let Some(ref hash) = self.parent_hash {
                w.write_child_hash(hash);
            } else {
                // Flag says has_parent but no hash - write zeros (shouldn't happen)
                w.write_child_hash(&[0u8; 4]);
            }
        }

        w.write_child_hash(&self.root_hash);
        w.write_varint(self.subtree_size);
        w.write_varint(self.tree_size);
        w.write_u32_be(self.keyspace_lo);
        w.write_u32_be(self.keyspace_hi);

        // pubkey (conditional on has_pubkey flag)
        if self.flags & PULSE_FLAG_HAS_PUBKEY != 0 {
            if let Some(ref pk) = self.pubkey {
                w.write_pubkey(pk);
            } else {
                // Flag says has_pubkey but no key - write zeros (shouldn't happen)
                w.write_pubkey(&[0u8; 32]);
            }
        }

        // Children: count is in flags, then N × (hash(4) + subtree_size(varint))
        // Note: children must be sorted by hash
        for (hash, size) in &self.children {
            w.write_child_hash(hash);
            w.write_varint(*size);
        }

        w.write_signature(&self.signature);
    }
}

impl Decode for Pulse {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let node_id = r.read_node_id()?;
        let flags = r.read_u8()?;

        // parent_hash (conditional on has_parent flag)
        let parent_hash = if flags & PULSE_FLAG_HAS_PARENT != 0 {
            Some(r.read_child_hash()?)
        } else {
            None
        };

        let root_hash = r.read_child_hash()?;
        let subtree_size = r.read_varint()?;
        let tree_size = r.read_varint()?;
        let keyspace_lo = r.read_u32_be()?;
        let keyspace_hi = r.read_u32_be()?;

        // pubkey (conditional on has_pubkey flag)
        let pubkey = if flags & PULSE_FLAG_HAS_PUBKEY != 0 {
            Some(r.read_pubkey()?)
        } else {
            None
        };

        // Children count from flags (bits 3-7)
        let child_count = (flags >> PULSE_CHILD_COUNT_SHIFT) as usize;

        // Validate children count to prevent memory exhaustion attacks
        if child_count > crate::types::MAX_CHILDREN {
            return Err(DecodeError::CapacityExceeded);
        }

        let mut children = ChildrenList::with_capacity(child_count);
        for _ in 0..child_count {
            let hash = r.read_child_hash()?;
            let size = r.read_varint()?;
            children.push((hash, size));
        }

        // Strict validation: children must be sorted by hash (ascending)
        for i in 1..children.len() {
            if children[i - 1].0 >= children[i].0 {
                return Err(DecodeError::InvalidValue);
            }
        }

        let signature = r.read_signature()?;

        // Strict validation: subtree_size must be >= 1 (node counts itself)
        if subtree_size == 0 {
            return Err(DecodeError::InvalidValue);
        }

        // Strict validation: tree_size must be >= subtree_size
        if tree_size < subtree_size {
            return Err(DecodeError::InvalidValue);
        }

        // Strict validation: keyspace range must be valid (lo <= hi)
        if keyspace_lo > keyspace_hi {
            return Err(DecodeError::InvalidValue);
        }

        Ok(Pulse {
            node_id,
            flags,
            parent_hash,
            root_hash,
            subtree_size,
            tree_size,
            keyspace_lo,
            keyspace_hi,
            pubkey,
            children,
            signature,
        })
    }
}

impl Encode for Routed {
    fn encode(&self, w: &mut Writer) {
        w.write_u8(self.flags_and_type);
        w.write_u32_be(self.dest_addr);

        // dest_hash (conditional on flag)
        if self.flags_and_type & ROUTED_FLAG_HAS_DEST_HASH != 0 {
            if let Some(ref hash) = self.dest_hash {
                w.write_child_hash(hash);
            } else {
                w.write_child_hash(&[0u8; 4]);
            }
        }

        // src_addr (conditional on flag)
        if self.flags_and_type & ROUTED_FLAG_HAS_SRC_ADDR != 0 {
            if let Some(addr) = self.src_addr {
                w.write_u32_be(addr);
            } else {
                w.write_u32_be(0);
            }
        }

        w.write_node_id(&self.src_node_id);

        // src_pubkey (conditional on flag)
        if self.flags_and_type & ROUTED_FLAG_HAS_SRC_PUBKEY != 0 {
            if let Some(ref pk) = self.src_pubkey {
                w.write_pubkey(pk);
            } else {
                w.write_pubkey(&[0u8; 32]);
            }
        }

        w.write_u8(self.ttl);
        w.write_len_prefixed(&self.payload);
        w.write_signature(&self.signature);
    }
}

impl Decode for Routed {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let flags_and_type = r.read_u8()?;

        // Strict validation: reserved bit 7 must be 0
        if flags_and_type & 0x80 != 0 {
            return Err(DecodeError::InvalidFlags);
        }

        // Strict validation: message type (bits 0-3) must be 0-4
        let msg_type = flags_and_type & 0x0F;
        if msg_type > crate::types::MSG_ACK {
            return Err(DecodeError::InvalidMessageType);
        }

        let dest_addr = r.read_u32_be()?;

        // dest_hash (conditional on flag)
        let dest_hash = if flags_and_type & ROUTED_FLAG_HAS_DEST_HASH != 0 {
            Some(r.read_child_hash()?)
        } else {
            None
        };

        // src_addr (conditional on flag)
        let src_addr = if flags_and_type & ROUTED_FLAG_HAS_SRC_ADDR != 0 {
            Some(r.read_u32_be()?)
        } else {
            None
        };

        let src_node_id = r.read_node_id()?;

        // src_pubkey (conditional on flag)
        let src_pubkey = if flags_and_type & ROUTED_FLAG_HAS_SRC_PUBKEY != 0 {
            Some(r.read_pubkey()?)
        } else {
            None
        };

        let ttl = r.read_u8()?;
        let payload = r.read_len_prefixed()?.to_vec();
        let signature = r.read_signature()?;

        Ok(Routed {
            flags_and_type,
            dest_addr,
            dest_hash,
            src_addr,
            src_node_id,
            src_pubkey,
            ttl,
            payload,
            signature,
        })
    }
}

impl Encode for Message {
    fn encode(&self, w: &mut Writer) {
        match self {
            Message::Pulse(p) => {
                w.write_u8(WIRE_TYPE_PULSE);
                p.encode(w);
            }
            Message::Routed(r) => {
                w.write_u8(WIRE_TYPE_ROUTED);
                r.encode(w);
            }
        }
    }
}

impl Decode for Message {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let msg_type = r.read_u8()?;
        match msg_type {
            WIRE_TYPE_PULSE => Ok(Message::Pulse(Pulse::decode(r)?)),
            WIRE_TYPE_ROUTED => Ok(Message::Routed(Routed::decode(r)?)),
            _ => Err(DecodeError::InvalidMessageType),
        }
    }
}

impl Encode for LocationEntry {
    fn encode(&self, w: &mut Writer) {
        w.write_node_id(&self.node_id);
        w.write_pubkey(&self.pubkey);
        w.write_u32_be(self.keyspace_addr);
        w.write_varint(self.seq);
        w.write_u8(self.replica_index);
        w.write_signature(&self.signature);
    }
}

impl Decode for LocationEntry {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let node_id = r.read_node_id()?;
        let pubkey = r.read_pubkey()?;
        let keyspace_addr = r.read_u32_be()?;
        let seq = r.read_varint()?;
        let replica_index = r.read_u8()?;

        // Strict validation: replica_index must be < K_REPLICAS (3)
        if replica_index as usize >= crate::types::K_REPLICAS {
            return Err(DecodeError::InvalidValue);
        }

        let signature = r.read_signature()?;

        Ok(LocationEntry {
            node_id,
            pubkey,
            keyspace_addr,
            seq,
            replica_index,
            signature,
            received_at: crate::time::Timestamp::ZERO,
        })
    }
}

/// Build the data to be signed for a Pulse message.
pub fn pulse_sign_data(pulse: &Pulse) -> Writer {
    let mut w = Writer::new();
    w.write_bytes(crate::types::DOMAIN_PULSE);
    w.write_node_id(&pulse.node_id);
    w.write_u8(pulse.flags);

    if pulse.flags & PULSE_FLAG_HAS_PARENT != 0 {
        if let Some(ref hash) = pulse.parent_hash {
            w.write_child_hash(hash);
        }
    }

    w.write_child_hash(&pulse.root_hash);
    w.write_varint(pulse.subtree_size);
    w.write_varint(pulse.tree_size);
    w.write_u32_be(pulse.keyspace_lo);
    w.write_u32_be(pulse.keyspace_hi);

    if pulse.flags & PULSE_FLAG_HAS_PUBKEY != 0 {
        if let Some(ref pk) = pulse.pubkey {
            w.write_pubkey(pk);
        }
    }

    for (hash, size) in &pulse.children {
        w.write_child_hash(hash);
        w.write_varint(*size);
    }

    w
}

/// Build the data to be signed for a Routed message (excludes ttl).
pub fn routed_sign_data(routed: &Routed) -> Writer {
    let mut w = Writer::new();
    w.write_bytes(crate::types::DOMAIN_ROUTE);
    w.write_u8(routed.flags_and_type);
    w.write_u32_be(routed.dest_addr);

    if routed.flags_and_type & ROUTED_FLAG_HAS_DEST_HASH != 0 {
        if let Some(ref hash) = routed.dest_hash {
            w.write_child_hash(hash);
        }
    }

    if routed.flags_and_type & ROUTED_FLAG_HAS_SRC_ADDR != 0 {
        if let Some(addr) = routed.src_addr {
            w.write_u32_be(addr);
        }
    }

    w.write_node_id(&routed.src_node_id);

    if routed.flags_and_type & ROUTED_FLAG_HAS_SRC_PUBKEY != 0 {
        if let Some(ref pk) = routed.src_pubkey {
            w.write_pubkey(pk);
        }
    }

    w.write_len_prefixed(&routed.payload);
    w
}

/// Build the data to be signed for a LocationEntry.
pub fn location_sign_data(node_id: &[u8; 16], keyspace_addr: u32, seq: u32) -> Writer {
    let mut w = Writer::new();
    w.write_bytes(crate::types::DOMAIN_LOC);
    w.write_node_id(node_id);
    w.write_u32_be(keyspace_addr);
    w.write_varint(seq);
    w
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::types::{Pulse, Routed, ALGORITHM_ED25519, MSG_DATA, MSG_PUBLISH};

    #[test]
    fn test_varint_roundtrip() {
        let test_cases = [0u32, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX];

        for &val in &test_cases {
            let mut w = Writer::new();
            w.write_varint(val);
            let encoded = w.finish();

            let mut r = Reader::new(&encoded);
            let decoded = r.read_varint().unwrap();
            assert_eq!(val, decoded, "varint roundtrip failed for {}", val);
            assert!(r.is_empty(), "reader should be empty after reading varint");
        }
    }

    #[test]
    fn test_pulse_roundtrip() {
        let pulse = Pulse {
            node_id: [1u8; 16],
            flags: Pulse::build_flags(true, true, true, 2),
            parent_hash: Some([2u8; 4]),
            root_hash: [3u8; 4],
            subtree_size: 10,
            tree_size: 100,
            keyspace_lo: 0x1000_0000,
            keyspace_hi: 0x2000_0000,
            pubkey: Some([4u8; 32]),
            children: vec![([0xAB, 0xCD, 0xEF, 0x01], 5), ([0xDE, 0xF0, 0x12, 0x34], 3)],
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [5u8; 64],
            },
        };

        let encoded = pulse.encode_to_vec();
        let decoded = Pulse::decode_from_slice(&encoded).unwrap();

        assert_eq!(pulse.node_id, decoded.node_id);
        assert_eq!(pulse.flags, decoded.flags);
        assert_eq!(pulse.parent_hash, decoded.parent_hash);
        assert_eq!(pulse.root_hash, decoded.root_hash);
        assert_eq!(pulse.subtree_size, decoded.subtree_size);
        assert_eq!(pulse.tree_size, decoded.tree_size);
        assert_eq!(pulse.keyspace_lo, decoded.keyspace_lo);
        assert_eq!(pulse.keyspace_hi, decoded.keyspace_hi);
        assert_eq!(pulse.pubkey, decoded.pubkey);
        assert_eq!(pulse.children.len(), decoded.children.len());
        assert_eq!(pulse.signature, decoded.signature);
    }

    #[test]
    fn test_pulse_no_parent_no_pubkey() {
        let pulse = Pulse {
            node_id: [1u8; 16],
            flags: Pulse::build_flags(false, false, false, 0),
            parent_hash: None,
            root_hash: [3u8; 4],
            subtree_size: 1,
            tree_size: 1,
            keyspace_lo: 0,
            keyspace_hi: u32::MAX,
            pubkey: None,
            children: vec![],
            signature: Signature::default(),
        };

        let encoded = pulse.encode_to_vec();
        let decoded = Pulse::decode_from_slice(&encoded).unwrap();

        assert_eq!(pulse.node_id, decoded.node_id);
        assert!(!decoded.has_parent());
        assert!(decoded.parent_hash.is_none());
        assert!(!decoded.has_pubkey());
        assert!(decoded.pubkey.is_none());
        assert_eq!(decoded.child_count(), 0);
    }

    #[test]
    fn test_routed_roundtrip() {
        let routed = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, true, true, false),
            dest_addr: 0x1234_5678,
            dest_hash: Some([0xAB, 0xCD, 0xEF, 0x01]),
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 32,
            payload: b"hello world".to_vec(),
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [8u8; 64],
            },
        };

        let encoded = routed.encode_to_vec();
        let decoded = Routed::decode_from_slice(&encoded).unwrap();

        assert_eq!(routed.flags_and_type, decoded.flags_and_type);
        assert_eq!(routed.dest_addr, decoded.dest_addr);
        assert_eq!(routed.dest_hash, decoded.dest_hash);
        assert_eq!(routed.src_addr, decoded.src_addr);
        assert_eq!(routed.src_node_id, decoded.src_node_id);
        assert_eq!(routed.src_pubkey, decoded.src_pubkey);
        assert_eq!(routed.ttl, decoded.ttl);
        assert_eq!(routed.payload, decoded.payload);
        assert_eq!(routed.signature, decoded.signature);
    }

    #[test]
    fn test_routed_minimal() {
        let routed = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_PUBLISH, false, false, false),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: None,
            src_node_id: [7u8; 16],
            src_pubkey: None,
            ttl: 255,
            payload: vec![],
            signature: Signature::default(),
        };

        let encoded = routed.encode_to_vec();
        let decoded = Routed::decode_from_slice(&encoded).unwrap();

        assert_eq!(decoded.msg_type(), MSG_PUBLISH);
        assert!(!decoded.has_dest_hash());
        assert!(decoded.dest_hash.is_none());
        assert!(!decoded.has_src_addr());
        assert!(decoded.src_addr.is_none());
    }

    #[test]
    fn test_routed_with_src_pubkey() {
        let routed = Routed {
            flags_and_type: Routed::build_flags_and_type(MSG_DATA, false, true, true),
            dest_addr: 0x1234_5678,
            dest_hash: None,
            src_addr: Some(0x8765_4321),
            src_node_id: [7u8; 16],
            src_pubkey: Some([9u8; 32]),
            ttl: 32,
            payload: b"data".to_vec(),
            signature: Signature::default(),
        };

        let encoded = routed.encode_to_vec();
        let decoded = Routed::decode_from_slice(&encoded).unwrap();

        assert!(decoded.has_src_pubkey());
        assert_eq!(decoded.src_pubkey, Some([9u8; 32]));
    }

    #[test]
    fn test_message_roundtrip() {
        let pulse = Pulse::default();
        let msg = Message::Pulse(pulse.clone());
        let encoded = msg.encode_to_vec();
        let decoded = Message::decode_from_slice(&encoded).unwrap();

        match decoded {
            Message::Pulse(p) => {
                assert_eq!(pulse.node_id, p.node_id);
            }
            _ => panic!("expected Pulse"),
        }

        let routed = Routed::default();
        let msg = Message::Routed(routed.clone());
        let encoded = msg.encode_to_vec();
        let decoded = Message::decode_from_slice(&encoded).unwrap();

        match decoded {
            Message::Routed(r) => {
                assert_eq!(routed.src_node_id, r.src_node_id);
            }
            _ => panic!("expected Routed"),
        }
    }

    #[test]
    fn test_location_entry_roundtrip() {
        let entry = LocationEntry {
            node_id: [9u8; 16],
            pubkey: [10u8; 32],
            keyspace_addr: 0x1234_5678,
            seq: 12345678,
            replica_index: 1,
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [11u8; 64],
            },
            received_at: crate::time::Timestamp::ZERO,
        };

        let encoded = entry.encode_to_vec();
        let decoded = LocationEntry::decode_from_slice(&encoded).unwrap();

        assert_eq!(entry.node_id, decoded.node_id);
        assert_eq!(entry.pubkey, decoded.pubkey);
        assert_eq!(entry.keyspace_addr, decoded.keyspace_addr);
        assert_eq!(entry.seq, decoded.seq);
        assert_eq!(entry.replica_index, decoded.replica_index);
        assert_eq!(entry.signature, decoded.signature);
    }

    #[test]
    fn test_canonical_varint() {
        // Test that canonical encoding works
        let mut w = Writer::new();
        w.write_varint(0);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x00]);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.read_varint().unwrap(), 0);

        let mut w = Writer::new();
        w.write_varint(127);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x7F]);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.read_varint().unwrap(), 127);

        let mut w = Writer::new();
        w.write_varint(128);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x80, 0x01]);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.read_varint().unwrap(), 128);
    }

    #[test]
    fn test_non_canonical_varint_rejected() {
        // Non-canonical encoding: 0x80 0x00 encodes 0 but should be 0x00
        let non_canonical = vec![0x80, 0x00];
        let mut r = Reader::new(&non_canonical);
        let result = r.read_varint();
        assert_eq!(result, Err(DecodeError::NonCanonicalVarint));

        // Non-canonical encoding: 0x80 0x80 0x00 encodes 0
        let non_canonical = vec![0x80, 0x80, 0x00];
        let mut r = Reader::new(&non_canonical);
        let result = r.read_varint();
        assert_eq!(result, Err(DecodeError::NonCanonicalVarint));

        // Non-canonical encoding of 1: should be 0x01, not 0x81 0x00
        let non_canonical = vec![0x81, 0x00];
        let mut r = Reader::new(&non_canonical);
        let result = r.read_varint();
        assert_eq!(result, Err(DecodeError::NonCanonicalVarint));
    }

    #[test]
    fn test_child_hash_roundtrip() {
        let hash: ChildHash = [0xAB, 0xCD, 0xEF, 0x01];
        let mut w = Writer::new();
        w.write_child_hash(&hash);
        let encoded = w.finish();

        let mut r = Reader::new(&encoded);
        let decoded = r.read_child_hash().unwrap();
        assert_eq!(hash, decoded);
    }
}
