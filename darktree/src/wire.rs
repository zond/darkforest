//! Wire format serialization and deserialization.
//!
//! Uses cursor-based encoding with varints for sizes and nibble-packed tree addresses.
//!
//! ## Tree Address Wire Format (Nibble-Packed)
//!
//! ```text
//! Wire format: [depth: u8] [nibbles: ceil(depth/2) bytes]
//! - High nibble first in each byte
//! - For odd depths, low nibble of last byte MUST be 0
//! - depth=0 (root) encoded as just 0x00
//!
//! Example: depth 5, path [3,7,2,15,1]
//!   → 0x05 0x37 0x2F 0x10
//! ```

use crate::types::{ChildrenList, LocationEntry, Pulse, Routed, Signature, MAX_TREE_DEPTH};

/// Decoding error types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Unexpected end of buffer.
    UnexpectedEof,
    /// Invalid varint encoding.
    InvalidVarint,
    /// Non-canonical varint encoding (must use minimal bytes).
    NonCanonicalVarint,
    /// Invalid length value.
    InvalidLength,
    /// Invalid signature format.
    InvalidSignature,
    /// Invalid message type.
    InvalidMessageType,
    /// Collection capacity exceeded.
    CapacityExceeded,
    /// Invalid tree address: depth exceeds MAX_TREE_DEPTH.
    TreeAddrTooDeep,
    /// Invalid tree address: odd depth with non-zero padding nibble.
    TreeAddrInvalidPadding,
    /// Invalid tree address: nibble value > 15.
    TreeAddrInvalidNibble,
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

    /// Read a PublicKey (32 bytes).
    pub fn read_pubkey(&mut self) -> Result<[u8; 32], DecodeError> {
        let bytes = self.read_bytes(32)?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(bytes);
        Ok(pk)
    }

    /// Read a Signature (1 + 64 bytes).
    pub fn read_signature(&mut self) -> Result<Signature, DecodeError> {
        let algorithm = self.read_u8()?;
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

    /// Read a nibble-packed tree address.
    ///
    /// Wire format: [depth: u8] [nibbles: ceil(depth/2) bytes]
    /// - High nibble first in each byte
    /// - For odd depths, low nibble of last byte MUST be 0
    /// - Returns Vec<u8> where each element is a nibble (0-15)
    pub fn read_tree_addr(&mut self) -> Result<Vec<u8>, DecodeError> {
        let depth = self.read_u8()? as usize;

        if depth > MAX_TREE_DEPTH {
            return Err(DecodeError::TreeAddrTooDeep);
        }

        if depth == 0 {
            return Ok(Vec::new());
        }

        let num_bytes = depth.div_ceil(2);
        let packed_bytes = self.read_bytes(num_bytes)?;

        let mut addr = Vec::with_capacity(depth);
        for (i, &byte) in packed_bytes.iter().enumerate() {
            let high_nibble = (byte >> 4) & 0x0F;
            let low_nibble = byte & 0x0F;

            // Always add the high nibble
            addr.push(high_nibble);

            // Add low nibble if within depth, otherwise verify it's zero padding
            if i * 2 + 1 < depth {
                addr.push(low_nibble);
            } else if low_nibble != 0 {
                return Err(DecodeError::TreeAddrInvalidPadding);
            }
        }

        Ok(addr)
    }

    /// Read an optional tree address (1 + 0 or nibble-packed addr).
    ///
    /// Wire format:
    /// - None: 0x00 (1 byte)
    /// - Some(addr): 0x01 [nibble-packed addr]
    pub fn read_optional_tree_addr(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
        let present = self.read_u8()?;
        if present == 0 {
            Ok(None)
        } else {
            Ok(Some(self.read_tree_addr()?))
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

    /// Write a nibble-packed tree address.
    ///
    /// Wire format: [depth: u8] [nibbles: ceil(depth/2) bytes]
    /// - High nibble first in each byte
    /// - For odd depths, low nibble of last byte is 0
    pub fn write_tree_addr(&mut self, addr: &[u8]) {
        let depth = addr.len();
        self.write_u8(depth as u8);

        if depth == 0 {
            return;
        }

        // Pack nibbles into bytes
        let num_bytes = depth.div_ceil(2);
        for i in 0..num_bytes {
            let high_nibble = addr.get(i * 2).copied().unwrap_or(0) & 0x0F;
            let low_nibble = addr.get(i * 2 + 1).copied().unwrap_or(0) & 0x0F;
            self.write_u8((high_nibble << 4) | low_nibble);
        }
    }

    /// Write an optional tree address (1 + 0 or nibble-packed addr).
    ///
    /// Wire format:
    /// - None: 0x00 (1 byte)
    /// - Some(addr): 0x01 [nibble-packed addr]
    pub fn write_optional_tree_addr(&mut self, addr: Option<&[u8]>) {
        match addr {
            None => self.write_u8(0),
            Some(addr) => {
                self.write_u8(1);
                self.write_tree_addr(addr);
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

    /// Decode from a byte slice.
    fn decode_from_slice(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        Self::decode(&mut r)
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
        w.write_optional_node_id(self.parent_id.as_ref());
        w.write_node_id(&self.root_id);
        w.write_varint(self.subtree_size);
        w.write_varint(self.tree_size);
        w.write_tree_addr(&self.tree_addr);
        w.write_u8(if self.need_pubkey { 1 } else { 0 });
        w.write_optional_pubkey(self.pubkey.as_ref());
        w.write_u8(self.child_prefix_len);
        w.write_varint(self.children.len() as u32);
        for (prefix, size) in &self.children {
            w.write_bytes(prefix);
            w.write_varint(*size);
        }
        w.write_signature(&self.signature);
    }
}

impl Decode for Pulse {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let node_id = r.read_node_id()?;
        let parent_id = r.read_optional_node_id()?;
        let root_id = r.read_node_id()?;
        let subtree_size = r.read_varint()?;
        let tree_size = r.read_varint()?;
        let tree_addr = r.read_tree_addr()?;
        let need_pubkey = r.read_u8()? != 0;
        let pubkey = r.read_optional_pubkey()?;
        let child_prefix_len = r.read_u8()?;
        let children_count = r.read_varint()? as usize;

        // Validate children count to prevent memory exhaustion attacks
        if children_count > crate::types::MAX_CHILDREN {
            return Err(DecodeError::CapacityExceeded);
        }

        let mut children = ChildrenList::with_capacity(children_count);
        for _ in 0..children_count {
            let prefix = r.read_bytes(child_prefix_len as usize)?.to_vec();
            let size = r.read_varint()?;
            children.push((prefix, size));
        }

        let signature = r.read_signature()?;

        Ok(Pulse {
            node_id,
            parent_id,
            root_id,
            subtree_size,
            tree_size,
            tree_addr,
            need_pubkey,
            pubkey,
            child_prefix_len,
            children,
            signature,
        })
    }
}

impl Encode for Routed {
    fn encode(&self, w: &mut Writer) {
        w.write_tree_addr(&self.dest_addr);
        w.write_optional_node_id(self.dest_node_id.as_ref());
        w.write_optional_tree_addr(self.src_addr.as_deref());
        w.write_node_id(&self.src_node_id);
        w.write_u8(self.msg_type);
        w.write_u8(self.ttl);
        w.write_len_prefixed(&self.payload);
        w.write_signature(&self.signature);
    }
}

impl Decode for Routed {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let dest_addr = r.read_tree_addr()?;
        let dest_node_id = r.read_optional_node_id()?;
        let src_addr = r.read_optional_tree_addr()?;
        let src_node_id = r.read_node_id()?;
        let msg_type = r.read_u8()?;
        let ttl = r.read_u8()?;
        let payload = r.read_len_prefixed()?.to_vec();
        let signature = r.read_signature()?;

        Ok(Routed {
            dest_addr,
            dest_node_id,
            src_addr,
            src_node_id,
            msg_type,
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
        w.write_tree_addr(&self.tree_addr);
        w.write_varint(self.seq);
        w.write_signature(&self.signature);
    }
}

impl Decode for LocationEntry {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let node_id = r.read_node_id()?;
        let tree_addr = r.read_tree_addr()?;
        // Use canonical varint to reject non-minimal encodings
        let seq = r.read_varint()?;
        let signature = r.read_signature()?;

        Ok(LocationEntry {
            node_id,
            tree_addr,
            seq,
            signature,
            received_at_secs: 0,
        })
    }
}

/// Build the data to be signed for a Pulse message.
pub fn pulse_sign_data(pulse: &Pulse) -> Writer {
    let mut w = Writer::new();
    w.write_bytes(crate::types::DOMAIN_PULSE);
    w.write_node_id(&pulse.node_id);
    w.write_optional_node_id(pulse.parent_id.as_ref());
    w.write_node_id(&pulse.root_id);
    w.write_varint(pulse.subtree_size);
    w.write_varint(pulse.tree_size);
    w.write_tree_addr(&pulse.tree_addr);
    w.write_u8(if pulse.need_pubkey { 1 } else { 0 });
    w.write_optional_pubkey(pulse.pubkey.as_ref());
    w.write_u8(pulse.child_prefix_len);
    w.write_varint(pulse.children.len() as u32);
    for (prefix, size) in &pulse.children {
        w.write_bytes(prefix);
        w.write_varint(*size);
    }
    w
}

/// Build the data to be signed for a Routed message (excludes ttl).
pub fn routed_sign_data(routed: &Routed) -> Writer {
    let mut w = Writer::new();
    w.write_bytes(crate::types::DOMAIN_ROUTE);
    w.write_tree_addr(&routed.dest_addr);
    w.write_optional_node_id(routed.dest_node_id.as_ref());
    w.write_optional_tree_addr(routed.src_addr.as_deref());
    w.write_node_id(&routed.src_node_id);
    w.write_u8(routed.msg_type);
    w.write_len_prefixed(&routed.payload);
    w
}

/// Build the data to be signed for a LocationEntry.
pub fn location_sign_data(node_id: &[u8; 16], tree_addr: &[u8], seq: u32) -> Writer {
    let mut w = Writer::new();
    w.write_bytes(crate::types::DOMAIN_LOC);
    w.write_node_id(node_id);
    w.write_tree_addr(tree_addr);
    w.write_varint(seq);
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ALGORITHM_ED25519;

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
            parent_id: Some([2u8; 16]),
            root_id: [3u8; 16],
            subtree_size: 10,
            tree_size: 100,
            tree_addr: vec![0, 1, 2],
            need_pubkey: true,
            pubkey: Some([4u8; 32]),
            child_prefix_len: 2,
            children: vec![(vec![0xAB, 0xCD], 5), (vec![0xDE, 0xF0], 3)],
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [5u8; 64],
            },
        };

        let encoded = pulse.encode_to_vec();
        let decoded = Pulse::decode_from_slice(&encoded).unwrap();

        assert_eq!(pulse.node_id, decoded.node_id);
        assert_eq!(pulse.parent_id, decoded.parent_id);
        assert_eq!(pulse.root_id, decoded.root_id);
        assert_eq!(pulse.subtree_size, decoded.subtree_size);
        assert_eq!(pulse.tree_size, decoded.tree_size);
        assert_eq!(pulse.tree_addr, decoded.tree_addr);
        assert_eq!(pulse.need_pubkey, decoded.need_pubkey);
        assert_eq!(pulse.pubkey, decoded.pubkey);
        assert_eq!(pulse.child_prefix_len, decoded.child_prefix_len);
        assert_eq!(pulse.children.len(), decoded.children.len());
        assert_eq!(pulse.signature, decoded.signature);
    }

    #[test]
    fn test_routed_roundtrip() {
        let routed = Routed {
            dest_addr: vec![1, 2, 3],
            dest_node_id: Some([6u8; 16]),
            src_addr: Some(vec![4, 5]),
            src_node_id: [7u8; 16],
            msg_type: crate::types::MSG_DATA,
            ttl: 32,
            payload: b"hello world".to_vec(),
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [8u8; 64],
            },
        };

        let encoded = routed.encode_to_vec();
        let decoded = Routed::decode_from_slice(&encoded).unwrap();

        assert_eq!(routed.dest_addr, decoded.dest_addr);
        assert_eq!(routed.dest_node_id, decoded.dest_node_id);
        assert_eq!(routed.src_addr, decoded.src_addr);
        assert_eq!(routed.src_node_id, decoded.src_node_id);
        assert_eq!(routed.msg_type, decoded.msg_type);
        assert_eq!(routed.ttl, decoded.ttl);
        assert_eq!(routed.payload, decoded.payload);
        assert_eq!(routed.signature, decoded.signature);
    }

    #[test]
    fn test_routed_roundtrip_no_src_addr() {
        let routed = Routed {
            dest_addr: vec![1, 2, 3],
            dest_node_id: None,
            src_addr: None, // No src_addr (e.g., PUBLISH messages)
            src_node_id: [7u8; 16],
            msg_type: crate::types::MSG_PUBLISH,
            ttl: 255,
            payload: b"location data".to_vec(),
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [8u8; 64],
            },
        };

        let encoded = routed.encode_to_vec();
        let decoded = Routed::decode_from_slice(&encoded).unwrap();

        assert_eq!(routed.dest_addr, decoded.dest_addr);
        assert_eq!(routed.dest_node_id, decoded.dest_node_id);
        assert_eq!(routed.src_addr, decoded.src_addr);
        assert!(decoded.src_addr.is_none());
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
            tree_addr: vec![1, 2, 3, 4],
            seq: 12345678,
            signature: Signature {
                algorithm: ALGORITHM_ED25519,
                sig: [10u8; 64],
            },
            received_at_secs: 0,
        };

        let encoded = entry.encode_to_vec();
        let decoded = LocationEntry::decode_from_slice(&encoded).unwrap();

        assert_eq!(entry.node_id, decoded.node_id);
        assert_eq!(entry.tree_addr, decoded.tree_addr);
        assert_eq!(entry.seq, decoded.seq);
        assert_eq!(entry.signature, decoded.signature);
    }

    #[test]
    fn test_tree_addr_roundtrip() {
        // Test root (depth 0)
        let mut w = Writer::new();
        w.write_tree_addr(&[]);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x00]); // Just depth byte
        let mut r = Reader::new(&encoded);
        let decoded = r.read_tree_addr().unwrap();
        assert!(decoded.is_empty());

        // Test even depth (depth 4)
        let addr = vec![3, 7, 2, 15];
        let mut w = Writer::new();
        w.write_tree_addr(&addr);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x04, 0x37, 0x2F]); // depth=4, nibbles packed
        let mut r = Reader::new(&encoded);
        let decoded = r.read_tree_addr().unwrap();
        assert_eq!(addr, decoded);

        // Test odd depth (depth 5) - last nibble should be padded with 0
        let addr = vec![3, 7, 2, 15, 1];
        let mut w = Writer::new();
        w.write_tree_addr(&addr);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x05, 0x37, 0x2F, 0x10]); // depth=5, last byte padded
        let mut r = Reader::new(&encoded);
        let decoded = r.read_tree_addr().unwrap();
        assert_eq!(addr, decoded);

        // Test depth 1
        let addr = vec![5];
        let mut w = Writer::new();
        w.write_tree_addr(&addr);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x01, 0x50]); // depth=1, one nibble, padded
        let mut r = Reader::new(&encoded);
        let decoded = r.read_tree_addr().unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_tree_addr_invalid_padding() {
        // Odd depth with non-zero padding nibble should be rejected
        let invalid = vec![0x03, 0x12, 0x3F]; // depth=3, last nibble is F, should be 0
        let mut r = Reader::new(&invalid);
        let result = r.read_tree_addr();
        assert_eq!(result, Err(DecodeError::TreeAddrInvalidPadding));
    }

    #[test]
    fn test_tree_addr_too_deep() {
        // Depth > MAX_TREE_DEPTH should be rejected
        let invalid = vec![128]; // depth=128 > 127
        let mut r = Reader::new(&invalid);
        let result = r.read_tree_addr();
        assert_eq!(result, Err(DecodeError::TreeAddrTooDeep));
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
    fn test_optional_tree_addr() {
        // Test None
        let mut w = Writer::new();
        w.write_optional_tree_addr(None);
        let encoded = w.finish();
        assert_eq!(encoded, vec![0x00]);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.read_optional_tree_addr().unwrap(), None);

        // Test Some
        let addr = vec![1, 2, 3];
        let mut w = Writer::new();
        w.write_optional_tree_addr(Some(&addr));
        let encoded = w.finish();
        let mut r = Reader::new(&encoded);
        assert_eq!(r.read_optional_tree_addr().unwrap(), Some(addr));
    }
}
