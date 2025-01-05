use std::io::Cursor;

use bytes::{Buf, BufMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub struct PacketFrame {
    buffer: bytes::Bytes,
}

impl PacketFrame {
    pub fn new(buffer: bytes::Bytes) -> Self {
        Self { buffer }
    }

    pub fn take_buffer(self) -> bytes::Bytes {
        self.buffer
    }
}

#[derive(Debug, Default)]
pub struct PacketCodec {
    expected_sequence: u8,
}

impl PacketCodec {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn reset_sequence(&mut self) {
        self.expected_sequence = 0;
    }

    pub fn sequence(&self) -> u8 {
        self.expected_sequence
    }
}

/// The maximum chunk size is 16MB (3 bytes)
pub const MAX_CHUNK_SIZE: usize = 0xFFFFFF;

/// The default maximum packet size is 1GB
pub const MAX_PACKET_SIZE: usize = 1024 * 1024 * 1024;

/// The header size is 4 bytes (3 bytes for the length and 1 byte for the sequence number)
pub const HEADER_SIZE: usize = 4;

impl Decoder for PacketCodec {
    type Item = PacketFrame;

    // Infaillible
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        let mut cursor = Cursor::new(&mut *src);
        let len = cursor.get_uint_le(3) as usize;
        let seq = cursor.get_u8();

        let chunk_size = HEADER_SIZE + len;
        if src.len() < chunk_size {
            src.reserve(chunk_size - src.len());
            return Ok(None);
        }

        src.advance(HEADER_SIZE);

        let bytes = src.split_to(len).freeze();

        #[cfg(feature = "tracing")]
        tracing::debug!("Decoded packet: seq={}, len={}", seq, len);

        if self.expected_sequence != seq {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid sequence number: expected {}, got {}",
                    self.expected_sequence, seq
                ),
            ));
        }

        self.expected_sequence = seq.wrapping_add(1);

        Ok(Some(PacketFrame { buffer: bytes }))
    }
}

// Encode a packet frame to send with the sequence number associated
impl Encoder<PacketFrame> for PacketCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: PacketFrame, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let mut remaining = item.buffer.len();

        if remaining > MAX_PACKET_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Packet size exceeds the maximum allowed size: {} > {}",
                    remaining, MAX_PACKET_SIZE
                ),
            ));
        }

        dst.reserve(HEADER_SIZE + remaining);

        while remaining > 0 {
            let len = std::cmp::min(remaining, MAX_CHUNK_SIZE);
            dst.put_uint_le(len as u64, 3);
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Encoded packet: seq={}, len={}",
                self.expected_sequence,
                len
            );
            dst.put_u8(self.expected_sequence);
            dst.put_slice(&item.buffer[item.buffer.len() - remaining..]);
            remaining -= len;
            self.expected_sequence = self.expected_sequence.wrapping_add(1);
        }

        if !item.buffer.is_empty() && (item.buffer.len() % MAX_CHUNK_SIZE) == 0 {
            dst.put_uint_le(0, 3);
            dst.put_u8(self.expected_sequence);
        }

        Ok(())
    }
}
