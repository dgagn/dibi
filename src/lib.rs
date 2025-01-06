use bytes::{Buf, BufMut};
use codec::PacketFrame;
use context::Context;

mod codec;
pub mod connection;
pub mod context;
pub mod protocol;
pub mod ssl;
pub mod stream;

pub mod my;

pub trait BytesExt {
    fn get_bytes_null(&mut self) -> Result<bytes::Bytes, std::io::Error>;
}

impl BytesExt for bytes::Bytes {
    fn get_bytes_null(&mut self) -> Result<bytes::Bytes, std::io::Error> {
        let end = self
            .iter()
            .position(|&b| b == 0)
            .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let bytes = self.split_to(end);
        self.advance(1);
        Ok(bytes)
    }
}

pub trait BufMutExt {
    fn put_len_encoded_int(&mut self, value: u64) -> u8;
    fn put_str_null_terminated(&mut self, value: impl AsRef<[u8]>);
    fn put_len_encoded_str(&mut self, value: impl AsRef<[u8]>);
}

impl<T: BufMut> BufMutExt for T {
    /// [lenec](https://dev.mysql.com/doc/dev/mysql-server/9.0.1/page_protocol_basic_dt_integers.html#sect_protocol_basic_dt_int_fixed)
    fn put_len_encoded_int(&mut self, value: u64) -> u8 {
        if value < 251 {
            self.put_u8(value as u8);
            1
        } else if value < 0x10000 {
            self.put_u8(0xfc);
            self.put_u16_le(value as u16);
            3
        } else if value < 0x1000000 {
            self.put_u8(0xfd);
            self.put_uint_le(value, 3);
            4
        } else {
            self.put_u8(0xfe);
            self.put_u64_le(value);
            9
        }
    }

    fn put_str_null_terminated(&mut self, value: impl AsRef<[u8]>) {
        self.put_slice(value.as_ref());
        self.put_u8(0);
    }

    fn put_len_encoded_str(&mut self, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        self.put_len_encoded_int(value.len() as u64);
        self.put_slice(value);
    }
}

pub trait DecodePacket: Sized {
    type Error;

    fn decode_packet(packet: PacketFrame, context: &Context) -> Result<Self, Self::Error>;
}

pub trait EncodePacket<T> {
    type Error;

    fn encode_packet(self, context: &Context) -> Result<T, Self::Error>;

    fn is_command_packet(&self) -> bool {
        false
    }
}

impl<U> EncodePacket<U> for PacketFrame
where
    U: DecodePacket,
{
    type Error = <U as DecodePacket>::Error;

    fn encode_packet(self, context: &Context) -> Result<U, Self::Error> {
        U::decode_packet(self, context)
    }
}
