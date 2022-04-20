/// RPv6 (Rope Protocol v6) is copy from IPv6, but with huge change.
/// Some parts of IPv6 have been kept to preserve the interop with IPv6 in boringtun.
/// RPv6 doesn't use DHCPv6, ICMPv6, so on, since the use case of RPv6 doesn't need such complex protocols.
/// Be careful!
/// The original idea is to use with boringtun -- which requires IP packet on top.
/// RPv6 try to emulate IPv6 to operate with boringtun. Actually it's a compat version of UDPv6.

/// version (3 bits) = 0b110 | reserved0 (5 bits) | flags (1 octet) 
/// src_port (2 octets) // ports <= 1023 are for internal use
/// payload_length (2 octets)
/// dst_port (2 octets)
/// src_addr (16 octets)
/// dst_addr (16 octets)
/// 
/// In future we may use more compat layout if we can customize wireguard impl.

use packed_struct::prelude::*;

pub const MAX_PACKET_SIZE: usize = 65535 - 40 - 32 - 8 - 40; // rpv6 header, wireguard data header, udp header, ip header (ipv6 40 bytes)

#[derive(PackedStruct, Default, Clone, Copy, Debug)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Header {
    #[packed_field(bits="0..=3")]
    pub version: Integer<u8, packed_bits::Bits::<4>>,
    #[packed_field(bits="4..=7")]
    _reserved0: ReservedZero<packed_bits::Bits::<4>>, // the first byte
    #[packed_field(bits="8..=15")]
    pub flags: u8,
    #[packed_field(bits="16..=31")]
    pub src_port: u16,
    #[packed_field(bits="32..=47")]
    pub payload_length: u16,
    #[packed_field(bits="48..=63")]
    pub dst_port: u16,
    #[packed_field(bits="64..=191")]
    pub src_addr: [u8; 16],
    #[packed_field(bits="192..=319")]
    pub dst_addr: [u8; 16],
}

impl Header {
    pub fn new(flags: u8, src_port: u16, payload_length: u16, dst_port: u16, src_addr: u128, dst_addr: u128) -> Self {
        Header {
            version: 6.into(),
            flags,
            src_port,
            payload_length,
            dst_port,
            src_addr: src_addr.to_be_bytes(),
            dst_addr: dst_addr.to_be_bytes(),
            .. Self::default()
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self, ParsingError> {
        if data.len() >= 40 {
            let mut header = [0; 40];
            for i in 0..40 {
                header[i] = data[i];
            }
            match Self::unpack(&header) {
                Ok(r) => Ok(r),
                Err(e) => Err(ParsingError::InternalError(e)),
            }
        } else {
            Err(ParsingError::SliceTooSmall)
        }
    }

    pub fn build(&self) -> [u8; 40] {
        self.pack().unwrap()
    }

    pub fn dst_addr_cmp(&self, other: u128) -> bool {
        other.to_be_bytes() == self.dst_addr
    }

    pub fn src_addr_cmp(&self, other: u128) -> bool {
        other.to_be_bytes() == self.src_addr
    }

    pub fn dst_addr_int(&self) -> u128 {
        u128::from_be_bytes(self.dst_addr)
    }

    pub fn src_addr_int(&self) -> u128 {
        u128::from_be_bytes(self.src_addr)
    }

    pub fn set_src_addr(&mut self, src_addr: u128) {
        self.src_addr = src_addr.to_be_bytes();
    }

    pub fn set_dst_addr(&mut self, dst_addr: u128) {
        self.dst_addr = dst_addr.to_be_bytes();
    }
}

#[derive(Debug)]
pub enum ParsingError {
    SliceTooSmall,
    InternalError(packed_struct::PackingError),
}

impl From<Header> for [u8; 40] {
    fn from(header: Header) -> Self { header.build() }
}

#[cfg(test)]
mod test_boringtun_interop {
    use super::*;

    #[test]
    fn validate_ipv6_packet_version() {
        let p0_addr = rand::random();
        let p1_addr = rand::random();
        let header: [u8; 40] = Header::new(0, 0, 0, 0, p1_addr, p0_addr).into();
        assert_eq!(header[0] >> 4, 6);
    }
}

/// Packet on stack frame.
/// It's very cheap since it's only parsed header and a slice of payload.
/// But it may not outlive the stack depends on the original buffer.
/// If you will copy the payload, consider BoxedPacket since it will try to avoid the copy if you need to overwrite the header.
#[derive(Clone)]
pub struct Packet<'a> {
    header: Header,
    payload: &'a [u8],
}

pub enum WriteBufferError {
    SliceTooSmall,
}

impl<'a> Packet<'a> {
    pub fn new(header: Header, payload: &'a [u8]) -> Self {
        Self {
            header: header,
            payload: payload
        }
    }

    pub fn parse(raw: &'a [u8]) -> Result<Self, ParsingError> {
        let header = Header::parse(raw)?;
        Ok(Self::new(header, &raw[40..]))
    }

    pub fn len(&self) -> usize {
        self.payload.len() + 40
    }

    pub fn get_header(&self) -> Header {
        self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        self.payload
    }

    pub fn write_buffer(&self, buf: &mut [u8]) -> Result<usize, WriteBufferError> {
        if buf.len() >= self.len() {
            let header: [u8; 40] = self.header.into();
            let _ = &buf[0..40].copy_from_slice(&header);
            for i in 0..self.payload.len() {
                buf[i+40] = self.payload[i];
            }
            Ok(self.len())
        } else {
            Err(WriteBufferError::SliceTooSmall)
        }
    }

    pub fn verify_length(&self) -> bool {
        usize::from(self.header.payload_length) == self.get_payload().len()
    }

    pub fn enforce_payload_size(&self) -> std::io::Result<u16> {
        if self.get_payload().len() <= MAX_PACKET_SIZE && self.verify_length() {
            Ok(self.header.payload_length.try_into().unwrap())
        } else {
            log::error!(target: "Packet.enforce_payload_size", "unexpected payload size: {}", self.get_payload().len());
            Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
        }
    }
}

/// Packet allocated on heap.
/// This helps packet outlive of stack frame.
#[derive(Clone)]
pub struct BoxedPacket {
    header: Header,
    payload: Vec<u8>,
    skipped_40: bool,
}

impl BoxedPacket {
    /// Get a new BoxedPacket.
    /// Set skipped_40 true if the payload already have header.
    pub fn new(header: Header, payload: Vec<u8>, skipped_40: bool) -> Self {
        Self { header: header, payload: payload, skipped_40: skipped_40 }
    }

    pub fn get_payload_mut(&mut self) -> &mut [u8] {
        if self.skipped_40 {
            &mut self.payload[40..]
        } else {
            &mut self.payload[..]
        }
    }

    pub fn get_payload(&self) -> &[u8] {
        if self.skipped_40 {
            &self.payload[40..]
        } else {
            &self.payload[..]
        }
    }

    pub fn get_header(&self) -> Header {
        self.header
    }

    pub fn replace_header(self, new_header: Header) -> Self {
        Self::new(new_header, self.payload, self.skipped_40)
    }

    pub fn len(&self) -> usize {
        self.payload.len() + (if self.skipped_40 { 0 } else { 40 })
    }

    /// Consume this BoxedPacket and get a buffer.
    /// This function can avoid one copy operation if there already have space for header (skipped_40 is set).
    pub fn to_buffer(mut self) -> Vec<u8> {
        let data_len = self.len() - 40;
        let skipped_40 = self.skipped_40;
        if !skipped_40 {
            self.payload.resize(self.len(), 0);
            let data = self.get_payload_mut();
            for i in 0..data_len {
                let ri = data_len - i - 1;
                data[ri+40] = data[ri];
            }
        } // If skipped_40 set, we don't need to move payload for header. Just do overwrite.
        let header_buf: [u8; 40] = self.header.into();
        let _ = &self.payload[0..40].copy_from_slice(&header_buf[..]);
        self.payload
    }

    pub fn parse(v: Vec<u8>) -> Result<Self, ParsingError> {
        let header = Header::parse(&v[..])?;
        Ok(Self::new(header, v, true))
    }

    pub fn verify_length(&self) -> bool {
        usize::from(self.header.payload_length) == self.get_payload().len()
    }

    pub fn enforce_payload_size(&self) -> std::io::Result<u16> {
        if self.get_payload().len() <= MAX_PACKET_SIZE && self.verify_length() {
            Ok(self.header.payload_length.try_into().unwrap())
        } else {
            log::error!(target: "BoxedPacket.enforce_payload_size", "unexpected payload size: {}", self.get_payload().len());
            Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
        }
    }
}

impl From<&Packet<'_>> for BoxedPacket {
    fn from(packet: &Packet) -> BoxedPacket {
        let mut payload = Vec::new();
        payload.resize(packet.payload.len()+40, 0);
        payload[40..].copy_from_slice(packet.payload);
        BoxedPacket::new(packet.header, payload, true)
    }
}

impl<'a> From<&'a BoxedPacket> for Packet<'a> {
    fn from(packet: &'a BoxedPacket) -> Packet<'a> {
        Packet::new(packet.header, &packet.get_payload())
    }
}

impl From<BoxedPacket> for Vec<u8> {
    fn from(packet: BoxedPacket) -> Vec<u8> {
        packet.to_buffer()
    }
}

impl From<BoxedPacket> for Box<[u8]> {
    fn from(packet: BoxedPacket) -> Box<[u8]> {
        packet.to_buffer().into_boxed_slice()
    }
}

impl std::fmt::Debug for BoxedPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("BoxedPacket {{ header: {:?}, payload: Vec<u8>[..{}], skipped_40: {} }}", self.get_header(), self.payload.len(), self.skipped_40))
    }
}

impl std::fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Packet {{ header: {:?}, payload: &[u8; {}] }}", self.header, self.payload.len()))
    }
}

#[derive(PackedStruct, Clone, Copy, Debug)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct Flags {
    #[packed_field(bits="0")]
    reserved0: bool,
    #[packed_field(bits="1")]
    reserved1: bool,
    #[packed_field(bits="2")]
    reserved2: bool,
    #[packed_field(bits="3")]
    reserved3: bool,
    #[packed_field(bits="4")]
    reserved4: bool,
    #[packed_field(bits="5")]
    reserved5: bool,
    #[packed_field(bits="6")]
    reserved6: bool,
    #[packed_field(bits="7")]
    reserved7: bool,
}

impl Default for Flags {
    fn default() -> Self {
        Self::unpack(&[0]).unwrap()
    }
}

impl From<Flags> for u8 {
    fn from(flags: Flags) -> u8 {
        flags.pack().unwrap()[0]
    }
}

impl From<[u8; 1]> for Flags {
    fn from(array: [u8; 1]) -> Flags {
        array[0].into()
    }
}

impl From<u8> for Flags {
    fn from(i: u8) -> Self {
        Self::unpack(&[i]).unwrap()
    }
}

use std::io;

pub fn enforce_payload_size(size: usize) -> io::Result<u16> {
    if size <= MAX_PACKET_SIZE {
        Ok(size.try_into().unwrap())
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidData))
    }
}
