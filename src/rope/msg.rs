use std::ops::Deref;

use super::rpv6::{BoxedPacket, Header};
use super::exaddr::ExternalAddr;

#[derive(Debug, Clone, Copy)]
pub struct MsgOpts {
    src_external_addr: ExternalAddr,
}

impl Default for MsgOpts {
    fn default() -> Self {
        Self {
            src_external_addr: ExternalAddr::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Msg {
    packet: BoxedPacket,
    opts: MsgOpts,
}

impl Deref for Msg {
    type Target = BoxedPacket;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl Msg {
    pub fn new(packet: BoxedPacket) -> Self {
        Self {
            packet,
            opts: MsgOpts::default(),
        }
    }

    pub fn set_src_external_addr<'a>(&'a mut self, new_addr: ExternalAddr) -> ExternalAddr {
        let old = self.opts.src_external_addr;
        self.opts.src_external_addr = new_addr;
        old
    }

    pub fn get_src_external_addr(&self) -> ExternalAddr {
        self.opts.src_external_addr
    }

    pub fn replace_header(self, header: Header) -> Self {
        let new_packet = self.packet.replace_header(header);
        Self {
            packet: new_packet,
            opts: self.opts,
        }
    }

    /// Consume this message and use the packet as binary.
    pub fn to_buffer(self) -> Vec<u8> {
        self.packet.to_buffer()
    }
}
