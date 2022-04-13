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

/// Msg is used to track local options for a packet.
/// Most functions of BoxedPacket can be applied here. Some of them may be overrided for better experience.
/// ## Avaliable options
/// - `src_external_addr` is the source address of the physical network.
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

    /// Set `src_external_addr`.
    /// This option help application identify the source address of the physical network.
    /// In most cases it's set by the router, before routing the packet.
    pub fn set_src_external_addr<'a>(&'a mut self, new_addr: ExternalAddr) -> ExternalAddr {
        let old = self.opts.src_external_addr;
        self.opts.src_external_addr = new_addr;
        old
    }

    /// Get `src_external_addr`.
    /// This option help application identify the source address of the physical network.
    pub fn get_src_external_addr(&self) -> ExternalAddr {
        self.opts.src_external_addr
    }

    /// Consume this message and return a new message with new RPv6 header and same option.
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
