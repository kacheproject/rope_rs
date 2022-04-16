use serde::{Deserialize, Serialize};
use crate::common::io::{BufWriter, WriteCounter};

pub trait ProtocolMessage {
    /// Return the message size. Return 0 if there is error in message.
    fn required_size(&self) -> usize;
}

/// Toolkit trait to apply `ProtocolMessage` and `CopiedProtocolMessage` in messagepack form when the struct meet requirements.
/// - `ProtocolMessage`: `serde::Serialize`
/// - `CopiedProtocolMessage`: `serde::Serialize + MessageKind + serde::Deserialize<'a>`
trait RMPProtocolMessage {}

impl<T: RMPProtocolMessage + Serialize> ProtocolMessage for T {
    fn required_size(&self) -> usize {
        let mut counter = WriteCounter::default();
        if let Ok(_) = rmp_serde::encode::write_named(&mut counter, self) {
            1 + counter.length
        } else {
            0
        }
    }
}

/// A trait for message kind.
trait MessageKind {
    const KIND_NUMBER: u8;
}

#[derive(Debug)]
pub enum DecodeError<E> {
    Internal(E),
    UndefinedKind,
}

#[derive(Debug)]
pub enum EncodeError<E> {
    Internal(E),
    InsuffientSize,
}

pub trait CopiedProtocolMessage<'a> : ProtocolMessage + Sized {
    type DecodeInternalError;
    type EncodeInternalError;

    fn parse(src: &'a [u8]) -> Result<Self, DecodeError<Self::DecodeInternalError>>;

    fn write(&self, dst: &mut [u8]) -> Result<usize, EncodeError<Self::EncodeInternalError>>;
}

impl<'a, T: RMPProtocolMessage + MessageKind + Serialize + Deserialize<'a>> CopiedProtocolMessage<'a> for T {
    type DecodeInternalError = rmp_serde::decode::Error;
    type EncodeInternalError = rmp_serde::encode::Error;

    fn parse(src: &'a [u8]) -> Result<Self, DecodeError<Self::DecodeInternalError>> {
        let content: T = rmp_serde::from_slice(&src[1..]).map_err(|e| DecodeError::Internal(e))?;
        Ok(content)
    }

    fn write(&self, dst: &mut [u8]) -> Result<usize, EncodeError<Self::EncodeInternalError>> {
        if dst.len() >= self.required_size() {
            dst[0] = Self::KIND_NUMBER;
            let mut dstio = BufWriter::new(dst, 1);
            rmp_serde::encode::write_named(&mut dstio, self).map_err(|e| EncodeError::Internal(e))?;
            Ok(dstio.len())
        } else {
            Err(EncodeError::InsuffientSize)
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct SyncContent {
    known: Vec<u128>
}

impl RMPProtocolMessage for SyncContent {}

impl MessageKind for SyncContent {
    const KIND_NUMBER: u8 = 0;
}

impl SyncContent {
    pub fn get_known(&self) -> &Vec<u128> {
        &self.known
    }

    pub fn get_known_mut(&mut self) -> &mut Vec<u128> {
        &mut self.known
    }

    pub fn new(known: Vec<u128>) -> Self {
        Self {
            known,
        }
    }
}

pub struct ByeContent;

impl ProtocolMessage for ByeContent {
    fn required_size(&self) -> usize {
        1
    }
}

impl MessageKind for ByeContent {
    const KIND_NUMBER: u8 = 1;
}

impl CopiedProtocolMessage<'_> for ByeContent {
    type DecodeInternalError = rmp_serde::decode::Error;

    type EncodeInternalError = rmp_serde::encode::Error;

    fn parse(_: &[u8]) -> Result<Self, DecodeError<Self::DecodeInternalError>> {
        Ok(Self {})
    }

    fn write(&self, dst: &mut [u8]) -> Result<usize, EncodeError<Self::EncodeInternalError>> {
        if dst.len() >= self.required_size() {
            dst[0] = 1;
            Ok(1)
        } else {
            Err(EncodeError::InsuffientSize)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AskQuestion {
    PublicKey,
    PhysicalWires,
}

impl From<AskQuestion> for u64 {
    fn from(value: AskQuestion) -> Self {
        match value {
            AskQuestion::PublicKey => 1,
            AskQuestion::PhysicalWires => 2,
        }
    }
}

impl TryFrom<u64> for AskQuestion {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AskQuestion::PublicKey),
            2 => Ok(AskQuestion::PhysicalWires),
            _ => Err("unknown question")
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct AskContent {
    id: u128,
    q: Vec<u64>,
}

impl RMPProtocolMessage for AskContent {}

impl MessageKind for AskContent {
    const KIND_NUMBER: u8 = 2;
}

impl AskContent {
    pub fn new(id: u128, q: Vec<u64>) -> Self {
        Self {
            id,
            q,
        }
    }
}

pub enum AnyMessage {
    NDSync(SyncContent),
    NDBye(ByeContent),
    NDAsk(AskContent),
}

pub fn parse(src: &[u8]) -> Result<AnyMessage, DecodeError<rmp_serde::decode::Error>> {
    let kind = src[0];
    match kind {
        SyncContent::KIND_NUMBER => Ok(AnyMessage::NDSync(SyncContent::parse(src)?)),
        ByeContent::KIND_NUMBER => Ok(AnyMessage::NDBye(ByeContent {})),
        AskContent::KIND_NUMBER => Ok(AnyMessage::NDAsk(AskContent::parse(src)?)),
        _ => Err(DecodeError::UndefinedKind)
    }
}
