use bytes::BufMut;
use url::Url;
use serde::{Deserialize, Serialize};

struct WriteCounter {
    pub length: usize,
}

impl Default for WriteCounter {
    fn default() -> Self {
        Self {
            length: 0,
        }
    }
}

impl std::io::Write for WriteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.length += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) } // just ignore
}

pub trait ProtocolMessage {
    /// Return the message size. Return 0 if there is error in message.
    fn required_size(&self) -> usize;
}

#[derive(Debug)]
pub enum DecodeError<E> {
    Internal(E),
    UndefinedKind,
}

#[derive(Debug)]
pub enum EncodeError<E> {
    Internal(E),
}

pub trait CopiedProtocolMessage : ProtocolMessage + Sized {
    type DecodeInternalError;
    type EncodeInternalError;

    fn parse(src: &[u8]) -> Result<Self, DecodeError<Self::DecodeInternalError>>;

    fn write(&self, dst: &mut Vec<u8>) -> Result<usize, EncodeError<Self::EncodeInternalError>>;
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct SyncContent {
    known: Vec<u128>
}

impl ProtocolMessage for SyncContent {
    fn required_size(&self) -> usize {
        let mut counter = WriteCounter::default();
        if let Ok(_) = rmp_serde::encode::write_named(&mut counter, self) {
            1 + counter.length
        } else {
            0
        }
    }
}

impl CopiedProtocolMessage for SyncContent {
    type DecodeInternalError = rmp_serde::decode::Error;
    type EncodeInternalError = rmp_serde::encode::Error;

    fn parse(src: &[u8]) -> Result<Self, DecodeError<Self::DecodeInternalError>> {
        let content: SyncContent = rmp_serde::from_slice(&src[1..]).map_err(|e| DecodeError::Internal(e))?;
        Ok(content)
    }

    fn write<'a>(&'a self, mut dst: &'a mut Vec<u8>) -> Result<usize, EncodeError<Self::EncodeInternalError>> {
        dst.put_u8(0);
        let old_len = dst.len();
        rmp_serde::encode::write_named(&mut dst, self).map_err(|e| EncodeError::Internal(e))?;
        Ok(dst.len() - old_len)
    }
}

impl TryFrom<&[u8]> for SyncContent {
    type Error = DecodeError<<Self as CopiedProtocolMessage>::DecodeInternalError>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
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

impl CopiedProtocolMessage for ByeContent {
    type DecodeInternalError = rmp_serde::decode::Error;

    type EncodeInternalError = rmp_serde::encode::Error;

    fn parse(_: &[u8]) -> Result<Self, DecodeError<Self::DecodeInternalError>> {
        Ok(Self {})
    }

    fn write(&self, dst: &mut Vec<u8>) -> Result<usize, EncodeError<Self::EncodeInternalError>> {
        dst.put_u8(1);
        Ok(self.required_size())
    }
}

pub struct AskContent {
    id: u128,
    q: Vec<u64>,
}

pub enum AnyMessage {
    NDSync(SyncContent),
    NDBye(ByeContent),
}

pub fn parse(src: &[u8]) -> Result<AnyMessage, DecodeError<rmp_serde::decode::Error>> {
    let kind = src[0];
    match kind {
        0 => Ok(AnyMessage::NDSync(SyncContent::try_from(src)?)),
        1 => Ok(AnyMessage::NDBye(ByeContent {})),
        _ => Err(DecodeError::UndefinedKind)
    }
}
