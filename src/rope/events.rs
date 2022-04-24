use super::{Router, Peer};
use std::sync::Arc;

#[derive(Clone)]
pub struct NewPeerEvent {
    pub peer: Arc<Peer>,
}
