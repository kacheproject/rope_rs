use rope_rs::rope::*;
use rope_rs::rope::wires::Transport;
use tokio::net::UdpSocket;
use simple_logger::SimpleLogger;
use rope_rs::transports::udp::UdpTransport;

use std::sync::Once;

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(|| {
        SimpleLogger::new().with_level(log::LevelFilter::Trace).init().unwrap();
    });
}

#[tokio::test]
async fn router_local_hello_test() {
    initialize();
    let r0 = Router::new_random();
    let r0_id = r0.get_id();
    let sock0 = r0.bind(0, 16).unwrap();
    let port0 = sock0.get_local_port();
    let sock1 = r0.bind(0, 16).unwrap();
    tokio::spawn(async move {
        sock1.send_to(r0_id, port0, "Hello World!".as_bytes(), 0).await.unwrap();
    });
    let packet = sock0.recv_packet().await.unwrap();
    assert_eq!(packet.get_payload(), "Hello World!".as_bytes());
}

#[tokio::test]
async fn router_remote_hello_test() {
    initialize();
    let r0 = Router::new_random();
    let r1 = Router::new_random();
    let r0_pk = r0.get_public_key();
    let r1_pk = r1.get_public_key();
    let r0_id = r0.get_id();
    let sock0 = r0.bind(0, 16).unwrap();
    let port0 = sock0.get_local_port();
    let sock1 = r1.bind(0, 16).unwrap();
    let peer0 = r1.new_peer(r0.get_id(), r0_pk).unwrap();
    let peer1 = r0.new_peer(r0.get_id(), r1_pk).unwrap();
    let transport0 = UdpTransport::new(UdpSocket::bind("[::1]:0").await.unwrap());
    let transport1 = UdpTransport::new(UdpSocket::bind("[::1]:0").await.unwrap());
    r0.attach_rx(transport0.create_rx());
    r1.attach_rx(transport1.create_rx());
    peer1.add_tx(transport0.create_tx(transport1.local_addr().unwrap()));
    peer0.add_tx(transport1.create_tx(transport0.local_addr().unwrap()));
    tokio::spawn(async move {
        sock1.send_to(r0_id, port0, "Hello World!".as_bytes(), 0).await.unwrap();
    });
    let packet = sock0.recv_packet().await.unwrap();
    assert_eq!(packet.get_payload(), "Hello World!".as_bytes());
}
