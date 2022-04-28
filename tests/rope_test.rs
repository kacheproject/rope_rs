use rope_rs::rope::*;
use rope_rs::rope::wires::Transport;
use std::sync::Arc;
use rope_rs::transports::udp::UdpTransport;

mod common;

use common::initialize;

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
    let transport0 = UdpTransport::bind("[::1]:0").await.unwrap();
    let transport1 = UdpTransport::bind("[::1]:0").await.unwrap();
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

#[tokio::test]
async fn router_remote_broadcast_hello_test() {
    initialize();
    let r0 = Router::new_random();
    let r1 = Router::new_random();
    let r0_pk = r0.get_public_key();
    let r1_pk = r1.get_public_key();
    let sock0 = r0.bind(0, 16).unwrap();
    let port0 = sock0.get_local_port();
    let sock1 = r1.bind(0, 16).unwrap();
    let peer0 = r1.new_peer(r0.get_id(), r0_pk).unwrap();
    let peer1 = r0.new_peer(r0.get_id(), r1_pk).unwrap();
    let transport0 = UdpTransport::bind("[::1]:0").await.unwrap();
    let transport1 = UdpTransport::bind("[::1]:0").await.unwrap();
    r0.attach_rx(transport0.create_rx());
    r1.attach_rx(transport1.create_rx());
    peer1.add_tx(transport0.create_tx(transport1.local_addr().unwrap()));
    peer0.add_tx(transport1.create_tx(transport0.local_addr().unwrap()));
    tokio::spawn(async move {
        sock1.send_to(0, port0, "Hello World!".as_bytes(), 0).await.unwrap();
    });
    let packet = sock0.recv_packet().await.unwrap();
    assert_eq!(packet.get_payload(), "Hello World!".as_bytes());
}

#[tokio::test]
async fn single_way_path_discovery_test() {
    initialize();
    let r0 = Router::new_random();
    let r0_id = r0.get_id();
    let transport0 = Arc::new(UdpTransport::bind("[::1]:0").await.unwrap());
    let transport0_addr = transport0.local_addr().unwrap();
    r0.attach_rx(transport0.create_rx());
    r0.set_default_transport("udp", transport0);
    let sock0 = r0.bind(0, 16).unwrap();
    let sock0_port = sock0.get_local_port();

    let r1 = Router::new_random();
    let transport1 = Arc::new(UdpTransport::bind("[::1]:0").await.unwrap());
    r1.attach_rx(transport1.create_rx());
    r1.set_default_transport("udp", transport1.clone());

    r0.new_peer(r1.get_id(), r1.get_public_key()).unwrap();

    let peer0 = r1.new_peer(r0.get_id(), r0.get_public_key()).unwrap();
    peer0.add_tx(transport1.create_tx(transport0_addr));

    tokio::spawn(async move {
        loop {
            let packet = sock0.recv_packet().await.unwrap();
            let header = packet.get_header();
            if packet.get_payload() == b"Hello" {
                sock0.send_to(header.src_addr_int(), header.src_port, b"Hello", 0).await.unwrap();
            } else {
                sock0.send_to(header.src_addr_int(), header.src_port, b"Bye", 0).await.unwrap();
                break;
            }
        }
    });

    let sock1 = r1.bind(0, 16).unwrap();
    sock1.send_to(r0_id, sock0_port, b"Hello", 0).await.unwrap();
    let packet = sock1.recv_packet().await.unwrap();
    assert_eq!(packet.get_payload(), b"Hello");
    sock1.send_to(r0_id, sock0_port, b"Bye", 0).await.unwrap();
    let packet = sock1.recv_packet().await.unwrap();
    assert_eq!(packet.get_payload(), b"Bye");
}
