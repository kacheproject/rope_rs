use log::info;
use rope_rs::rope::Router;
use rope_rs::rope::wires::Transport;
use rope_rs::transports::udp::UdpTransport;
use rope_rs::peer_discovery::PeerDiscoveryServ;
use std::sync::Arc;

mod common;
use common::initialize;

#[tokio::test]
async fn single_way_wire_discovery_test() {
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
            info!("waiting for data...");
            let packet = sock0.recv_packet().await.unwrap();
            let header = packet.get_header();
            info!("got {:?}", packet.get_payload());
            if packet.get_payload() == b"Hello" {
                sock0.send_to(header.src_addr_int(), header.src_port, b"Hello", 0).await.unwrap();
            } else {
                sock0.send_to(header.src_addr_int(), header.src_port, b"Bye", 0).await.unwrap();
                break;
            }
        }
        info!("bye!");
    });

    let sock1 = r1.bind(0, 16).unwrap();
    sock1.send_to(r0_id, sock0_port, b"Hello", 0).await.unwrap();
    info!("hello sent");
    let packet = sock1.recv_packet().await.unwrap();
    info!("got hello");
    assert_eq!(packet.get_payload(), b"Hello");
    sock1.send_to(r0_id, sock0_port, b"Bye", 0).await.unwrap();
    info!("bye sent");
    let packet = sock1.recv_packet().await.unwrap();
    info!("got bye");
    assert_eq!(packet.get_payload(), b"Bye");
}
