//! 隧道层集成测试 (无需 TUN/root)

use std::sync::Arc;
use vnet_core::tunnel::{handshake, kcp, quic, tcp, ws, ws::WsTunnel, Tunnel};
use vnet_proto::{PacketType, TunnelPacket};

fn make_identity(name: &str, secret: &str, vip: &str, peer_id: u64) -> handshake::Identity {
    handshake::Identity {
        network_name: name.into(),
        network_secret: secret.into(),
        peer_id,
        hostname: "test".into(),
        virtual_ip: vip.into(),
        proxy_cidrs: vec![],
        listen_addrs: vec![],
        udp_mapped_addr: std::sync::Arc::new(parking_lot::RwLock::new(None)),
    }
}

fn make_data_packet(from: u64, to: u64, data: &[u8]) -> TunnelPacket {
    TunnelPacket {
        from_peer: from,
        to_peer: to,
        packet_type: PacketType::Data as i32,
        payload: data.to_vec(),
    }
}

async fn echo_both_ways(
    client: &(dyn Tunnel + Sync),
    server: &(dyn Tunnel + Sync),
    id_a: u64,
    id_b: u64,
) {
    let pkt = make_data_packet(id_a, id_b, b"hello-vnet");
    client.send(&pkt).await.unwrap();
    let got = server.recv().await.unwrap();
    assert_eq!(got.from_peer, id_a);
    assert_eq!(got.payload, b"hello-vnet");

    let pkt2 = make_data_packet(id_b, id_a, b"reply");
    server.send(&pkt2).await.unwrap();
    let got2 = client.recv().await.unwrap();
    assert_eq!(got2.payload, b"reply");
}

#[tokio::test]
async fn tcp_tunnel_handshake_and_echo() {
    let id_a = make_identity("net1", "secret", "10.0.0.1", 1001);
    let id_b = make_identity("net1", "secret", "10.0.0.2", 1002);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let id_b_clone = id_b.clone();
    let server = tokio::spawn(async move {
        let (stream, from) = listener.accept().await.unwrap();
        tcp::from_stream(stream, from.to_string(), &id_b_clone)
            .await
            .unwrap()
    });

    let (client_tun, hs_client) = tcp::connect(&addr.to_string(), &id_a).await.unwrap();
    assert_eq!(hs_client.peer.peer_id, 1002);
    let (server_tun, hs_server) = server.await.unwrap();
    assert_eq!(hs_server.peer.peer_id, 1001);

    echo_both_ways(&client_tun, &server_tun, 1001, 1002).await;
}

#[tokio::test]
async fn handshake_rejects_network_mismatch() {
    let id_a = make_identity("net-A", "s", "10.0.0.1", 1);
    let id_b = make_identity("net-B", "s", "10.0.0.2", 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, from) = listener.accept().await.unwrap();
        let _ = tcp::from_stream(stream, from.to_string(), &id_b).await;
    });

    let r = tcp::connect(&addr.to_string(), &id_a).await;
    assert!(r.is_err(), "不同 network 应拒绝握手");
}

#[tokio::test]
async fn kcp_tunnel_echo() {
    let id_a = make_identity("net-kcp", "secret", "10.0.0.1", 2001);
    let id_b = make_identity("net-kcp", "secret", "10.0.0.2", 2002);

    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    drop(listener);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let id_b_clone = id_b.clone();
    let bind_clone = bind.clone();
    tokio::spawn(async move {
        kcp::listener_loop(&bind_clone, id_b_clone, move |tun, hs, _from| {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send((tun, hs));
            }
        })
        .await
        .unwrap();
    });

    // 等监听器就绪
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (client_tun, hs_client) = kcp::connect(&bind, &id_a).await.unwrap();
    assert_eq!(hs_client.peer.peer_id, 2002);
    let (server_tun, hs_server) = rx.await.unwrap();
    assert_eq!(hs_server.peer.peer_id, 2001);

    echo_both_ways(&client_tun, &server_tun, 2001, 2002).await;
}

#[tokio::test]
async fn quic_tunnel_echo() {
    let id_a = make_identity("net-quic", "secret", "10.0.0.1", 3001);
    let id_b = make_identity("net-quic", "secret", "10.0.0.2", 3002);

    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    drop(listener);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let id_b_clone = id_b.clone();
    let bind_clone = bind.clone();
    tokio::spawn(async move {
        quic::listener_loop(&bind_clone, id_b_clone, move |tun, hs, _from| {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send((tun, hs));
            }
        })
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (client_tun, hs_client) = quic::connect(&bind, &id_a).await.unwrap();
    assert_eq!(hs_client.peer.peer_id, 3002);
    let (server_tun, hs_server) = rx.await.unwrap();
    assert_eq!(hs_server.peer.peer_id, 3001);

    echo_both_ways(&client_tun, &server_tun, 3001, 3002).await;
}

#[tokio::test]
async fn ws_tunnel_echo() {
    let id_a = make_identity("net-ws", "secret", "10.0.0.1", 4001);
    let id_b = make_identity("net-ws", "secret", "10.0.0.2", 4002);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    drop(listener);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let id_b_clone = id_b.clone();
    let bind_clone = bind.clone();
    tokio::spawn(async move {
        ws::listener_loop(
            &bind_clone,
            None,
            id_b_clone,
            move |tun: WsTunnel, hs, _from| {
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send((tun, hs));
                }
            },
        )
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let url = format!("ws://{bind}/");
    let (client_tun, hs_client) = WsTunnel::connect(&url, &id_a, None).await.unwrap();
    assert_eq!(hs_client.peer.peer_id, 4002);
    let (server_tun, hs_server) = rx.await.unwrap();
    assert_eq!(hs_server.peer.peer_id, 4001);

    echo_both_ways(&client_tun, &server_tun, 4001, 4002).await;
}
