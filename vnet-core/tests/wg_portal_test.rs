//! WireGuard 门户集成测试: 用 boringtun 模拟手机客户端, 验证
//! WG 握手 -> 封装 IP 包 -> 门户解封装 -> PeerManager 入站通道

use boringtun::noise::{Tunn, TunnResult};
use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use vnet_core::peer::PeerManager;
use vnet_core::vpn_portal::{self, WgClientConfig};

const SERVER_PEER_ID: u64 = 9001;
const CLIENT_PEER_ID: u64 = 9002;

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 构造 ICMP echo 请求 IPv4 包
fn icmp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45; // ver+IHL
    p[1] = 0x00;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64; // ttl
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let cksum = ip_checksum(&p[..20]);
    p[10..12].copy_from_slice(&cksum.to_be_bytes());
    // ICMP echo request
    p[20] = 8;
    let icmp_cksum = ip_checksum(&p[20..]);
    p[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());
    p
}

/// 驱动一次客户端 -> 服务端 -> 客户端的 UDP 往返
async fn pump(
    client: &mut Tunn,
    sock: &UdpSocket,
    server: SocketAddr,
    out: &mut [u8],
) -> bool {
    // 取出客户端排队的网络包并发送
    loop {
        let r = client.encapsulate(&[], out);
        match r {
            TunnResult::WriteToNetwork(p) => {
                let _ = sock.send_to(p, server).await;
            }
            TunnResult::Done => break,
            TunnResult::Err(_) => return false,
            _ => break,
        }
    }
    // 接收服务端响应并喂回客户端
    let mut buf = vec![0u8; 65536 + 64];
    if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await
    {
        let mut dst = vec![0u8; 65536 + 64];
        let r = client.decapsulate(Some(from.ip()), &buf[..n], &mut dst);
        if let TunnResult::WriteToNetwork(p) = r {
            let reply = p.to_vec();
            let _ = sock.send_to(&reply, server).await;
        }
        true
    } else {
        false
    }
}

#[tokio::test]
async fn wg_portal_handshake_and_data() {
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (connect_tx, _connect_rx) = tokio::sync::mpsc::channel::<String>(64);
    let mgr = PeerManager::new(SERVER_PEER_ID, inbound_tx, connect_tx);
    // 数据归属判断依赖 identity (目标==本机 vip 才本地投递)
    *mgr.identity.write() = Some(vnet_core::tunnel::handshake::Identity {
        network_name: "t".into(),
        network_secret: "t".into(),
        peer_id: SERVER_PEER_ID,
        hostname: "srv".into(),
        virtual_ip: "10.99.0.1".into(),
        proxy_cidrs: vec![],
        listen_addrs: vec![],
        udp_mapped_addr: std::sync::Arc::new(parking_lot::RwLock::new(None)),
    });

    // 服务器/客户端密钥
    let mut rng = rand::rngs::OsRng;
    let server_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let server_public = x25519_dalek::PublicKey::from(&server_secret);
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let client_public = x25519_dalek::PublicKey::from(&client_secret);

    let client_cfg = WgClientConfig {
        name: "phone".into(),
        vip: "10.99.0.2".parse().unwrap(),
        peer_public_key: client_public.to_bytes(),
        peer_id: CLIENT_PEER_ID,
    };

    let bind = "127.0.0.1:11099";
    let _portal = vpn_portal::WgPortal::start(bind, server_secret.to_bytes(), vec![client_cfg], mgr.clone())
        .await
        .unwrap();

    // boringtun 客户端
    let mut client = Tunn::new(client_secret, server_public, None, Some(25), 1, None);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server: SocketAddr = bind.parse().unwrap();
    let mut out = vec![0u8; 65536 + 64];

    // 反复驱动直到握手完成
    let mut handshake_ok = false;
    for _ in 0..5 {
        pump(&mut client, &sock, server, &mut out).await;
        if client.time_since_last_handshake().is_some() {
            handshake_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(handshake_ok, "WG 握手应在 5 轮内完成");

    // 封装一个 ICMP 包 (client vip -> server vip)
    let ip = icmp_packet("10.99.0.2".parse().unwrap(), "10.99.0.1".parse().unwrap());
    let r = client.encapsulate(&ip, &mut out);
    match r {
        TunnResult::WriteToNetwork(p) => {
            sock.send_to(p, server).await.unwrap();
        }
        _other => panic!("encapsulate 应返回 WriteToNetwork, got other TunnResult"),
    }

    // 门户 decapsulate 后应把 IP 包送入 PeerManager 的 inbound 通道
    let got = tokio::time::timeout(Duration::from_secs(3), inbound_rx.recv())
        .await
        .expect("timeout 等待入站包")
        .expect("inbound channel closed");
    assert_eq!(&got[12..16], &Ipv4Addr::new(10, 99, 0, 2).octets());
    assert_eq!(&got[16..20], &Ipv4Addr::new(10, 99, 0, 1).octets());

    // peer 已注册
    assert!(mgr.peer_ids().contains(&CLIENT_PEER_ID));
}
