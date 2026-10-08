//! UDP 打洞协调
//!
//! 流程:
//! 1. A 经中继/现有隧道路由到 B, 发送 PunchRequest{target=B, my_udp_mapped_addr}
//! 2. B 收到后回复 PunchResponse{peer_udp_mapped_addr}, 同时开始向 A 的映射地址打洞
//! 3. A 收到 PunchResponse 后也开始向 B 的映射地址打洞
//! 4. 双方打洞包 = 明文 Handshake, 一旦 NAT 洞打开, 对端 demux 收到握手即建立 UDP 会话

use crate::common::error::Result;
use crate::tunnel::udp_demux::UdpDemux;
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;

/// 向目标映射地址持续打洞 (发送明文握手), 持续 n 次或直至会话建立
pub async fn punch_hole(
    demux: Arc<UdpDemux>,
    target: SocketAddr,
    handshake_payload: Vec<u8>,
) -> Result<()> {
    for _ in 0..10 {
        if demux.has_session(target) {
            break; // 对方已响应, 会话建立
        }
        demux.send_raw(&handshake_payload, target).await?;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    Ok(())
}

/// 构造用于打洞的明文握手包
pub fn make_punch_payload(id: &crate::tunnel::handshake::Identity) -> (Vec<u8>, [u8; 32]) {
    let (my_pub, _secret) = crate::crypto::generate_ephemeral_keypair();
    let hello = vnet_proto::Handshake {
        network_name: id.network_name.clone(),
        public_key: my_pub.as_bytes().to_vec(),
        peer_id: id.peer_id,
        hostname: id.hostname.clone(),
        virtual_ip: id.virtual_ip.clone(),
        version: crate::common::constants::PROTOCOL_VERSION,
        proxy_cidrs: id.proxy_cidrs.clone(),
        listen_addrs: id.listen_addrs.clone(),
        udp_mapped_addr: id.udp_mapped_addr.read().clone().unwrap_or_default(),
    };
    (hello.encode_to_vec(), *my_pub.as_bytes())
}
