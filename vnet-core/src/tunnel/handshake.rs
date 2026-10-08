//! 握手协议: X25519 密钥交换 + 身份确认

use crate::common::constants::PROTOCOL_VERSION;
use crate::common::error::{Error, Result};
use crate::crypto;
use crate::tunnel::frame;
use aes_gcm::Aes256Gcm;
use prost::Message;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use vnet_proto::Handshake;

/// 本端身份信息
#[derive(Clone)]
pub struct Identity {
    pub network_name: String,
    pub network_secret: String,
    pub peer_id: u64,
    pub hostname: String,
    pub virtual_ip: String,
    pub proxy_cidrs: Vec<String>,
    /// 本机监听地址 (gossip 通告用, 避免通告连接的临时端口)
    pub listen_addrs: Vec<String>,
    /// 本机 UDP socket 经 STUN 探测得到的外网映射地址 (host:port); Arc 共享给 PeerManager,
    /// 握手时 read 出来填入 Handshake.udp_mapped_addr, 用于 NAT 打洞
    pub udp_mapped_addr: Arc<parking_lot::RwLock<Option<String>>>,
}

/// 握手结果
pub struct HandshakeResult {
    pub peer: Handshake,   // 对端身份信息
    pub cipher: Aes256Gcm, // 派生的会话密钥
}

/// 在任意流上执行握手 (双方同时发送自己的 Handshake, 然后读对端的)
pub async fn do_handshake<S>(stream: &mut S, id: &Identity) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (my_pub, my_secret) = crypto::generate_ephemeral_keypair();

    let hello = Handshake {
        network_name: id.network_name.clone(),
        public_key: my_pub.as_bytes().to_vec(),
        peer_id: id.peer_id,
        hostname: id.hostname.clone(),
        virtual_ip: id.virtual_ip.clone(),
        version: PROTOCOL_VERSION,
        proxy_cidrs: id.proxy_cidrs.clone(),
        listen_addrs: id.listen_addrs.clone(),
        udp_mapped_addr: id.udp_mapped_addr.read().clone().unwrap_or_default(),
    };
    tracing::info!(
        peer_id = id.peer_id,
        udp_mapped = %hello.udp_mapped_addr,
        "do_handshake: 发送 Handshake (含 udp_mapped_addr)"
    );
    let payload = hello.encode_to_vec();
    frame::write_len_prefixed(stream, &payload).await?;

    let peer_buf = frame::read_len_prefixed(stream).await?;
    let peer = Handshake::decode(&peer_buf[..])
        .map_err(|e| Error::Handshake(format!("bad handshake msg: {e}")))?;
    tracing::info!(
        peer_id = peer.peer_id,
        peer_udp_mapped = %peer.udp_mapped_addr,
        "do_handshake: 收到对端 Handshake"
    );

    // 校验: 同网络 + 协议版本兼容
    if peer.network_name != id.network_name {
        return Err(Error::Handshake(format!(
            "network mismatch: {} vs {}",
            peer.network_name, id.network_name
        )));
    }
    if peer.version != PROTOCOL_VERSION {
        return Err(Error::Handshake(format!(
            "version mismatch: {} vs {}",
            peer.version, PROTOCOL_VERSION
        )));
    }
    if peer.public_key.len() != 32 {
        return Err(Error::Handshake("bad public key".into()));
    }

    let peer_pub_bytes: [u8; 32] = peer.public_key.clone().try_into().unwrap();
    let peer_pub = x25519_dalek::PublicKey::from(peer_pub_bytes);
    let shared = my_secret.diffie_hellman(&peer_pub);
    let key = crypto::derive_key(shared.as_bytes(), &id.network_secret);
    let cipher = crypto::make_cipher(&key);

    Ok(HandshakeResult { peer, cipher })
}
