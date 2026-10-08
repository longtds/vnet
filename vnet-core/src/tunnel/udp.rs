//! UDP 隧道 (基于共享 demux 的会话)

use super::{frame, handshake, udp_demux::UdpDemux, Tunnel};
use crate::common::error::{Error, Result};
use async_trait::async_trait;
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use vnet_proto::TunnelPacket;

pub struct UdpTunnel {
    demux: Arc<UdpDemux>,
    peer_addr: SocketAddr,
    sender: frame::FrameSender,
    receiver: frame::FrameReceiver,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl UdpTunnel {
    /// 主动发起: 通过共享 socket 发握手, 从 demux 注册会话收响应
    pub async fn connect(
        demux: Arc<UdpDemux>,
        addr: SocketAddr,
        id: &handshake::Identity,
    ) -> Result<(Self, handshake::HandshakeResult)> {
        let (my_pub, my_secret) = crate::crypto::generate_ephemeral_keypair();
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
        let payload = hello.encode_to_vec();

        // 先注册会话, 再打洞式重发握手 (打洞场景下需要多次尝试)
        let mut rx = demux.register(addr);
        demux.send_raw(&payload, addr).await?;

        // 等待握手响应 (最多 5s, 期间重发)
        let mut attempts = 0;
        let peer: vnet_proto::Handshake = loop {
            attempts += 1;
            match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
                Ok(Some(data)) => {
                    if let Ok(hs) = <vnet_proto::Handshake as Message>::decode(&data[..]) {
                        if hs.public_key.len() == 32 {
                            break hs;
                        }
                    }
                }
                Ok(None) => {
                    demux.unregister(addr);
                    return Err(Error::Handshake("demux closed".into()));
                }
                Err(_) => {
                    if attempts >= 5 {
                        demux.unregister(addr);
                        return Err(Error::Handshake("timeout".into()));
                    }
                    demux.send_raw(&payload, addr).await?; // 重发
                }
            }
        };
        validate_peer(&peer, id)?;

        let peer_pub: [u8; 32] = peer
            .public_key
            .clone()
            .try_into()
            .map_err(|_| Error::Handshake("bad pubkey".into()))?;
        let shared = my_secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_pub));
        let key = crate::crypto::derive_key(shared.as_bytes(), &id.network_secret);
        let cipher = crate::crypto::make_cipher(&key);

        Ok((
            Self {
                demux: demux.clone(),
                peer_addr: addr,
                sender: frame::FrameSender::new(cipher.clone()),
                receiver: frame::FrameReceiver::new(cipher.clone()),
                rx: tokio::sync::Mutex::new(rx),
            },
            handshake::HandshakeResult { peer, cipher },
        ))
    }

    /// 被动接受: 收到明文握手后构造 (会话已在 demux 注册)
    pub async fn from_handshake(
        demux: Arc<UdpDemux>,
        addr: SocketAddr,
        peer: vnet_proto::Handshake,
        peer_ephemeral_pub: [u8; 32],
        id: &handshake::Identity,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<(Self, handshake::HandshakeResult)> {
        let (my_pub, my_secret) = crate::crypto::generate_ephemeral_keypair();
        let resp = vnet_proto::Handshake {
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
        demux.send_raw(resp.encode_to_vec().as_slice(), addr).await?;

        let shared = my_secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_ephemeral_pub));
        let key = crate::crypto::derive_key(shared.as_bytes(), &id.network_secret);
        let cipher = crate::crypto::make_cipher(&key);

        Ok((
            Self {
                demux: demux.clone(),
                peer_addr: addr,
                sender: frame::FrameSender::new(cipher.clone()),
                receiver: frame::FrameReceiver::new(cipher.clone()),
                rx: tokio::sync::Mutex::new(rx),
            },
            handshake::HandshakeResult { peer, cipher },
        ))
    }
}

fn validate_peer(peer: &vnet_proto::Handshake, id: &handshake::Identity) -> Result<()> {
    if peer.network_name != id.network_name {
        return Err(Error::Handshake("network mismatch".into()));
    }
    if peer.version != crate::common::constants::PROTOCOL_VERSION {
        return Err(Error::Handshake("version mismatch".into()));
    }
    Ok(())
}

#[async_trait]
impl Tunnel for UdpTunnel {
    async fn send(&self, pkt: &TunnelPacket) -> Result<()> {
        let plain = pkt.encode_to_vec();
        let frame = self.sender.encode(&plain)?;
        self.demux.send_raw(&frame, self.peer_addr).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<TunnelPacket> {
        let data = {
            let mut rx = self.rx.lock().await;
            rx.recv().await.ok_or_else(|| Error::Tunnel("udp session closed".into()))?
        };
        let plain = self.receiver.decode(&data)?;
        TunnelPacket::decode(&plain[..]).map_err(|e| Error::Protocol(format!("decode: {e}")))
    }

    fn remote_addr(&self) -> String {
        self.peer_addr.to_string()
    }

    fn proto(&self) -> &'static str {
        "udp"
    }
}
