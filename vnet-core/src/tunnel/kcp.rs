//! KCP 隧道: 基于 UDP 的可靠传输, 高丢包弱网下显著优于 TCP

use super::{handshake, stream_tunnel::StreamTunnel};
use crate::common::error::{Error, Result};
use std::net::SocketAddr;
use tokio_kcp::{KcpConfig, KcpListener, KcpNoDelayConfig, KcpStream};

pub type KcpTunnel = StreamTunnel<KcpStream>;

/// 弱网优化配置: 开启 nodelay/fast, 立即 flush
fn fast_config() -> KcpConfig {
    KcpConfig {
        mtu: 1400,
        nodelay: KcpNoDelayConfig::fastest(),
        wnd_size: (256, 256),
        session_expire: std::time::Duration::from_secs(90),
        flush_write: true,
        flush_acks_input: true,
        stream: true,
        allow_recv_empty_packet: false,
    }
}

pub async fn connect(addr: &str, id: &handshake::Identity) -> Result<(KcpTunnel, handshake::HandshakeResult)> {
    let sa: SocketAddr = addr
        .parse()
        .map_err(|_| Error::Config(format!("bad kcp addr {addr}")))?;
    let stream = KcpStream::connect(&fast_config(), sa)
        .await
        .map_err(|e| Error::Tunnel(format!("kcp connect {addr}: {e}")))?;
    KcpTunnel::handshake_on(stream, addr.to_string(), "kcp", id).await
}

pub async fn listener_loop(
    bind: &str,
    id: handshake::Identity,
    on_accept: impl Fn(KcpTunnel, handshake::HandshakeResult, SocketAddr) + Send + Sync + Clone + 'static,
) -> Result<()> {
    let mut listener = KcpListener::bind(fast_config(), bind)
        .await
        .map_err(|e| Error::Tunnel(format!("kcp bind {bind}: {e}")))?;
    tracing::info!(%bind, "kcp listening");
    loop {
        let (stream, from) = listener
            .accept()
            .await
            .map_err(|e| Error::Tunnel(format!("kcp accept: {e}")))?;
        let id = id.clone();
        let on_accept = on_accept.clone();
        tokio::spawn(async move {
            match KcpTunnel::handshake_on(stream, from.to_string(), "kcp", &id).await {
                Ok((tun, hs)) => on_accept(tun, hs, from),
                Err(e) => tracing::warn!(%from, ?e, "kcp handshake failed"),
            }
        });
    }
}
