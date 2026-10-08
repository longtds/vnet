//! TCP 隧道 (StreamTunnel 的薄封装)

use super::{handshake, stream_tunnel::StreamTunnel};
use crate::common::error::{Error, Result};
use tokio::net::TcpStream;

pub type TcpTunnel = StreamTunnel<TcpStream>;

pub async fn connect(addr: &str, id: &handshake::Identity) -> Result<(TcpTunnel, handshake::HandshakeResult)> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| Error::Tunnel(format!("connect {addr}: {e}")))?;
    stream
        .set_nodelay(true)
        .map_err(|e| Error::Tunnel(format!("set nodelay: {e}")))?;
    TcpTunnel::handshake_on(stream, addr.to_string(), "tcp", id).await
}

pub async fn from_stream(
    stream: TcpStream,
    addr: String,
    id: &handshake::Identity,
) -> Result<(TcpTunnel, handshake::HandshakeResult)> {
    // 小包低延迟关键: 禁用 Nagle, 否则与对端延迟 ACK 叠加产生 ~40ms 尖刺
    let _ = stream.set_nodelay(true);
    TcpTunnel::handshake_on(stream, addr, "tcp", id).await
}
