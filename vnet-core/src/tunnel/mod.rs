//! 隧道抽象层: 多协议 (TCP/UDP/KCP/QUIC/WS/WSS) 加密隧道

use crate::common::error::Result;
use async_trait::async_trait;
use vnet_proto::TunnelPacket;

pub mod frame;
pub mod handshake;
pub mod kcp;
pub mod quic;
pub mod stream_tunnel;
pub mod tcp;
pub mod tls_util;
pub mod udp;
pub mod udp_demux;
pub mod ws;

/// 加密隧道: 传输 TunnelPacket
#[async_trait]
pub trait Tunnel: Send + Sync {
    /// 发送一个 TunnelPacket (内部加密)
    async fn send(&self, pkt: &TunnelPacket) -> Result<()>;
    /// 接收一个 TunnelPacket (内部解密)
    async fn recv(&self) -> Result<TunnelPacket>;
    /// 远端地址描述
    fn remote_addr(&self) -> String;
    /// 隧道协议名 (tcp/udp/kcp/quic/ws/wss/wg)
    fn proto(&self) -> &'static str;
}
