//! UDP 分发器: 共享一个 UDP socket, 按源地址分发到各会话
//!
//! 打洞要求同一端口收发所有 UDP 流量 (NAT 映射基于端口),
//! 因此所有 UDP 会话必须共享 socket, 由 demux 按源地址路由。

use crate::common::error::Result;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// STUN 协议 magic cookie (RFC 5389), bytes 4-7
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// 未知源地址的包 (可能是新握手或打洞包)
pub struct UnknownPacket {
    pub from: SocketAddr,
    pub data: Vec<u8>,
}

pub struct UdpDemux {
    pub socket: Arc<UdpSocket>,
    /// 已建立会话: 源地址 -> 会话收包通道
    sessions: DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
    /// 未知源包通道 (由上层处理握手/打洞)
    unknown_tx: mpsc::Sender<UnknownPacket>,
    /// STUN 响应通道: 仅在 stun 查询任务运行期间设置, 否则 None.
    /// 修复 race: stun.rs 与 demux 都在 socket 上 recv_from, 响应会被 demux 抢走.
    /// 改为 demux 识别 STUN 响应并路由到本通道, stun.rs 从这里读.
    stun_tx: parking_lot::Mutex<Option<mpsc::Sender<UnknownPacket>>>,
}

impl UdpDemux {
    /// 启动 demux, 返回 (demux, 未知源包接收端)
    pub fn start(socket: Arc<UdpSocket>) -> (Arc<Self>, mpsc::Receiver<UnknownPacket>) {
        let (unknown_tx, unknown_rx) = mpsc::channel(256);
        let demux = Arc::new(Self {
            socket,
            sessions: DashMap::new(),
            unknown_tx,
            stun_tx: parking_lot::Mutex::new(None),
        });
        let d = demux.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match d.socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let data = buf[..n].to_vec();
                        if let Some(tx) = d.sessions.get(&from) {
                            // 会话通道满了则丢弃 (UDP 语义: 允许丢包)
                            let _ = tx.try_send(data);
                        } else if is_stun_response(&data) {
                            // STUN 响应优先交给 stun 查询任务 (若已注册), 否则丢弃
                            let stun_tx = d.stun_tx.lock().clone();
                            if let Some(tx) = stun_tx {
                                let _ = tx.try_send(UnknownPacket { from, data });
                            }
                        } else if d.unknown_tx.try_send(UnknownPacket { from, data }).is_err() {
                            tracing::trace!(%from, "unknown packet dropped (queue full)");
                        }
                    }
                    Err(e) => {
                        tracing::error!(?e, "udp demux recv error");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        (demux, unknown_rx)
    }

    /// 注册会话, 返回该会话的收包通道
    pub fn register(&self, addr: SocketAddr) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(256);
        self.sessions.insert(addr, tx);
        rx
    }

    pub fn unregister(&self, addr: SocketAddr) {
        self.sessions.remove(&addr);
    }

    /// 是否有已注册会话
    pub fn has_session(&self, addr: SocketAddr) -> bool {
        self.sessions.contains_key(&addr)
    }

    /// 发送原始包到指定地址
    pub async fn send_raw(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    /// 注册 STUN 响应处理通道 (stun.rs 调用); 期间所有 STUN 响应包会被路由到此
    pub fn set_stun_handler(&self, tx: mpsc::Sender<UnknownPacket>) {
        *self.stun_tx.lock() = Some(tx);
    }

    /// 清除 STUN 响应处理通道 (stun.rs 结束时调用)
    pub fn clear_stun_handler(&self) {
        *self.stun_tx.lock() = None;
    }
}

/// 判断 UDP 数据包是否为 STUN Binding Response (RFC 5389):
/// 长度 ≥ 20, bytes[4..8] == magic cookie 0x2112A442.
/// 即便是 error response 也带 magic cookie, 都会被识别并交给 stun 查询任务处理.
fn is_stun_response(data: &[u8]) -> bool {
    data.len() >= 20
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == STUN_MAGIC_COOKIE
}
