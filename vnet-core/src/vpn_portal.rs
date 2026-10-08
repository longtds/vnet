//! WireGuard 门户: 允许手机原生 WG 客户端接入 vnet
//!
//! 每个已注册的 WG client (公钥+虚拟IP) 对应一个 boringtun Tunn,
//! WgTunnel 实现 Tunnel trait, 因此 WG client 对 PeerManager 而言
//! 就是一个普通 peer (DATA 自动进 TUN/转发, 出站自动路由到 WG)。

use crate::common::error::{Error, Result};
use crate::peer::PeerManager;
use crate::tunnel::Tunnel;
use async_trait::async_trait;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use parking_lot::Mutex;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vnet_proto::{PacketType, PeerInfo, TunnelPacket};

const WG_BUF_SIZE: usize = 65536 + 64;

/// WG 客户端配置
#[derive(Clone)]
pub struct WgClientConfig {
    pub name: String,
    pub vip: Ipv4Addr,
    pub peer_public_key: [u8; 32],
    pub peer_id: u64,
}

/// 解析 base64 编码的 WG 密钥
pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let raw = base64::prelude::BASE64_STANDARD
        .decode(s.trim())
        .map_err(|e| Error::Config(format!("bad base64 key: {e}")))?;
    raw.try_into().map_err(|_| Error::Config("key must be 32 bytes".into()))
}

/// 生成新的 WG 私钥/公钥对 (返回 base64)
pub fn gen_keypair() -> (String, String) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&secret);
    let s_bytes: [u8; 32] = secret.to_bytes();
    (
        base64::prelude::BASE64_STANDARD.encode(s_bytes),
        base64::prelude::BASE64_STANDARD.encode(public.as_bytes()),
    )
}

struct ClientState {
    cfg: WgClientConfig,
    tunn: Mutex<Tunn>,
    endpoint: Mutex<Option<SocketAddr>>,
    pkt_in_tx: mpsc::Sender<TunnelPacket>,
}

pub struct WgPortal {
    socket: Arc<UdpSocket>,
    clients: Vec<Arc<ClientState>>,
    server_peer_id: u64,
}

impl WgPortal {
    /// 启动门户: 绑定 UDP, 为每个 client 建 Tunn
    pub async fn start(
        bind: &str,
        server_private_key: [u8; 32],
        client_cfgs: Vec<WgClientConfig>,
        mgr: Arc<PeerManager>,
    ) -> Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(bind).await?);

        let mut clients = Vec::new();
        for (i, c) in client_cfgs.iter().enumerate() {
            let tunn = Tunn::new(
                x25519_dalek::StaticSecret::from(server_private_key),
                x25519_dalek::PublicKey::from(c.peer_public_key),
                None,
                Some(25),
                (i + 1) as u32,
                None,
            );
            let (pkt_in_tx, pkt_in_rx) = mpsc::channel(256);
            let state = Arc::new(ClientState {
                cfg: c.clone(),
                tunn: Mutex::new(tunn),
                endpoint: Mutex::new(None),
                pkt_in_tx,
            });
            clients.push(state.clone());

            // 作为普通 peer 注册到 PeerManager
            let tunnel: Arc<dyn Tunnel> = Arc::new(WgTunnel {
                socket: socket.clone(),
                client: state,
                pkt_in_rx: tokio::sync::Mutex::new(pkt_in_rx),
            });
            let info = PeerInfo {
                peer_id: c.peer_id,
                hostname: format!("wg:{}", c.name),
                virtual_ip: c.vip.to_string(),
                public_addrs: vec![],
                proxy_cidrs: vec![],
                last_seen: 0,
                nat_type: "WireGuard".into(),
                udp_mapped_addr: String::new(),
            };
            mgr.add_peer(info, tunnel, "wg-portal");
        }

        let portal = Arc::new(WgPortal {
            socket,
            clients,
            server_peer_id: mgr.my_peer_id,
        });

        // UDP 收包循环
        let p = portal.clone();
        tokio::spawn(async move { p.recv_loop().await });

        // WG 定时器 (重传/保活), 每 100ms
        let p = portal.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
            loop {
                tick.tick().await;
                p.timer_tick();
            }
        });

        tracing::info!(%bind, clients = portal.clients.len(), "wireguard portal listening");
        Ok(portal)
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; WG_BUF_SIZE];
        loop {
            let (n, from) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "wg recv error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let datagram = buf[..n].to_vec();
            // client 数量少, 逐个尝试 decapsulate 识别归属
            for c in &self.clients {
                let mut dst = vec![0u8; WG_BUF_SIZE];
                let result = {
                    let mut tunn = c.tunn.lock();
                    tunn.decapsulate(Some(from.ip()), &datagram, &mut dst)
                };
                match result {
                    TunnResult::Done => {
                        *c.endpoint.lock() = Some(from);
                        break; // 已识别
                    }
                    TunnResult::Err(_) => continue,
                    TunnResult::WriteToNetwork(out) => {
                        let out = out.to_vec();
                        *c.endpoint.lock() = Some(from);
                        let _ = self.socket.send_to(&out, from).await;
                        self.drain_network(c, from).await;
                        break;
                    }
                    TunnResult::WriteToTunnelV4(ip, _src) => {
                        let ip = ip.to_vec();
                        *c.endpoint.lock() = Some(from);
                        let pkt = TunnelPacket {
                            from_peer: c.cfg.peer_id,
                            to_peer: self.server_peer_id,
                            packet_type: PacketType::Data as i32,
                            payload: ip,
                        };
                        let _ = c.pkt_in_tx.send(pkt).await;
                        self.drain_network(c, from).await;
                        break;
                    }
                    TunnResult::WriteToTunnelV6(_, _) => {
                        // 暂不支持 v6
                        *c.endpoint.lock() = Some(from);
                        self.drain_network(c, from).await;
                        break;
                    }
                }
            }
        }
    }

    /// decapsulate/encapsulate 后可能有排队的响应包, 全部发走
    async fn drain_network(&self, c: &Arc<ClientState>, from: SocketAddr) {
        loop {
            let mut dst = vec![0u8; WG_BUF_SIZE];
            let result = {
                let mut tunn = c.tunn.lock();
                tunn.decapsulate(Some(from.ip()), &[], &mut dst)
            };
            match result {
                TunnResult::WriteToNetwork(out) => {
                    let _ = self.socket.send_to(out, from).await;
                }
                _ => break,
            }
        }
    }

    fn timer_tick(&self) {
        for c in &self.clients {
            let Some(ep) = *c.endpoint.lock() else { continue };
            let mut dst = vec![0u8; WG_BUF_SIZE];
            let result = {
                let mut tunn = c.tunn.lock();
                tunn.update_timers(&mut dst)
            };
            if let TunnResult::WriteToNetwork(out) = result {
                let out = out.to_vec();
                let sock = self.socket.clone();
                tokio::spawn(async move {
                    let _ = sock.send_to(&out, ep).await;
                });
            }
        }
    }
}

pub struct WgTunnel {
    socket: Arc<UdpSocket>,
    client: Arc<ClientState>,
    pkt_in_rx: tokio::sync::Mutex<mpsc::Receiver<TunnelPacket>>,
}

#[async_trait]
impl Tunnel for WgTunnel {
    async fn send(&self, pkt: &TunnelPacket) -> Result<()> {
        let ep = *self.client.endpoint.lock();
        let Some(ep) = ep else {
            // client 尚未握手, 无法加密发送; 记录日志便于排查首次连接问题
            tracing::debug!(
                client = %self.client.cfg.name,
                peer_id = pkt.to_peer,
                "wg client has no endpoint yet, drop packet"
            );
            return Ok(());
        };
        // encapsulate + 排空队列
        let mut outputs = Vec::new();
        {
            let mut tunn = self.client.tunn.lock();
            let mut dst = vec![0u8; WG_BUF_SIZE];
            let r = tunn.encapsulate(&pkt.payload, &mut dst);
            if let TunnResult::WriteToNetwork(out) = r {
                outputs.push(out.to_vec());
            }
            loop {
                let r = tunn.decapsulate(Some(ep.ip()), &[], &mut dst);
                match r {
                    TunnResult::WriteToNetwork(out) => outputs.push(out.to_vec()),
                    _ => break,
                }
            }
        }
        for out in outputs {
            self.socket.send_to(&out, ep).await?;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<TunnelPacket> {
        self.pkt_in_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::Tunnel("wg channel closed".into()))
    }

    fn remote_addr(&self) -> String {
        match *self.client.endpoint.lock() {
            Some(a) => a.to_string(),
            None => "wg".to_string(),
        }
    }

    fn proto(&self) -> &'static str {
        "wg"
    }
}
