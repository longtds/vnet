//! 节点实例 (生命周期管理)

use crate::common::config::NodeConfig;
use crate::common::error::{Error, Result};
use crate::crypto;
use crate::nat::portmap::{self, Mapping, Proto};
use crate::peer::PeerManager;
use crate::tun::{device, packet};
use crate::tunnel::udp_demux::UdpDemux;
use crate::tunnel::{
    handshake,
    kcp, quic,
    tcp, tls_util,
    udp::UdpTunnel,
    ws::{self, WsTunnel},
};
use crate::vpn_portal::{self, WgClientConfig};
use bytes::Bytes;
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tun::AsyncDevice;
use vnet_proto::PeerInfo;

const INBOUND_CHANNEL_CAP: usize = 1024;
const CONNECT_CHANNEL_CAP: usize = 256;

/// 节点运行实例
pub struct Instance {
    pub config: NodeConfig,
    pub peer_mgr: Arc<PeerManager>,
    /// 入站包发送端: 收到对端来的 IP 包后, 通过它写入 TUN
    pub inbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: parking_lot::Mutex<Option<mpsc::Receiver<Bytes>>>,
    identity: handshake::Identity,
    connect_tx: mpsc::Sender<String>,
    connect_rx: parking_lot::Mutex<Option<mpsc::Receiver<String>>>,
}

impl Instance {
    pub fn new(config: NodeConfig) -> Self {
        let (tx, rx) = mpsc::channel(INBOUND_CHANNEL_CAP);
        let (connect_tx, connect_rx) = mpsc::channel(CONNECT_CHANNEL_CAP);
        let hostname = gethostname::gethostname().to_string_lossy().to_string();
        let vip = config
            .virtual_ip
            .map(|i| i.to_string())
            .unwrap_or_default();
        let peer_id = crypto::derive_peer_id(&config.network_secret, &vip, &hostname);
        // 共享 Arc: STUN 探测结果同时供 PeerManager API 和 Identity 握手时读取
        let udp_mapped_addr = std::sync::Arc::new(parking_lot::RwLock::new(None));
        let identity = handshake::Identity {
            network_name: config.network_name.clone(),
            network_secret: config.network_secret.clone(),
            peer_id,
            hostname,
            virtual_ip: vip,
            proxy_cidrs: config.proxy_cidrs.clone(),
            listen_addrs: config.listeners.clone(),
            udp_mapped_addr: udp_mapped_addr.clone(),
        };
        let peer_mgr = PeerManager::with_udp_mapped_addr(
            peer_id,
            tx.clone(),
            connect_tx.clone(),
            udp_mapped_addr,
        );
        *peer_mgr.identity.write() = Some(identity.clone());
        Self {
            config,
            peer_mgr,
            inbound_tx: tx,
            inbound_rx: parking_lot::Mutex::new(Some(rx)),
            identity,
            connect_tx,
            connect_rx: parking_lot::Mutex::new(Some(connect_rx)),
        }
    }

    /// 启动节点: TUN -> 监听器 -> 主动连接 peers
    pub async fn start(&self) -> Result<()> {
        let ip = self
            .config
            .virtual_ip
            .ok_or_else(|| Error::Config("virtual_ip required".into()))?;

        // 1. TUN 设备 + 数据面
        let tun = device::create_tun(
            &self.config.tun_name,
            ip,
            self.config.prefix_len,
            self.config.mtu,
        )
        .await?;
        let (reader, writer) = tokio::io::split(tun);
        let inbound_rx = self
            .inbound_rx
            .lock()
            .take()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("already started")))?;

        let mgr_out = self.peer_mgr.clone();
        let out_task = tokio::spawn(outbound_loop(reader, mgr_out));
        let in_task = tokio::spawn(inbound_loop(writer, inbound_rx));

        crate::gateway::check_and_hint(&self.config);
        self.start_network().await?;

        tracing::info!(%ip, peer_id = self.identity.peer_id, "vnet instance started");

        tokio::select! {
            _ = out_task => {},
            _ = in_task => {},
        }
        Ok(())
    }

    /// 中继模式: 不创建 TUN, 仅转发 + 参与 Peer 发现
    pub async fn start_relay(&self) -> Result<()> {
        self.peer_mgr
            .relay_mode
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.start_network().await?;
        tracing::info!(peer_id = self.identity.peer_id, "vnet relay started");
        // 中继只需保持网络任务运行
        tokio::signal::ctrl_c().await?;
        Ok(())
    }

    /// 启动网络层: 监听器 + 主动连接 + gossip + 管理 API
    async fn start_network(&self) -> Result<()> {
        // 2. 启动监听器
        for l in &self.config.listeners {
            self.spawn_listener(l).await;
        }

        // 管理 API
        crate::api::start_api(self.config.admin_port, self.peer_mgr.clone(), self.identity.clone());

        // 3. STUN 探测本机 UDP 映射地址. 等待 UDP listener 启动并注册 demux (spawn_listener 只调度不等待),
        // 轮询最多 3s. 若超时则跳过 STUN (打洞不可用).
        if self.config.listeners.iter().any(|l| l.starts_with("udp://")) {
            let demux = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if let Some(d) = self.peer_mgr.demux.read().clone() {
                        return d;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }).await;
            match demux {
                Ok(demux) => {
                    let stun_server = self.config.stun_server.clone();
                    let (stun_tx, stun_rx) = mpsc::channel(16);
                    demux.set_stun_handler(stun_tx);
                    let stun_res = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        crate::nat::stun::query_mapped_addr(&demux.socket, &stun_server, stun_rx),
                    ).await;
                    demux.clear_stun_handler();
                    match stun_res {
                        Ok(Ok(addr)) => {
                            tracing::info!(%addr, "STUN mapped address");
                            *self.peer_mgr.my_udp_mapped_addr.write() = Some(addr.to_string());
                        }
                        Ok(Err(e)) => tracing::warn!(?e, "STUN failed"),
                        Err(_) => tracing::warn!("STUN timeout (5s), skipping"),
                    }

                    // 定期刷新 STUN 映射地址 (每 5min). 同之前逻辑, 略...
                    let mgr = self.peer_mgr.clone();
                    let stun_server_clone = self.config.stun_server.clone();
                    tokio::spawn(async move {
                        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
                        tick.tick().await;
                        loop {
                            tick.tick().await;
                            let (stun_tx, stun_rx) = mpsc::channel(16);
                            demux.set_stun_handler(stun_tx);
                            let res = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                crate::nat::stun::query_mapped_addr(&demux.socket, &stun_server_clone, stun_rx),
                            ).await;
                            demux.clear_stun_handler();
                            match res {
                                Ok(Ok(addr)) => {
                                    let new_str = addr.to_string();
                                    let changed = {
                                        let cur = mgr.my_udp_mapped_addr.read();
                                        cur.as_deref() != Some(&new_str)
                                    };
                                    if changed {
                                        tracing::info!(old = ?*mgr.my_udp_mapped_addr.read(), %addr, "STUN mapped address changed, re-gossip");
                                        *mgr.my_udp_mapped_addr.write() = Some(new_str);
                                        let _ = mgr.broadcast_topology().await;
                                    } else {
                                        tracing::debug!(%addr, "STUN mapped address unchanged");
                                    }
                                }
                                Ok(Err(e)) => tracing::warn!(?e, "periodic STUN failed"),
                                Err(_) => tracing::debug!("periodic STUN timeout"),
                            }
                        }
                    });
                }
                Err(_) => tracing::warn!("UDP listener not ready after 3s, skipping STUN"),
            }
        }

        // 4. 主动连接循环 (消费 connect_tx, 含初始 peers 和 gossip 发现的新 peers)
        let mut connect_rx = self
            .connect_rx
            .lock()
            .take()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("already started")))?;
        for p in &self.config.peers {
            let _ = self.connect_tx.send(p.clone()).await;
        }
        let id = self.identity.clone();
        let mgr = self.peer_mgr.clone();
        let tls_ca = self.config.tls_ca.clone();
        tokio::spawn(async move {
            while let Some(addr) = connect_rx.recv().await {
                let id = id.clone();
                let mgr = mgr.clone();
                let tls_ca = tls_ca.clone();
                tokio::spawn(async move {
                    let result = connect_peer(&addr, &id, mgr.clone(), tls_ca).await;
                    let success = result.is_ok();
                    if let Err(e) = &result {
                        tracing::debug!(%addr, ?e, "connect peer failed");
                    }
                    mgr.finish_connect_attempt(&addr, success);
                });
            }
        });

        // 5. 定期 gossip 拓扑
        let mgr = self.peer_mgr.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                mgr.broadcast_topology().await;
            }
        });

        // 5.5 心跳保活 + 死链剔除 (10s ping, 60s 无流量判死)
        self.peer_mgr
            .spawn_keepalive(std::time::Duration::from_secs(10), std::time::Duration::from_secs(60));

        // 5.6 P2P 优先重试周期: 每 30s 对已有中继 peer 重新尝试 UDP 打洞.
        // NAT 洞可能被防火墙定时回收, 持续重试确保最终 P2P 连通.
        self.peer_mgr
            .spawn_p2p_retry(std::time::Duration::from_secs(30));

        // 5.7 断线自动重连: 周期重试配置的 peers (已连接/连接中则跳过)
        if !self.config.peers.is_empty() {
            let peers_cfg = self.config.peers.clone();
            let mgr = self.peer_mgr.clone();
            let connect_tx = self.connect_tx.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                tick.tick().await; // 首次 tick 立即返回, 跳过 (初始连接已触发)
                loop {
                    tick.tick().await;
                    for p in &peers_cfg {
                        if mgr.has_addr_connected(p) || mgr.is_connecting(p) {
                            continue;
                        }
                        tracing::debug!(%p, "reconnect attempt");
                        let _ = connect_tx.send(p.clone()).await;
                    }
                }
            });
        }

        // 6. UPnP/NAT-PMP 自动端口映射
        if self.config.enable_port_mapping {
            let mappings = collect_mappings(&self.config);
            if !mappings.is_empty() {
                let mgr = self.peer_mgr.clone();
                tokio::spawn(async move {
                    let r = portmap::setup_mappings(mappings).await;
                    tracing::info!("auto port mapping: {} entries", r.len());
                    if !r.is_empty() {
                        // 映射结果反馈到节点发现: 写入 PeerManager, 经管理 API / 日志对外可见
                        let mut addrs = Vec::with_capacity(r.len());
                        for (m, ext_ip) in &r {
                            let scheme = match m.proto {
                                Proto::Tcp => "tcp",
                                Proto::Udp => "udp",
                            };
                            addrs.push(format!("{scheme}://{ext_ip}:{}", m.port));
                        }
                        tracing::info!(?addrs, "external mapped addrs");
                        *mgr.mapped_addrs.write() = addrs;
                    }
                });
            }
        }

        // 7. WireGuard 门户 (手机接入)
        if let (Some(listen), Some(key_b64)) =
            (self.config.wg_listen.clone(), self.config.wg_private_key.clone())
        {
            match build_wg_clients(&self.config) {
                Ok(client_cfgs) => match vpn_portal::decode_key(&key_b64) {
                    Ok(key) => {
                        if let Err(e) =
                            vpn_portal::WgPortal::start(&listen, key, client_cfgs, self.peer_mgr.clone()).await
                        {
                            tracing::error!(?e, "wireguard portal failed");
                        }
                    }
                    Err(e) => tracing::error!(?e, "bad wg private key"),
                },
                Err(e) => tracing::error!(?e, "bad wg client config"),
            }
        }

        Ok(())
    }

    async fn spawn_listener(&self, addr: &str) {
        let id = self.identity.clone();
        let mgr = self.peer_mgr.clone();
        let tls_cert = self.config.tls_cert.clone();
        let tls_key = self.config.tls_key.clone();
        let addr = addr.to_string();
        tokio::spawn(async move {
            let res: Result<()> = if let Some(rest) = addr.strip_prefix("tcp://") {
                tcp_listener_loop(rest, id, mgr).await
            } else if let Some(rest) = addr.strip_prefix("udp://") {
                udp_listener_loop(rest, id, mgr).await
            } else if let Some(rest) = addr.strip_prefix("kcp://") {
                let m = mgr.clone();
                let cb = move |tun: kcp::KcpTunnel, hs: handshake::HandshakeResult, from: SocketAddr| {
                    let via = format!("kcp://{from}");
                    m.add_peer(peer_info_from_handshake(&hs.peer, &via), Arc::new(tun), &via);
                };
                kcp::listener_loop(rest, id, cb).await
            } else if let Some(rest) = addr.strip_prefix("quic://") {
                let m = mgr.clone();
                let cb = move |tun: quic::QuicTunnel, hs: handshake::HandshakeResult, from: SocketAddr| {
                    let via = format!("quic://{from}");
                    m.add_peer(peer_info_from_handshake(&hs.peer, &via), Arc::new(tun), &via);
                };
                quic::listener_loop(rest, id, cb).await
            } else if addr.starts_with("ws://") || addr.starts_with("wss://") {
                let rest = addr.strip_prefix("wss://").or_else(|| addr.strip_prefix("ws://")).unwrap();
                let tls = if addr.starts_with("wss://") {
                    Some(match wss_server_config(tls_cert, tls_key).await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!(?e, "wss tls config failed");
                            return;
                        }
                    })
                } else {
                    None
                };
                let scheme = if tls.is_some() { "wss" } else { "ws" };
                let m = mgr.clone();
                let cb = move |tun: WsTunnel, hs: handshake::HandshakeResult, from: SocketAddr| {
                    let via = format!("{scheme}://{from}");
                    m.add_peer(peer_info_from_handshake(&hs.peer, &via), Arc::new(tun), &via);
                };
                ws::listener_loop(rest, tls, id, cb).await
            } else {
                tracing::warn!(%addr, "unknown listener scheme");
                Ok(())
            };
            if let Err(e) = res {
                tracing::error!(%addr, ?e, "listener failed");
            }
        });
    }
}

/// 构造 WSS 服务端 rustls 配置: 优先用证书文件, 否则启动时自签
async fn wss_server_config(
    cert_path: Option<String>,
    key_path: Option<String>,
) -> Result<Arc<rustls::ServerConfig>> {
    if let (Some(cp), Some(kp)) = (cert_path, key_path) {
        let cert_pem = tokio::fs::read(&cp)
            .await
            .map_err(|e| Error::Config(format!("read cert {cp}: {e}")))?;
        let key_pem = tokio::fs::read(&kp)
            .await
            .map_err(|e| Error::Config(format!("read key {kp}: {e}")))?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .filter_map(|r| r.ok())
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| Error::Config(format!("parse key: {e}")))?
            .ok_or_else(|| Error::Config("no private key in pem".into()))?;
        let cfg = rustls::ServerConfig::builder_with_provider(tls_util::ring_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tunnel(format!("rustls versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Config(format!("rustls: {e}")))?;
        Ok(Arc::new(cfg))
    } else {
        tracing::info!("wss: no cert/key configured, using ephemeral self-signed cert");
        tls_util::self_signed_server_config()
    }
}

/// 从配置解析 WG 客户端: "name=10.144.144.3=<base64公钥>"
fn build_wg_clients(config: &NodeConfig) -> Result<Vec<WgClientConfig>> {
    let mut out = Vec::new();
    for item in &config.wg_clients {
        let parts: Vec<&str> = item.splitn(3, '=').collect();
        if parts.len() != 3 || parts[2].is_empty() {
            return Err(Error::Config(format!(
                "bad wg client '{item}', expected name=ip=pubkey"
            )));
        }
        let name = parts[0].to_string();
        let vip: std::net::Ipv4Addr = parts[1]
            .parse()
            .map_err(|_| Error::Config(format!("bad wg client ip: {}", parts[1])))?;
        let peer_public_key = vpn_portal::decode_key(parts[2])?;
        let peer_id = crypto::derive_peer_id(&config.network_secret, &vip.to_string(), &format!("wg:{name}"));
        out.push(WgClientConfig {
            name,
            vip,
            peer_public_key,
            peer_id,
        });
    }
    Ok(out)
}

/// 收集需要自动映射的监听端口
fn collect_mappings(config: &NodeConfig) -> Vec<Mapping> {
    let mut v = Vec::new();
    for l in &config.listeners {
        let (scheme, rest) = if let Some(r) = l.split_once("://") {
            r
        } else {
            continue;
        };
        if let Ok(sa) = rest.parse::<SocketAddr>() {
            let proto = match scheme {
                "tcp" | "ws" | "wss" => Proto::Tcp,
                "udp" | "kcp" | "quic" => Proto::Udp,
                _ => continue,
            };
            v.push(Mapping {
                port: sa.port(),
                proto,
                desc: format!("vnet-{scheme}"),
            });
        }
    }
    if let Some(l) = &config.wg_listen {
        if let Ok(sa) = l.parse::<SocketAddr>() {
            v.push(Mapping {
                port: sa.port(),
                proto: Proto::Udp,
                desc: "vnet-wg".into(),
            });
        }
    }
    v
}

/// 主动连接 peer (支持 tcp:// udp:// kcp:// quic:// ws:// wss://)
async fn connect_peer(
    addr: &str,
    id: &handshake::Identity,
    mgr: Arc<PeerManager>,
    tls_ca: Option<String>,
) -> Result<()> {
    if let Some(rest) = addr.strip_prefix("tcp://") {
        let (tun, hs) = tcp::connect(rest, id).await?;
        let info = peer_info_from_handshake(&hs.peer, addr);
        mgr.add_peer(info, Arc::new(tun), &format!("tcp://{rest}"));
        tracing::info!(%addr, peer_id = hs.peer.peer_id, "connected via tcp");
    } else if let Some(rest) = addr.strip_prefix("udp://") {
        // 用共享 demux socket (打洞需要端口一致)
        let demux = mgr
            .demux
            .read()
            .clone()
            .ok_or_else(|| Error::Config("udp not enabled (no udp listener)".into()))?;
        let sa = resolve_host_port(rest).await?;
        let (tun, hs) = UdpTunnel::connect(demux, sa, id).await?;
        let info = peer_info_from_handshake(&hs.peer, addr);
        mgr.add_peer(info, Arc::new(tun), &format!("udp://{rest}"));
        tracing::info!(%addr, peer_id = hs.peer.peer_id, "connected via udp");
    } else if let Some(rest) = addr.strip_prefix("kcp://") {
        let sa = resolve_host_port(rest).await?;
        let (tun, hs) = kcp::connect(&sa.to_string(), id).await?;
        mgr.add_peer(peer_info_from_handshake(&hs.peer, addr), Arc::new(tun), &format!("kcp://{rest}"));
        tracing::info!(%addr, peer_id = hs.peer.peer_id, "connected via kcp");
    } else if let Some(rest) = addr.strip_prefix("quic://") {
        let (tun, hs) = quic::connect(rest, id).await?;
        mgr.add_peer(peer_info_from_handshake(&hs.peer, addr), Arc::new(tun), &format!("quic://{rest}"));
        tracing::info!(%addr, peer_id = hs.peer.peer_id, "connected via quic");
    } else if addr.starts_with("ws://") || addr.starts_with("wss://") {
        // 配置了 CA 则对 wss 服务端证书做严格校验, 否则跳过 (兼容自签)
        let tls_client = if addr.starts_with("wss://") {
            match tls_ca {
                Some(ca_path) => {
                    let pem = tokio::fs::read(&ca_path)
                        .await
                        .map_err(|e| Error::Config(format!("read ca {ca_path}: {e}")))?;
                    Some(tls_util::ca_client_config(&pem)?)
                }
                None => None,
            }
        } else {
            None
        };
        let (tun, hs) = WsTunnel::connect(addr, id, tls_client).await?;
        let scheme = if addr.starts_with("wss") { "wss" } else { "ws" };
        mgr.add_peer(peer_info_from_handshake(&hs.peer, addr), Arc::new(tun), addr);
        tracing::info!(%addr, peer_id = hs.peer.peer_id, "connected via {scheme}");
    } else {
        return Err(Error::Config(format!("unknown scheme: {addr}")));
    }
    Ok(())
}

/// 解析 "host:port" 为 SocketAddr, 支持域名 (tcp 由 ToSocketAddrs 天然支持)
async fn resolve_host_port(host_port: &str) -> Result<SocketAddr> {
    if let Ok(sa) = host_port.parse::<SocketAddr>() {
        return Ok(sa);
    }
    tokio::net::lookup_host(host_port)
        .await
        .map_err(|e| Error::Config(format!("resolve {host_port}: {e}")))?
        .next()
        .ok_or_else(|| Error::Config(format!("resolve {host_port}: no addr")))
}

/// 从握手消息提取对端可通告地址.
/// 优先使用 handshake.listen_addrs (配置监听器), 并将 0.0.0.0 替换为连接来源 IP;
/// 若未提供则 fallback 到实际连接地址 via.
fn peer_info_from_handshake(hs: &vnet_proto::Handshake, via: &str) -> PeerInfo {
    let host_port = via.split_once("://").map(|(_, r)| r).unwrap_or(via);
    let source_ip = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let addrs: Vec<String> = if hs.listen_addrs.is_empty() {
        vec![via.to_string()]
    } else {
        hs.listen_addrs
            .iter()
            .map(|a| {
                if let Some((scheme, rest)) = a.split_once("://") {
                    if let Some((host, port)) = rest.rsplit_once(':') {
                        if host == "0.0.0.0" || host == "[::]" || host == "::" {
                            return format!("{scheme}://{source_ip}:{port}");
                        }
                    }
                }
                a.clone()
            })
            .collect()
    };
    PeerInfo {
        peer_id: hs.peer_id,
        hostname: hs.hostname.clone(),
        virtual_ip: hs.virtual_ip.clone(),
        public_addrs: addrs,
        proxy_cidrs: hs.proxy_cidrs.clone(),
        last_seen: 0,
        nat_type: String::new(),
        udp_mapped_addr: hs.udp_mapped_addr.clone(),
    }
}

async fn tcp_listener_loop(
    bind: &str,
    id: handshake::Identity,
    mgr: Arc<PeerManager>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, "tcp listening");
    loop {
        let (stream, from) = listener.accept().await?;
        let id = id.clone();
        let mgr = mgr.clone();
        tokio::spawn(async move {
            match tcp::from_stream(stream, from.to_string(), &id).await {
                Ok((tun, hs)) => {
                    let info = peer_info_from_handshake(&hs.peer, &format!("tcp://{from}"));
                    mgr.add_peer(info, Arc::new(tun), &format!("tcp://{from}"));
                    tracing::info!(%from, peer_id = hs.peer.peer_id, "accepted tcp peer");
                }
                Err(e) => tracing::warn!(%from, ?e, "tcp handshake failed"),
            }
        });
    }
}

async fn udp_listener_loop(
    bind: &str,
    id: handshake::Identity,
    mgr: Arc<PeerManager>,
) -> Result<()> {
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    tracing::info!(%bind, "udp listening (demux)");
    let (demux, mut unknown_rx) = UdpDemux::start(sock);
    *mgr.demux.write() = Some(demux.clone());

    // 处理未知源包: 新握手 / 打洞包
    while let Some(upkt) = unknown_rx.recv().await {
        if demux.has_session(upkt.from) {
            continue;
        }
        if let Ok(hs) = <vnet_proto::Handshake as Message>::decode(&upkt.data[..]) {
            if hs.public_key.len() == 32 && hs.network_name == id.network_name {
                let id = id.clone();
                let mgr = mgr.clone();
                let demux = demux.clone();
                let from = upkt.from;
                tokio::spawn(async move {
                    let pub_bytes: [u8; 32] = hs.public_key.clone().try_into().unwrap();
                    let rx = demux.register(from);
                    match UdpTunnel::from_handshake(demux, from, hs.clone(), pub_bytes, &id, rx).await {
                        Ok((tun, hs_res)) => {
                            let info = peer_info_from_handshake(&hs_res.peer, &format!("udp://{from}"));
                            mgr.add_peer(info, Arc::new(tun), &format!("udp://{from}"));
                            tracing::info!(%from, peer_id = hs_res.peer.peer_id, "accepted udp peer");
                        }
                        Err(e) => tracing::warn!(%from, ?e, "udp handshake failed"),
                    }
                });
            }
        }
    }
    Ok(())
}

/// 出站循环: TUN -> 解析目标 -> PeerManager 路由发送
async fn outbound_loop(
    mut reader: ReadHalf<AsyncDevice>,
    mgr: Arc<PeerManager>,
) -> Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(Error::Tun("tun read EOF".into()));
        }
        let pkt = &buf[..n];
        let Some(dst) = packet::dst_addr(pkt) else {
            continue;
        };
        if let Err(e) = mgr.send_data(dst, Bytes::copy_from_slice(pkt)).await {
            // 无路由时静默丢弃 (ARP/广播等常见)
            tracing::trace!(%dst, ?e, "drop outbound");
        }
    }
}

/// 入站循环: 对端 IP 包 -> TUN
async fn inbound_loop(
    mut writer: WriteHalf<AsyncDevice>,
    mut rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    while let Some(pkt) = rx.recv().await {
        writer.write_all(&pkt).await?;
    }
    Ok(())
}
