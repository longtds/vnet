//! Peer 管理: 隧道注册、收发循环、按虚拟 IP 路由、Peer 发现 gossip

pub mod route;

use crate::common::error::{Error, Result};
use crate::tunnel::udp_demux::UdpDemux;
use crate::tunnel::Tunnel;
use bytes::Bytes;
use dashmap::DashMap;
use prost::Message as _;
use route::RouteTable;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use vnet_proto::{control_packet::Msg, ControlPacket, PacketType, PeerInfo, TunnelPacket};

/// 一个已建立隧道的对端
pub struct PeerHandle {
    pub info: PeerInfo,
    pub tunnel: Arc<dyn Tunnel>,
    /// 最近收到包的 unix 秒
    pub last_seen: parking_lot::Mutex<i64>,
    /// 直连 (p2p/直接连接) 或中继
    pub via: String,
    /// 累计收发字节数 (协议级统计)
    pub tx_bytes: std::sync::atomic::AtomicU64,
    pub rx_bytes: std::sync::atomic::AtomicU64,
}

/// Peer 管理器
pub struct PeerManager {
    pub my_peer_id: u64,
    peers: DashMap<u64, Arc<PeerHandle>>,
    routes: RouteTable,
    inbound_tx: mpsc::Sender<Bytes>,
    /// 请求主动连接某地址 (由 instance 的连接循环消费)
    connect_tx: mpsc::Sender<String>,
    /// 正在连接中的地址, 防重复
    connecting: DashMap<String, ()>,
    /// UDP demux (打洞用); None 表示未启用 UDP
    pub demux: parking_lot::RwLock<Option<Arc<UdpDemux>>>,
    /// 本机 UDP 外网映射地址 (STUN 探测结果); Arc 共享给 Identity 以便握手时携带
    pub my_udp_mapped_addr: Arc<parking_lot::RwLock<Option<String>>>,
    /// 自动端口映射得到的外网地址列表, 如 ["tcp://1.2.3.4:11010"]
    pub mapped_addrs: parking_lot::RwLock<Vec<String>>,
    /// 本端身份 (构造打洞握手包用)
    pub identity: parking_lot::RwLock<Option<crate::tunnel::handshake::Identity>>,
    /// 中继模式: 无 TUN, 收到的数据包继续按目标 IP 转发
    pub relay_mode: std::sync::atomic::AtomicBool,
}

impl PeerManager {
    pub fn new(
        my_peer_id: u64,
        inbound_tx: mpsc::Sender<Bytes>,
        connect_tx: mpsc::Sender<String>,
    ) -> Arc<Self> {
        Self::with_udp_mapped_addr(
            my_peer_id,
            inbound_tx,
            connect_tx,
            Arc::new(parking_lot::RwLock::new(None)),
        )
    }

    /// 显式传入共享的 udp_mapped_addr (供 Identity 与 PeerManager 共享同一 Arc, 保证
    /// STUN 写入后 Identity 在握手时能读到最新值)
    pub fn with_udp_mapped_addr(
        my_peer_id: u64,
        inbound_tx: mpsc::Sender<Bytes>,
        connect_tx: mpsc::Sender<String>,
        udp_mapped_addr: Arc<parking_lot::RwLock<Option<String>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            my_peer_id,
            peers: DashMap::new(),
            routes: RouteTable::new(),
            inbound_tx,
            connect_tx,
            connecting: DashMap::new(),
            demux: parking_lot::RwLock::new(None),
            my_udp_mapped_addr: udp_mapped_addr,
            mapped_addrs: parking_lot::RwLock::new(Vec::new()),
            identity: parking_lot::RwLock::new(None),
            relay_mode: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 注册新 peer 并启动其读循环; 同 peer_id 重连时替换旧隧道
    /// (UDP 类隧道无 FIN, 对端进程退出后旧会话要到 session_expire 才消失,
    ///  若拒绝重连则换协议重连会被静默丢弃)
    pub fn add_peer(self: &Arc<Self>, info: PeerInfo, tunnel: Arc<dyn Tunnel>, via: &str) -> bool {
        let peer_id = info.peer_id;
        if peer_id == self.my_peer_id {
            return false; // 连自己, 丢弃
        }
        if let Ok(ip) = info.virtual_ip.parse::<Ipv4Addr>() {
            self.routes.insert_host(ip, peer_id);
        }
        for cidr in &info.proxy_cidrs {
            self.routes.insert_cidr(cidr, peer_id);
        }

        let handle = Arc::new(PeerHandle {
            info,
            tunnel: tunnel.clone(),
            last_seen: parking_lot::Mutex::new(now_secs()),
            via: via.to_string(),
            tx_bytes: std::sync::atomic::AtomicU64::new(0),
            rx_bytes: std::sync::atomic::AtomicU64::new(0),
        });
        let replaced = self.peers.insert(peer_id, handle).is_some();
        tracing::info!(%peer_id, %via, replaced, "peer added");

        // 读循环: 隧道 -> 分发
        let mgr = self.clone();
        let tun = tunnel.clone();
        tokio::spawn(async move {
            loop {
                match tun.recv().await {
                    Ok(pkt) => {
                        if let Err(e) = mgr.handle_packet(peer_id, pkt).await {
                            tracing::warn!(%peer_id, ?e, "handle packet failed");
                        }
                    }
                    Err(e) => {
                        tracing::info!(%peer_id, ?e, "tunnel closed");
                        // 仅当当前注册的还是这条隧道时才移除 (避免旧隧道退出误删重连的新隧道)
                        mgr.remove_peer_if_same(peer_id, &tun);
                        break;
                    }
                }
            }
        });

        // 向新 peer 请求全量 Peer 列表 (发现更多节点)
        let req = ControlPacket {
            msg: Some(Msg::PeerListRequest(vnet_proto::PeerListRequest {})),
        };
        let mgr = self.clone();
        tokio::spawn(async move {
            let _ = mgr.send_control(peer_id, req).await;
        });

        // gossip: 广播新 peer 加入
        let mgr = self.clone();
        tokio::spawn(async move { mgr.broadcast_topology().await });
        true
    }

    /// 仅当当前注册的 handle 仍持有该隧道时才移除
    fn remove_peer_if_same(self: &Arc<Self>, peer_id: u64, tunnel: &Arc<dyn Tunnel>) {
        let same = self
            .peers
            .get(&peer_id)
            .map(|h| Arc::ptr_eq(&h.tunnel, tunnel))
            .unwrap_or(false);
        if same {
            self.remove_peer(peer_id);
        }
    }

    pub fn remove_peer(self: &Arc<Self>, peer_id: u64) {
        if let Some((_, h)) = self.peers.remove(&peer_id) {
            self.routes.remove_peer(peer_id);
            tracing::info!(%peer_id, vip = %h.info.virtual_ip, "peer removed");
            let mgr = self.clone();
            tokio::spawn(async move { mgr.broadcast_topology().await });
        }
    }

    /// 广播当前拓扑 (RouteUpdate) 给所有 peer
    pub async fn broadcast_topology(&self) {
        let peers = self.list_peer_info();
        tracing::info!(
            count = peers.len(),
            "broadcast_topology 发送, 各 peer udp_mapped_addr:"
        );
        for p in &peers {
            tracing::info!(
                peer_id = p.peer_id,
                vip = %p.virtual_ip,
                udp_mapped = %p.udp_mapped_addr,
                "  PeerInfo"
            );
        }
        let update = ControlPacket {
            msg: Some(Msg::RouteUpdate(vnet_proto::RouteUpdate {
                added: peers,
                removed_peer_ids: vec![],
            })),
        };
        let ids: Vec<u64> = self.peers.iter().map(|h| *h.key()).collect();
        for id in ids {
            let _ = self.send_control(id, update.clone()).await;
        }
    }

    /// 按目标虚拟 IP 发送数据包
    pub async fn send_data(&self, dst_ip: Ipv4Addr, ip_packet: Bytes) -> Result<()> {
        let peer_id = self
            .routes
            .lookup(dst_ip)
            .ok_or_else(|| Error::NoRoute(dst_ip.to_string()))?;
        self.send_data_to(peer_id, ip_packet).await
    }

    pub async fn send_data_to(&self, peer_id: u64, ip_packet: Bytes) -> Result<()> {
        let handle = self
            .peers
            .get(&peer_id)
            .ok_or(Error::PeerNotFound(peer_id))?;
        handle
            .tx_bytes
            .fetch_add(ip_packet.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let pkt = TunnelPacket {
            from_peer: self.my_peer_id,
            to_peer: peer_id,
            packet_type: PacketType::Data as i32,
            payload: ip_packet.to_vec(),
        };
        handle.tunnel.send(&pkt).await
    }

    /// 转发数据包 (多跳): 不改变 from_peer, 只换下一跳
    pub async fn forward_data(&self, pkt: &TunnelPacket, dst_ip: Ipv4Addr) -> Result<()> {
        let next = self
            .routes
            .lookup(dst_ip)
            .ok_or_else(|| Error::NoRoute(dst_ip.to_string()))?;
        if next == self.my_peer_id {
            return Err(Error::Protocol("forward loop".into()));
        }
        let handle = self.peers.get(&next).ok_or(Error::PeerNotFound(next))?;
        handle
            .tx_bytes
            .fetch_add(pkt.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
        handle.tunnel.send(pkt).await
    }

    /// 向指定 peer 发送控制消息
    pub async fn send_control(&self, peer_id: u64, ctrl: ControlPacket) -> Result<()> {
        let handle = self
            .peers
            .get(&peer_id)
            .ok_or(Error::PeerNotFound(peer_id))?;
        handle
            .tx_bytes
            .fetch_add(ctrl.encoded_len() as u64, std::sync::atomic::Ordering::Relaxed);
        let pkt = TunnelPacket {
            from_peer: self.my_peer_id,
            to_peer: peer_id,
            packet_type: PacketType::Control as i32,
            payload: prost::Message::encode_to_vec(&ctrl),
        };
        handle.tunnel.send(&pkt).await
    }

    async fn handle_packet(&self, from: u64, pkt: TunnelPacket) -> Result<()> {
        if let Some(h) = self.peers.get(&from) {
            *h.last_seen.lock() = now_secs();
            h.rx_bytes
                .fetch_add(pkt.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        match PacketType::try_from(pkt.packet_type).unwrap_or(PacketType::Data) {
            PacketType::Data => {
                let is_relay = self.relay_mode.load(std::sync::atomic::Ordering::Relaxed);
                // 按 payload 目标 IP 判断归属: 目标是本机虚拟 IP 或本机代理子网时本地投递,
                // 否则转发 (支持多跳). 不能用 to_peer: 多跳转发时它是下一跳, 不可靠.
                let Some(dst) = crate::tun::packet::dst_addr(&pkt.payload) else {
                    return Ok(()); // 无法解析目标 IP, 丢弃
                };
                let id = self.identity.read().clone();
                let my_vip: Option<Ipv4Addr> =
                    id.as_ref().and_then(|i| i.virtual_ip.parse().ok());
                let for_me = my_vip.map(|v| v == dst).unwrap_or(false)
                    || id
                        .as_ref()
                        .map(|i| i.proxy_cidrs.iter().any(|c| cidr_contains(c, dst)))
                        .unwrap_or(false);
                if is_relay || !for_me {
                    return self.forward_data(&pkt, dst).await;
                }
                self.inbound_tx
                    .send(Bytes::from(pkt.payload))
                    .await
                    .map_err(|_| Error::Tunnel("inbound channel closed".into()))?;
            }
            PacketType::Control => {
                let ctrl: ControlPacket = prost::Message::decode(&pkt.payload[..])
                    .map_err(|e| Error::Protocol(format!("bad control: {e}")))?;
                self.handle_control(from, ctrl).await;
            }
        }
        Ok(())
    }

    async fn handle_control(&self, from: u64, ctrl: ControlPacket) {
        match ctrl.msg {
            Some(Msg::Ping(ping)) => {
                let pong = ControlPacket {
                    msg: Some(Msg::Pong(vnet_proto::Pong {
                        seq: ping.seq,
                        ts_ms: ping.ts_ms,
                    })),
                };
                let _ = self.send_control(from, pong).await;
            }
            Some(Msg::PeerListRequest(_)) => {
                let peers = self.list_peer_info();
                let resp = ControlPacket {
                    msg: Some(Msg::PeerListResponse(vnet_proto::PeerListResponse { peers })),
                };
                let _ = self.send_control(from, resp).await;
            }
            Some(Msg::PeerListResponse(resp)) => {
                // 学到新 peer 且对方通告了 udp_mapped_addr 时, 尝试 NAT 打洞
                tracing::info!(
                    count = resp.peers.len(),
                    "RouteUpdate(PeerListResponse) 收到, 各 peer udp_mapped_addr:"
                );
                for info in &resp.peers {
                    tracing::info!(
                        peer_id = info.peer_id,
                        vip = %info.virtual_ip,
                        udp_mapped = %info.udp_mapped_addr,
                        public_addrs = ?info.public_addrs,
                        "  PeerInfo"
                    );
                }
                for info in &resp.peers {
                    self.maybe_punch_peer(info);
                }
                self.discover_peers(resp.peers).await;
            }
            Some(Msg::RouteUpdate(ru)) => {
                // 所有节点从 gossip 学习路由 (直连优先, 若已直连则忽略)
                tracing::info!(
                    count = ru.added.len(),
                    from,
                    "RouteUpdate 收到, 各 peer udp_mapped_addr:"
                );
                for info in &ru.added {
                    tracing::info!(
                        peer_id = info.peer_id,
                        vip = %info.virtual_ip,
                        udp_mapped = %info.udp_mapped_addr,
                        public_addrs = ?info.public_addrs,
                        "  PeerInfo"
                    );
                }
                for info in &ru.added {
                    if info.peer_id != self.my_peer_id {
                        self.learn_route_via(info, from);
                        self.maybe_punch_peer(info);
                    }
                }
                self.discover_peers(ru.added).await;
            }
            Some(Msg::PunchRequest(req)) => {
                // 对端请求与我打洞: 回复我的映射地址, 并主动向对端映射地址打洞
                let my_addr = self.my_udp_mapped_addr.read().clone().unwrap_or_default();
                let resp = ControlPacket {
                    msg: Some(Msg::PunchResponse(vnet_proto::PunchResponse {
                        from_peer_id: self.my_peer_id,
                        peer_udp_mapped_addr: my_addr,
                    })),
                };
                let _ = self.send_control(from, resp).await;
                self.trigger_udp_punch(req.my_udp_mapped_addr);
            }
            Some(Msg::PunchResponse(resp)) => {
                self.trigger_udp_punch(resp.peer_udp_mapped_addr);
            }
            _ => {}
        }
    }

    /// 从 PeerInfo 列表中发现新节点并尝试直连
    async fn discover_peers(&self, peers: Vec<PeerInfo>) {
        for info in peers {
            if info.peer_id == self.my_peer_id || self.peers.contains_key(&info.peer_id) {
                continue;
            }
            for addr in &info.public_addrs {
                if self.connecting.contains_key(addr) {
                    continue;
                }
                self.connecting.insert(addr.clone(), ());
                let _ = self.connect_tx.send(addr.clone()).await;
                break; // 每个 peer 先试第一个地址
            }
        }
    }

    pub fn finish_connect_attempt(&self, addr: &str) {
        self.connecting.remove(addr);
    }

    /// 从 gossip 学习路由 (直连优先): 把 peer 的虚拟 IP/CIDR 指向下一跳
    fn learn_route_via(&self, info: &PeerInfo, next_hop: u64) {
        if let Ok(ip) = info.virtual_ip.parse::<Ipv4Addr>() {
            self.routes.insert_host_if_absent(ip, next_hop);
        }
        for cidr in &info.proxy_cidrs {
            self.routes.insert_cidr_if_absent(cidr, next_hop);
        }
    }

    /// 触发 UDP 直连打洞: 把 "udp://<mapped_addr>" 投递到 connect_tx,
    /// 由 instance::connect_peer → UdpTunnel::connect 完成完整握手 (保证双方密钥一致),
    /// 成功后调用 add_peer 注册 UDP 隧道. 用 connect_tx 而非直接 raw send 是因为
    /// 后者会让双方各自生成新密钥对, 导致 cipher 不匹配 (decrypt failed).
    fn trigger_udp_punch(&self, target_addr: String) {
        if target_addr.is_empty() {
            return;
        }
        let addr = format!("udp://{target_addr}");
        if self.connecting.contains_key(&addr) {
            return;
        }
        self.connecting.insert(addr.clone(), ());
        tracing::info!(%target_addr, "触发 UDP 直连打洞 (经 connect_tx)");
        let connect_tx = self.connect_tx.clone();
        tokio::spawn(async move {
            let _ = connect_tx.send(addr).await;
        });
    }

    /// 若对方通告了 UDP 映射地址且我们尚未与之直连, 触发打洞 (双方同时打, NAT 洞开后建立 UDP 会话)
    fn maybe_punch_peer(&self, info: &PeerInfo) {
        if info.peer_id == self.my_peer_id {
            return;
        }
        if self.peers.contains_key(&info.peer_id) {
            return; // 已直连, 不需打洞
        }
        if info.udp_mapped_addr.is_empty() {
            return;
        }
        tracing::info!(
            peer_id = info.peer_id,
            vip = %info.virtual_ip,
            target = %info.udp_mapped_addr,
            "gossip 发现新 peer 且有 UDP 映射地址, 启动 NAT 打洞"
        );
        self.trigger_udp_punch(info.udp_mapped_addr.clone());
    }

    /// 启动心跳保活: 周期向所有 peer 发 Ping; 超过 timeout 无任何流量的 peer 判死剔除
    pub fn spawn_keepalive(
        self: &Arc<Self>,
        interval: std::time::Duration,
        timeout: std::time::Duration,
    ) {
        let mgr = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                mgr.ping_all().await;
                mgr.expire_peers(timeout);
            }
        });
    }

    async fn ping_all(&self) {
        let ping = ControlPacket {
            msg: Some(Msg::Ping(vnet_proto::Ping { seq: 0, ts_ms: 0 })),
        };
        for id in self.peer_ids() {
            let _ = self.send_control(id, ping.clone()).await;
        }
    }

    fn expire_peers(self: &Arc<Self>, timeout: std::time::Duration) {
        let now = now_secs();
        let dead: Vec<u64> = self
            .peers
            .iter()
            .filter(|h| now - *h.last_seen.lock() > timeout.as_secs() as i64)
            .map(|h| *h.key())
            .collect();
        for id in dead {
            tracing::warn!(%id, "peer expired (keepalive timeout), removing");
            self.remove_peer(id);
        }
    }

    /// 该地址是否已有连接 (客户端拨号成功时 via == 配置地址; 或对端通告的监听地址)
    pub fn has_addr_connected(&self, addr: &str) -> bool {
        self.peers.iter().any(|h| {
            h.via == addr || h.info.public_addrs.iter().any(|a| a == addr)
        })
    }

    pub fn is_connecting(&self, addr: &str) -> bool {
        self.connecting.contains_key(addr)
    }

    pub fn list_peer_info(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|h| h.info.clone()).collect()
    }

    pub fn peer_ids(&self) -> Vec<u64> {
        self.peers.iter().map(|h| *h.key()).collect()
    }

    /// 导出路由表 (API 用): (目标字符串, 下一跳 peer_id)
    pub fn dump_routes(&self) -> Vec<(String, u64)> {
        self.routes.dump()
    }

    pub fn get_peer(&self, peer_id: u64) -> Option<Arc<PeerHandle>> {
        self.peers.get(&peer_id).map(|h| h.clone())
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// 判断 ip 是否落在 "a.b.c.d/n" 网段内
fn cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((net, plen)) = route::parse_cidr(cidr) else {
        return false;
    };
    if plen == 0 {
        return true;
    }
    let shift = 32 - plen;
    (u32::from(ip) >> shift) == (net >> shift)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
