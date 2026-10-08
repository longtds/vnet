//! 节点配置

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 节点配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// 网络名称 (组网标识, 同一网络的节点必须一致)
    pub network_name: String,
    /// 网络密钥 (用于派生 peer_id 和加密)
    pub network_secret: String,
    /// 本节点虚拟 IP, 如 "10.144.144.1"; None 表示仅作中继
    pub virtual_ip: Option<Ipv4Addr>,
    /// 虚拟网络前缀长度, 默认 24
    pub prefix_len: u8,
    /// 监听地址列表, 支持 tcp:// udp:// ws:// wss:// kcp:// quic://
    pub listeners: Vec<String>,
    /// 要连接的初始 peer 地址 (同样支持多种 scheme)
    pub peers: Vec<String>,
    /// 代理的子网, 如 ["10.1.1.0/24"]
    pub proxy_cidrs: Vec<String>,
    /// STUN 服务器 (探测 UDP 映射地址用)
    pub stun_server: String,
    /// TUN 设备名
    pub tun_name: String,
    /// 管理 API 端口
    pub admin_port: u16,
    /// MTU
    pub mtu: u16,
    /// WSS 证书 PEM 路径 (wss listener 必需)
    pub tls_cert: Option<String>,
    /// WSS 私钥 PEM 路径
    pub tls_key: Option<String>,
    /// 连接 wss:// 时校验服务端证书的 CA PEM 路径; None 表示跳过校验 (兼容自签)
    pub tls_ca: Option<String>,
    /// WireGuard 门户监听地址, 如 "0.0.0.0:11013"
    pub wg_listen: Option<String>,
    /// WireGuard 服务器私钥 (base64)
    pub wg_private_key: Option<String>,
    /// WG 客户端列表, 每项 "name=10.144.144.3=<base64公钥>"
    pub wg_clients: Vec<String>,
    /// 是否启用 UPnP/NAT-PMP 自动端口映射
    pub enable_port_mapping: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network_name: "default".to_string(),
            network_secret: String::new(),
            virtual_ip: None,
            prefix_len: 24,
            listeners: vec![
                "tcp://0.0.0.0:11010".to_string(),
                "udp://0.0.0.0:11010".to_string(),
            ],
            peers: vec![],
            proxy_cidrs: vec![],
            stun_server: "stun.l.google.com:19302".to_string(),
            tun_name: "vnet0".to_string(),
            admin_port: 22020,
            mtu: 1380,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            wg_listen: None,
            wg_private_key: None,
            wg_clients: vec![],
            enable_port_mapping: false,
        }
    }
}
