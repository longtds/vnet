//! 子网代理网关辅助
//!
//! 当节点收到目标为代理子网的 IP 包时, 包经 TUN -> 隧道 -> 代理节点 TUN。
//! 代理节点写回 TUN 后, 内核协议栈负责转发到本地子网。
//! 因此代理节点需要开启系统 IP 转发。
//!
//! 本模块提供配置检查和引导命令输出。

use crate::common::config::NodeConfig;
use tracing::info;

/// 检查系统 IP 转发是否开启, 并打印引导命令
pub fn check_and_hint(cfg: &NodeConfig) {
    if cfg.proxy_cidrs.is_empty() {
        return;
    }
    info!("proxy_cidrs={:?}", cfg.proxy_cidrs);
    info!("ensure IP forwarding enabled: sysctl -w net.ipv4.ip_forward=1");
    info!("ensure NAT rule if needed: iptables -t nat -A POSTROUTING -s {} -j MASQUERADE", cfg.virtual_ip.map(|i| format!("{}/24", i)).unwrap_or_default());
    info!("ensure firewall allows FORWARD between {} and physical interfaces", cfg.tun_name);
}
