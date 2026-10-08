//! TUN 设备封装

use crate::common::error::{Error, Result};
use std::net::Ipv4Addr;
use tun::{AsyncDevice, Configuration};

/// 创建并配置 TUN 设备
pub async fn create_tun(
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
) -> Result<AsyncDevice> {
    let mut config = Configuration::default();
    config
        .tun_name(name)
        .address(addr)
        .netmask(prefix_to_netmask(prefix_len))
        .mtu(mtu)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|c| {
        c.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config).map_err(|e| Error::Tun(e.to_string()))?;
    tracing::info!(%name, %addr, prefix_len, mtu, "TUN device created");
    Ok(dev)
}

/// 前缀长度转子网掩码
fn prefix_to_netmask(prefix_len: u8) -> Ipv4Addr {
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(mask)
}
