//! 自动端口映射: UPnP-IGD + NAT-PMP
//!
//! 启动时尝试为所有监听端口在路由器上建立映射, 并定期续租。
//! 两种协议都失败时静默跳过 (节点仍可通过中继/打洞组网)。

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// 需要映射的端口描述
#[derive(Debug, Clone)]
pub struct Mapping {
    pub port: u16,
    pub proto: Proto,
    pub desc: String,
}

/// 实际生效的映射协议 (续约策略不同)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapProto {
    Upnp,
    NatPmp,
}

/// 尝试映射全部端口, 返回成功映射的外部地址列表; 后台定期续租
pub async fn setup_mappings(mappings: Vec<Mapping>) -> Vec<(Mapping, Ipv4Addr)> {
    let mut mapped = Vec::new();

    // 1. 优先 UPnP
    match try_upnp(&mappings).await {
        Some(v) => {
            for (m, ext_ip) in v {
                tracing::info!(port = m.port, proto = ?m.proto, %ext_ip, "UPnP port mapped");
                mapped.push((m, ext_ip));
            }
            if !mapped.is_empty() {
                spawn_renew(mappings.clone(), MapProto::Upnp);
                return mapped;
            }
        }
        None => tracing::debug!("UPnP gateway not found"),
    }

    // 2. 回退 NAT-PMP (同步 crate, 放 blocking 线程)
    let for_blocking = mappings.clone();
    match tokio::task::spawn_blocking(move || try_natpmp_blocking(&for_blocking)).await {
        Ok(Some(v)) => {
            for (m, ext_ip) in v {
                tracing::info!(port = m.port, proto = ?m.proto, %ext_ip, "NAT-PMP port mapped");
                mapped.push((m, ext_ip));
            }
            if !mapped.is_empty() {
                spawn_renew(mappings.clone(), MapProto::NatPmp);
            }
        }
        Ok(None) => tracing::debug!("NAT-PMP gateway not available"),
        Err(_) => {}
    }

    mapped
}

/// 获取本机在内网的 IPv4 地址 (UDP connect 不实际发包)
fn local_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

async fn try_upnp(mappings: &[Mapping]) -> Option<Vec<(Mapping, Ipv4Addr)>> {
    use igd::aio::search_gateway;
    use igd::{PortMappingProtocol, SearchOptions};

    let gateway = search_gateway(SearchOptions::default()).await.ok()?;
    let ext_ip = gateway.get_external_ip().await.ok()?;
    let local_ip = local_ipv4()?;
    let mut out = Vec::new();
    for m in mappings {
        let proto = match m.proto {
            Proto::Tcp => PortMappingProtocol::TCP,
            Proto::Udp => PortMappingProtocol::UDP,
        };
        let local = SocketAddrV4::new(local_ip, m.port);
        // 租约 600s, 续约间隔 60s, 留出充足的重试窗口
        match gateway.add_port(proto, m.port, local, 600, &m.desc).await {
            Ok(()) => out.push((m.clone(), ext_ip)),
            Err(e) => tracing::debug!(port = m.port, ?e, "UPnP add_port failed"),
        }
    }
    Some(out)
}

fn try_natpmp_blocking(mappings: &[Mapping]) -> Option<Vec<(Mapping, Ipv4Addr)>> {
    use natpmp::{Natpmp, Protocol, Response};

    let mut n = Natpmp::new().ok()?;
    // 获取外网地址
    n.send_public_address_request().ok()?;
    let mut ext_ip = None;
    for _ in 0..3 {
        if let Ok(Response::Gateway(addr)) = n.read_response_or_retry() {
            ext_ip = Some(*addr.public_address());
            break;
        }
    }
    let ext_ip = ext_ip?;

    let mut out = Vec::new();
    for m in mappings {
        let proto = match m.proto {
            Proto::Tcp => Protocol::TCP,
            Proto::Udp => Protocol::UDP,
        };
        if n.send_port_mapping_request(proto, m.port, m.port, 3600).is_err() {
            continue;
        }
        for _ in 0..3 {
            match n.read_response_or_retry() {
                Ok(Response::UDP(r)) | Ok(Response::TCP(r)) => {
                    if r.public_port() == m.port {
                        out.push((m.clone(), ext_ip));
                    }
                    break;
                }
                _ => continue,
            }
        }
    }
    Some(out)
}

fn spawn_renew(mappings: Vec<Mapping>, proto: MapProto) {
    tokio::spawn(async move {
        // UPnP 租约 600s -> 60s 续约; NAT-PMP 租约 3600s -> 半程 (1800s) 续约
        let interval_secs = match proto {
            MapProto::Upnp => 60,
            MapProto::NatPmp => 1800,
        };
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // 跳过立即触发
        loop {
            ticker.tick().await;
            let m = mappings.clone();
            match proto {
                MapProto::Upnp => {
                    tokio::spawn(async move {
                        let _ = try_upnp(&m).await;
                    });
                }
                MapProto::NatPmp => {
                    tokio::task::spawn_blocking(move || {
                        let _ = try_natpmp_blocking(&m);
                    });
                }
            }
        }
    });
}
