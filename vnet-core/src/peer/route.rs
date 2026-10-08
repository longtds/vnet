//! 路由表: 虚拟 IP / 代理 CIDR -> peer_id

use dashmap::DashMap;
use std::net::Ipv4Addr;

/// 最长前缀匹配路由表
pub struct RouteTable {
    /// 主机路由: /32
    hosts: DashMap<Ipv4Addr, u64>,
    /// 网段路由: (网络地址, 前缀长) -> peer_id
    cidrs: DashMap<(u32, u8), u64>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            hosts: DashMap::new(),
            cidrs: DashMap::new(),
        }
    }

    pub fn insert_host(&self, ip: Ipv4Addr, peer_id: u64) {
        self.hosts.insert(ip, peer_id);
    }

    /// 仅当路由不存在时插入 (gossip 学习用, 直连路由优先)
    pub fn insert_host_if_absent(&self, ip: Ipv4Addr, peer_id: u64) {
        self.hosts.entry(ip).or_insert(peer_id);
    }

    pub fn insert_cidr(&self, cidr: &str, peer_id: u64) {
        if let Some((net, plen)) = parse_cidr(cidr) {
            self.cidrs.insert((net, plen), peer_id);
        }
    }

    /// 仅当 CIDR 路由不存在时插入
    pub fn insert_cidr_if_absent(&self, cidr: &str, peer_id: u64) {
        if let Some((net, plen)) = parse_cidr(cidr) {
            self.cidrs.entry((net, plen)).or_insert(peer_id);
        }
    }

    /// 最长前缀匹配
    pub fn lookup(&self, dst: Ipv4Addr) -> Option<u64> {
        if let Some(p) = self.hosts.get(&dst) {
            return Some(*p);
        }
        let dst_u32 = u32::from(dst);
        let mut best: Option<(u8, u64)> = None;
        for e in self.cidrs.iter() {
            let (net, plen) = *e.key();
            if plen <= 32 && (dst_u32 >> (32 - plen)) == (net >> (32 - plen)) {
                if best.map_or(true, |(bplen, _)| plen > bplen) {
                    best = Some((plen, *e.value()));
                }
            }
        }
        best.map(|(_, p)| p)
    }

    /// 移除某 peer 的所有路由
    pub fn remove_peer(&self, peer_id: u64) {
        self.hosts.retain(|_, p| *p != peer_id);
        self.cidrs.retain(|_, p| *p != peer_id);
    }

    /// 导出所有路由 (API 用)
    pub fn dump(&self) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for e in self.hosts.iter() {
            out.push((e.key().to_string(), *e.value()));
        }
        for e in self.cidrs.iter() {
            let (net, plen) = *e.key();
            out.push((format!("{}/{}", Ipv4Addr::from(net), plen), *e.value()));
        }
        out
    }
}

/// 解析 "10.1.1.0/24" -> (网络地址 u32, 前缀长)
pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (ip_str, plen_str) = s.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let plen: u8 = plen_str.parse().ok()?;
    if plen > 32 {
        return None;
    }
    Some((u32::from(ip), plen))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup() {
        let rt = RouteTable::new();
        rt.insert_host("10.144.144.2".parse().unwrap(), 2);
        rt.insert_cidr("10.1.1.0/24", 3);
        assert_eq!(rt.lookup("10.144.144.2".parse().unwrap()), Some(2));
        assert_eq!(rt.lookup("10.1.1.5".parse().unwrap()), Some(3));
        assert_eq!(rt.lookup("10.2.2.2".parse().unwrap()), None);
    }
}
