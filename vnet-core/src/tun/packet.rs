//! IPv4 包解析

use std::net::Ipv4Addr;

/// 从 IPv4 包头提取目标地址 (偏移 16-19)
pub fn dst_addr(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    // 检查版本字段 (高 4 位 = 4)
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// 从 IPv4 包头提取源地址 (偏移 12-15)
pub fn src_addr(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}
