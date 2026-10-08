//! STUN 客户端 (RFC 5389 简化实现): 获取 UDP 外网映射地址

use crate::common::error::{Error, Result};
use crate::tunnel::udp_demux::UnknownPacket;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MAGIC_COOKIE: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// 通过 STUN 服务器查询本 socket 的外网映射地址.
/// socket 必须已绑定 (通常复用 UDP 监听 socket, 保证映射端口一致).
/// stun_rx: 从 demux 路由过来的 STUN 响应包 (修复 race: 若直接在 socket 上 recv_from,
///          响应会被 demux 的读循环抢先消费).
pub async fn query_mapped_addr(
    socket: &UdpSocket,
    stun_server: &str,
    mut stun_rx: mpsc::Receiver<UnknownPacket>,
) -> Result<SocketAddr> {
    let server: SocketAddr = match stun_server.parse() {
        Ok(sa) => sa,
        Err(_) => {
            // 域名地址: host:port → lookup_host
            let parts: Vec<&str> = stun_server.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(Error::Config(format!("bad stun addr {stun_server}")));
            }
            let port: u16 = parts[0].parse()
                .map_err(|_| Error::Config(format!("bad stun port in {stun_server}")))?;
            let mut addrs = tokio::net::lookup_host((parts[1], port))
                .await
                .map_err(|e| Error::Config(format!("stun dns resolve {stun_server}: {e}")))?;
            addrs
                .next()
                .ok_or_else(|| Error::Config(format!("stun dns no results {stun_server}")))?
        }
    };

    // 构造 Binding Request: type(2) len(2) magic(4) txid(12)
    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    let txid: [u8; 12] = rand::random();
    req.extend_from_slice(&txid);

    socket.send_to(&req, server).await?;

    for _ in 0..3 {
        match tokio::time::timeout(std::time::Duration::from_secs(2), stun_rx.recv()).await {
            Ok(Some(upkt)) => {
                if upkt.from != server {
                    continue;
                }
                if let Some(addr) = parse_binding_response(&upkt.data, &txid)? {
                    return Ok(addr);
                }
            }
            Ok(None) => return Err(Error::Protocol("stun channel closed".into())),
            Err(_) => {
                socket.send_to(&req, server).await?; // 重试
            }
        }
    }
    Err(Error::Protocol("stun timeout".into()))
}

fn parse_binding_response(data: &[u8], expected_txid: &[u8; 12]) -> Result<Option<SocketAddr>> {
    if data.len() < 20 {
        return Ok(None);
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_SUCCESS {
        return Ok(None);
    }
    if &data[8..20] != expected_txid {
        return Ok(None);
    }
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut pos = 20;
    while pos + 4 <= data.len().min(20 + msg_len) {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let val_start = pos + 4;
        if val_start + attr_len > data.len() {
            break;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
            let family = data[val_start + 1];
            if family == 0x01 {
                // IPv4: port XOR magic 高16位, addr XOR magic
                let port = u16::from_be_bytes([data[val_start + 2], data[val_start + 3]])
                    ^ (MAGIC_COOKIE >> 16) as u16;
                let mut addr = [0u8; 4];
                for i in 0..4 {
                    addr[i] = data[val_start + 4 + i] ^ MAGIC_COOKIE.to_be_bytes()[i];
                }
                return Ok(Some(SocketAddr::new(addr.into(), port)));
            }
        }
        // 属性按 4 字节对齐
        pos = val_start + attr_len.div_ceil(4) * 4;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xor_mapped() {
        // 手工构造: Binding Success + XOR-MAPPED-ADDRESS (192.0.2.1:12345)
        let txid = [1u8; 12];
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0); msg.push(0x01);
        let port = 12345u16 ^ (MAGIC_COOKIE >> 16) as u16;
        msg.extend_from_slice(&port.to_be_bytes());
        let ip: std::net::Ipv4Addr = "192.0.2.1".parse().unwrap();
        for i in 0..4 {
            msg.push(ip.octets()[i] ^ MAGIC_COOKIE.to_be_bytes()[i]);
        }
        let got = parse_binding_response(&msg, &txid).unwrap().unwrap();
        assert_eq!(got, "192.0.2.1:12345".parse().unwrap());
    }
}
