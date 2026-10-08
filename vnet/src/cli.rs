//! vnet-cli: 查询运行中 vnet 节点的管理 API

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vnet-cli", about = "vnet 管理工具", version)]
struct Cli {
    /// 管理 API 地址
    #[arg(long, default_value = "http://127.0.0.1:22020")]
    admin: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 查看已连接 Peer
    Peer,
    /// 查看路由表
    Route,
    /// 查看本节点信息
    Node,
    /// 查看全部状态
    Status,
    /// 生成 WireGuard 密钥对 (输出 server_private / client_public 之外的两对: 门户私钥+公钥)
    WgKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::WgKey = cli.cmd {
        let (priv_key, pub_key) = vnet_core::vpn_portal::gen_keypair();
        println!("# 门户服务器 (--wg-private-key):");
        println!("{priv_key}");
        println!("# 服务器公钥 (配置给客户端的 peer endpoint 公钥):");
        println!("{pub_key}");
        let (c_priv, c_pub) = vnet_core::vpn_portal::gen_keypair();
        println!("# 客户端私钥 (写入手机 WG App):");
        println!("{c_priv}");
        println!("# 客户端公钥 (--wg-client name=ip=<此值>):");
        println!("{c_pub}");
        return Ok(());
    }
    let base = cli.admin.trim_end_matches('/');
    match cli.cmd {
        Cmd::WgKey => unreachable!(),
        Cmd::Peer => {
            let peers = get_list(&format!("{base}/api/peers")).await?;
            println!(
                "{:<20} {:<16} {:<18} {:<8} {:<26} {:<12} {:<20}",
                "peer_id", "hostname", "virtual_ip", "proto", "via", "rx/tx", "proxy_cidrs"
            );
            for p in peers {
                let rx = p["rx_bytes"].as_u64().unwrap_or(0);
                let tx = p["tx_bytes"].as_u64().unwrap_or(0);
                println!(
                    "{:<20} {:<16} {:<18} {:<8} {:<26} {:<12} {:<20}",
                    p["peer_id"], p["hostname"], p["virtual_ip"], p["proto"], p["via"],
                    format!("{}/{}", fmt_bytes(rx), fmt_bytes(tx)),
                    p["proxy_cidrs"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default(),
                );
            }
        }
        Cmd::Route => {
            let routes = get_list(&format!("{base}/api/routes")).await?;
            println!("{:<22} {:<20}", "dst", "next_hop");
            for r in routes {
                println!("{:<22} {:<20}", r["dst"], r["next_hop"]);
            }
        }
        Cmd::Node => {
            let n: serde_json::Value = get(&format!("{base}/api/node")).await?;
            println!("peer_id:        {}", n["peer_id"]);
            println!("hostname:       {}", n["hostname"]);
            println!("virtual_ip:     {}", n["virtual_ip"]);
            println!("network_name:   {}", n["network_name"]);
            println!("udp_mapped:     {}", n["udp_mapped_addr"]);
            let mapped = n["mapped_addrs"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            println!("port_mapped:    {}", if mapped.is_empty() { "-".into() } else { mapped });
            println!("relay_mode:     {}", n["relay_mode"]);
        }
        Cmd::Status => {
            let n: serde_json::Value = get(&format!("{base}/api/node")).await?;
            let peers = get_list(&format!("{base}/api/peers")).await?;
            let routes = get_list(&format!("{base}/api/routes")).await?;
            println!("== Node ==");
            println!("  peer_id={} vip={} hostname={}", n["peer_id"], n["virtual_ip"], n["hostname"]);
            println!("== Peers: {} ==", peers.len());
            for p in peers {
                println!(
                    "  {} {} {} ({}, ↓{} ↑{})",
                    p["peer_id"], p["virtual_ip"], p["hostname"], p["proto"],
                    fmt_bytes(p["rx_bytes"].as_u64().unwrap_or(0)),
                    fmt_bytes(p["tx_bytes"].as_u64().unwrap_or(0)),
                );
            }
            println!("== Routes: {} ==", routes.len());
            for r in routes {
                println!("  {} -> {}", r["dst"], r["next_hop"]);
            }
        }
    }
    Ok(())
}

async fn get(url: &str) -> Result<serde_json::Value> {
    let resp = reqwest::get(url).await.context(format!("GET {url}"))?;
    resp.json().await.context("parse json")
}

/// 字节数人性化显示
fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}G", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

async fn get_list(url: &str) -> Result<Vec<serde_json::Value>> {
    let v = get(url).await?;
    Ok(v.as_array().cloned().unwrap_or_default())
}
