use anyhow::Result;
use clap::Parser;
use vnet_core::NodeConfig;

#[derive(Parser, Debug)]
#[command(name = "vnet", about = "vnet 异地组网", version)]
struct Cli {
    /// 网络名称
    #[arg(short = 'n', long, default_value = "default")]
    network_name: String,

    /// 网络密钥
    #[arg(short = 's', long, default_value = "")]
    network_secret: String,

    /// 本机虚拟 IP (如 10.144.144.1)
    #[arg(short = 'i', long)]
    virtual_ip: Option<std::net::Ipv4Addr>,

    /// 监听地址 (可重复), 支持 tcp:// udp:// ws:// wss:// kcp:// quic://
    #[arg(short = 'l', long, default_values = &["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"])]
    listen: Vec<String>,

    /// 对端 peer 地址 (可重复), scheme 同 --listen
    #[arg(short = 'p', long)]
    peer: Vec<String>,

    /// 代理子网 (可重复)
    #[arg(long)]
    proxy_cidr: Vec<String>,

    /// TUN 设备名
    #[arg(long, default_value = "vnet0")]
    tun_name: String,

    /// STUN 服务器
    #[arg(long, default_value = "stun.l.google.com:19302")]
    stun_server: String,

    /// 管理 API 端口
    #[arg(long, default_value = "22020")]
    admin_port: u16,

    /// MTU
    #[arg(long, default_value = "1380")]
    mtu: u16,

    /// 仅运行中继模式 (不创建 TUN)
    #[arg(long)]
    relay_only: bool,

    /// WSS 证书 PEM 文件
    #[arg(long)]
    tls_cert: Option<String>,

    /// WSS 私钥 PEM 文件
    #[arg(long)]
    tls_key: Option<String>,

    /// 连接 wss:// 时校验服务端证书的 CA PEM 文件 (不设置则跳过校验, 兼容自签)
    #[arg(long)]
    tls_ca: Option<String>,

    /// WireGuard 门户监听地址, 如 0.0.0.0:11013
    #[arg(long)]
    wg_listen: Option<String>,

    /// WireGuard 门户服务器私钥 (base64, 可用 vnet-cli wg-key 生成)
    #[arg(long)]
    wg_private_key: Option<String>,

    /// WG 客户端, 格式 name=虚拟IP=<客户端base64公钥> (可重复)
    #[arg(long)]
    wg_client: Vec<String>,

    /// 启用 UPnP/NAT-PMP 自动端口映射
    #[arg(long)]
    enable_port_mapping: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = NodeConfig {
        network_name: cli.network_name,
        network_secret: cli.network_secret,
        virtual_ip: cli.virtual_ip,
        prefix_len: 24,
        listeners: cli.listen,
        peers: cli.peer,
        proxy_cidrs: cli.proxy_cidr,
        stun_server: cli.stun_server,
        tun_name: cli.tun_name,
        admin_port: cli.admin_port,
        mtu: cli.mtu,
        tls_cert: cli.tls_cert,
        tls_key: cli.tls_key,
        tls_ca: cli.tls_ca,
        wg_listen: cli.wg_listen,
        wg_private_key: cli.wg_private_key,
        wg_clients: cli.wg_client,
        enable_port_mapping: cli.enable_port_mapping,
    };

    if cli.relay_only {
        let mut cfg = cfg;
        cfg.virtual_ip = None;
        let inst = vnet_core::Instance::new(cfg);
        tracing::info!("relay-only mode");
        inst.start_relay().await?;
        return Ok(());
    }

    let inst = vnet_core::Instance::new(cfg);
    tokio::select! {
        r = inst.start() => { r?; }
        _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); }
    }
    Ok(())
}
