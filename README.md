# vnet

用 Rust 编写的异地组网（mesh VPN）工具，[EasyTier](https://github.com/EasyTier/EasyTier) 同类产品。节点间自动建立加密隧道、互相发现、NAT 打洞、必要时经中继转发，并支持子网代理与 WireGuard 门户接入。

- **Rust** 2021 / MSRV 1.85，tokio 异步运行时，无自定义 unsafe 网络代码
- 双二进制：`vnet`（守护进程）、`vnet-cli`（管理命令行）
- 许可证：LGPL-3.0

## 功能特性

- **多协议加密隧道**：`tcp://` `udp://` `kcp://` `quic://` `ws://` `wss://`，同一套握手与加解密抽象（`Tunnel` trait），节点可同时监听多种协议
- **自动组网**：基于 gossip 的 Peer 发现与路由传播，只需配置一个初始 peer 即可自动学习全网拓扑
- **NAT 穿透**：STUN 探测映射地址 + UDP 打洞直连；打洞不通时自动走中继多跳转发；可选 UPnP / NAT-PMP 自动端口映射
- **自动重连**：连接断开后按 30s 周期重试，同 peer_id 重连自动替换旧隧道
- **子网代理**：节点可把本地物理子网（`--proxy-cidr`）发布到虚拟网络，供其他节点访问
- **WireGuard 门户**：内置 boringtun 用户态 WG 实现，手机/电脑原生 WG 客户端可直接接入
- **管理面**：内置 HTTP API（`/api/node` `/api/peers` `/api/routes`）+ Web 仪表盘 + `vnet-cli`
- **安全**：每条隧道 X25519 ECDH 协商会话密钥，HKDF 结合网络密钥派生，AES-256-GCM 加密

## 仓库结构

```
vnet-proto/          protobuf 定义 (prost 0.13 生成), build.rs 编译 proto
  proto/vnet.proto   唯一消息定义源: Handshake / TunnelPacket / ControlPacket
vnet-core/           核心库
  src/instance.rs    节点生命周期: 组装 TUN/隧道/PeerManager, 连接调度, 重连
  src/common/        NodeConfig, Error/Result, 常量
  src/tun/           TUN 设备读写, IP 包解析
  src/tunnel/        Tunnel trait + 各协议实现
    handshake.rs     X25519 ECDH + AES-GCM 会话密钥派生 + Identity
    stream_tunnel.rs 流式隧道通用实现 (TCP/KCP/QUIC/WS 复用)
    tcp.rs udp.rs kcp.rs quic.rs ws.rs   各协议 connect/listener
    udp_demux.rs     UDP socket 复用 (打洞 + 数据 + 握手 + STUN 共用一个源端口)
    tls_util.rs      rustls 配置 (ring provider, 自签/CA 校验)
  src/peer/          PeerManager (DashMap), 路由表, gossip 发现, keepalive
  src/nat/           stun.rs, punch.rs (UDP 打洞), portmap.rs (UPnP/NAT-PMP)
  src/crypto/        临时密钥对, HKDF 派生, AES-256-GCM
  src/api.rs         axum 管理 API + 内嵌 Web UI
  src/gateway.rs     子网代理的系统转发检查提示
  src/vpn_portal.rs  WireGuard 门户 (boringtun 用户态实现)
  tests/             tunnel_test.rs (5 协议 echo), wg_portal_test.rs
vnet/                可执行入口
  src/main.rs        clap 参数定义 -> NodeConfig -> Instance (vnet 守护进程)
  src/cli.rs         vnet-cli: node/peer/route/status/wg-key 子命令
vagrant/             Vagrant + KVM 三节点集群与测试脚本
```

## 数据通路

```
应用 -> TUN 读 IP 包 -> PeerManager.send_data_to/forward_data
     -> TunnelPacket{from,to,type,payload} -> AES-GCM 加密
     -> tcp/udp/kcp/quic/ws 任一隧道 -> 对端解密
     -> 按 payload 目标 IP 判断: 本机 vip 或本机 proxy_cidrs -> 写 TUN
                                 否则查路由表多跳转发
```

关键设计：DATA 包归属只按 payload 目标 IP 判断（不信任 `to_peer`，多跳时它是下一跳而非最终目的地）。

## 构建

依赖 Rust 1.85+（需联网拉取 crates）：

```bash
# 调试构建
cargo build --workspace

# 发布构建: LTO + codegen-units=1 + panic=abort + strip
cargo build --release --workspace
```

产物：`target/release/vnet`、`target/release/vnet-cli`。

Linux 上运行守护进程需要创建 TUN 设备的权限（root 或 `CAP_NET_ADMIN`）。

## 快速开始

三节点最小组网（一台公网 hub + 两台内网节点）：

```bash
# hub (公网机器, 多协议监听)
sudo vnet -n mynet -s mysecret -i 10.144.144.2 \
  -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010 \
  -l kcp://0.0.0.0:11011 -l quic://0.0.0.0:11012 \
  -l ws://0.0.0.0:11013

# node1 (任意一台机器, 初始 peer 指向 hub)
sudo vnet -n mynet -s mysecret -i 10.144.144.1 \
  -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010 \
  -p tcp://<hub公网IP>:11010

# node3 (用 quic 接入; 启动后经 gossip 自动发现 node1 并尝试 UDP 打洞)
sudo vnet -n mynet -s mysecret -i 10.144.144.3 \
  -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010 \
  -p quic://<hub公网IP>:11012
```

同一网络的节点 `-n`（网络名）和 `-s`（网络密钥）必须一致。组网后：

```bash
ping 10.144.144.3
vnet-cli peer          # 查看已连接 peer (协议/地址/流量)
vnet-cli route         # 查看路由表
vnet-cli status        # 节点 + peer + 路由汇总
```

纯中继节点（无 TUN、不占虚拟 IP，仅转发）：

```bash
vnet --relay-only -n mynet -s mysecret \
  -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010
```

子网代理（把本机所在的 `10.1.1.0/24` 发布到虚拟网络）：

```bash
sudo vnet -n mynet -s mysecret -i 10.144.144.1 \
  -p tcp://hub.example:11010 --proxy-cidr 10.1.1.0/24
```

## 守护进程参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-n, --network-name` | 网络名称，同一组网必须一致 | `default` |
| `-s, --network-secret` | 网络密钥，用于派生 peer_id 和加密 | 空 |
| `-i, --virtual-ip` | 本机虚拟 IP（如 `10.144.144.1`）；中继模式不填 | — |
| `-l, --listen` | 监听地址，可重复；支持 tcp/udp/kcp/quic/ws/wss | tcp+udp `:11010` |
| `-p, --peer` | 初始对端地址，可重复，scheme 同 `--listen` | — |
| `--proxy-cidr` | 代理子网（CIDR），可重复 | — |
| `--tun-name` | TUN 设备名 | `vnet0` |
| `--mtu` | TUN MTU | `1380` |
| `--stun-server` | STUN 服务器（NAT 打洞用） | `stun.l.google.com:19302` |
| `--admin-port` | 管理 API / Web UI 端口 | `22020` |
| `--relay-only` | 仅中继模式，不创建 TUN | 关 |
| `--tls-cert` / `--tls-key` | WSS 监听器证书/私钥 PEM | — |
| `--tls-ca` | 连接 wss:// 时校验服务端证书的 CA；不设则兼容自签 | — |
| `--wg-listen` | WireGuard 门户监听地址 | — |
| `--wg-private-key` | WG 门户服务器私钥（base64，`vnet-cli wg-key` 生成） | — |
| `--wg-client` | WG 客户端 `name=虚拟IP=base64公钥`，可重复 | — |
| `--enable-port-mapping` | 启用 UPnP / NAT-PMP 自动端口映射 | 关 |

环境变量 `RUST_LOG` 控制日志级别（如 `RUST_LOG=debug`）。

## 协议与握手

- 所有隧道共用同一握手：X25519 ECDH → 结合 `network_secret` 做 HKDF → AES-256-GCM 会话密钥
- 握手为明文交换公钥与身份（网络名/peer_id/虚拟 IP/监听地址/STUN 映射地址），之后数据全部加密
- 地址统一用 URL scheme：`tcp://` `udp://` `kcp://` `quic://` `ws://` `wss://`
- 域名地址：tcp 走系统解析；kcp/udp 经 tokio `lookup_host`；QUIC SNI 从地址推导

### NAT 打洞流程

1. 节点启动时（有 UDP 监听）同步向 STUN 查询外网映射地址，写入握手与 gossip 消息
2. gossip 互相传播 `udp_mapped_addr`；发现新 peer 且双方都有映射地址时触发打洞
3. 双方同时向对方映射地址发起 `udp://` 连接（完整加密握手），洞开后直连建立
4. 打洞失败的流量仍可经已有 peer 多跳中继，不影响连通性

## WireGuard 门户

让原生 WG 客户端作为普通 peer 接入虚拟网络：

```bash
# 1. 生成密钥
vnet-cli wg-key

# 2. 启动门户 (11013/UDP), 注册一个手机客户端
sudo vnet -n mynet -s mysecret -i 10.144.144.1 \
  -l tcp://0.0.0.0:11010 -p tcp://hub.example:11010 \
  --wg-listen 0.0.0.0:11013 --wg-private-key <门户私钥base64> \
  --wg-client phone=10.144.144.10=<客户端公钥base64>
```

手机 WG App 中配置：端点指向 `服务器IP:11013`，peer 公钥填门户公钥，AllowedIPs 含 `10.144.144.0/24`。

## 管理 API 与 Web UI

启动后访问 `http://127.0.0.1:22020`（云主机用 `--admin-port` 指定的端口）：

- `GET /` — Web 仪表盘（节点信息、peer 列表、路由表）
- `GET /api/node` — 本节点信息（peer_id、虚拟 IP、STUN 映射、端口映射结果、中继模式）
- `GET /api/peers` — peer 列表（协议、远端地址、rx/tx 字节数、代理子网）
- `GET /api/routes` — 路由表（目标 IP/CIDR → 下一跳 peer_id）

CLI 默认连接 `http://127.0.0.1:22020`，远程节点用 `vnet-cli --admin http://<ip>:<port> status`。

## 测试

```bash
# 单元 + 集成测试 (5 协议 echo、WG 门户等)
cargo test --workspace

# 只做编译检查 (含 tests/examples)
cargo build --workspace --all-targets
```

VM 集群测试（Vagrant + vagrant-libvirt + KVM，3 台 Ubuntu 24.04：node1/node2/node3 = 192.168.56.11/12/13，虚拟 IP 10.144.144.1/2/3，node2 为 hub）：

```bash
cd vagrant
vagrant up                 # 首次启动
vagrant rsync              # 重新同步 target/debug (软链按实体传输)
bash e2e-test.sh           # 功能 E2E: 直连/多跳中继/协议切换重连
bash perf-test.sh          # iperf3 性能: 基线 + 各协议直连 + 多跳
```

测试纪律：启动新集群前先在所有节点 `pkill -x vnet`，并用 `pgrep -ax vnet`、`ss -tuln | grep 1101` 确认零残留。

## 性能基线

release 构建，3×512MB 单核 VM 局域网（物理基线 ≈ 16 Gbps）：

| 路径 | 吞吐 |
|---|---|
| quic / ws 直连 | ≈ 400 Mbps |
| tcp 直连 / 多跳中继 | ≈ 300 Mbps |
| kcp 直连 | ≈ 230 Mbps |

跨公网实测（云主机中继 + 家用宽带两侧 VM）：NAT 打洞成功后 node↔node UDP 直连 RTT 约 10 ms，对比经公网 hub 中继约 440 ms，iperf3 约 85–95 Mbps（瓶颈在物理上行带宽，vnet 开销极小）。

## 开发约定

- 注释与提交信息使用中文；错误统一走 `common/error.rs` 的 `Error/Result`，库内不直接 panic
- 修改 `vnet-proto/proto/vnet.proto` 后无需手动生成代码（`build.rs` 构建时处理）；新增字段用新 tag 号保持向后兼容
- parking_lot 锁守卫不要跨 `.await` 持有
- 新增传输协议：实现 `Tunnel` trait 并复用 `handshake::do_handshake`（流式协议套 `StreamTunnel::handshake_on`），在 `instance::connect_peer` 注册 scheme 分发
