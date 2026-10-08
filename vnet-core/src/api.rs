//! 管理 API: axum HTTP 服务, 提供 peers/routes/node/status 查询

use crate::peer::PeerManager;
use crate::tunnel::handshake::Identity;
use axum::{extract::State, response::Html, routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;

#[derive(Clone)]
struct ApiState {
    mgr: Arc<PeerManager>,
    identity: Identity,
}

#[derive(Serialize)]
struct PeerView {
    peer_id: u64,
    hostname: String,
    virtual_ip: String,
    via: String,
    proto: String,
    last_seen: i64,
    proxy_cidrs: Vec<String>,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Serialize)]
struct NodeView {
    peer_id: u64,
    hostname: String,
    virtual_ip: String,
    network_name: String,
    udp_mapped_addr: Option<String>,
    mapped_addrs: Vec<String>,
    relay_mode: bool,
}

/// 启动管理 API 服务 (后台任务)
pub fn start_api(port: u16, mgr: Arc<PeerManager>, identity: Identity) {
    let state = ApiState { mgr, identity };
    let app = Router::new()
        .route("/", get(index))
        .route("/api/node", get(node))
        .route("/api/peers", get(peers))
        .route("/api/routes", get(routes))
        .with_state(state);
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(?e, %port, "admin api bind failed");
                return;
            }
        };
        tracing::info!(%port, "admin api listening");
        let _ = axum::serve(listener, app).await;
    });
}

async fn node(State(s): State<ApiState>) -> Json<NodeView> {
    let id = &s.identity;
    Json(NodeView {
        peer_id: id.peer_id,
        hostname: id.hostname.clone(),
        virtual_ip: id.virtual_ip.clone(),
        network_name: id.network_name.clone(),
        udp_mapped_addr: s.mgr.my_udp_mapped_addr.read().clone(),
        mapped_addrs: s.mgr.mapped_addrs.read().clone(),
        relay_mode: s.mgr.relay_mode.load(std::sync::atomic::Ordering::Relaxed),
    })
}

async fn peers(State(s): State<ApiState>) -> Json<Vec<PeerView>> {
    let mut out = Vec::new();
    for pid in s.mgr.peer_ids() {
        if let Some(h) = s.mgr.get_peer(pid) {
            out.push(PeerView {
                peer_id: h.info.peer_id,
                hostname: h.info.hostname.clone(),
                virtual_ip: h.info.virtual_ip.clone(),
                via: h.via.clone(),
                proto: h.tunnel.proto().to_string(),
                last_seen: *h.last_seen.lock(),
                proxy_cidrs: h.info.proxy_cidrs.clone(),
                tx_bytes: h.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
                rx_bytes: h.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
            });
        }
    }
    Json(out)
}

#[derive(Serialize)]
struct RouteView {
    dst: String,
    next_hop: u64,
}

async fn routes(State(s): State<ApiState>) -> Json<Vec<RouteView>> {
    let mut out = Vec::new();
    for (dst, nh) in s.mgr.dump_routes() {
        out.push(RouteView { dst, next_hop: nh });
    }
    Json(out)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>vnet 管理</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#222}
h1{font-size:1.4em} h2{font-size:1.1em;margin-top:2em}
table{border-collapse:collapse;width:100%;font-size:0.9em}
th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}
th{background:#f5f5f5}
.card{background:#f8f9fa;border-radius:8px;padding:1em;display:inline-block;margin-right:1em}
.card b{display:block;font-size:1.2em}
</style>
</head>
<body>
<h1>vnet 节点状态</h1>
<div id="node"></div>
<h2>Peers</h2>
<table id="peers"><thead><tr><th>peer_id</th><th>主机名</th><th>虚拟 IP</th><th>连接</th><th>协议</th><th>代理子网</th><th>流量</th><th>最后活跃</th></tr></thead><tbody></tbody></table>
<h2>路由</h2>
<table id="routes"><thead><tr><th>目标</th><th>下一跳</th></tr></thead><tbody></tbody></table>
<script>
function fmtB(n){
  if(n<1024) return n+'B';
  if(n<1048576) return (n/1024).toFixed(1)+'K';
  if(n<1073741824) return (n/1048576).toFixed(1)+'M';
  return (n/1073741824).toFixed(2)+'G';
}
async function refresh(){
  const node = await (await fetch('/api/node')).json();
  document.getElementById('node').innerHTML =
    `<div class="card"><b>${node.virtual_ip||'(relay)'}</b>虚拟 IP</div>
     <div class="card"><b>${node.peer_id}</b>Peer ID</div>
     <div class="card"><b>${node.hostname}</b>主机名</div>
     <div class="card"><b>${node.udp_mapped_addr||'-'}</b>UDP 映射地址</div>
     <div class="card"><b>${(node.mapped_addrs||[]).join(', ')||'-'}</b>端口映射</div>
     <div class="card"><b>${node.relay_mode?'中继':'节点'}</b>模式</div>`;
  const peers = await (await fetch('/api/peers')).json();
  document.querySelector('#peers tbody').innerHTML = peers.map(p =>
    `<tr><td>${p.peer_id}</td><td>${p.hostname}</td><td>${p.virtual_ip}</td><td>${p.via}</td><td>${p.proto}</td><td>${p.proxy_cidrs.join(', ')}</td><td>↓${fmtB(p.rx_bytes)} ↑${fmtB(p.tx_bytes)}</td><td>${new Date(p.last_seen*1000).toLocaleTimeString()}</td></tr>`).join('');
  const routes = await (await fetch('/api/routes')).json();
  document.querySelector('#routes tbody').innerHTML = routes.map(r =>
    `<tr><td>${r.dst}</td><td>${r.next_hop}</td></tr>`).join('');
}
refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>"#;
