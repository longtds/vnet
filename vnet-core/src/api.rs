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
    listen_addrs: Vec<String>,
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
        listen_addrs: id.listen_addrs.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NodeView 序列化应包含 listen_addrs 字段, 但不应包含 network_secret
    #[test]
    fn node_view_serialization_contains_listen_addrs() {
        let view = NodeView {
            peer_id: 1234567890,
            hostname: "testhost".into(),
            virtual_ip: "10.144.144.1".into(),
            network_name: "testnet".into(),
            udp_mapped_addr: Some("1.2.3.4:54321".into()),
            mapped_addrs: vec!["tcp://0.0.0.0:11010".into()],
            listen_addrs: vec![
                "tcp://0.0.0.0:11010".into(),
                "udp://0.0.0.0:11010".into(),
                "quic://0.0.0.0:11012".into(),
            ],
            relay_mode: false,
        };
        let json = serde_json::to_string(&view).unwrap();
        // listen_addrs 存在且包含 3 个地址
        assert!(json.contains("listen_addrs"), "listen_addrs 应在 JSON 中");
        assert!(json.contains("tcp://0.0.0.0:11010"));
        assert!(json.contains("quic://0.0.0.0:11012"));
        // network_secret 不应出现在 NodeView 中
        assert!(!json.contains("network_secret"), "secret 不应暴露");
        // 其他关键字段
        assert!(json.contains("\"peer_id\":1234567890"));
        assert!(json.contains("\"relay_mode\":false"));
        assert!(json.contains("\"udp_mapped_addr\":\"1.2.3.4:54321\""));
    }

    /// relay_mode=true, udp_mapped_addr=null 等边界值序列化正确
    #[test]
    fn node_view_serialization_edge_cases() {
        let view = NodeView {
            peer_id: 0,
            hostname: String::new(),
            virtual_ip: String::new(),
            network_name: String::new(),
            udp_mapped_addr: None,
            mapped_addrs: vec![],
            listen_addrs: vec![],
            relay_mode: true,
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("\"udp_mapped_addr\":null"));
        assert!(json.contains("\"relay_mode\":true"));
        assert!(json.contains("\"listen_addrs\":[]"));
    }

    /// INDEX_HTML 必须包含加入网络命令生成器的所有关键元素
    #[test]
    fn index_html_contains_join_form_elements() {
        // 元素 ID
        for id in [
            "j-secret", "j-hub", "j-vip", "j-proto", "j-cmd", "j-copy",
        ] {
            assert!(
                INDEX_HTML.contains(&format!("id=\"{}\"", id)),
                "INDEX_HTML 应包含元素 #{}",
                id
            );
        }
        // 函数名
        for func in [
            "generateJoinCmd", "copyCmd", "parseProtos", "refreshJoinForm",
        ] {
            assert!(
                INDEX_HTML.contains(func),
                "INDEX_HTML 应包含函数 {}",
                func
            );
        }
    }

    /// INDEX_HTML 必须包含基础表格和已有元素, 确保重构未破坏
    #[test]
    fn index_html_contains_existing_elements() {
        for id in ["node", "peers", "routes"] {
            assert!(
                INDEX_HTML.contains(&format!("id=\"{}\"", id)),
                "INDEX_HTML 应包含 #{}",
                id
            );
        }
        assert!(INDEX_HTML.contains("<title>vnet 管理</title>"));
        assert!(INDEX_HTML.contains("vnet 节点状态"));
        assert!(INDEX_HTML.contains("Peers"));
        assert!(INDEX_HTML.contains("路由"));
    }

    /// 安全: HTML 中不应暴露 network_secret, secret 应由用户手动输入
    #[test]
    fn index_html_does_not_expose_secret() {
        assert!(
            INDEX_HTML.contains("type=\"password\""),
            "secret 输入框应为 password type"
        );
        assert!(
            INDEX_HTML.contains("手动输入网络密钥"),
            "应提示用户手动输入"
        );
        // HTML 中不应出现任何具体的 network_secret 值
        // (INDEX_HTML 是静态字符串, 不含运行时 secret)
    }

    /// generateJoinCmd 逻辑的 JS 字符串应包含所有协议 scheme
    #[test]
    fn parse_proto_regex_covers_all_schemes() {
        assert!(
            INDEX_HTML.contains(r#"^(tcp|udp|kcp|quic|ws|wss):\/\/"#),
            "parseProtos 正则应覆盖全部 6 种协议"
        );
    }

    /// 直接调用 node handler 测试 (需要构造 ApiState)
    #[tokio::test]
    async fn node_handler_returns_correct_data() {
        use crate::peer::PeerManager;
        use crate::tunnel::handshake::Identity;

        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let (connect_tx, _) = tokio::sync::mpsc::channel(1);
        // Identity 和 PeerManager 必须共享同一个 udp_mapped_addr Arc
        let udp_mapped = Arc::new(parking_lot::RwLock::new(Some("5.6.7.8:12345".into())));
        let mgr = PeerManager::with_udp_mapped_addr(999, inbound_tx, connect_tx, udp_mapped.clone());
        mgr.relay_mode.store(true, std::sync::atomic::Ordering::Relaxed);

        let identity = Identity {
            network_name: "testnet".into(),
            network_secret: "should_not_leak".into(),
            peer_id: 999,
            hostname: "testnode".into(),
            virtual_ip: "10.144.144.42".into(),
            proxy_cidrs: vec![],
            listen_addrs: vec![
                "tcp://0.0.0.0:11010".into(),
                "udp://0.0.0.0:11010".into(),
            ],
            udp_mapped_addr: udp_mapped,
        };

        let state = ApiState { mgr, identity };
        let resp = node(axum::extract::State(state)).await;
        let body = resp.0; // Json<NodeView>

        assert_eq!(body.peer_id, 999);
        assert_eq!(body.hostname, "testnode");
        assert_eq!(body.virtual_ip, "10.144.144.42");
        assert_eq!(body.network_name, "testnet");
        assert_eq!(body.udp_mapped_addr.as_deref(), Some("5.6.7.8:12345"));
        assert_eq!(body.relay_mode, true);
        assert_eq!(body.listen_addrs.len(), 2);
        assert_eq!(body.listen_addrs[0], "tcp://0.0.0.0:11010");
    }

    /// peers handler 在空 PeerManager 上返回空数组
    #[tokio::test]
    async fn peers_handler_empty_manager() {
        use crate::peer::PeerManager;

        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let (connect_tx, _) = tokio::sync::mpsc::channel(1);
        let mgr = PeerManager::new(1, inbound_tx, connect_tx);
        let identity = make_test_identity(1);

        let state = ApiState { mgr, identity };
        let resp = peers(axum::extract::State(state)).await;
        let body = resp.0;
        assert!(body.is_empty(), "空 PeerManager 应返回空 peers 数组");
    }

    /// routes handler 在空 PeerManager 上返回空数组
    #[tokio::test]
    async fn routes_handler_empty_manager() {
        use crate::peer::PeerManager;

        let (inbound_tx, _) = tokio::sync::mpsc::channel(1);
        let (connect_tx, _) = tokio::sync::mpsc::channel(1);
        let mgr = PeerManager::new(1, inbound_tx, connect_tx);
        let identity = make_test_identity(1);

        let state = ApiState { mgr, identity };
        let resp = routes(axum::extract::State(state)).await;
        let body = resp.0;
        assert!(body.is_empty(), "空 PeerManager 应返回空 routes 数组");
    }

    fn make_test_identity(peer_id: u64) -> Identity {
        Identity {
            network_name: "test".into(),
            network_secret: "secret".into(),
            peer_id,
            hostname: "test".into(),
            virtual_ip: "".into(),
            proxy_cidrs: vec![],
            listen_addrs: vec![],
            udp_mapped_addr: Arc::new(parking_lot::RwLock::new(None)),
        }
    }
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
.card{background:#f8f9fa;border-radius:8px;padding:1em;display:inline-block;margin-right:1em;margin-bottom:1em}
.card b{display:block;font-size:1.2em}
.join-box{background:#f8f9fa;border-radius:8px;padding:1.5em;margin-top:1em;border:1px solid #e0e0e0}
.join-box h3{margin-top:0;font-size:1em;color:#444}
.join-row{display:flex;align-items:center;gap:0.5em;margin:0.5em 0;flex-wrap:wrap}
.join-row label{min-width:80px;font-size:0.9em;color:#555}
.join-row input,.join-row select{flex:1;min-width:120px;padding:6px 10px;border:1px solid #ccc;border-radius:4px;font-size:0.9em}
.cmd-preview{background:#1e1e1e;color:#d4d4d4;padding:12px 14px;border-radius:6px;font-family:monospace;font-size:0.85em;white-space:pre-wrap;word-break:break-all;margin:1em 0;line-height:1.6;min-height:1.2em}
.btn-copy{background:#2563eb;color:#fff;border:none;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:0.9em;font-weight:500}
.btn-copy:hover{background:#1d4ed8}
.btn-copy.ok{background:#16a34a}
.btn-copy.err{background:#dc2626}
.tip{font-size:0.8em;color:#888;margin-top:0.5em}
.tip code{background:#eee;padding:2px 6px;border-radius:3px;font-family:monospace}
</style>
</head>
<body>
<h1>vnet 节点状态</h1>
<div id="node"></div>
<h2>Peers</h2>
<table id="peers"><thead><tr><th>peer_id</th><th>主机名</th><th>虚拟 IP</th><th>连接</th><th>协议</th><th>代理子网</th><th>流量</th><th>最后活跃</th></tr></thead><tbody></tbody></table>
<h2>路由</h2>
<table id="routes"><thead><tr><th>目标</th><th>下一跳</th></tr></thead><tbody></tbody></table>
<h2>加入网络</h2>
<div class="join-box">
  <h3>生成加入网络的命令</h3>
  <div class="join-row">
    <label>网络密钥</label>
    <input id="j-secret" type="password" placeholder="手动输入网络密钥 (不可从页面读取)">
  </div>
  <div class="join-row">
    <label>Hub 地址</label>
    <input id="j-hub" placeholder="如 192.168.1.100 或 hub.example.com">
    <select id="j-proto" title="隧道协议"></select>
  </div>
  <div class="join-row">
    <label>虚拟 IP</label>
    <input id="j-vip" placeholder="如 10.144.144.10, 可选">
  </div>
  <div class="cmd-preview" id="j-cmd"></div>
  <div>
    <button class="btn-copy" id="j-copy">拷贝命令</button>
  </div>
  <div class="tip">提示: 命令在本地运行需要 root 权限创建 TUN 设备; Hub 地址是本节点在外部可访问的 IP/域名, 协议从本节点监听列表自动填充</div>
</div>
<script>
let curNode = null; // 缓存当前 node 数据

function fmtB(n){
  if(n<1024) return n+'B';
  if(n<1048576) return (n/1024).toFixed(1)+'K';
  if(n<1073741824) return (n/1048576).toFixed(1)+'M';
  return (n/1073741824).toFixed(2)+'G';
}

// 从 listen_addrs 提取 scheme 和端口, 用于协议下拉框
function parseProtos(addrs){
  const protos = [];
  (addrs||[]).forEach(a=>{
    const m = a.match(/^(tcp|udp|kcp|quic|ws|wss):\/\/([^:]+):(\d+)$/);
    if(m) protos.push({scheme:m[1], host:m[2], port:m[3], raw:a});
  });
  return protos;
}

function refreshJoinForm(){
  const protos = parseProtos(curNode?.listen_addrs);
  const select = document.getElementById('j-proto');
  select.innerHTML = '';
  // 替换 0.0.0.0 为 window.location.hostname
  const host = window.location.hostname || '127.0.0.1';
  const firstHub = document.getElementById('j-hub').value || host;
  let html = '';
  protos.forEach((p,i)=>{
    let displayHost = p.host === '0.0.0.0' ? host : p.host;
    html += `<option value="${p.scheme}://${displayHost}:${p.port}">${p.scheme}://${displayHost}:${p.port}</option>`;
    if(!i) document.getElementById('j-hub').value = firstHub || (p.host === '0.0.0.0' ? host : p.host);
  });
  if(!protos.length){
    html = '<option value="tcp://'+host+':11010">tcp://'+host+':11010</option>';
  }
  select.innerHTML = html;
  // 更新命令预览
  generateJoinCmd();
}

function generateJoinCmd(){
  if(!curNode){ document.getElementById('j-cmd').textContent = '# 等待节点数据...'; return; }
  const secret = document.getElementById('j-secret').value;
  const hub = document.getElementById('j-hub').value.trim();
  const protoOpt = document.getElementById('j-proto').value;
  const vip = document.getElementById('j-vip').value.trim();
  const netName = curNode.network_name || 'default';

  // 从 proto option 提取 host:port
  let peerArg = '';
  if(hub && protoOpt){
    const m = protoOpt.match(/^(tcp|udp|kcp|quic|ws|wss):\/\/([^:]+):(\d+)$/);
    if(m){
      let port = m[3];
      // 如果用户改了 hub 地址, 用新地址替换 scheme 里的 host
      let peerHost = hub;
      peerArg = `-p ${m[1]}://${peerHost}:${port}`;
    } else {
      peerArg = `-p ${protoOpt}`;
    }
  }

  let cmd = 'sudo vnet';
  cmd += ` -n ${netName}`;
  cmd += secret ? ` -s ${secret}` : ' -s <网络密钥>';
  if(vip) cmd += ` -i ${vip}`;
  cmd += ` ${peerArg}`;

  document.getElementById('j-cmd').textContent = cmd;
}

function copyCmd(){
  const text = document.getElementById('j-cmd').textContent;
  const btn = document.getElementById('j-copy');
  if(!text || text.startsWith('#')) return;
  const fallbackCopy = ()=>{
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position='fixed'; ta.style.left='-9999px';
    document.body.appendChild(ta); ta.focus(); ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  };
  const doCopy = async()=>{
    let ok = false;
    try{
      if(navigator.clipboard && window.isSecureContext){
        await navigator.clipboard.writeText(text);
        ok = true;
      } else {
        ok = fallbackCopy();
      }
    } catch(e){ ok = fallbackCopy(); }
    if(ok){ btn.textContent='已拷贝 ✓'; btn.classList.add('ok'); }
    else { btn.textContent='拷贝失败 ✗'; btn.classList.add('err'); }
    setTimeout(()=>{ btn.textContent='拷贝命令'; btn.classList.remove('ok','err'); }, 2000);
  };
  doCopy();
}

async function refresh(){
  let node = {};
  try{ node = await (await fetch('/api/node')).json(); }catch(e){ /* keep old */ }
  curNode = node;
  document.getElementById('node').innerHTML =
    `<div class="card"><b>${node.virtual_ip||'(relay)'}</b>虚拟 IP</div>
     <div class="card"><b>${node.peer_id}</b>Peer ID</div>
     <div class="card"><b>${node.hostname}</b>主机名</div>
     <div class="card"><b>${node.udp_mapped_addr||'-'}</b>UDP 映射地址</div>
     <div class="card"><b>${(node.mapped_addrs||[]).join(', ')||'-'}</b>端口映射</div>
     <div class="card"><b>${node.relay_mode?'中继':'节点'}</b>模式</div>`;
  // 更新协议下拉框 (只在第一次或 listen_addrs 变化时)
  const curProtoSel = document.getElementById('j-proto');
  const oldProtoLen = curProtoSel.options?.length || 0;
  const newProtos = (node.listen_addrs||[]).length;
  if(newProtos && oldProtoLen !== newProtos) refreshJoinForm();

  let peers = [];
  try{ peers = await (await fetch('/api/peers')).json(); }catch(e){}
  document.querySelector('#peers tbody').innerHTML = peers.map(p =>
    `<tr><td>${p.peer_id}</td><td>${p.hostname}</td><td>${p.virtual_ip}</td><td>${p.via}</td><td>${p.proto}</td><td>${p.proxy_cidrs.join(', ')}</td><td>↓${fmtB(p.rx_bytes)} ↑${fmtB(p.tx_bytes)}</td><td>${new Date(p.last_seen*1000).toLocaleTimeString()}</td></tr>`).join('');

  let routes = [];
  try{ routes = await (await fetch('/api/routes')).json(); }catch(e){}
  document.querySelector('#routes tbody').innerHTML = routes.map(r =>
    `<tr><td>${r.dst}</td><td>${r.next_hop}</td></tr>`).join('');
}

// 命令生成器事件绑定
document.getElementById('j-secret').addEventListener('input', generateJoinCmd);
document.getElementById('j-hub').addEventListener('input', generateJoinCmd);
document.getElementById('j-vip').addEventListener('input', generateJoinCmd);
document.getElementById('j-proto').addEventListener('change', generateJoinCmd);
document.getElementById('j-copy').addEventListener('click', copyCmd);

refresh(); setInterval(refresh, 3000);
// 首次刷新后初始化协议下拉框
setTimeout(refreshJoinForm, 500);
</script>
</body>
</html>"#;
