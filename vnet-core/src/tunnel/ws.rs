//! WebSocket / WSS 隧道: 可走 443 端口伪装, 穿越严格防火墙/CDN
//!
//! 每条 WS Binary 消息 = 一帧:
//!   握手阶段: 明文 Handshake protobuf
//!   加密阶段: [seq(8B)][AES-GCM ciphertext] (WS 消息天然有边界, 无需长度前缀)

use super::{frame, handshake, tls_util, Tunnel};
use crate::common::error::{Error, Result};
use async_trait::async_trait;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use prost::Message;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{
    accept_async, connect_async_tls_with_config, Connector, WebSocketStream,
};
use vnet_proto::TunnelPacket;

type WsSink<S> = futures::stream::SplitSink<WebSocketStream<S>, WsMessage>;
type WsStreamPart<S> = SplitStream<WebSocketStream<S>>;

/// 写循环指令
enum WriteCmd {
    Frame(Vec<u8>),
    Pong(Vec<u8>),
}

pub struct WsTunnel {
    tx: tokio::sync::mpsc::Sender<WriteCmd>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    remote_addr: String,
    proto_name: &'static str,
}

/// WS 底层 IO 流必须满足的约束 (WebSocketStream<S> 据此实现 Stream/Sink)
pub trait WsIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {}
impl<T> WsIo for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {}

impl WsTunnel {
    /// 主动连接 (ws:// 明文, wss:// TLS)
    ///
    /// `tls_client`: wss 使用的客户端 TLS 配置; None 时跳过证书校验 (兼容自签证书),
    /// 传入 `tls_util::ca_client_config` 结果则启用严格校验
    pub async fn connect(
        url: &str,
        id: &handshake::Identity,
        tls_client: Option<rustls::ClientConfig>,
    ) -> Result<(Self, handshake::HandshakeResult)> {
        if url.starts_with("wss://") {
            let req = url
                .into_client_request()
                .map_err(|e| Error::Config(format!("bad ws url {url}: {e}")))?;
            let crypto = match tls_client {
                Some(c) => c,
                None => tls_util::insecure_client_config()?,
            };
            // 第三个参数 disable_nagle: 小包低延迟必须开启
            let (ws, _) = connect_async_tls_with_config(
                req,
                None,
                true,
                Some(Connector::Rustls(Arc::new(crypto))),
            )
            .await
            .map_err(|e| Error::Tunnel(format!("wss connect {url}: {e}")))?;
            Self::build(ws, url.to_string(), "wss", id).await
        } else {
            let req = url
                .into_client_request()
                .map_err(|e| Error::Config(format!("bad ws url {url}: {e}")))?;
            let (ws, _) = connect_async_tls_with_config(req, None, true, None)
                .await
                .map_err(|e| Error::Tunnel(format!("ws connect {url}: {e}")))?;
            Self::build(ws, url.to_string(), "ws", id).await
        }
    }

    /// 服务端接受已 upgrade 的 WebSocket
    pub async fn accept<S>(
        stream: WebSocketStream<S>,
        addr: String,
        proto_name: &'static str,
        id: &handshake::Identity,
    ) -> Result<(Self, handshake::HandshakeResult)>
    where
        S: WsIo,
    {
        Self::build(stream, addr, proto_name, id).await
    }

    async fn build<S>(
        stream: WebSocketStream<S>,
        remote_addr: String,
        proto_name: &'static str,
        id: &handshake::Identity,
    ) -> Result<(Self, handshake::HandshakeResult)>
    where
        S: WsIo,
    {
        let (mut sink, mut st) = stream.split();

        let (my_pub, my_secret) = crate::crypto::generate_ephemeral_keypair();
        let hello = vnet_proto::Handshake {
            network_name: id.network_name.clone(),
            public_key: my_pub.as_bytes().to_vec(),
            peer_id: id.peer_id,
            hostname: id.hostname.clone(),
            virtual_ip: id.virtual_ip.clone(),
            version: crate::common::constants::PROTOCOL_VERSION,
            proxy_cidrs: id.proxy_cidrs.clone(),
            listen_addrs: id.listen_addrs.clone(),
            udp_mapped_addr: id.udp_mapped_addr.read().clone().unwrap_or_default(),
        };
        sink.send(WsMessage::Binary(hello.encode_to_vec().into()))
            .await
            .map_err(|e| Error::Handshake(format!("send hs: {e}")))?;

        let peer = loop {
            match st.next().await {
                Some(Ok(WsMessage::Binary(b))) => {
                    break <vnet_proto::Handshake as Message>::decode(&b[..])
                        .map_err(|e| Error::Handshake(format!("bad hs: {e}")))?;
                }
                Some(Ok(WsMessage::Ping(p))) => {
                    sink.send(WsMessage::Pong(p)).await.ok();
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(Error::Handshake(format!("recv hs: {e}"))),
                None => return Err(Error::Handshake("ws closed during hs".into())),
            }
        };
        if peer.network_name != id.network_name {
            return Err(Error::Handshake("network mismatch".into()));
        }
        if peer.version != crate::common::constants::PROTOCOL_VERSION {
            return Err(Error::Handshake("version mismatch".into()));
        }
        let peer_pub: [u8; 32] = peer
            .public_key
            .clone()
            .try_into()
            .map_err(|_| Error::Handshake("bad pubkey".into()))?;
        let shared = my_secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_pub));
        let key = crate::crypto::derive_key(shared.as_bytes(), &id.network_secret);
        let cipher = crate::crypto::make_cipher(&key);

        let (tx_in, rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (tx_out, rx_out) = tokio::sync::mpsc::channel::<WriteCmd>(256);
        let dec = frame::FrameReceiver::new(cipher.clone());
        let enc = frame::FrameSender::new(cipher.clone());
        tokio::spawn(ws_read_loop(st, dec, tx_in, tx_out.clone()));
        tokio::spawn(ws_write_loop(sink, enc, rx_out));

        Ok((
            WsTunnel {
                tx: tx_out,
                rx: tokio::sync::Mutex::new(rx_in),
                remote_addr,
                proto_name,
            },
            handshake::HandshakeResult { peer, cipher },
        ))
    }
}

async fn ws_read_loop<S>(
    mut stream: WsStreamPart<S>,
    dec: frame::FrameReceiver,
    tx_in: tokio::sync::mpsc::Sender<Vec<u8>>,
    tx_write: tokio::sync::mpsc::Sender<WriteCmd>,
) where
    S: WsIo,
{
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(WsMessage::Binary(b)) => {
                if let Ok(plain) = dec.decode(&b) {
                    if tx_in.send(plain).await.is_err() {
                        break;
                    }
                }
            }
            Ok(WsMessage::Ping(p)) => {
                let _ = tx_write.send(WriteCmd::Pong(p.to_vec())).await;
            }
            Ok(WsMessage::Pong(_)) | Ok(WsMessage::Text(_)) | Ok(WsMessage::Frame(_)) => {}
            Ok(WsMessage::Close(_)) => break,
            Err(_) => break,
        }
    }
}

async fn ws_write_loop<S>(
    mut sink: WsSink<S>,
    enc: frame::FrameSender,
    mut rx: tokio::sync::mpsc::Receiver<WriteCmd>,
) where
    S: WsIo,
{
    while let Some(cmd) = rx.recv().await {
        let msg = match cmd {
            WriteCmd::Frame(plain) => match enc.encode(&plain) {
                Ok(f) => WsMessage::Binary(f.into()),
                Err(_) => continue,
            },
            WriteCmd::Pong(p) => WsMessage::Pong(p.into()),
        };
        if sink.send(msg).await.is_err() {
            break;
        }
    }
}

#[async_trait]
impl Tunnel for WsTunnel {
    async fn send(&self, pkt: &TunnelPacket) -> Result<()> {
        self.tx
            .send(WriteCmd::Frame(pkt.encode_to_vec()))
            .await
            .map_err(|_| Error::Tunnel("ws send closed".into()))
    }

    async fn recv(&self) -> Result<TunnelPacket> {
        let data = {
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| Error::Tunnel("ws recv closed".into()))?
        };
        TunnelPacket::decode(&data[..]).map_err(|e| Error::Protocol(format!("decode: {e}")))
    }

    fn remote_addr(&self) -> String {
        self.remote_addr.clone()
    }

    fn proto(&self) -> &'static str {
        self.proto_name
    }
}

/// ws/wss 监听器
///
/// `tls`: wss 需要 rustls ServerConfig; ws 传 None
pub async fn listener_loop(
    bind: &str,
    tls: Option<Arc<rustls::ServerConfig>>,
    id: handshake::Identity,
    on_accept: impl Fn(WsTunnel, handshake::HandshakeResult, std::net::SocketAddr)
        + Send
        + Sync
        + Clone
        + 'static,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| Error::Tunnel(format!("ws bind {bind}: {e}")))?;
    let is_wss = tls.is_some();
    tracing::info!(%bind, wss = is_wss, "websocket listening");

    loop {
        let (mut tcp, from) = listener.accept().await?;
        // 小包低延迟: 禁用 Nagle (与对端延迟 ACK 叠加会产生 ~40ms 尖刺)
        let _ = tcp.set_nodelay(true);
        let tls = tls.clone();
        let id = id.clone();
        let on_accept = on_accept.clone();
        tokio::spawn(async move {
            let result: Result<(WsTunnel, handshake::HandshakeResult)> = if let Some(tls) = tls {
                let acceptor = tokio_rustls::TlsAcceptor::from(tls);
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(%from, ?e, "wss tls failed");
                        return;
                    }
                };
                let ws = match accept_async(tls_stream).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        tracing::warn!(%from, ?e, "wss upgrade failed");
                        return;
                    }
                };
                WsTunnel::accept(ws, from.to_string(), "wss", &id).await
            } else {
                let ws = match accept_async(tcp).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        tracing::warn!(%from, ?e, "ws upgrade failed");
                        return;
                    }
                };
                WsTunnel::accept(ws, from.to_string(), "ws", &id).await
            };
            match result {
                Ok((t, hs)) => on_accept(t, hs, from),
                Err(e) => tracing::warn!(%from, ?e, "ws handshake failed"),
            }
        });
    }
}
