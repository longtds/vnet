//! QUIC 隧道: 基于 UDP 的多路复用安全传输, 抗丢包、无队头阻塞

use super::{handshake, stream_tunnel::StreamTunnel, tls_util};
use crate::common::error::{Error, Result};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type QuicTunnel = StreamTunnel<BiStream>;

/// QUIC 双向流包装 (对 StreamTunnel 呈现为单个 AsyncRead+AsyncWrite)
pub struct BiStream {
    send: SendStream,
    recv: RecvStream,
    /// 客户端 endpoint 需与隧道同寿命; 服务端为 None (由 listener 持有)
    _endpoint: Option<Arc<Endpoint>>,
}

impl AsyncRead for BiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

fn transport_config() -> quinn::TransportConfig {
    let mut cfg = quinn::TransportConfig::default();
    cfg.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    cfg.keep_alive_interval(Some(Duration::from_secs(10)));
    cfg
}

/// 从 "host:port" 推导 QUIC SNI: 域名地址用域名 (配合真实证书校验), IP 地址用占位名
fn sni_from_addr(addr: &str) -> &str {
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or("");
    if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
        host
    } else {
        "vnet"
    }
}

pub async fn connect(addr: &str, id: &handshake::Identity) -> Result<(QuicTunnel, handshake::HandshakeResult)> {
    // 支持 IP:port 与域名:port 两种形式
    let sa: SocketAddr = match addr.parse() {
        Ok(sa) => sa,
        Err(_) => tokio::net::lookup_host(addr)
            .await
            .map_err(|e| Error::Config(format!("resolve quic addr {addr}: {e}")))?
            .next()
            .ok_or_else(|| Error::Config(format!("no address resolved for {addr}")))?,
    };
    let sni = sni_from_addr(addr).to_string();

    // 客户端: 跳过证书校验 (自签), 显式 ring provider
    let crypto = tls_util::insecure_client_config()?;
    let mut client_cfg = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| Error::Tunnel(format!("quic crypto: {e}")))?,
    ));
    client_cfg.transport_config(Arc::new(transport_config()));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| Error::Tunnel(format!("quic endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);
    let endpoint = Arc::new(endpoint);

    let connection: Connection = endpoint
        .connect(sa, &sni)
        .map_err(|e| Error::Tunnel(format!("quic connect {addr}: {e}")))?
        .await
        .map_err(|e| Error::Tunnel(format!("quic handshake {addr}: {e}")))?;

    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| Error::Tunnel(format!("quic open_bi: {e}")))?;

    let stream = BiStream {
        send,
        recv,
        _endpoint: Some(endpoint),
    };
    QuicTunnel::handshake_on(stream, addr.to_string(), "quic", id).await
}

pub async fn listener_loop(
    bind: &str,
    id: handshake::Identity,
    on_accept: impl Fn(QuicTunnel, handshake::HandshakeResult, SocketAddr) + Send + Sync + Clone + 'static,
) -> Result<()> {
    let (certs, key) = tls_util::self_signed_cert()?;
    let rustls_server = rustls::ServerConfig::builder_with_provider(tls_util::ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tunnel(format!("rustls versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tunnel(format!("quic server cert: {e}")))?;
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server)
        .map_err(|e| Error::Tunnel(format!("quic server crypto: {e}")))?;
    let mut server_cfg = ServerConfig::with_crypto(Arc::new(quic_server));
    server_cfg.transport_config(Arc::new(transport_config()));

    let endpoint = Endpoint::server(
        server_cfg,
        bind.parse().map_err(|_| Error::Config(format!("bad bind {bind}")))?,
    )
    .map_err(|e| Error::Tunnel(format!("quic bind {bind}: {e}")))?;
    tracing::info!(%bind, "quic listening");

    while let Some(incoming) = endpoint.accept().await {
        let from = incoming.remote_address();
        let id = id.clone();
        let on_accept = on_accept.clone();
        tokio::spawn(async move {
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(%from, ?e, "quic accept failed");
                    return;
                }
            };
            let connection = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(%from, ?e, "quic handshake failed");
                    return;
                }
            };
            let (send, recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(%from, ?e, "quic accept_bi failed");
                    return;
                }
            };
            let stream = BiStream {
                send,
                recv,
                _endpoint: None,
            };
            match QuicTunnel::handshake_on(stream, from.to_string(), "quic", &id).await {
                Ok((tun, hs)) => on_accept(tun, hs, from),
                Err(e) => tracing::warn!(%from, ?e, "quic tunnel handshake failed"),
            }
        });
    }
    Ok(())
}
