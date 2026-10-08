//! 通用流式隧道: 任何 AsyncRead+AsyncWrite (TCP/KCP/QUIC bi-stream) 都可复用
//!
//! 线上格式: 握手(明文 length-prefixed) -> 加密帧(length-prefixed)

use super::{frame, handshake, Tunnel};
use crate::common::error::{Error, Result};
use async_trait::async_trait;
use prost::Message;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncWrite};
use vnet_proto::TunnelPacket;

pub struct StreamTunnel<S = ()> {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    receiver: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    remote_addr: String,
    proto_name: &'static str,
    _marker: PhantomData<S>,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> StreamTunnel<S> {
    /// 在任意流上执行握手并启动读写循环
    pub async fn handshake_on(
        stream: S,
        remote_addr: String,
        proto_name: &'static str,
        id: &handshake::Identity,
    ) -> Result<(Self, handshake::HandshakeResult)> {
        let mut stream = stream;
        let hs = handshake::do_handshake(&mut stream, id).await?;
        Ok(Self::spawn(stream, remote_addr, proto_name, hs))
    }

    /// 流已在外部完成握手时使用
    pub fn spawn(
        stream: S,
        remote_addr: String,
        proto_name: &'static str,
        hs: handshake::HandshakeResult,
    ) -> (Self, handshake::HandshakeResult) {
        let (read_half, write_half) = tokio::io::split(stream);
        let (tx_in, rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (tx_out, rx_out) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        let receiver = frame::FrameReceiver::new(hs.cipher.clone());
        tokio::spawn(read_loop(read_half, receiver, tx_in));
        let sender = frame::FrameSender::new(hs.cipher.clone());
        tokio::spawn(write_loop(write_half, sender, rx_out));

        let tunnel = StreamTunnel {
            sender: tx_out,
            receiver: tokio::sync::Mutex::new(rx_in),
            remote_addr,
            proto_name,
            _marker: PhantomData,
        };
        (tunnel, hs)
    }
}

#[async_trait]
impl<S: Send + Sync> Tunnel for StreamTunnel<S> {
    async fn send(&self, pkt: &TunnelPacket) -> Result<()> {
        let buf = pkt.encode_to_vec();
        self.sender
            .send(buf)
            .await
            .map_err(|_| Error::Tunnel("send channel closed".into()))
    }

    async fn recv(&self) -> Result<TunnelPacket> {
        let data = {
            let mut rx = self.receiver.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| Error::Tunnel("recv channel closed".into()))?
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

async fn read_loop<R: AsyncRead + Unpin>(
    mut r: R,
    dec: frame::FrameReceiver,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        let frame = frame::read_len_prefixed(&mut r).await?;
        let plain = dec.decode(&frame)?;
        if tx.send(plain).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut w: W,
    enc: frame::FrameSender,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    while let Some(plain) = rx.recv().await {
        let frame = enc.encode(&plain)?;
        frame::write_len_prefixed(&mut w, &frame).await?;
    }
    Ok(())
}
