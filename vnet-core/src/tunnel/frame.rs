//! 加密帧编解码: 在流/包之上提供加密消息边界

use crate::common::constants::{MAX_TUNNEL_PACKET_SIZE, NONCE_LEN};
use crate::common::error::{Error, Result};
use crate::crypto;
use aes_gcm::Aes256Gcm;
use bytes::{BufMut, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 加密帧发送器: 每帧使用递增 seq 作为 nonce (防重放由 seq 单调保证)
pub struct FrameSender {
    cipher: Aes256Gcm,
    seq: AtomicU64,
}

impl FrameSender {
    pub fn new(cipher: Aes256Gcm) -> Self {
        Self {
            cipher,
            seq: AtomicU64::new(0),
        }
    }

    /// 加密并编码一帧: [seq(8B)][ciphertext]
    pub fn encode(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; NONCE_LEN];
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let ct = crypto::encrypt(&self.cipher, &nonce, plaintext)
            .ok_or_else(|| Error::Crypto("encrypt failed".into()))?;
        let mut out = Vec::with_capacity(8 + ct.len());
        out.put_u64(seq);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

/// 加密帧接收器
pub struct FrameReceiver {
    cipher: Aes256Gcm,
}

impl FrameReceiver {
    pub fn new(cipher: Aes256Gcm) -> Self {
        Self { cipher }
    }

    /// 解码一帧
    pub fn decode(&self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 8 {
            return Err(Error::Protocol("frame too short".into()));
        }
        let seq = u64::from_be_bytes(frame[..8].try_into().unwrap());
        let mut nonce = [0u8; NONCE_LEN];
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        crypto::decrypt(&self.cipher, &nonce, &frame[8..])
            .ok_or_else(|| Error::Crypto("decrypt failed".into()))
    }
}

// ========== TCP 流上的长度前缀帧 ==========

/// 从流中读取一帧: [len(4B BE)][payload]
pub async fn read_len_prefixed<R: AsyncRead + Unpin>(r: &mut R) -> Result<BytesMut> {
    let len = r.read_u32().await? as usize;
    if len > MAX_TUNNEL_PACKET_SIZE {
        return Err(Error::Protocol(format!("frame too large: {len}")));
    }
    let mut buf = BytesMut::with_capacity(len);
    buf.resize(len, 0);
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// 向流中写入一帧
pub async fn write_len_prefixed<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    w.write_u32(payload.len() as u32).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}
