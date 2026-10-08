//! 统一错误类型

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tun device error: {0}")]
    Tun(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("peer not found: {0}")]
    PeerNotFound(u64),

    #[error("route not found for: {0}")]
    NoRoute(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
