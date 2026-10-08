//! 常量定义

/// 协议版本
pub const PROTOCOL_VERSION: u32 = 1;

/// 默认监听端口
pub const DEFAULT_PORT: u16 = 11010;

/// 心跳间隔 (秒)
pub const HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// 心跳超时 (秒) - 超过此时间未收到心跳则断开
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 45;

/// 隧道包最大大小
pub const MAX_TUNNEL_PACKET_SIZE: usize = 65535;

/// 加密 nonce 长度 (AES-GCM)
pub const NONCE_LEN: usize = 12;
