//! vnet 协议定义 (由 prost 从 proto/vnet.proto 生成)

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/vnet.rs"));
}

pub use pb::*;
