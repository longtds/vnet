//! vnet-core: 异地组网核心库

pub mod api;
pub mod common;
pub mod crypto;
pub mod gateway;
pub mod instance;
pub mod nat;
pub mod peer;
pub mod tunnel;
pub mod tun;
pub mod vpn_portal;

pub use common::config::NodeConfig;
pub use common::error::{Error, Result};
pub use instance::Instance;
