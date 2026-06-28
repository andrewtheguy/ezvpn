//! The IP-over-QUIC tunnel: client and server data planes, datagram framing,
//! offload handling, and the handshake signaling protocol.

pub mod client;
pub mod datagram;
pub mod offload;
pub mod server;
pub mod signaling;

pub use client::VpnClient;
pub use server::VpnServer;
