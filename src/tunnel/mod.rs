//! The IP-over-QUIC tunnel: client and server data planes, stream framing,
//! offload handling, and the handshake signaling protocol.

pub mod client;
pub mod dns_proxy;
pub mod offload;
pub mod signaling;
pub mod stream;

// The server data plane creates a TUN, manages an IP pool, and routes between
// clients — none of which a mobile client (iOS extension, Android VpnService)
// does. Desktop-only.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod server;

// The slim mobile connect path: drives an OS-provided tun fd, with routing and
// interface configuration owned by the iOS/macOS app extension or the Android
// VpnService.
#[cfg(any(target_os = "ios", target_os = "macos", target_os = "android"))]
pub mod mobile;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub use client::VpnClient;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub use server::VpnServer;
