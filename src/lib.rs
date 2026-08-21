//! ezvpn
//!
//! IP-over-QUIC VPN tunnel via iroh P2P connections.
//! Uses ed25519 client keypairs for access control and TLS 1.3/QUIC for
//! encryption.
//!
//! This is the library crate. The desktop CLI (`src/main.rs`) and the Apple
//! Network Extension FFI (`src/ffi.rs`, built into a `staticlib`) both consume
//! it. Desktop platforms (Linux/macOS/Windows) get the full client/server with
//! TUN creation, routing, single-instance lock, and the control socket. The
//! mobile clients — Apple app extensions (`src/ffi.rs`) and the Android
//! `VpnService` (`src/ffi_android.rs`) — get the portable data plane (iroh
//! connect + handshake + data-stream loop) and drive an OS-provided tun fd;
//! routing and IP configuration are owned by the `NEPacketTunnelProvider` /
//! `VpnService.Builder`, not this crate.

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "ios",
    target_os = "android"
)))]
compile_error!("ezvpn only supports Linux, macOS, Windows, iOS, and Android");

// Re-exported so downstream consumers (the FFI layers, the CLI) can name the
// shared key types without depending on the git crate themselves.
pub use flexaccess_keys;

pub mod auth;
pub mod config;
pub mod error;
pub mod net;
pub mod secret;
pub mod transport;
pub mod tunnel;

// Desktop modules: the single-instance lock and Unix/Windows control socket are
// omitted from the mobile targets (iOS, Android). The gates remain broader on
// macOS because the same library crate also serves the native CLI there.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod control;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod runtime;

// Key helpers shared by the two (target-disjoint) FFI surfaces below. Built
// everywhere so the desktop test run covers it.
pub mod ffi_common;

// fd-based C FFI surface: consumed by the iOS/macOS Network Extension directly,
// and wrapped by the JNI layer below on Android (same lifecycle, same JSON).
#[cfg(any(target_os = "ios", target_os = "macos", target_os = "android"))]
pub mod ffi;

// Android JNI surface consumed by the `ezvpn-android` app's `VpnService`. Thin
// wrapper over `ffi`: the VpnService owns the tun interface and routes, exactly
// like the Apple provider, and hands over the fd.
#[cfg(target_os = "android")]
pub mod ffi_android;

// Windows C FFI surface consumed by the native Windows GUI (`ezvpn-windows`),
// P/Invoked from .NET. Wraps the desktop `VpnClient` (which owns the wintun
// adapter and routing table), unlike the fd-based Apple `ffi` module.
#[cfg(target_os = "windows")]
pub mod ffi_windows;
