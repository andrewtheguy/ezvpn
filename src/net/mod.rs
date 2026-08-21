//! Host networking primitives: the TUN device and packet buffer arenas.

pub mod buffer;
pub mod device;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod local_networks;
