//! Slim iOS connect path.
//!
//! iOS VPNs run inside a `NEPacketTunnelProvider` app extension. Unlike the
//! desktop [`crate::tunnel::client::VpnClient`], this path:
//!
//! - does **not** create a `utun` or configure routes/IP/MTU — the extension
//!   owns that via `NEPacketTunnelNetworkSettings`, then hands us the tunnel's
//!   `utun` fd;
//! - does **not** install underlay-bypass routes — the iOS MVP is an IPv4
//!   **private** split tunnel, so the iroh underlay (server public address +
//!   relays) never falls inside a routed prefix and cannot self-capture;
//! - does **not** take the single-instance lock or open a control socket.
//!
//! It reuses the portable data plane wholesale: the same handshake
//! ([`crate::tunnel::client::perform_handshake`]) and datagram loop
//! ([`crate::tunnel::client::run_tunnel`]).
//!
//! The flow is two-phase because the extension needs the server-assigned IPv4
//! address and MTU to build its network settings *before* it can produce the
//! `utun` fd:
//!
//! 1. [`IosSession::connect`] — create an iroh endpoint, connect, handshake.
//! 2. read [`IosSession::network_config`], apply it as
//!    `NEPacketTunnelNetworkSettings`, obtain the `utun` fd.
//! 3. [`IosSession::run`] — drive the tunnel over that fd until it ends.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::sync::Arc;

use ipnet::Ipv4Net;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;

use crate::error::{VpnError, VpnResult};
use crate::net::device::TunDevice;
use crate::transport::endpoint::create_client_endpoint;
use crate::tunnel::client::{
    ServerInfo, collect_local_iroh_udp_ports, perform_handshake, run_tunnel,
};

/// Connection parameters supplied by the iOS app (built from the FFI JSON).
#[derive(Debug, Clone)]
pub struct IosConfig {
    /// Server's iroh endpoint id (node id), as a string.
    pub server_node_id: String,
    /// Pre-built ALPN value (`ezvpn/<ver>/<token>`).
    pub alpn: Vec<u8>,
    /// Optional ezvpn auth token.
    pub auth_token: Option<String>,
    /// Relay URL hints. When empty, iroh uses its default relay map.
    pub relay_urls: Vec<String>,
    /// Force relay-only transport (skip hole punching). Usually false.
    pub relay_only: bool,
}

/// The IPv4 parameters the extension needs for `NEPacketTunnelNetworkSettings`.
#[derive(Debug, Clone, Copy)]
pub struct IosNetworkConfig {
    /// Assigned client VPN address.
    pub assigned_ip: Ipv4Addr,
    /// Subnet mask for the assigned address.
    pub netmask: Ipv4Addr,
    /// VPN gateway (server's in-subnet address).
    pub gateway: Ipv4Addr,
    /// Server-dictated tunnel MTU.
    pub mtu: u16,
}

/// A connected, handshaked-but-not-yet-running iOS tunnel session.
pub struct IosSession {
    endpoint: Endpoint,
    connection: Connection,
    server_info: ServerInfo,
}

impl IosSession {
    /// Create an iroh endpoint, connect to the server, and perform the
    /// handshake. The endpoint identity is ephemeral (a fresh key per session),
    /// so the server may assign a different IP on each connect — acceptable for
    /// the MVP.
    pub async fn connect(cfg: &IosConfig) -> VpnResult<Self> {
        let endpoint = create_client_endpoint(&cfg.relay_urls, cfg.relay_only, None, None)
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to create iroh endpoint: {e}")))?;

        let server_id: EndpointId = cfg
            .server_node_id
            .parse()
            .map_err(|e| VpnError::config_with_source("Invalid server node ID", e))?;

        let mut addr = EndpointAddr::new(server_id);
        for relay in &cfg.relay_urls {
            let url: RelayUrl = relay
                .parse()
                .map_err(|e| VpnError::config_with_source(format!("Invalid relay URL: {relay}"), e))?;
            addr = addr.with_relay_url(url);
        }

        let connection = endpoint
            .connect(addr, cfg.alpn.as_slice())
            .await
            .map_err(|e| VpnError::Signaling(format!("Failed to connect to server: {e}")))?;

        // Random per-session id, like the desktop client. The server keys IP
        // allocation by (endpoint id, device id).
        let device_id: u64 = rand::rng().random();
        let server_info =
            perform_handshake(&connection, device_id, cfg.auth_token.as_deref()).await?;

        // The MVP is IPv4-only split tunnel; require an IPv4 assignment.
        if server_info.assigned_ip.is_none() {
            return Err(VpnError::Signaling(
                "iOS MVP requires an IPv4 assignment, but the server returned none \
                 (IPv6-only server?)"
                    .into(),
            ));
        }

        log::info!(
            "iOS handshake OK: ip={:?} net={:?} gw={:?} mtu={}",
            server_info.assigned_ip,
            server_info.network,
            server_info.server_ip,
            server_info.mtu
        );

        Ok(Self {
            endpoint,
            connection,
            server_info,
        })
    }

    /// The IPv4 network parameters for the extension's tunnel settings.
    pub fn network_config(&self) -> VpnResult<IosNetworkConfig> {
        let assigned_ip = self
            .server_info
            .assigned_ip
            .ok_or_else(|| VpnError::Signaling("missing assigned IPv4".into()))?;
        let network: Ipv4Net = self
            .server_info
            .network
            .ok_or_else(|| VpnError::Signaling("missing IPv4 network".into()))?;
        let gateway = self
            .server_info
            .server_ip
            .ok_or_else(|| VpnError::Signaling("missing IPv4 gateway".into()))?;
        Ok(IosNetworkConfig {
            assigned_ip,
            netmask: network.netmask(),
            gateway,
            mtu: self.server_info.mtu,
        })
    }

    /// Drive the tunnel over the extension-provided `utun` fd until it ends
    /// (peer close, idle timeout, or a fatal I/O error). Consumes the session.
    ///
    /// No bypass-route manager and no server-address publisher channel: a
    /// private split tunnel needs neither (see module docs), so both
    /// `run_tunnel` hooks are passed as `None`.
    pub async fn run(self, tun_fd: RawFd) -> VpnResult<()> {
        let tun = TunDevice::from_raw_fd(tun_fd, self.server_info.mtu)?;

        let max_datagram_size = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| VpnError::Signaling("Peer does not support QUIC datagrams".into()))?;

        let local_iroh_udp_ports: Arc<HashSet<u16>> =
            Arc::new(collect_local_iroh_udp_ports(&self.endpoint));

        run_tunnel(
            tun,
            self.connection,
            self.server_info.server_gso_enabled,
            max_datagram_size,
            None,
            None,
            local_iroh_udp_ports,
        )
        .await
    }

    /// Close the iroh endpoint, tearing down the connection. Used when the app
    /// stops the tunnel before [`Self::run`] (or to force teardown).
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}
