# iOS App (Proof of Concept)

`ezvpn` can run on iOS as a Network Extension. This is a **proof of concept**:
it tunnels real traffic on a physical device, but it is intentionally scoped and
not prepared for App Store distribution.

The iOS client is split across two repositories:

- **This repo (`ezvpn`)** — the Rust core, compiled into a static library
  (`libezvpn.a`) plus a small C FFI. This is where the iOS-specific Rust code
  and the build script live.
- **[`ezvpn-ios`](https://github.com/andrewtheguy/ezvpn-ios)** — the Swift Xcode
  project: a SwiftUI container app and the `NEPacketTunnelProvider` app
  extension that links `libezvpn.a`. Build/sign/run instructions live in that
  repo's README.

## Scope

In scope:

- **Dual-stack split tunnel** — IPv4, IPv6, or both, to explicit routed
  prefixes. Both route lists are optional and independent.
- **Optional underlay bypass** — automatically carves the few server underlay
  addresses that overlap a routed prefix back out of the tunnel (see below).
- **Real-device testing** — a Packet Tunnel Provider does not run in the iOS
  Simulator.

Out of scope (by design):

- **Full tunnel** (`0.0.0.0/0` / `::/0`) — never offered on iOS.
- **App Store / TestFlight** preparation, persistent identity, and background
  reconnect polish. The iroh identity is ephemeral per session, so the server
  may assign a different VPN IP on each connect.

## How it reuses the core

The iOS data plane is the **same** portable code the desktop client uses. iOS
only differs in who owns the tunnel device and the routing table:

| Concern | Desktop | iOS |
|---|---|---|
| TUN device | created by `ezvpn` (`TunDevice::create`) | created by the OS; `ezvpn` wraps the handed-over fd (`TunDevice::from_raw_fd`) |
| Routing / IP / MTU | `ip`/`route`/`netsh` | `NEPacketTunnelNetworkSettings` (extension) |
| Underlay bypass | `BypassRouteManager` host routes | `NEIPv4Settings`/`NEIPv6Settings` `excludedRoutes` |
| Single-instance lock, control socket | yes | not used (the OS owns the extension lifecycle) |

The macOS `utun` fast path (4-byte address-family-prefixed frames) is shared with
iOS via the `target_vendor = "apple"` cfg, so the read/write hot path is
identical. The handshake (`perform_handshake`) and datagram loop (`run_tunnel`)
are used verbatim.

Key source in this repo:

- `src/tunnel/ios.rs` — `IosSession` (connect → handshake → run) and the
  network-config it returns to the extension.
- `src/ffi.rs` — the C entry points.
- `src/net/device.rs` — `TunDevice::from_raw_fd` and the shared Darwin fd I/O.
- `ios/ezvpn.h` — the C header (also the authoritative JSON config/result shapes).
- `build-ios.sh` — builds and stages the library + header.

## C interface

The extension drives the tunnel with three calls (full signatures and JSON
shapes in [`ios/ezvpn.h`](../ios/ezvpn.h)):

1. `ezvpn_connect(config_json, out_buf, out_len)` — create an iroh endpoint,
   connect, handshake. Returns an opaque handle and writes the assigned network
   config (IPv4 and/or IPv6 addresses, gateway, MTU, and the computed
   `excluded_routes`/`excluded_routes6`) as JSON.
2. `ezvpn_run(handle, utun_fd)` — start the datagram loop on the OS-provided
   `utun` fd (obtained after the extension applies the network settings).
3. `ezvpn_stop(handle)` — tear down and free the handle.

```
EzvpnApp (SwiftUI)            PacketTunnel (NEPacketTunnelProvider)
  installs VPN config  ──VPN──▶  startTunnel:
  start/stop                       ezvpn_connect(json) ──▶ libezvpn.a
                                   setTunnelNetworkSettings   (iroh connect
                                   ezvpn_run(utun_fd) ─────▶   + handshake
                                  stopTunnel: ezvpn_stop        + datagram loop)
```

## Underlay bypass on iOS

Full tunnel is out of scope, so the routed prefixes are private/explicit and the
public iroh underlay (relays, public server addresses) never overlaps them — no
relay-set bypass is needed. The one case that does need handling: the server's
**own underlay address is private and falls inside a routed prefix** (e.g. the
server is on a LAN at `192.168.1.5` and you route `192.168.0.0/16`). Without
intervention iOS would route iroh's own QUIC packets into the tunnel and the
connection would self-capture and stall.

The core computes this automatically and unconditionally: it intersects the
server's handshake-advertised underlay candidate addresses (`server_addrs`,
which include private/LAN/ULA addresses) with the configured routes, and returns
each overlap as a host route (`/32` / `/128`). The extension applies them as
`excludedRoutes`, so the OS keeps those packets on the underlay (Wi-Fi/cellular).
This is the declarative iOS equivalent of the desktop `BypassRouteManager`. Only
the static handshake-time set is used; dynamic mid-session address updates are
not handled.

**Caveat** (same as desktop — see the README "Routing" section and
`docs/ARCHITECTURE.md`): a bypassed server underlay IP is reachable only over the
underlay while connected. To reach the server *through* the tunnel, use its
VPN-internal gateway IP, not the public address that doubles as the transport
endpoint.

## Building

From this repo:

```sh
./build-ios.sh release
```

This builds `libezvpn.a` for `aarch64-apple-ios` and stages it with the header
in `dist/ios/`. If the sibling `../ezvpn-ios` checkout is present, it also syncs
the artifacts into that project's `vendor/`.

Then follow the [`ezvpn-ios`](https://github.com/andrewtheguy/ezvpn-ios) README
to generate the Xcode project, set your signing team, and run on a device. Note
that the Network Extension (`packet-tunnel-provider`) capability requires a paid
Apple Developer account.
