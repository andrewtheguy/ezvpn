# Android App

A native Kotlin/Jetpack Compose client for Android that connects to an `ezvpn`
server built from this repo. The tunnel runs in a `VpnService` in the app's
own process; there is no Play Store packaging or signing — it is a sideloaded
debug/release APK built from source.

The Android client is split across two repositories:

- **This repo (`ezvpn`)** — the Rust core, packaged as `libezvpn.so` per ABI
  (`arm64-v8a`, `armeabi-v7a`, `x86_64`) plus a small JNI surface. This is
  where the Android Rust code, the in-tunnel split-DNS forwarder, and the build
  script live.
- **[`ezvpn-android`](https://github.com/flexaccessdev/ezvpn-android)** — the
  Gradle project: a Compose app, the `VpnService`, and a pure-Kotlin
  `tunnelcore` module (IP/CIDR math, profile model and validation, the
  interface plan) with JVM unit tests. Build/install/run instructions live in
  that repo's README.

## Scope

In scope:

- **Dual-stack split tunnel** — IPv4, IPv6, or both, to explicit routed
  prefixes. Both route lists are optional and independent.
- **Optional tunnel DNS, including split DNS (match domains)** — the same
  profile fields as iOS. Android has no per-domain DNS for VPNs, so match
  domains are implemented by an in-tunnel forwarder in the Rust core (see
  [Split DNS on Android](#split-dns-on-android)); without match domains the
  servers are handed to the OS and answer every name.
- **Optional underlay bypass** — the few server underlay addresses that overlap
  a routed prefix are carved back out of the tunnel (see below).
- **Always-on VPN** — the service accepts the system's always-on start and
  connects the last-used profile.
- **On-device testing** — developed and tested on an adb-connected arm64
  Android emulator (a `VpnService` cannot run on the JVM); the physical device
  only receives the signed release APK.

Out of scope (by design):

- **Full tunnel** (`0.0.0.0/0` / `::/0`) is not offered by the app's editor.
- **Play Store distribution**, Play signing, and Android TV/Auto form factors.
- **Session migration across networks** — like the Apple app, a network change
  disconnects; the user reconnects on the new network.

## How it reuses the core

The Android data plane is the same portable code the desktop client and the
Apple extension use (`src/tunnel/mobile.rs`, `MobileSession`): the OS owns the
tun interface, addresses, routes, DNS, and MTU; Rust is handed the fd.

| Concern | Desktop CLI | Android `VpnService` |
|---|---|---|
| TUN device | created by `ezvpn` (`TunDevice::create`) | created by the OS (`Builder.establish()`); `ezvpn` wraps the fd (`TunDevice::from_raw_fd`) |
| Routing / IP / MTU / DNS | `ip`/`route`/`netsh`, OS resolver config | `VpnService.Builder` (`addAddress`, `addRoute`, `addDnsServer`, `setMtu`) |
| Underlay bypass | `BypassRouteManager` host routes | no `excludeRoute` before API 33: the app *subtracts* the bypass `/32`s and `/128`s from the routed prefixes (`tunnelcore` `RouteMath.subtract`) and installs the remainder |
| Split DNS | OS conditional forwarding (`docs/Client-Split-DNS.md`) | in-tunnel forwarder (`src/tunnel/dns_proxy.rs`) |
| Single-instance lock, control socket | yes | not used (one `VpnService`; the app and service share a process) |

Key source in this repo:

- `src/tunnel/mobile.rs` — `MobileSession` (connect → handshake → run) and the
  network config it returns, shared with the Apple extension.
- `src/ffi.rs` — the shared connect/run/stop bodies and JSON shapes.
- `src/ffi_android.rs` — the JNI entry points bound to the Kotlin object
  `dev.flexaccess.ezvpn.EzvpnNative` (the symbol names encode that class name;
  it must not move even if the `applicationId` changes).
- `src/tunnel/dns_proxy.rs` — the Android-only split-DNS forwarder.
- `src/net/device.rs` — `TunDevice::from_raw_fd` for Android (the `tun` crate's
  `raw_fd` configuration; no offload — `VpnService` tun devices have none).
- `build-android.sh` — builds one `libezvpn.so` per ABI with `cargo ndk` and
  stages `dist/android/jniLibs/<abi>/libezvpn.so` plus
  `dist/android/libezvpn-android.zip` (the release asset the app downloads by
  URL + sha256).

## JNI interface

`EzvpnNative` (Kotlin, in the app) ↔ `src/ffi_android.rs`:

| Kotlin | Purpose |
|---|---|
| `init(context)` | once per process, from `Application.onCreate`: logcat logging (tag `ezvpn`) and the JVM/context registration that iroh's Android DNS and interface discovery (`hickory-resolver`, `netwatch`, via `ndk-context`) need — without it the first connect aborts the process |
| `generateClientKey()` / `clientPublicKey(secret)` | the shared FlexAccess ed25519 key format, never reimplemented in Kotlin |
| `connect(configJson, out)` → handle | connect + handshake; `out[0]` receives the network-config JSON (or the error) |
| `run(handle, tunFd)` | start the data loop on the `establish()`ed fd (dup'ed before it returns) |
| `connPath(handle)` | the live iroh path / custom-relay snapshot JSON |
| `stop(handle)` | abort, close, free |
| `onTunnelExit(handle, error)` | **callback** from the library when the loop ends on its own (never after `stop`) so the service tears the interface down |

The config and result JSON are the shapes documented in
[`ios/ezvpn.h`](../ios/ezvpn.h), plus one Android-only config object:

```json
"dns_proxy": {
  "addresses": ["198.18.0.53", "fd7e:7a00:d45::53"],
  "match_domains": ["corp.example"],
  "servers": ["10.0.0.53"],
  "fallback_servers": ["192.168.1.1", "fe80::1%5"],
  "fallback_fds": [41, 42]
}
```

```
ezvpn app (Compose)          EzvpnVpnService (same process)
  TunnelsManager.connect ──▶  startService → worker thread:
                                EzvpnNative.connect(json) ──▶ libezvpn (iroh connect + handshake)
                                TunnelPlan.from(netConfig)    (tunnelcore: routes − bypass, DNS, families)
                                Builder…establish() → fd
                                EzvpnNative.run(handle, fd) ─▶ data loop (+ DNS forwarder)
  state: StateFlow  ◀──────── onConnected / onDisconnected
  disconnect ───────────────▶ EzvpnNative.stop(handle); close fd
```

`connect` blocks for the handshake and runs on its own thread; everything that
touches the session (the connect continuation, stop, the exit callback, path
queries) is serialized on one worker thread so a handle is never stopped twice.
A disconnect that lands while a connect is in flight is honored when the
handshake returns. No foreground notification is used: the system binds the
`VpnService` while its interface is established, which keeps the process alive
(the WireGuard app relies on the same).

## Underlay bypass in the Android app

Same computation as the Apple app: `connect` returns `excluded_routes` /
`excluded_routes6`, the global-scope relay and server underlay addresses a
routed prefix would capture. Android's `VpnService.Builder` has no
`excludeRoute` before API 33 (the app's `minSdk` is 29), so the app subtracts
those host prefixes from its route list (splitting each containing prefix into
the sibling prefixes that do not contain the address) and installs the result.
The detail screen shows both the installed routes and the bypass set.

An address family the server did not assign is explicitly `allowFamily`'d:
a `VpnService` blocks every family it has no address for by default, which is
the wrong default for a split tunnel.

## Split DNS on Android

`VpnService.Builder` offers only `addDnsServer` (resolvers for *all* names of
every app the VPN applies to) and `addSearchDomain`. There is no equivalent of
iOS `NEDNSSettings.matchDomains`, and an app cannot bind port 53. So when a
profile names match domains the app does what Tailscale's MagicDNS does:

1. It tells the OS the VPN's DNS server is a **proxy address** inside the
   tunnel — `198.18.0.53` and/or `fd7e:7a00:d45::53` (RFC 2544 benchmarking
   space and a ULA, so they never collide with a real network) — and routes
   that address as a host route into the interface, for whichever families the
   server assigned.
2. The data path intercepts UDP packets to `<proxy>:53` before they reach the
   server (`DnsIntercept::wants`, a few byte compares per outbound packet),
   parses the first question name, and forwards the query:
   - names equal to or under a match domain → the profile's DNS servers,
     through ordinary sockets — the resolvers sit inside a tunnel route, so the
     OS routes the query into the tun and through the tunnel like any app
     traffic;
   - everything else → the underlying network's resolvers (read from the
     physical network's `LinkProperties` before `establish()`), through UDP
     sockets the service `protect()`ed and handed over as fds, so they never
     loop into the VPN even under a wide route.
3. The answer is written back into the tun as a UDP packet from `<proxy>:53`
   with the client's original DNS id restored (ids are rewritten per in-flight
   query so one upstream socket per family multiplexes every app's queries).

TCP DNS is not proxied: a SYN to `<proxy>:53` (a stub retrying a truncated
answer) or `<proxy>:853` (Android's opportunistic DNS-over-TLS probe) gets a
RST so the stub falls back at once; an answer that would not fit the tunnel MTU
is returned truncated (TC) with the question only. With no fallback resolvers
known, every name goes to the profile's servers — all-DNS-through-tunnel rather
than broken resolution.

This is a workaround for a platform limitation and is **Android-only**: the
`dns_proxy` config object is absent on every other platform, the OS keeps doing
conditional forwarding there (iOS via `NEDNSSettings`, desktop via OS resolver
configuration, see `docs/Client-Split-DNS.md`), and nothing in the forwarder
runs unless the object is present.

## Network changes, secrets, local-network refusal

- **Network change → disconnect.** A `ConnectivityManager` callback records the
  physical networks present at connect time; a new Wi-Fi/Ethernet network, or
  the loss of a baseline network, tears the session down (cellular appearing
  next to Wi-Fi, or a lingering cellular link dropping while Wi-Fi stays, is
  ignored). Same policy as the Apple app.
- **Split-tunnel overlap refusal.** Before connecting, the service enumerates
  the on-link subnets of the current Wi-Fi/Ethernet networks and refuses to
  start when a configured prefix overlaps one (see *Split-Tunnel Overlap
  Refusal* in `docs/Architecture.md`).
- **Secrets.** The shared key list and each profile's own copy of its auth key
  and relay token are AES-GCM-encrypted under an `AndroidKeyStore` key in a
  private `SharedPreferences` file (the Keychain's counterpart). Public keys
  are re-derived from the secret on load, never stored.

## Building

```bash
# Android NDK (r28+) via the SDK's ndk/<version>, ANDROID_NDK_HOME, or sysroot mode
cargo install cargo-ndk
./build-android.sh              # release, ABIs: arm64-v8a armeabi-v7a x86_64
ABIS="armeabi-v7a" ./build-android.sh debug
```

Output: `dist/android/jniLibs/<abi>/libezvpn.so` and
`dist/android/libezvpn-android.zip`. The release workflow publishes the zip as
a release asset; the app's Gradle build downloads it by tag + sha256
(`scripts/bump-jnilibs.sh <tag>` in the app repo pins a new one). For local FFI
development the app links `../ezvpn/dist/android/jniLibs` directly when
`EZVPN_LOCAL_JNILIBS=1`.

Hosts without an official NDK (Google ships Linux NDKs for x86_64 only): copy
any NDK's `toolchains/llvm/prebuilt/*/sysroot` plus its
`lib/clang/<ver>/lib/linux/<arch>/libunwind.a` files into
`<sysroot>/usr/lib/<triple>/`, and set `EZVPN_NDK_SYSROOT` to drive the system
`clang` + `lld` against it. Apple-silicon Macs have a native NDK and use the
default `cargo ndk` path.

Verify on the host with the Android target's clippy (the module is `cfg`-gated,
so the Linux host clippy never type-checks it):

```bash
cargo ndk -t arm64-v8a --platform 29 clippy --lib -- -D warnings
```
