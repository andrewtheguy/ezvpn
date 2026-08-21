//! In-tunnel split-DNS forwarder for Android (the "magic DNS" workaround).
//!
//! Every other platform gets conditional forwarding from the OS: iOS through
//! `NEDNSSettings.matchDomains`, the desktop clients through their resolver
//! configuration. Android's `VpnService.Builder` has only `addDnsServer`, which
//! replaces the resolvers for *all* names of every app the VPN applies to, and
//! an app cannot bind port 53 — so per-domain forwarding cannot be expressed to
//! the OS at all. This module does what Tailscale's MagicDNS does instead: the
//! app points the VPN's DNS at a *proxy address* that is routed into the tun
//! (a host route, e.g. `198.18.0.53/32`), and the data path answers those
//! packets itself:
//!
//! * a UDP query to `<proxy>:53` is parsed, its first question name is matched
//!   against the profile's match domains, and it is forwarded either to the
//!   tunnel's private resolvers (plain sockets — the resolvers sit inside a
//!   tunnel route, so the OS routes the query back into the tun and through
//!   the tunnel like any other app traffic) or to the underlying network's
//!   resolvers through sockets the `VpnService` has `protect()`ed, so they
//!   never loop into the VPN even under a full-tunnel route;
//! * the reply is written back into the tun as a UDP packet from `<proxy>:53`;
//! * a TCP SYN to `<proxy>:53` (a stub retrying a truncated answer) or
//!   `<proxy>:853` (Android's opportunistic DNS-over-TLS probe) gets a RST, so
//!   the stub falls back immediately instead of timing out. TCP DNS is not
//!   proxied; an answer that would not fit the tunnel MTU is returned
//!   truncated (TC) with the question only.
//!
//! DNS ids are rewritten per in-flight query so one upstream socket per family
//! can multiplex every app's queries without collisions; the original id is
//! restored on the way back. The module is platform-independent Rust (and unit
//! tested on the host), but only the Android app configures it — every other
//! caller passes `None` to `run_tunnel` and nothing here runs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::VPN_MTU;
use crate::tunnel::client::{InboundTunWrite, enqueue_inbound_tun_write};

pub const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
/// How long a forwarded query may wait for its answer before its id is freed.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on in-flight queries; beyond it the oldest are dropped first.
const MAX_PENDING: usize = 1024;
/// Captured packets queued from the tun reader to the proxy task.
const CAPTURE_QUEUE: usize = 256;
/// Largest DNS message read back from an upstream (EDNS-sized).
const UPSTREAM_BUF: usize = 4096;

/// What the app decided: where the proxy listens, what it matches, and where
/// it forwards to.
pub struct DnsProxyConfig {
    /// Proxy addresses the OS was pointed at (at most one per family); packets
    /// to `<address>:53` are intercepted. Both families may be listed even when
    /// only one is routed — an unrouted one simply sees no traffic.
    pub addresses: Vec<IpAddr>,
    /// Suffixes (no leading/trailing dot, lowercase) whose names resolve via
    /// `servers`; everything else goes to `fallback_servers`.
    pub match_domains: Vec<String>,
    /// The tunnel's resolvers (inside a tunnel route).
    pub servers: Vec<SocketAddr>,
    /// The underlying network's resolvers. Empty means "unknown": every name
    /// then goes to `servers`, which degrades to all-DNS-through-tunnel rather
    /// than breaking resolution.
    pub fallback_servers: Vec<SocketAddr>,
    /// UDP sockets the app has `protect()`ed, one per family at most, used for
    /// the fallback upstreams (switched to non-blocking here). A family without
    /// one gets a plain socket (fine unless a tunnel route captures the
    /// fallback resolver).
    pub fallback_sockets: Vec<std::net::UdpSocket>,
}

impl std::fmt::Debug for DnsProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsProxyConfig")
            .field("addresses", &self.addresses)
            .field("match_domains", &self.match_domains)
            .field("servers", &self.servers)
            .field("fallback_servers", &self.fallback_servers)
            .field("fallback_sockets", &self.fallback_sockets.len())
            .finish()
    }
}

impl DnsProxyConfig {
    /// Normalize the match domains (trim dots and whitespace, lowercase) and
    /// drop empties, so matching is a plain suffix comparison.
    pub fn normalized(mut self) -> Self {
        self.match_domains = self
            .match_domains
            .iter()
            .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        self
    }
}

/// The tun reader's side of the proxy: a cheap "is this for the proxy?" test
/// on the raw IP header plus the handoff channel. Cloned into the outbound
/// task; the per-packet cost for non-DNS traffic is one version-nibble check
/// and a 4- or 16-byte compare per proxy address.
#[derive(Clone)]
pub(crate) struct DnsIntercept {
    addrs4: Vec<[u8; 4]>,
    addrs6: Vec<[u8; 16]>,
    tx: mpsc::Sender<Bytes>,
}

impl DnsIntercept {
    /// True when the packet's destination is one of the proxy addresses.
    pub(crate) fn wants(&self, packet: &[u8]) -> bool {
        match packet.first().map(|b| b >> 4) {
            Some(4) if packet.len() >= 20 => self.addrs4.iter().any(|a| a[..] == packet[16..20]),
            Some(6) if packet.len() >= 40 => self.addrs6.iter().any(|a| a[..] == packet[24..40]),
            _ => false,
        }
    }

    /// Hand a packet to the proxy task. Never blocks the tun reader: when the
    /// queue is full the query is dropped and the stub resolver retries.
    pub(crate) fn capture(&self, packet: &[u8]) {
        if self.tx.try_send(Bytes::copy_from_slice(packet)).is_err() {
            log::debug!("DNS proxy queue full or closed; dropping a captured packet");
        }
    }
}

/// Build the intercept handle and the receiver the proxy task consumes.
pub(crate) fn intercept_channel(cfg: &DnsProxyConfig) -> (DnsIntercept, mpsc::Receiver<Bytes>) {
    let (tx, rx) = mpsc::channel(CAPTURE_QUEUE);
    let mut addrs4 = Vec::new();
    let mut addrs6 = Vec::new();
    for addr in &cfg.addresses {
        match addr {
            IpAddr::V4(a) => addrs4.push(a.octets()),
            IpAddr::V6(a) => addrs6.push(a.octets()),
        }
    }
    (DnsIntercept { addrs4, addrs6, tx }, rx)
}

// ---------------------------------------------------------------------------
// Packet classification and construction (pure)

/// A captured packet the proxy acts on.
#[derive(Debug, PartialEq, Eq)]
enum Captured<'a> {
    /// UDP datagram to `<proxy>:53` carrying a DNS message.
    Query {
        client: SocketAddr,
        proxy: SocketAddr,
        dns: &'a [u8],
    },
    /// TCP connection attempt to the proxy's DNS or DoT port.
    TcpSyn {
        client: SocketAddr,
        proxy: SocketAddr,
        seq: u32,
    },
}

fn classify(packet: &[u8]) -> Option<Captured<'_>> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    let (src, dst): (IpAddr, IpAddr) = match sliced.net? {
        NetSlice::Ipv4(v4) => (
            Ipv4Addr::from(v4.header().source()).into(),
            Ipv4Addr::from(v4.header().destination()).into(),
        ),
        NetSlice::Ipv6(v6) => (
            Ipv6Addr::from(v6.header().source()).into(),
            Ipv6Addr::from(v6.header().destination()).into(),
        ),
        _ => return None,
    };
    match sliced.transport? {
        TransportSlice::Udp(udp) if udp.destination_port() == DNS_PORT => Some(Captured::Query {
            client: SocketAddr::new(src, udp.source_port()),
            proxy: SocketAddr::new(dst, DNS_PORT),
            dns: udp.payload(),
        }),
        TransportSlice::Tcp(tcp)
            if tcp.syn()
                && !tcp.ack()
                && (tcp.destination_port() == DNS_PORT || tcp.destination_port() == DOT_PORT) =>
        {
            Some(Captured::TcpSyn {
                client: SocketAddr::new(src, tcp.source_port()),
                proxy: SocketAddr::new(dst, tcp.destination_port()),
                seq: tcp.sequence_number(),
            })
        }
        _ => None,
    }
}

/// The end of the question section of a DNS message (offset just past the
/// first question's type/class), or None if the header or question is
/// malformed. Only the first question is examined — that is all stubs send.
fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut total = 0usize;
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // Compression never appears in a query's question section.
        if len & 0xC0 != 0 {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        pos += len;
        msg.get(pos.checked_sub(1)?)?;
    }
    let end = pos + 4;
    (end <= msg.len()).then_some(end)
}

/// The lowercased first question name (no trailing dot) of a DNS *query*;
/// None for a response, an empty question section, or a malformed message.
fn question_name(msg: &[u8]) -> Option<String> {
    question_end(msg)?;
    if msg[2] & 0x80 != 0 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    let mut pos = 12;
    loop {
        let len = msg[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(&msg[pos..pos + len]).to_ascii_lowercase());
        pos += len;
    }
    Some(labels.join("."))
}

/// Whether `name` equals or sits under one of the (normalized) domains.
fn matches_domain(name: &str, domains: &[String]) -> bool {
    domains.iter().any(|d| {
        name == d
            || name
                .strip_suffix(d.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Shrink an answer to its header + question with TC set, for replies that
/// would not fit a tunnel-MTU datagram. The stub retries over TCP, which the
/// proxy refuses with a RST — a fast, explicit failure for the rare oversized
/// answer rather than a silently lost one.
fn truncate_reply(msg: &mut Vec<u8>) {
    if let Some(end) = question_end(msg) {
        msg.truncate(end);
        msg[2] |= 0x02;
        msg[6..12].fill(0);
    }
}

/// Largest DNS payload that fits one tunnel-MTU datagram for the family.
fn max_payload(proxy: &SocketAddr) -> usize {
    let headers = if proxy.is_ipv4() { 20 + 8 } else { 40 + 8 };
    usize::from(VPN_MTU).saturating_sub(headers)
}

/// UDP reply packet `proxy -> client` carrying `payload`. None when the two
/// ends are not the same family (never the case for a captured query).
fn build_udp_reply(proxy: SocketAddr, client: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + 48);
    match (proxy.ip(), client.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), 64)
            .udp(proxy.port(), client.port())
            .write(&mut out, payload)
            .ok()?,
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), 64)
            .udp(proxy.port(), client.port())
            .write(&mut out, payload)
            .ok()?,
        _ => return None,
    }
    Some(out)
}

/// TCP RST/ACK answering a SYN to the proxy (acknowledging `seq + 1`).
fn build_tcp_rst(proxy: SocketAddr, client: SocketAddr, seq: u32) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(60);
    let ack = seq.wrapping_add(1);
    match (proxy.ip(), client.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), 64)
            .tcp(proxy.port(), client.port(), 0, 0)
            .rst()
            .ack(ack)
            .write(&mut out, &[])
            .ok()?,
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), 64)
            .tcp(proxy.port(), client.port(), 0, 0)
            .rst()
            .ack(ack)
            .write(&mut out, &[])
            .ok()?,
        _ => return None,
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The forwarder task

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum UpstreamKind {
    Tunnel,
    Fallback,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Family {
    V4,
    V6,
}

fn family_of(addr: &SocketAddr) -> Family {
    if addr.is_ipv4() { Family::V4 } else { Family::V6 }
}

/// One forwarded query awaiting its answer.
struct Pending {
    client: SocketAddr,
    proxy: SocketAddr,
    upstream: SocketAddr,
    original_id: u16,
    sent_at: Instant,
}

/// Lazily created upstream sockets, one per (kind, family); the fallback ones
/// come pre-protected from the app. Each socket has a reader task feeding
/// `reply_tx`; the tasks are aborted with the proxy so the sockets close then,
/// not after the next stray datagram.
struct Upstreams {
    sockets: HashMap<(UpstreamKind, Family), Arc<UdpSocket>>,
    readers: Vec<tokio::task::JoinHandle<()>>,
    reply_tx: mpsc::Sender<(Bytes, SocketAddr)>,
}

impl Drop for Upstreams {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}

impl Upstreams {
    async fn socket(&mut self, kind: UpstreamKind, family: Family) -> Option<Arc<UdpSocket>> {
        if let Some(s) = self.sockets.get(&(kind, family)) {
            return Some(s.clone());
        }
        let bind: SocketAddr = match family {
            Family::V4 => (Ipv4Addr::UNSPECIFIED, 0).into(),
            Family::V6 => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = match UdpSocket::bind(bind).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::warn!("DNS proxy: cannot bind {kind:?} {family:?} upstream socket: {e}");
                return None;
            }
        };
        if kind == UpstreamKind::Fallback {
            log::warn!(
                "DNS proxy: no protected {family:?} socket from the app; using an unprotected one \
                 (fallback resolvers inside a tunnel route will not be reachable)"
            );
        }
        self.install(kind, family, socket.clone());
        Some(socket)
    }

    fn install(&mut self, kind: UpstreamKind, family: Family, socket: Arc<UdpSocket>) {
        let reader = socket.clone();
        let reply_tx = self.reply_tx.clone();
        self.readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; UPSTREAM_BUF];
            loop {
                match reader.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if reply_tx.send((Bytes::copy_from_slice(&buf[..n]), from)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        // Transient (ICMP unreachable surfacing as an error on
                        // Linux); keep serving.
                        log::debug!("DNS proxy: upstream recv error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }));
        self.sockets.insert((kind, family), socket);
    }
}

/// Run the forwarder until the capture channel closes (the tun reader ended)
/// or the task is aborted by `run_tunnel`'s cleanup.
pub(crate) async fn run_dns_proxy(
    cfg: DnsProxyConfig,
    mut captured: mpsc::Receiver<Bytes>,
    tun_tx: mpsc::Sender<InboundTunWrite>,
) {
    let (reply_tx, mut replies) = mpsc::channel::<(Bytes, SocketAddr)>(CAPTURE_QUEUE);
    let mut upstreams = Upstreams {
        sockets: HashMap::new(),
        readers: Vec::new(),
        reply_tx,
    };
    for std_socket in cfg.fallback_sockets {
        let family = match std_socket.local_addr() {
            Ok(addr) => family_of(&addr),
            Err(e) => {
                log::warn!("DNS proxy: ignoring a fallback socket with no local address: {e}");
                continue;
            }
        };
        // tokio requires the socket to be non-blocking before adopting it.
        if let Err(e) = std_socket.set_nonblocking(true) {
            log::warn!("DNS proxy: cannot make the protected {family:?} socket non-blocking: {e}");
            continue;
        }
        match UdpSocket::from_std(std_socket) {
            Ok(s) => upstreams.install(UpstreamKind::Fallback, family, Arc::new(s)),
            Err(e) => log::warn!("DNS proxy: cannot adopt the protected {family:?} socket: {e}"),
        }
    }

    let tunnel_servers = cfg.servers;
    let fallback_servers = cfg.fallback_servers;
    let match_domains = cfg.match_domains;
    log::info!(
        "DNS proxy on {:?}: {} domain(s) -> {:?}, others -> {}",
        cfg.addresses,
        match_domains.len(),
        tunnel_servers,
        if fallback_servers.is_empty() {
            "tunnel resolvers (no fallback resolvers known)".to_string()
        } else {
            format!("{fallback_servers:?}")
        }
    );

    let mut pending: HashMap<u16, Pending> = HashMap::new();
    let mut rotation: u64 = 0;
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    // `ThreadRng` is `!Send`; a `StdRng` seeded from it keeps the task spawnable.
    let mut rng = StdRng::from_rng(&mut rand::rng());

    loop {
        tokio::select! {
            packet = captured.recv() => {
                let Some(packet) = packet else { break };
                match classify(&packet) {
                    Some(Captured::TcpSyn { client, proxy, seq }) => {
                        if let Some(rst) = build_tcp_rst(proxy, client, seq) {
                            write_tun(&tun_tx, rst).await;
                        }
                    }
                    Some(Captured::Query { client, proxy, dns }) => {
                        let Some(name) = question_name(dns) else {
                            log::trace!("DNS proxy: ignoring a non-query or malformed message from {client}");
                            continue;
                        };
                        let kind = if fallback_servers.is_empty() || matches_domain(&name, &match_domains) {
                            UpstreamKind::Tunnel
                        } else {
                            UpstreamKind::Fallback
                        };
                        let servers = match kind {
                            UpstreamKind::Tunnel => &tunnel_servers,
                            UpstreamKind::Fallback => &fallback_servers,
                        };
                        if servers.is_empty() {
                            log::trace!("DNS proxy: no {kind:?} resolver for {name}");
                            continue;
                        }
                        rotation = rotation.wrapping_add(1);
                        let upstream = servers[(rotation % servers.len() as u64) as usize];
                        let Some(socket) = upstreams.socket(kind, family_of(&upstream)).await else {
                            continue;
                        };
                        if pending.len() >= MAX_PENDING {
                            evict_oldest(&mut pending);
                        }
                        let original_id = u16::from_be_bytes([dns[0], dns[1]]);
                        let id = loop {
                            let candidate: u16 = rng.random();
                            if !pending.contains_key(&candidate) {
                                break candidate;
                            }
                        };
                        let mut out = dns.to_vec();
                        out[0..2].copy_from_slice(&id.to_be_bytes());
                        match socket.send_to(&out, upstream).await {
                            Ok(_) => {
                                log::trace!("DNS proxy: {name} -> {kind:?} {upstream} (id {original_id:#06x} -> {id:#06x})");
                                pending.insert(id, Pending { client, proxy, upstream, original_id, sent_at: Instant::now() });
                            }
                            Err(e) => log::debug!("DNS proxy: send to {upstream} failed: {e}"),
                        }
                    }
                    None => log::trace!("DNS proxy: ignoring a packet to the proxy address that is not DNS"),
                }
            }
            reply = replies.recv() => {
                let Some((msg, from)) = reply else { break };
                if msg.len() < 12 {
                    continue;
                }
                let id = u16::from_be_bytes([msg[0], msg[1]]);
                let Some(entry) = pending.get(&id) else {
                    log::trace!("DNS proxy: unexpected reply id {id:#06x} from {from}");
                    continue;
                };
                if entry.upstream.ip() != from.ip() || entry.upstream.port() != from.port() {
                    log::debug!("DNS proxy: reply for id {id:#06x} from {from}, expected {}", entry.upstream);
                    continue;
                }
                let entry = pending.remove(&id).expect("checked above");
                let mut out = msg.to_vec();
                out[0..2].copy_from_slice(&entry.original_id.to_be_bytes());
                if out.len() > max_payload(&entry.proxy) {
                    truncate_reply(&mut out);
                }
                if let Some(packet) = build_udp_reply(entry.proxy, entry.client, &out) {
                    write_tun(&tun_tx, packet).await;
                }
            }
            _ = sweep.tick() => {
                expire(&mut pending, QUERY_TIMEOUT);
            }
        }
    }
    log::debug!("DNS proxy task exiting");
}

fn expire(pending: &mut HashMap<u16, Pending>, max_age: Duration) {
    let now = Instant::now();
    let before = pending.len();
    pending.retain(|_, p| now.duration_since(p.sent_at) <= max_age);
    let dropped = before - pending.len();
    if dropped > 0 {
        log::trace!("DNS proxy: expired {dropped} unanswered query(ies)");
    }
}

/// Make room for one more in-flight query by dropping the oldest one.
fn evict_oldest(pending: &mut HashMap<u16, Pending>) {
    if let Some(id) = pending.iter().min_by_key(|(_, p)| p.sent_at).map(|(id, _)| *id) {
        pending.remove(&id);
        log::trace!("DNS proxy: pending table full; evicted the oldest query (id {id:#06x})");
    }
}

async fn write_tun(tun_tx: &mpsc::Sender<InboundTunWrite>, packet: Vec<u8>) {
    let req = InboundTunWrite {
        packet: Bytes::from(packet),
        offload: None,
    };
    if !enqueue_inbound_tun_write(tun_tx, req).await {
        log::trace!("DNS proxy: tun writer closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, id: u16) -> Vec<u8> {
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&id.to_be_bytes());
        msg[2] = 0x01; // RD
        msg[5] = 1; // QDCOUNT
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&[0, 1, 0, 1]); // A IN
        msg
    }

    fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        build_udp_reply(src, dst, payload).unwrap()
    }

    #[test]
    fn question_name_parses_and_lowercases() {
        assert_eq!(question_name(&query("Host.Corp.Example", 7)).as_deref(), Some("host.corp.example"));
        let mut response = query("a.b", 1);
        response[2] |= 0x80;
        assert_eq!(question_name(&response), None);
        assert_eq!(question_name(&[0u8; 11]), None);
        let mut no_question = query("a.b", 1);
        no_question[5] = 0;
        assert_eq!(question_name(&no_question), None);
        let mut truncated = query("a.b", 1);
        truncated.truncate(16);
        assert_eq!(question_name(&truncated), None);
    }

    #[test]
    fn domain_matching_is_suffix_on_label_boundaries() {
        let domains = DnsProxyConfig {
            addresses: vec![],
            match_domains: vec![" Corp.Example. ".into(), "".into(), "lab".into()],
            servers: vec![],
            fallback_servers: vec![],
            fallback_sockets: vec![],
        }
        .normalized()
        .match_domains;
        assert_eq!(domains, vec!["corp.example".to_string(), "lab".to_string()]);
        assert!(matches_domain("corp.example", &domains));
        assert!(matches_domain("host.corp.example", &domains));
        assert!(matches_domain("deep.host.lab", &domains));
        assert!(!matches_domain("notcorp.example", &domains));
        assert!(!matches_domain("example", &domains));
        assert!(!matches_domain("corp.example.com", &domains));
    }

    #[test]
    fn classifies_udp_queries_and_tcp_syns() {
        let client: SocketAddr = "10.124.0.2:40000".parse().unwrap();
        let proxy: SocketAddr = "198.18.0.53:53".parse().unwrap();
        let dns = query("x.corp.example", 9);
        let packet = udp_packet(client, proxy, &dns);
        assert_eq!(
            classify(&packet),
            Some(Captured::Query { client, proxy, dns: &dns })
        );

        let other_port = udp_packet(client, "198.18.0.53:5353".parse().unwrap(), &dns);
        assert_eq!(classify(&other_port), None);

        let mut syn = Vec::new();
        PacketBuilder::ipv4([10, 124, 0, 2], [198, 18, 0, 53], 64)
            .tcp(41000, 853, 1234, 65535)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        assert_eq!(
            classify(&syn),
            Some(Captured::TcpSyn {
                client: "10.124.0.2:41000".parse().unwrap(),
                proxy: "198.18.0.53:853".parse().unwrap(),
                seq: 1234
            })
        );
        let rst = build_tcp_rst(proxy, client, 1234).unwrap();
        let parsed = SlicedPacket::from_ip(&rst).unwrap();
        match parsed.transport.unwrap() {
            TransportSlice::Tcp(tcp) => {
                assert!(tcp.rst() && tcp.ack());
                assert_eq!(tcp.acknowledgment_number(), 1235);
            }
            other => panic!("unexpected transport {other:?}"),
        }
    }

    #[test]
    fn intercept_filter_matches_only_proxy_addresses() {
        let cfg = DnsProxyConfig {
            addresses: vec!["198.18.0.53".parse().unwrap(), "fd7e:7a00:d45::53".parse().unwrap()],
            match_domains: vec![],
            servers: vec![],
            fallback_servers: vec![],
            fallback_sockets: vec![],
        };
        let (intercept, _rx) = intercept_channel(&cfg);
        let dns = query("a", 1);
        let to_proxy = udp_packet("10.124.0.2:1".parse().unwrap(), "198.18.0.53:53".parse().unwrap(), &dns);
        let to_proxy6 = udp_packet("[fd7a::2]:1".parse().unwrap(), "[fd7e:7a00:d45::53]:53".parse().unwrap(), &dns);
        let elsewhere = udp_packet("10.124.0.2:1".parse().unwrap(), "10.124.0.1:53".parse().unwrap(), &dns);
        assert!(intercept.wants(&to_proxy));
        assert!(intercept.wants(&to_proxy6));
        assert!(!intercept.wants(&elsewhere));
        assert!(!intercept.wants(&[0x45, 0x00]));
    }

    #[test]
    fn truncation_keeps_header_and_question() {
        let mut msg = query("host.corp.example", 3);
        let question_len = msg.len();
        msg[7] = 1; // ANCOUNT
        msg.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
        truncate_reply(&mut msg);
        assert_eq!(msg.len(), question_len);
        assert_eq!(msg[2] & 0x02, 0x02);
        assert_eq!(&msg[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(max_payload(&"198.18.0.53:53".parse().unwrap()), 1280 - 28);
        assert_eq!(max_payload(&"[fd7e::53]:53".parse().unwrap()), 1280 - 48);
    }

    /// End to end on the host: a fake resolver on loopback answers through the
    /// proxy task, and the reply comes back as a tun write to the original
    /// client with the original id.
    #[tokio::test]
    async fn forwards_and_restores_ids() {
        let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                // Echo the name back in a fake answer so sizes differ from the query.
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
                reply[7] = 1;
                resolver.send_to(&reply, from).await.unwrap();
            }
        });

        let cfg = DnsProxyConfig {
            addresses: vec!["198.18.0.53".parse().unwrap()],
            match_domains: vec!["corp.example".into()],
            servers: vec![resolver_addr],
            fallback_servers: vec![],
            fallback_sockets: vec![],
        }
        .normalized();
        let (intercept, rx) = intercept_channel(&cfg);
        let (tun_tx, mut tun_rx) = mpsc::channel::<InboundTunWrite>(8);
        tokio::spawn(run_dns_proxy(cfg, rx, tun_tx));

        let client: SocketAddr = "10.124.0.2:40000".parse().unwrap();
        let proxy: SocketAddr = "198.18.0.53:53".parse().unwrap();
        let dns = query("host.corp.example", 0xBEEF);
        let packet = udp_packet(client, proxy, &dns);
        assert!(intercept.wants(&packet));
        intercept.capture(&packet);

        let written = tokio::time::timeout(Duration::from_secs(5), tun_rx.recv())
            .await
            .expect("reply in time")
            .expect("channel open");
        match classify(&written.packet) {
            // The reply flows proxy -> client, so from classify's point of view
            // the "client" port is 53 and it is not a Query (dst port 40000).
            None => {}
            other => panic!("reply misclassified as {other:?}"),
        }
        let parsed = SlicedPacket::from_ip(&written.packet).unwrap();
        let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
            panic!("not udp");
        };
        assert_eq!(udp.source_port(), 53);
        assert_eq!(udp.destination_port(), 40000);
        let reply = udp.payload();
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), 0xBEEF);
        assert_eq!(reply[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
    }
}
