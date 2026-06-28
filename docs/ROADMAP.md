# ezvpn Roadmap

This document outlines planned features and improvements for `ezvpn`.

## Current Status

`ezvpn` provides iroh-based VPN tunneling with:

- Full-network IP-over-QUIC transport
- Token authentication
- Dynamic per-session client IP assignment
- Optional dual-stack IPv4/IPv6 operation
- Auto-reconnect with QUIC keep-alive / idle-timeout connection health

---

## Planned Features

### IPv6-Only Hardening

**Status:** In progress

Improve operational guidance and defaults for IPv6-only VPN deployments.

### Authentication Rate Limiting

**Status:** Idea

Add configurable rate limiting for invalid auth-token attempts to reduce brute-force and resource abuse risk.


### Dynamic Client Whitelisting for Self-Hosted Relay

**Status:** Idea

For self-hosted `iroh-relay`, explore dynamic allow/deny integration keyed by authenticated client identity so relay-level access can track active authorized sessions.

### Connection Migration (IP Change Resilience)

**Status:** Idea

Improve tunnel continuity when clients switch networks (for example, Wi-Fi to cellular) by better leveraging QUIC path migration behavior.

### Performance Metrics

**Status:** Idea

Add built-in metrics for latency, throughput, loss, reconnect counts, and tunnel uptime.

### Multi-Path Support

**Status:** Idea

Use multiple network paths simultaneously for higher throughput or failover.

### Web UI

**Status:** Idea

Browser-based interface for configuration, connection state, and diagnostics.
