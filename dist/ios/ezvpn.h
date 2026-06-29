/*
 * ezvpn.h — C interface to libezvpn.a for the iOS Network Extension.
 *
 * Build the static library with ./build-ios.sh (produces
 * dist/ios/libezvpn.a alongside a copy of this header).
 *
 * Lifecycle (call from your NEPacketTunnelProvider):
 *
 *   1. ezvpn_connect(configJson, buf, len)  -> handle (or NULL on error)
 *        On success `buf` holds the network-config JSON; use it to build
 *        NEPacketTunnelNetworkSettings, then setTunnelNetworkSettings.
 *        On error `buf` holds the error message.
 *   2. ezvpn_run(handle, utunFd)            -> 0 on success, -1 on error
 *        Pass the utun file descriptor obtained after the settings apply.
 *   3. ezvpn_stop(handle)                   (in stopTunnel / on teardown)
 *
 * All functions are NULL-safe and never unwind into Swift.
 */
#ifndef EZVPN_H
#define EZVPN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle. Created by ezvpn_connect, freed by ezvpn_stop. */
typedef struct EzvpnHandle EzvpnHandle;

/*
 * Initialize logging (stderr -> unified log / Console). Honors RUST_LOG,
 * defaults to "info". Idempotent; safe to call more than once.
 */
void ezvpn_init_logging(void);

/*
 * Connect to the server and perform the handshake.
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"server_node_id":"<id>","alpn_token":"<token>",
 *    "auth_token":null,"relay_urls":[],"relay_only":false}
 * out_buf/out_len : caller buffer. On success receives the network-config JSON
 *   {"assigned_ip":"10.0.0.2","netmask":"255.255.255.0",
 *    "gateway":"10.0.0.1","mtu":1400}; on failure receives an error message.
 *   Always NUL-terminated (truncated to fit).
 *
 * Returns a non-NULL handle on success, NULL on failure.
 */
EzvpnHandle *ezvpn_connect(const char *config_json, char *out_buf, size_t out_len);

/*
 * Start the tunnel data loop on the given utun fd. The library keeps its own
 * dup of the fd, so the caller may close its copy. Returns 0 on success, -1 on
 * error (NULL handle, no pending session, or already running).
 */
int ezvpn_run(EzvpnHandle *handle, int tun_fd);

/*
 * Stop the tunnel and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void ezvpn_stop(EzvpnHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* EZVPN_H */
