#ifndef _DOH_PROXY_H_
#define _DOH_PROXY_H_

#include <ev.h>

#include "dns_listener.h"
#include "https_client.h"
#include "stat.h"

enum {
  HOSTNAME_BUFFER_SIZE = 256,  // To store max hostname length per RFC1035 2.3.4
  PORT_STR_LENGTH = 5,         // Port shouldn't exceed 5 chars: "65535"
};

// The DoH proxy core. Owns the per-request lifecycle (allocate state on
// inbound, hand to the HTTPS client, route the response back to the
// originating listener, free) and the curl resolve list driven by the
// bootstrap DNS poller.
typedef struct doh_proxy doh_proxy_t;

// Optional callback invoked the first time the proxy is ready to serve
// requests (after bootstrap completes,). Called at most once.
typedef void (*doh_proxy_bootstrap_done_cb)(void);

doh_proxy_t * doh_proxy_create(struct ev_loop *loop,
                               https_client_t *client,
                               const char *resolver_url,
                               stat_t *stat);

// Mark the proxy as awaiting bootstrap. Until the first successful resolver
// update, inbound DNS requests will be dropped (libcurl would otherwise fall
// back to gethostbyname() and may deadlock if our resolver depends on us).
// Optionally set a one-shot "ready" notifier (e.g. systemd_notify_ready).
// Fires when the first resolver update completes.
void doh_proxy_await_bootstrap(doh_proxy_t *p, doh_proxy_bootstrap_done_cb cb);

void doh_proxy_set_port(doh_proxy_t *p, uint16_t port);

// Set static resolv list (for when no polling is used).
void doh_proxy_set_resolv(doh_proxy_t *p, const char *buf);

// dns_request_fn — pass to dns_*_listener_create as the request callback.
// `ctx` must be a doh_proxy_t *.
void doh_proxy_handle_request(void *ctx, dns_listener_t *listener,
                              struct sockaddr *raddr,
                              char *dns_req, size_t dns_req_len);

// dns_poller_cb — pass to dns_poller_init as the resolver-update callback.
// Takes ownership of `addr_list` (will free it).
void doh_proxy_handle_resolver_update(const char *hostname, void *ctx,
                                      const char *addr_list);

void doh_proxy_destroy(doh_proxy_t *p);

#endif // _DOH_PROXY_H_
