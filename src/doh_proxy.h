#ifndef _DOH_PROXY_H_
#define _DOH_PROXY_H_

#include <ev.h>

#include "dns_listener.h"
#include "dns_poller.h"
#include "https_client.h"
#include "stat.h"

// The DoH proxy core. Owns the per-request lifecycle (allocate state on
// inbound, hand to the HTTPS client, route the response back to the
// originating listener, free) and the curl resolve list driven by the
// bootstrap DNS poller.
typedef struct doh_proxy doh_proxy_t;

// Optional callback invoked the first time the proxy is ready to serve
// requests (after bootstrap completes, if bootstrap was required). Called
// at most once.
typedef void (*doh_proxy_ready_fn)(void *ctx);

doh_proxy_t * doh_proxy_create(struct ev_loop *loop,
                               https_client_t *client,
                               const char *resolver_url,
                               stat_t *stat);

// Mark the proxy as awaiting bootstrap. Until the first successful resolver
// update, inbound DNS requests will be dropped (libcurl would otherwise fall
// back to gethostbyname() and may deadlock if our resolver depends on us).
void doh_proxy_await_bootstrap(doh_proxy_t *p);

// Set a one-shot "ready" notifier (e.g. systemd_notify_ready). Fires when
// bootstrap completes, or never if await_bootstrap was never called.
void doh_proxy_set_on_ready(doh_proxy_t *p, doh_proxy_ready_fn cb, void *cb_ctx);

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
