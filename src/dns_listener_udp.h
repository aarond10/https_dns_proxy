#ifndef _DNS_LISTENER_UDP_H_
#define _DNS_LISTENER_UDP_H_

#include <netdb.h>
#include <ev.h>

#include "dns_listener.h"

// Create a UDP DNS listener bound to `listen_addrinfo`. The returned listener
// implements the dns_listener_t interface; callers should treat it as such
// and use dns_listener_stop / dns_listener_destroy for lifecycle.
//
// `cb` is invoked once per inbound DNS request.
dns_listener_t * dns_udp_listener_create(struct ev_loop *loop,
                                         struct addrinfo *listen_addrinfo,
                                         dns_request_fn cb, void *ctx);

#endif // _DNS_LISTENER_UDP_H_
