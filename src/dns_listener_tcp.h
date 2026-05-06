#ifndef _DNS_LISTENER_TCP_H_
#define _DNS_LISTENER_TCP_H_

#include <netdb.h>
#include <stdint.h>
#include <ev.h>

#include "dns_listener.h"

// Create a TCP DNS listener bound to `listen_addrinfo`. The returned listener
// implements the dns_listener_t interface; callers should treat it as such
// and use dns_listener_stop / dns_listener_destroy for lifecycle.
//
// `client_limit` caps the number of concurrent TCP clients. `cb` is invoked
// once per fully-received DNS request from any client.
dns_listener_t * dns_tcp_listener_create(struct ev_loop *loop,
                                         struct addrinfo *listen_addrinfo,
                                         uint16_t client_limit,
                                         dns_request_fn cb, void *ctx);

#endif // _DNS_LISTENER_TCP_H_
