#ifndef _DNS_LISTENER_H_
#define _DNS_LISTENER_H_

#include <sys/socket.h>
#include <sys/types.h>

// A DNS listener accepts requests on some transport (UDP, TCP, ...) and routes
// responses back to the originating peer. The proxy core never branches on
// transport — all listener-specific behaviour (datagram-vs-stream framing,
// EDNS-aware truncation, per-client state) lives behind the function pointers
// on dns_listener.

typedef struct dns_listener dns_listener_t;

// Transport classification, exposed for callers that need to bin metrics or
// log per-transport — not used for dispatch (dispatch is via the function
// pointers on dns_listener itself).
typedef enum {
  DNS_TRANSPORT_UDP,
  DNS_TRANSPORT_TCP,
} dns_transport_t;

// Invoked once per fully-received DNS request. `dns_req` is heap-allocated
// and ownership transfers to the callee. `listener` is a back-pointer the
// callee uses later to deliver the matching response.
typedef void (*dns_request_fn)(void *ctx, dns_listener_t *listener,
                               struct sockaddr *raddr,
                               char *dns_req, size_t dns_req_len);

struct dns_listener {
  // Send `dns_resp` to `raddr`. UDP listeners may EDNS-truncate the response
  // in place using `dns_req`; TCP listeners ignore the request bytes.
  void (*respond)(dns_listener_t *self, struct sockaddr *raddr,
                  const char *dns_req, size_t dns_req_len,
                  char *dns_resp, size_t dns_resp_len);
  // Stop accepting new requests. Existing per-client state (TCP) is retained
  // so any in-flight DoH responses can still be delivered during graceful
  // drain.
  void (*stop)(dns_listener_t *self);
  // Free the listener and any owned resources.
  void (*destroy)(dns_listener_t *self);

  dns_transport_t transport;
};

#endif // _DNS_LISTENER_H_
