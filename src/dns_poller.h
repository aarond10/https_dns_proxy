#ifndef _DNS_POLLER_H_
#define _DNS_POLLER_H_

#include <ares.h>
#include <ev.h>

// Fast DNS querying mode
// Requests will be send after 0, 0.8, 1.3, 1.75 second
// And waiting extra 4.2 seconds for reply
// That's total: 8,05 second for trying
#define POLLER_QUERY_TIMEOUT_MS 700
#define POLLER_QUERY_TRIES 4

// enough for minimum 64 pcs IPv4 address or 25 pcs IPv6
#define POLLER_ADDR_LIST_SIZE 1024

// Callback to be called periodically when we get a valid DNS response.
typedef void (*dns_poller_cb)(const char* hostname, void *data,
                              const char *addr_list);

typedef struct {
  ares_channel ares;
  struct ev_loop *loop;
  const char *hostname;
  int family;  // AF_UNSPEC for IPv4 or IPv6, AF_INET for IPv4 only.
  dns_poller_cb cb;
  int polling_interval;
  int request_ongoing;
  void *cb_data;

  ev_timer timer;
  ev_io *io_events;
  int io_events_count;
} dns_poller_t;

// Initializes c-ares and starts a timer for periodic DNS resolution on the
// provided ev_loop. `bootstrap_dns` is a comma-separated list of DNS servers to
// use for the lookup `hostname` every `interval_seconds`. For each successful
// lookup, `cb` will be called with the resolved address.
// `family` should be AF_INET for IPv4 or AF_UNSPEC for both IPv4 and IPv6.
//
// Note: hostname *not* copied. It should remain valid until
// dns_poller_cleanup called.
void dns_poller_init(dns_poller_t *d, struct ev_loop *loop,
                     const char *bootstrap_dns,
                     int bootstrap_dns_polling_interval,
                     const char *hostname,
                     int family, dns_poller_cb cb, void *cb_data);

// Tears down timer and frees resources associated with a dns poller.
void dns_poller_cleanup(dns_poller_t *d);

#endif
