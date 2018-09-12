#ifndef _DNS_POLLER_H_
#define _DNS_POLLER_H_

#include <ares.h>
#include <ev.h>

// Due to c-ares not playing nicely with libev, the intervals below also
// wind up functioning as the timeout values after which any pending
// queries are cancelled and treated as if they've failed.
#define POLLER_INTVL_NORM 120
#define POLLER_INTVL_ERR 5

// Callback to be called periodically when we get a valid DNS response.
typedef void (*dns_poller_cb)(const char* hostname, void *data,
                              struct sockaddr_in *addr);

typedef struct {
  ares_channel ares;
  struct ev_loop *loop;
  const char *hostname;
  dns_poller_cb cb;
  void *cb_data;

  ev_timer timer;
  // Lazy approach. FD_SETSIZE is 1k under linux. sizeof(ev_io) is 48 bytes.
  ev_io fd[FD_SETSIZE];
} dns_poller_t;

// Initializes c-ares and starts a timer for periodic DNS resolution on the
// provided ev_loop. `bootstrap_dns` is a comma-separated list of DNS servers to
// use for the lookup `hostname` every `interval_seconds`. For each successful
// lookup, `cb` will be called with the resolved address.
//
// Note: hostname *not* copied. It should remain valid until
// dns_poller_cleanup called.
void dns_poller_init(dns_poller_t *d, struct ev_loop *loop,
                     const char *bootstrap_dns, const char *hostname,
                     dns_poller_cb cb, void *cb_data);

// Tears down timer and frees resources associated with a dns poller.
void dns_poller_cleanup(dns_poller_t *d);

#endif
