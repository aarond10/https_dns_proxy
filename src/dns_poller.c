#include <netdb.h>       // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>      // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "dns_poller.h"
#include "logging.h"

static void sock_cb(struct ev_loop __attribute__((unused)) *loop,
                    ev_io *w, int revents) {
  dns_poller_t *d = (dns_poller_t *)w->data;
  ares_process_fd(d->ares, (revents & EV_READ) ? w->fd : ARES_SOCKET_BAD,
                  (revents & EV_WRITE) ? w->fd : ARES_SOCKET_BAD);
}

static struct ev_io * get_io_event(dns_poller_t *d, int sock) {
  for (int i = 0; i < d->io_events_count; i++) {
    if (d->io_events[i].fd == sock) {
      return &d->io_events[i];
    }
  }
  return NULL;
}

static void sock_state_cb(void *data, int fd, int read, int write) {
  dns_poller_t *d = (dns_poller_t *)data;
  // stop and release used event
  struct ev_io *io_event_ptr = get_io_event(d, fd);
  if (io_event_ptr) {
    ev_io_stop(d->loop, io_event_ptr);
    io_event_ptr->fd = 0;
    DLOG("Released used io event: %p", io_event_ptr);
  }
  if (!read && !write) {
    return;
  }
  // reserve and start new event on unused slot
  io_event_ptr = get_io_event(d, 0);
  if (!io_event_ptr) {
    FLOG("c-ares needed more IO event handler, than the number of provided nameservers: %d", d->io_events_count);
  }
  DLOG("Reserved new io event: %p", io_event_ptr);
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_io_init(io_event_ptr, sock_cb, fd,
             (read ? EV_READ : 0) | (write ? EV_WRITE : 0));
  ev_io_start(d->loop, io_event_ptr);
}

static char *get_addr_listing(char** addr_list, const int af) {
  char *list = (char *)calloc(1, POLLER_ADDR_LIST_SIZE);
  char *pos = list;
  if (list == NULL) {
    FLOG("Out of mem");
  }
  for (int i = 0; addr_list[i]; i++) {
    const char *res = ares_inet_ntop(af, addr_list[i], pos,
                                     list + POLLER_ADDR_LIST_SIZE - 1 - pos);
    if (res != NULL) {
      pos += strlen(pos);
      *pos = ',';
      pos++;
    }
  }
  if (pos == list) {
    free((void*)list);
    list = NULL;
  } else {
    *(pos-1) = '\0';
  }
  return list;
}

static void ares_cb(void *arg, int status, int __attribute__((unused)) timeouts,
                    struct hostent *h) {
  dns_poller_t *d = (dns_poller_t *)arg;
  d->request_ongoing = 0;
  ev_tstamp interval = 5;  // retry by default after some time

  if (status != ARES_SUCCESS) {
    WLOG("DNS lookup of '%s' failed: %s", d->hostname, ares_strerror(status));
  } else if (!h || h->h_length < 1) {
    WLOG("No hosts found for '%s'", d->hostname);
  } else {
    interval = d->polling_interval;
    d->cb(d->hostname, d->cb_data, get_addr_listing(h->h_addr_list, h->h_addrtype));
  }

  if (status != ARES_EDESTRUCTION) {
    DLOG("DNS poll interval changed to: %.0lf", interval);
    ev_timer_stop(d->loop, &d->timer);
    ev_timer_set(&d->timer, interval, 0);
    ev_timer_start(d->loop, &d->timer);
  }
}

static ev_tstamp get_timeout(dns_poller_t *d)
{
    static struct timeval max_tv = {.tv_sec = 5, .tv_usec = 0};
    struct timeval tv;
    struct timeval *tvp = ares_timeout(d->ares, &max_tv, &tv);
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    ev_tstamp after = tvp->tv_sec + tvp->tv_usec * 1e-6;
    return after ? after : 0.1;
}

static void timer_cb(struct ev_loop __attribute__((unused)) *loop,
                     ev_timer *w, int __attribute__((unused)) revents) {
  dns_poller_t *d = (dns_poller_t *)w->data;

  if (d->request_ongoing) {
    // process query timeouts
    DLOG("Processing DNS queries");
    ares_process(d->ares, NULL, NULL);
  } else {
    DLOG("Starting DNS query");
    // Cancel any pending queries before making new ones. c-ares can't be depended on to
    // execute ares_cb() even after the specified query timeout has been reached, e.g. if
    // the packet was dropped without any response from the network. This also serves to
    // free memory tied up by any "zombie" queries.
    ares_cancel(d->ares);
    d->request_ongoing = 1;
    ares_gethostbyname(d->ares, d->hostname, d->family, ares_cb, d);
  }

  if (d->request_ongoing) {  // need to re-check, it might change!
    const ev_tstamp interval = get_timeout(d);
    DLOG("DNS poll interval changed to: %.03f", interval);
    ev_timer_stop(d->loop, &d->timer);
    ev_timer_set(&d->timer, interval, 0);
    ev_timer_start(d->loop, &d->timer);
  }
}

void dns_poller_init(dns_poller_t *d, struct ev_loop *loop,
                     const char *bootstrap_dns,
                     int bootstrap_dns_polling_interval,
                     const char *hostname,
                     int family, dns_poller_cb cb, void *cb_data) {
  int r = ares_library_init(ARES_LIB_INIT_ALL);
  if (r != ARES_SUCCESS) {
    FLOG("ares_library_init error: %s", ares_strerror(r));
  }

  struct ares_options options = {
    .timeout = POLLER_QUERY_TIMEOUT_MS,
    .tries = POLLER_QUERY_TRIES,
    .sock_state_cb = sock_state_cb,
    .sock_state_cb_data = d
  };
  int optmask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB;

  r = ares_init_options(&d->ares, &options, optmask);
  if (r != ARES_SUCCESS) {
    FLOG("ares_init_options error: %s", ares_strerror(r));
  }

  r = ares_set_servers_ports_csv(d->ares, bootstrap_dns);
  if (r != ARES_SUCCESS) {
    FLOG("ares_set_servers_ports_csv error: %s", ares_strerror(r));
  }

  d->loop = loop;
  d->hostname = hostname;
  d->family = family;
  d->cb = cb;
  d->polling_interval = bootstrap_dns_polling_interval;
  d->request_ongoing = 0;
  d->cb_data = cb_data;

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_timer_init(&d->timer, timer_cb, 0, 0);
  d->timer.data = d;
  ev_timer_start(d->loop, &d->timer);

  int nameservers = 1;
  for (int i = 0; bootstrap_dns[i]; i++) {
    if (bootstrap_dns[i] == ',') {
      nameservers++;
    }
  }
  DLOG("Nameservers count: %d", nameservers);
  d->io_events = (ev_io *)calloc(nameservers, sizeof(ev_io));  // zeroed!
  if (!d->io_events) {
    FLOG("Out of mem");
  }
  for (int i = 0; i < nameservers; i++) {
    d->io_events[i].data = d;
  }
  d->io_events_count = nameservers;
}

void dns_poller_cleanup(dns_poller_t *d) {
  ares_destroy(d->ares);
  ev_timer_stop(d->loop, &d->timer);
  ares_library_cleanup();
  free(d->io_events);
}
