#include <math.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
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

static void sock_state_cb(void *data, int fd, int read, int write) {
  dns_poller_t *d = (dns_poller_t *)data;
  if (!read && !write) {
    ev_io_stop(d->loop, &d->fd[fd]);
    d->fd[fd].fd = 0;
  } else if (d->fd[fd].fd != 0) {
    ev_io_stop(d->loop, &d->fd[fd]);
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    ev_io_init(&d->fd[fd], sock_cb, fd,
               (read ? EV_READ : 0) | (write ? EV_WRITE : 0));
    d->fd[fd].data = d;
    ev_io_start(d->loop, &d->fd[fd]);
  } else {
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    ev_io_init(&d->fd[fd], sock_cb, fd,
               (read ? EV_READ : 0) | (write ? EV_WRITE : 0));
    d->fd[fd].data = d;
    ev_io_start(d->loop, &d->fd[fd]);
  }
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
  ev_tstamp interval = NAN;

  if (status != ARES_SUCCESS) {
    interval = POLLER_INTVL_ERR;
    WLOG("DNS lookup failed: %s", ares_strerror(status));
  } else if (!h || h->h_length < 1) {
    interval = POLLER_INTVL_ERR;
    WLOG("No hosts.");
  } else {
    interval = d->polling_interval;
    d->cb(d->hostname, d->cb_data, get_addr_listing(h->h_addr_list, h->h_addrtype));
  }

  if (interval != d->timer.repeat && status != ARES_EDESTRUCTION) {
    DLOG("DNS poll interval changed from %.0lf -> %.0lf", d->timer.repeat, interval);
    ev_timer_stop(d->loop, &d->timer);
    ev_timer_set(&d->timer, interval, interval);
    ev_timer_start(d->loop, &d->timer);
  }
}

static void timer_cb(struct ev_loop __attribute__((unused)) *loop,
                     ev_timer *w, int __attribute__((unused)) revents) {
  dns_poller_t *d = (dns_poller_t *)w->data;
  // Cancel any pending queries before making new ones. c-ares can't be depended on to
  // execute ares_cb() even after the specified query timeout has been reached, e.g. if
  // the packet was dropped without any response from the network. This also serves to
  // free memory tied up by any "zombie" queries.
  ares_cancel(d->ares);
  ares_gethostbyname(d->ares, d->hostname, d->family, ares_cb, d);
}

void dns_poller_init(dns_poller_t *d, struct ev_loop *loop,
                     const char *bootstrap_dns,
                     int bootstrap_dns_polling_interval,
                     const char *hostname,
                     int family, dns_poller_cb cb, void *cb_data) {
  int i = 0;
  for (i = 0; i < FD_SETSIZE; i++) {
    d->fd[i].fd = 0;
  }

  int r = 0;
  ares_library_init(ARES_LIB_INIT_ALL);

  struct ares_options options;
  options.sock_state_cb = sock_state_cb;
  options.sock_state_cb_data = d;

  if ((r = ares_init_options(
      &d->ares, &options, ARES_OPT_SOCK_STATE_CB)) != ARES_SUCCESS) {
    FLOG("ares_init_options error: %s", ares_strerror(r));
  }

  if((r = ares_set_servers_ports_csv(d->ares, bootstrap_dns)) != ARES_SUCCESS) {
    FLOG("ares_set_servers_ports_csv error: %s", ares_strerror(r));
  }

  d->loop = loop;
  d->hostname = hostname;
  d->family = family;
  d->cb = cb;
  d->polling_interval = bootstrap_dns_polling_interval;
  d->cb_data = cb_data;

  // Start with a shorter polling interval and switch after we've bootstrapped.
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_timer_init(&d->timer, timer_cb, 0, POLLER_INTVL_ERR);
  d->timer.data = d;
  ev_timer_start(d->loop, &d->timer);
}

void dns_poller_cleanup(dns_poller_t *d) {
  ares_destroy(d->ares);
  ev_timer_stop(d->loop, &d->timer);
  ares_library_cleanup();
}
