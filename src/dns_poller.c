#include <sys/socket.h>
#include <sys/types.h>

#include <ares.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dns_poller.h"
#include "logging.h"

static void sock_cb(struct ev_loop *loop, ev_io *w, int revents) {
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
    ev_io_init(&d->fd[fd], sock_cb, fd,
               (read ? EV_READ : 0) | (write ? EV_WRITE : 0));
    d->fd[fd].data = d;
    ev_io_start(d->loop, &d->fd[fd]);
  } else {
    ev_io_init(&d->fd[fd], sock_cb, fd,
               (read ? EV_READ : 0) | (write ? EV_WRITE : 0));
    d->fd[fd].data = d;
    ev_io_start(d->loop, &d->fd[fd]);
  }
}

static void ares_cb(void *arg, int status, int timeouts, struct hostent *h) {
  dns_poller_t *d = (dns_poller_t *)arg;
  if (status != ARES_SUCCESS) {
    WLOG("DNS lookup failed: %d", status);
  } else if (!h || h->h_length < 1) {
    WLOG("No hosts.");
  } else {
    d->cb(d->hostname, d->cb_data, (struct sockaddr_in *)h->h_addr_list[0]);
  }
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  dns_poller_t *d = (dns_poller_t *)w->data;
  ares_gethostbyname(d->ares, d->hostname, AF_INET, ares_cb, d);
}

void dns_poller_init(dns_poller_t *d, struct ev_loop *loop,
                     const char *bootstrap_dns, const char *hostname,
                     int interval_seconds, dns_poller_cb cb, void *cb_data) {
  int i;
  for (i = 0; i < FD_SETSIZE; i++) {
    d->fd[i].fd = 0;
  }

  int r;
  ares_library_init(ARES_LIB_INIT_ALL);

  struct ares_options options;
  options.sock_state_cb = sock_state_cb;
  options.sock_state_cb_data = d;

  options.servers = NULL;
  options.nservers = 0;
  char *csv = strdup(bootstrap_dns);
  if (!csv) {
    FLOG("Out of mem");
  }
  char *last = NULL;
  char *ipstr = strtok_r(csv, ",", &last);
  while (ipstr) {
    options.servers = (struct in_addr *)realloc(
        options.servers, sizeof(struct in_addr)*(options.nservers + 1));
    if (!options.servers) {
      FLOG("Out of mem");
    }
    if (ares_inet_pton(AF_INET, ipstr, 
                       &options.servers[options.nservers++]) != 1) {
      if (ares_inet_pton(AF_INET6, ipstr, 
                         &options.servers[options.nservers++]) != 1) {
        FLOG("Failed to parse '%s'", ipstr);
      }
    }
    ipstr = strtok_r(NULL, ",", &last);
  }
  free(csv);

  if ((r = ares_init_options(
      &d->ares, &options, 
      ARES_OPT_SOCK_STATE_CB | ARES_OPT_SERVERS)) != ARES_SUCCESS) {
    FLOG("ares_init_options error: %s", ares_strerror(r));
  }

  free(options.servers);

  d->loop = loop;
  d->hostname = hostname;
  d->cb = cb;
  d->cb_data = cb_data;

  ev_timer_init(&d->timer, timer_cb, 0, interval_seconds);
  d->timer.data = d;
  ev_timer_start(d->loop, &d->timer);
}

void dns_poller_cleanup(dns_poller_t *d) {
  ev_timer_stop(d->loop, &d->timer);
  ares_destroy(d->ares);
  ares_library_cleanup();
}
