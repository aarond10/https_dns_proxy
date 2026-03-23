#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns_common.h"
#include "dns_listener_udp.h"
#include "dns_truncate.h"
#include "logging.h"

typedef struct dns_listener_udp_s {
  dns_listener_t base;

  struct ev_loop *loop;
  int sock;
  socklen_t addrlen;
  ev_io watcher;

  dns_request_fn cb;
  void *cb_data;
} dns_listener_udp_t;

// Creates and binds a listening UDP socket for incoming requests.
static int get_listen_sock(struct addrinfo *listen_addrinfo) {
  int sock = socket(listen_addrinfo->ai_family, SOCK_DGRAM, 0);
  if (sock < 0) {
    FLOG("Error creating socket: %s (%d)", strerror(errno), errno);
  }

  uint16_t port = 0;
  char ipstr[INET6_ADDRSTRLEN];
  if (listen_addrinfo->ai_family == AF_INET) {
    port = ntohs(((struct sockaddr_in*) listen_addrinfo->ai_addr)->sin_port);
    inet_ntop(AF_INET, &((struct sockaddr_in *)listen_addrinfo->ai_addr)->sin_addr, ipstr, sizeof(ipstr));
  } else if (listen_addrinfo->ai_family == AF_INET6) {
    port = ntohs(((struct sockaddr_in6*) listen_addrinfo->ai_addr)->sin6_port);
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)listen_addrinfo->ai_addr)->sin6_addr, ipstr, sizeof(ipstr));
  } else {
    FLOG("Unknown address family: %d", listen_addrinfo->ai_family);
  }

  int res = bind(sock, listen_addrinfo->ai_addr, listen_addrinfo->ai_addrlen);
  if (res < 0) {
    FLOG("Error binding on %s:%d UDP: %s (%d)", ipstr, port,
         strerror(errno), errno);
  }

  ILOG("Listening on %s:%d UDP", ipstr, port);

  return sock;
}

static void watcher_cb(struct ev_loop __attribute__((unused)) *loop,
                       ev_io *w, int __attribute__((unused)) revents) {
  dns_listener_udp_t *d = (dns_listener_udp_t *)w->data;

  char tmp_buf[DNS_REQUEST_BUFFER_SIZE];
  struct sockaddr_storage tmp_raddr;
  socklen_t tmp_addrlen = d->addrlen;  // recvfrom can write to addrlen
  ssize_t len = recvfrom(w->fd, tmp_buf, DNS_REQUEST_BUFFER_SIZE, MSG_TRUNC,
                         (struct sockaddr*)&tmp_raddr, &tmp_addrlen);
  if (len < 0) {
    ELOG("recvfrom failed: %s", strerror(errno));
    return;
  }
  if (len > DNS_REQUEST_BUFFER_SIZE) {
    WLOG("Unsupported request received, too large: %d. Limit is: %d",
         len, DNS_REQUEST_BUFFER_SIZE);
    return;
  }
  if (len < DNS_HEADER_LENGTH) {
    WLOG("Malformed request received, too short: %d", len);
    return;
  }

  char *dns_req = (char *)malloc((size_t)len);  // freed when DoH request completes
  if (dns_req == NULL) {
    FLOG("Out of mem");
  }
  memcpy(dns_req, tmp_buf, (size_t)len);

  d->cb(d->cb_data, &d->base, (struct sockaddr*)&tmp_raddr, dns_req, (size_t)len);
}

static void udp_respond(dns_listener_t *self, struct sockaddr *raddr,
                        const char *dns_req, size_t dns_req_len,
                        char *dns_resp, size_t dns_resp_len) {
  dns_listener_udp_t *d = (dns_listener_udp_t *)self;

  if (dns_resp_len < DNS_HEADER_LENGTH) {
    WLOG("Malformed response received, invalid length: %u", dns_resp_len);
    return;
  }
  dns_truncate_for_udp(dns_req, dns_req_len, dns_resp, &dns_resp_len);

  ssize_t len = sendto(d->sock, dns_resp, dns_resp_len, 0, raddr, d->addrlen);
  if (len == -1) {
    DLOG("sendto failed: %s", strerror(errno));
  }
}

static void udp_stop(dns_listener_t *self) {
  dns_listener_udp_t *d = (dns_listener_udp_t *)self;
  ev_io_stop(d->loop, &d->watcher);
}

static void udp_destroy(dns_listener_t *self) {
  dns_listener_udp_t *d = (dns_listener_udp_t *)self;
  close(d->sock);
  free(d);
}

dns_listener_t * dns_udp_listener_create(struct ev_loop *loop,
                                         struct addrinfo *listen_addrinfo,
                                         dns_request_fn cb, void *ctx) {
  dns_listener_udp_t *d = (dns_listener_udp_t *)calloc(1, sizeof(dns_listener_udp_t));
  if (d == NULL) {
    FLOG("Out of mem");
  }
  d->base.respond = udp_respond;
  d->base.stop = udp_stop;
  d->base.destroy = udp_destroy;
  d->base.transport = DNS_TRANSPORT_UDP;
  d->loop = loop;
  d->sock = get_listen_sock(listen_addrinfo);
  d->addrlen = listen_addrinfo->ai_addrlen;
  d->cb = cb;
  d->cb_data = ctx;
  ev_io_init(&d->watcher, watcher_cb, d->sock, EV_READ);
  d->watcher.data = d;
  ev_io_start(d->loop, &d->watcher);
  return &d->base;
}
