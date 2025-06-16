#include <ares.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <errno.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <stdint.h>
#include <string.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "dns_server.h"
#include "logging.h"


// Creates and bind a listening UDP socket for incoming requests.
static int get_listen_sock(struct addrinfo *listen_addrinfo) {
  int sock = socket(listen_addrinfo->ai_family, SOCK_DGRAM, 0);
  if (sock < 0) {
    FLOG("Error creating socket: %s (%d)", strerror(errno), errno);
  }

  char ipstr[INET6_ADDRSTRLEN];
  if (listen_addrinfo->ai_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)listen_addrinfo->ai_addr)->sin_addr, ipstr, sizeof(ipstr));
  } else if (listen_addrinfo->ai_family == AF_INET6) {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)listen_addrinfo->ai_addr)->sin6_addr, ipstr, sizeof(ipstr));
  } else {
    FLOG("Unknown address family: %d", listen_addrinfo->ai_family);
  }

  uint16_t port = ntohs(((struct sockaddr_in*) listen_addrinfo->ai_addr)->sin_port);

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
  dns_server_t *d = (dns_server_t *)w->data;

  char tmp_buf[UINT16_MAX];  // stack buffer for largest UDP packet to support EDNS
  struct sockaddr_storage tmp_raddr;
  socklen_t tmp_addrlen = d->addrlen;  // recvfrom can write to addrlen
  ssize_t len = recvfrom(w->fd, tmp_buf, UINT16_MAX, 0, (struct sockaddr*)&tmp_raddr,
                         &tmp_addrlen);
  if (len < 0) {
    ELOG("recvfrom failed: %s", strerror(errno));
    return;
  }

  if (len < (int)sizeof(uint16_t)) {
    WLOG("Malformed request received, too short: %d", len);
    return;
  }

  char *dns_req = (char *)malloc(len);  // To free buffer after https request is complete.
  if (dns_req == NULL) {
    FLOG("Out of mem");
  }
  memcpy(dns_req, tmp_buf, len);  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

  d->cb(d, 0, d->cb_data, (struct sockaddr*)&tmp_raddr, dns_req, len);
}

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     struct addrinfo *listen_addrinfo,
                     dns_req_received_cb cb, void *data) {
  d->loop = loop;
  d->sock = get_listen_sock(listen_addrinfo);
  d->addrlen = listen_addrinfo->ai_addrlen;
  d->cb = cb;
  d->cb_data = data;

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_io_init(&d->watcher, watcher_cb, d->sock, EV_READ);
  d->watcher.data = d;
  ev_io_start(d->loop, &d->watcher);
}

void dns_server_respond(dns_server_t *d, struct sockaddr *raddr, char *buf,
                        size_t blen) {
  ssize_t len = sendto(d->sock, buf, blen, 0, raddr, d->addrlen);
  if(len == -1) {
    DLOG("sendto failed: %s", strerror(errno));
  }
}

void dns_server_stop(dns_server_t *d) {
  ev_io_stop(d->loop, &d->watcher);
}

void dns_server_cleanup(dns_server_t *d) {
  close(d->sock);
}
