#include <ares.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <arpa/inet.h>      // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <errno.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <netdb.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <netinet/in.h>     // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/socket.h>     // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "dns_server.h"
#include "logging.h"

// Creates and bind a listening UDP socket for incoming requests.
static int get_listen_sock(const char *listen_addr, int listen_port,
                           unsigned int *addrlen) {
  struct addrinfo *ai = NULL;
  struct addrinfo hints;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memset(&hints, 0, sizeof(struct addrinfo));
  /* prevent DNS lookups if leakage is our worry */
  hints.ai_flags = AI_NUMERICHOST;

  int res = getaddrinfo(listen_addr, NULL, &hints, &ai);
  if(res != 0) {
    FLOG("Error parsing listen address %s:%d (getaddrinfo): %s", listen_addr, listen_port,
          gai_strerror(res));
    if(ai) {
      freeaddrinfo(ai);
    }
    return -1;
  }

  struct sockaddr_in *saddr = (struct sockaddr_in*) ai->ai_addr;

  *addrlen = ai->ai_addrlen;
  saddr->sin_port = htons(listen_port);

  int sock = socket(ai->ai_family, SOCK_DGRAM, 0);
  if (sock < 0) {
    FLOG("Error creating socket");
  }

  if ((res = bind(sock, ai->ai_addr, ai->ai_addrlen)) < 0) {
    FLOG("Error binding %s:%d: %s (%d)", listen_addr, listen_port,
         strerror(errno), res);
  }

  freeaddrinfo(ai);

  ILOG("Listening on %s:%d", listen_addr, listen_port);
  return sock;
}

// A default MTU. We don't do TCP so any bigger is likely a waste.
#define REQUEST_MAX 1500

static void watcher_cb(struct ev_loop __attribute__((unused)) *loop,
                       ev_io *w, int __attribute__((unused)) revents) {
  dns_server_t *d = (dns_server_t *)w->data;

  char *buf = (char *)calloc(1, REQUEST_MAX + 1);
  if (buf == NULL) {
    FLOG("Out of mem");
  }
  struct sockaddr_storage raddr;
  /* recvfrom can write to addrlen */
  socklen_t tmp_addrlen = d->addrlen;
  ssize_t len = recvfrom(w->fd, buf, REQUEST_MAX, 0, (struct sockaddr*)&raddr,
                         &tmp_addrlen);
  if (len < 0) {
    ELOG("recvfrom failed: %s", strerror(errno));
    return;
  }

  if (len < (int)sizeof(uint16_t)) {
    WLOG("Malformed request received (too short).");
    return;
  }

  uint16_t tx_id = ntohs(*((uint16_t*)buf));
  d->cb(d, d->cb_data, (struct sockaddr*)&raddr, tx_id, buf, len);
}

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     const char *listen_addr, int listen_port,
                     dns_req_received_cb cb, void *data) {
  d->loop = loop;
  d->sock = get_listen_sock(listen_addr, listen_port, &d->addrlen);
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
