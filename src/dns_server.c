#include <sys/socket.h>
#include <sys/types.h>

#include <ares.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <ev.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dns_server.h"
#include "logging.h"

// Creates and bind a listening UDP socket for incoming requests.
static int get_listen_sock(const char *listen_addr, int listen_port,
                           unsigned int *addrlen) {
  struct addrinfo *ai = NULL;
  struct addrinfo hints;
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
    FLOG("Error binding %s:%d: %s", listen_addr, listen_port, strerror(res));
  }

  freeaddrinfo(ai);

  ILOG("Listening on %s:%d", listen_addr, listen_port);
  return sock;
}

static uint16_t next_uint16(unsigned char **const p) {
  uint16_t u;
  memcpy(&u, *p, sizeof(u));
  *p += sizeof(u);
  return u;
}

static void watcher_cb(struct ev_loop *loop, ev_io *w, int revents) {
  dns_server_t *d = (dns_server_t *)w->data;

  // A default MTU. We don't do TCP so any bigger is likely a waste.
  unsigned char buf[1500];
  struct sockaddr_storage raddr;
  /* recvfrom can write to addrlen */
  socklen_t tmp_addrlen = d->addrlen;
  int len = recvfrom(w->fd, buf, sizeof(buf), 0, (struct sockaddr*)&raddr,
                     &tmp_addrlen);
  if (len < 0) {
    WLOG("recvfrom failed: %s", strerror(errno));
    return;
  }

  if (len < sizeof(uint16_t) * 3) {
    DLOG("Malformed request received (too short).");
    return;
  }

  unsigned char *p = buf;
  uint16_t tx_id = ntohs(next_uint16(&p));
  uint16_t flags = ntohs(next_uint16(&p));
  uint16_t num_q = ntohs(next_uint16(&p));
  //uint16_t num_rr = ntohs(next_uint16(&p));
  next_uint16(&p);
  //uint16_t num_arr = ntohs(next_uint16(&p));
  next_uint16(&p);
  //uint16_t num_xrr = ntohs(next_uint16(&p));
  next_uint16(&p);

  if (num_q != 1) {
    DLOG("Malformed request received.");
    return;
  };
  char *domain_name;
  long enc_len;
  if (ares_expand_name(p, buf, len, &domain_name, &enc_len) != ARES_SUCCESS) {
    DLOG("Malformed request received.");
    return;
  }
  p += enc_len;
  uint16_t type = ntohs(next_uint16(&p));

  d->cb(d, d->cb_data, (struct sockaddr*)&raddr, tx_id, flags, domain_name, type);

  ares_free_string(domain_name);
}

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     const char *listen_addr, int listen_port,
                     dns_req_received_cb cb, void *data) {
  d->loop = loop;
  d->sock = get_listen_sock(listen_addr, listen_port, &d->addrlen);
  d->cb = cb;
  d->cb_data = data;

  ev_io_init(&d->watcher, watcher_cb, d->sock, EV_READ);
  d->watcher.data = d;
  ev_io_start(d->loop, &d->watcher);
}

void dns_server_respond(dns_server_t *d, struct sockaddr *raddr, char *buf,
                        int blen) {
  size_t len = sendto(d->sock, buf, blen, 0, raddr, d->addrlen);
  if(len == -1) {
    DLOG("sendto failed: %s", strerror(errno));
  }
}

void dns_server_cleanup(dns_server_t *d) {
  ev_io_stop(d->loop, &d->watcher);
  close(d->sock);
}
