#include "dns_server_tcp.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#define REQUEST_MAX 4096

typedef struct {
  int fd;
  ev_io io;
  ev_timer timer;
  dns_server_tcp_t *server;
} tcp_client_t;

#define TCP_IDLE_TIMEOUT 90.0

static int get_listen_sock_tcp(const char *listen_addr, int listen_port) {
  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", listen_port);
  int res = getaddrinfo(listen_addr, port_str, &hints, &ai);
  if (res != 0) {
    FLOG("getaddrinfo failed: %s", gai_strerror(res));
    return -1;
  }

  int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (sock < 0) {
    FLOG("socket failed: %s", strerror(errno));
    freeaddrinfo(ai);
    return -1;
  }

  int optval = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
    FLOG("bind failed: %s", strerror(errno));
    close(sock);
    freeaddrinfo(ai);
    return -1;
  }

  if (listen(sock, 128) < 0) {
    FLOG("listen failed: %s", strerror(errno));
    close(sock);
    freeaddrinfo(ai);
    return -1;
  }

  freeaddrinfo(ai);
  ILOG("TCP Listening on %s:%d", listen_addr, listen_port);
  return sock;
}

static void tcp_client_close(struct ev_loop *loop, tcp_client_t *client) {
  ev_io_stop(loop, &client->io);
  ev_timer_stop(loop, &client->timer);
  close(client->fd);
  free(client);
}

static void tcp_client_timeout_cb(struct ev_loop *loop, ev_timer *w, int __attribute__((unused)) revents) {
  tcp_client_t *client = (tcp_client_t *)w->data;
  DLOG("TCP client fd %d timed out after %ds inactivity", client->fd, (int)TCP_IDLE_TIMEOUT);
  tcp_client_close(loop, client);
}

static void tcp_client_cb(struct ev_loop *loop, ev_io *w, int __attribute__((unused)) revents) {
  tcp_client_t *client = (tcp_client_t *)w->data;
  int client_fd = client->fd;
  uint8_t lenbuf[2];
  ssize_t n = recv(client_fd, lenbuf, 2, MSG_PEEK);
  if (n < 2) {
    tcp_client_close(loop, client);
    return;
  }
  recv(client_fd, lenbuf, 2, 0);
  uint16_t msglen = (lenbuf[0] << 8) | lenbuf[1];
  if (msglen > REQUEST_MAX) {
    WLOG("TCP DNS request too large");
    tcp_client_close(loop, client);
    return;
  }
  char *buf = (char *)calloc(1, msglen + 1);
  if (!buf) {
    FLOG("Out of mem");
    tcp_client_close(loop, client);
    return;
  }
  ssize_t rlen = recv(client_fd, buf, msglen, 0);
  if (rlen < msglen) {
    WLOG("Short TCP DNS read");
    free(buf);
    tcp_client_close(loop, client);
    return;
  }
  uint16_t tx_id = ntohs(*((uint16_t*)buf));
  dns_server_tcp_t *d = client->server;
  d->cb(d, d->cb_data, client_fd, tx_id, buf, msglen);
  // Reset inactivity timer
  ev_timer_stop(loop, &client->timer);
  ev_timer_set(&client->timer, TCP_IDLE_TIMEOUT, 0.0);
  ev_timer_start(loop, &client->timer);
}

static void tcp_accept_cb(struct ev_loop *loop, ev_io *w, int __attribute__((unused)) revents) {
  dns_server_tcp_t *d = (dns_server_tcp_t *)w->data;
  int client_fd = accept(w->fd, NULL, NULL);
  if (client_fd < 0) {
    ELOG("accept failed: %s", strerror(errno));
    return;
  }
  tcp_client_t *client = (tcp_client_t *)calloc(1, sizeof(tcp_client_t));
  if (!client) {
    FLOG("Out of mem");
    close(client_fd);
    return;
  }
  client->fd = client_fd;
  client->server = d;
  client->io.data = client;
  client->timer.data = client;
  ev_io_init(&client->io, tcp_client_cb, client_fd, EV_READ);
  ev_timer_init(&client->timer, tcp_client_timeout_cb, TCP_IDLE_TIMEOUT, 0.0);
  ev_io_start(loop, &client->io);
  ev_timer_start(loop, &client->timer);
}

void dns_server_tcp_init(dns_server_tcp_t *d, struct ev_loop *loop,
                        const char *listen_addr, int listen_port,
                        dns_tcp_req_received_cb cb, void *data) {
  d->loop = loop;
  d->sock = get_listen_sock_tcp(listen_addr, listen_port);
  d->cb = cb;
  d->cb_data = data;
  ev_io_init(&d->watcher, tcp_accept_cb, d->sock, EV_READ);
  d->watcher.data = d;
  ev_io_start(d->loop, &d->watcher);
}

void dns_server_tcp_respond(int client_fd, char *buf, size_t blen) {
  uint8_t lenbuf[2];
  lenbuf[0] = (blen >> 8) & 0xff;
  lenbuf[1] = blen & 0xff;
  send(client_fd, lenbuf, 2, 0);
  send(client_fd, buf, blen, 0);
}

void dns_server_tcp_stop(dns_server_tcp_t *d) {
  ev_io_stop(d->loop, &d->watcher);
}

void dns_server_tcp_cleanup(dns_server_tcp_t *d) {
  close(d->sock);
}
