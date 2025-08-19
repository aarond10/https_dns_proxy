#ifndef _DNS_SERVER_TCP_H_
#define _DNS_SERVER_TCP_H_

#include <stdint.h>
#include <ev.h>

struct dns_server_tcp_s;

typedef void (*dns_tcp_req_received_cb)(struct dns_server_tcp_s *dns_server, void *data,
                                        int client_fd, uint16_t tx_id,
                                        char *dns_req, size_t dns_req_len);

typedef struct dns_server_tcp_s {
  struct ev_loop *loop;
  void *cb_data;
  dns_tcp_req_received_cb cb;
  int sock;
  ev_io watcher;
} dns_server_tcp_t;

void dns_server_tcp_init(dns_server_tcp_t *d, struct ev_loop *loop,
                        const char *listen_addr, int listen_port,
                        dns_tcp_req_received_cb cb, void *data);

void dns_server_tcp_respond(int client_fd, char *buf, size_t blen);

void dns_server_tcp_stop(dns_server_tcp_t *d);

void dns_server_tcp_cleanup(dns_server_tcp_t *d);

#endif // _DNS_SERVER_TCP_H_
