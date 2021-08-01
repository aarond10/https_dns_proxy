#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <ev.h>

struct dns_server_s;

typedef void (*dns_req_received_cb)(struct dns_server_s *dns_server, void *data,
                                    struct sockaddr* addr, uint16_t tx_id,
                                    char *dns_req, size_t dns_req_len);

typedef struct dns_server_s {
  struct ev_loop *loop;
  void *cb_data;
  dns_req_received_cb cb;
  int sock;
  socklen_t addrlen;
  ev_io watcher;
} dns_server_t;

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     const char *listen_addr, int listen_port,
                     dns_req_received_cb cb, void *data);

// Sends a DNS response 'buf' of length 'blen' to 'raddr'.
void dns_server_respond(dns_server_t *d, struct sockaddr *raddr, char *buf,
                        size_t blen);

void dns_server_stop(dns_server_t *d);

void dns_server_cleanup(dns_server_t *d);

#endif // _DNS_SERVER_H_
