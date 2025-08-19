#ifndef _DNS_SERVER_UDP_H_
#define _DNS_SERVER_UDP_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <ev.h>

struct dns_server_udp_s;

typedef void (*dns_udp_req_received_cb)(struct dns_server_udp_s *dns_server, void *data,
                                        struct sockaddr* addr, uint16_t tx_id,
                                        char *dns_req, size_t dns_req_len);

typedef struct dns_server_udp_s {
  struct ev_loop *loop;
  void *cb_data;
  dns_udp_req_received_cb cb;
  int sock;
  socklen_t addrlen;
  ev_io watcher;
} dns_server_udp_t;

void dns_server_udp_init(dns_server_udp_t *d, struct ev_loop *loop,
                        const char *listen_addr, int listen_port,
                        dns_udp_req_received_cb cb, void *data);

// Sends a DNS response 'buf' of length 'blen' to 'raddr'.
void dns_server_udp_respond(dns_server_udp_t *d, struct sockaddr *raddr, char *buf,
                            size_t blen);

void dns_server_udp_stop(dns_server_udp_t *d);

void dns_server_udp_cleanup(dns_server_udp_t *d);

#endif // _DNS_SERVER_UDP_H_
