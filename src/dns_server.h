#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <ev.h>

enum {
  DNS_HEADER_LENGTH = 12,  // RFC1035 4.1.1 header size
  DNS_SIZE_LIMIT = 512,
  DNS_REQUEST_BUFFER_SIZE = 4096  // EDNS default before DNS Flag Day 2020
};

struct dns_server_s;

typedef void (*dns_req_received_cb)(void *dns_server, uint8_t is_tcp, void *data,
                                    struct sockaddr* addr, char *dns_req, size_t dns_req_len);

typedef struct dns_server_s {
  struct ev_loop *loop;
  void *cb_data;
  dns_req_received_cb cb;
  int sock;
  socklen_t addrlen;
  ev_io watcher;
} dns_server_t;

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     struct addrinfo *listen_addrinfo,
                     dns_req_received_cb cb, void *data);

// Sends a DNS response 'buf' of length 'blen' to 'raddr'.
void dns_server_respond(dns_server_t *d, struct sockaddr *raddr,
    const char *dns_req, const size_t dns_req_len, char *dns_resp, size_t dns_resp_len);

void dns_server_stop(dns_server_t *d);

void dns_server_cleanup(dns_server_t *d);

#endif // _DNS_SERVER_H_
