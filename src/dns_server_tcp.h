#ifndef _DNS_SERVER_TCP_H_
#define _DNS_SERVER_TCP_H_

#include "dns_server.h"

typedef struct dns_server_tcp_s dns_server_tcp_t;

dns_server_tcp_t * dns_server_tcp_create(
    struct ev_loop *loop, struct addrinfo *listen_addrinfo,
    dns_req_received_cb cb, void *data, uint16_t tcp_client_limit);

void dns_server_tcp_respond(dns_server_tcp_t *d,
    struct sockaddr *raddr, char *resp, size_t resp_len);

void dns_server_tcp_stop(dns_server_tcp_t *d);

void dns_server_tcp_cleanup(dns_server_tcp_t *d);

#endif // _DNS_SERVER_H_
