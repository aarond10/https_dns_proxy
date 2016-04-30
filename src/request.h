#ifndef _REQUEST_H_
#define _REQUEST_H_

#include <arpa/inet.h>
#include <curl/curl.h>
#include <stdint.h>

struct Request {
  CURL *curl;
  uint16_t tx_id;
  char *buf;
  size_t buflen;
  struct sockaddr_in raddr;
};

void request_init(struct Request* r, uint16_t tx_id, const char *url, 
                  struct sockaddr_in raddr, struct curl_slist *resolv);

void request_send_response(struct Request *r, int listen_sock);

void request_cleanup(struct Request *r);

#endif // _REQUEST_H_
