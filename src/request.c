#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dns_packet.h"
#include "options.h"
#include "logging.h"
#include "request.h"

static size_t write_buffer(
    void *contents, size_t size, size_t nmemb, void *userp) {
  struct Request *r = (struct Request *)userp;
  char *new_buf = (char *)realloc(r->buf, r->buflen + size * nmemb + 1);
  if(new_buf == NULL) {
    ELOG("Out of memory!");
    return 0;
  }
  r->buf = new_buf;
  memcpy(&(r->buf[r->buflen]), contents, size * nmemb);
  r->buflen += size * nmemb;
  // note: this doesn't mean strlen() is safe, just that we shouldn't overrun.
  r->buf[r->buflen] = '\0';
  return size * nmemb;
}
void request_init(struct Request* r, uint16_t tx_id, const char *url, 
                  struct sockaddr_in raddr, struct curl_slist *resolv) {
  r->curl = curl_easy_init();
  r->tx_id = tx_id;
  r->buf = NULL;
  r->buflen = 0;
  r->raddr = raddr;

  CURLcode res;
  if ((res = curl_easy_setopt(r->curl, CURLOPT_RESOLVE, resolv)) != CURLE_OK) {
    FLOG("CURLOPT_RESOLV error: %s", curl_easy_strerror(res));
  }
  curl_easy_setopt(r->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(r->curl, CURLOPT_URL, url);
  curl_easy_setopt(r->curl, CURLOPT_WRITEFUNCTION, &write_buffer);
  curl_easy_setopt(r->curl, CURLOPT_WRITEDATA, r);
  curl_easy_setopt(r->curl, CURLOPT_TCP_KEEPALIVE, 5L);
  curl_easy_setopt(r->curl, CURLOPT_USERAGENT, "dns-to-https-proxy/0.1");
  DLOG("Req %04x: %s", r->tx_id, url);
}

void request_send_response(struct Request *r, int listen_sock) {
  if (r->buf == NULL) {
    DLOG("No response received. Ignoring.");
    return;
  }
  uint8_t ret[1500];
  int len;
  if ((len = json_to_dns(r->tx_id, r->buf, ret, sizeof(ret))) < 0) {
    DLOG("Failed to translate JSON to DNS response.");
    return;
  }
  if (len > 0) {
    sendto(listen_sock, ret, len, 0, (struct sockaddr *)&r->raddr, sizeof(r->raddr));
  }
  DLOG("Resp %04x", r->tx_id);
}


void request_cleanup(struct Request *r) {
  curl_easy_cleanup(r->curl);
  free(r->buf);
}
