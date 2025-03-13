#ifndef _HTTPS_CLIENT_H_
#define _HTTPS_CLIENT_H_

#include <curl/curl.h>

#include "options.h"
#include "stat.h"

enum {
  HTTPS_SOCKET_LIMIT = 12,
  HTTPS_CONNECTION_LIMIT = 8,
};

// Callback type for receiving data when a transfer finishes.
typedef void (*https_response_cb)(void *data, char *buf, size_t buflen);

// Internal: Holds state on an individual transfer.
struct https_fetch_ctx {
  CURL *curl;
  char curl_errbuf[CURL_ERROR_SIZE];

  uint16_t id;

  https_response_cb cb;
  void *cb_data;

  char *buf;
  size_t buflen;

  struct https_fetch_ctx *next;
};

// Holds state on the whole multiplexed CURL machine.
typedef struct {
  struct ev_loop *loop;
  CURLM *curlm;
  struct curl_slist *header_list;
  struct https_fetch_ctx *fetches;

  ev_timer timer;
  ev_io io_events[HTTPS_SOCKET_LIMIT];
  int connections;

  options_t *opt;
  stat_t *stat;
} https_client_t;

void https_client_init(https_client_t *c, options_t *opt,
                       stat_t *stat, struct ev_loop *loop);

void https_client_fetch(https_client_t *c, const char *url,
                        const char* postdata, size_t postdata_len,
                        struct curl_slist *resolv, uint16_t id,
                        https_response_cb cb, void *data);

// Used to reset state of libcurl because streaming connections + IP changes
// seem to cause curl to flip out.
void https_client_reset(https_client_t *c);

void https_client_cleanup(https_client_t *c);

#endif // _HTTPS_CLIENT_H_
