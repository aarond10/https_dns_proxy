#ifndef _HTTPS_CLIENT_H_
#define _HTTPS_CLIENT_H_

#include <curl/curl.h>

#include "options.h"

// Callback type for receiving data when a transfer finishes.
typedef void (*https_response_cb)(void *data, char *buf, size_t buflen);

// Internal: Holds state on an individual transfer.
struct https_fetch_ctx {
  CURL *curl;
  struct curl_slist *header_list;

  https_response_cb cb;
  void *cb_data;

  char *buf;
  size_t buflen;

  struct https_fetch_ctx *next;
};

// Internal: Holds state on a socket watcher.
struct https_fd_watcher {
  ev_io watcher;
  struct https_fd_watcher *next;
};

// Holds state on the whole multiplexed CURL machine.
typedef struct {
  struct ev_loop *loop;
  CURLM *curlm;
  struct https_fetch_ctx *fetches;

  ev_timer timer;
  ev_io fd[FD_SETSIZE]; // I'm lazy.
  int still_running;

  options_t *opt;
} https_client_t;

void https_client_init(https_client_t *c, options_t *opt, struct ev_loop *loop);

void https_client_fetch(https_client_t *c, const char *url,
                        const char* postdata, size_t postdata_len,
                        struct curl_slist *resolv, https_response_cb cb,
                        void *data);

// Used to reset state of libcurl because streaming connections + IP changes
// seem to cause curl to flip out.
void https_client_reset(https_client_t *c);

void https_client_cleanup(https_client_t *c);

#endif // _HTTPS_CLIENT_H_
