#include <errno.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <ev.h>            // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <math.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <netinet/in.h>    // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/socket.h>    // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <ctype.h>

#include "https_client.h"
#include "logging.h"
#include "options.h"

#define ASSERT_CURL_MULTI_SETOPT(curlm, option, param) \
  do { \
    CURLMcode code = curl_multi_setopt(curlm, option, param); \
    if (code != CURLM_OK) { \
      FLOG(#option " error %d: %s", code, curl_multi_strerror(code)); \
    } \
  } while(0);

#define ASSERT_CURL_EASY_SETOPT(curl, option, param) \
  do { \
    CURLcode code = curl_easy_setopt(curl, option, param); \
    if (code != CURLE_OK) { \
      FLOG(#option " error %d: %s", code, curl_easy_strerror(code)); \
    } \
  } while(0);

static size_t write_buffer(void *buf, size_t size, size_t nmemb, void *userp) {
  struct https_fetch_ctx *ctx = (struct https_fetch_ctx *)userp;
  char *new_buf = (char *)realloc(
      ctx->buf, ctx->buflen + size * nmemb + 1);
  if (new_buf == NULL) {
    ELOG("Out of memory!");
    return 0;
  }
  ctx->buf = new_buf;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memcpy(&(ctx->buf[ctx->buflen]), buf, size * nmemb);
  ctx->buflen += size * nmemb;
  // We always expect to receive valid non-null ASCII but just to be safe...
  ctx->buf[ctx->buflen] = '\0';
  return size * nmemb;
}

static curl_socket_t opensocket_callback(void *clientp, curlsocktype purpose,
                                         struct curl_sockaddr *addr) {
  curl_socket_t sock = socket(addr->family, addr->socktype, addr->protocol);

  DLOG("curl opened socket: %d", sock);

#if defined(IP_TOS)
  if (purpose != CURLSOCKTYPE_IPCXN) {
    return sock;
  }

  if (sock != -1) {
    if (addr->family == AF_INET) {
        (void)setsockopt(sock, IPPROTO_IP, IP_TOS, (int *)clientp, sizeof(int));
    }
#if defined(IPV6_TCLASS)
    else if (addr->family == AF_INET6) {
        (void)setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (int *)clientp, sizeof(int));
    }
#endif
  }
#endif

  return sock;
}

static int closesocket_callback(void __attribute__((unused)) *clientp, curl_socket_t item)
{
  DLOG("curl closed socket: %d", item);
  return 0;
}

static void https_fetch_ctx_init(https_client_t *client,
                                 struct https_fetch_ctx *ctx, const char *url,
                                 const char* data, size_t datalen,
                                 struct curl_slist *resolv,
                                 https_response_cb cb, void *cb_data) {
  ctx->curl = curl_easy_init(); // if fails, first setopt will fail
  ctx->cb = cb;
  ctx->cb_data = cb_data;
  ctx->buf = NULL;
  ctx->buflen = 0;
  ctx->next = client->fetches;
  client->fetches = ctx;

  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_RESOLVE, resolv);

  DLOG("Requesting HTTP/1.1: %d\n", client->opt->use_http_1_1);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_HTTP_VERSION,
                          client->opt->use_http_1_1 ?
                          CURL_HTTP_VERSION_1_1 :
                          CURL_HTTP_VERSION_2_0);
  if (logging_debug_enabled()) {
    ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_VERBOSE, 1L);
    ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
    ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_CLOSESOCKETFUNCTION, closesocket_callback);
  }
#if defined(IP_TOS)
  if (client->opt->dscp) {
    ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_OPENSOCKETDATA, &client->opt->dscp);
    if (!logging_debug_enabled()) {
        ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
      }
  }
#endif
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_URL, url);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_HTTPHEADER, client->header_list);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_POSTFIELDSIZE, datalen);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_POSTFIELDS, data);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_WRITEFUNCTION, &write_buffer);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_WRITEDATA, ctx);
#ifdef CURLOPT_MAXAGE_CONN
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_TCP_KEEPALIVE, 1L);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_TCP_KEEPIDLE, 50L);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_TCP_KEEPINTVL, 50L);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_MAXAGE_CONN, 300L);
#endif
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_USERAGENT, "dns-to-https-proxy/0.2");
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_FOLLOWLOCATION, 0);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_NOSIGNAL, 0);
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_TIMEOUT, 10 /* seconds */);
  // We know Google supports this, so force it.
  ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
  if (client->opt->curl_proxy) {
    DLOG("Using curl proxy: %s", client->opt->curl_proxy);
    ASSERT_CURL_EASY_SETOPT(ctx->curl, CURLOPT_PROXY, client->opt->curl_proxy);
  }
  CURLMcode code = curl_multi_add_handle(client->curlm, ctx->curl);
  if (code != CURLM_OK) {
    FLOG("curl_multi_add_handle error %d: %s", code, curl_multi_strerror(code));
  }
}

static void https_log_response_content(char *ptr, size_t size)
{
  const size_t width = 0x10;

  for (size_t i = 0; i < size; i += width) {
    char hex[3 * width + 1];
    char str[width + 1];
    size_t hex_off = 0;
    size_t str_off = 0;
    memset(hex, 0, sizeof(hex));
    memset(str, 0, sizeof(str));

    for (size_t c = 0; c < width; c++) {
      if (i+c < size) {
        hex_off += snprintf(hex + hex_off, sizeof(hex) - hex_off,
                            "%02x ", (unsigned char)ptr[i+c]);
        str_off += snprintf(str + str_off, sizeof(str) - str_off,
                            "%c", isprint(ptr[i+c]) ? ptr[i+c] : '.');
      } else {
        hex_off += snprintf(hex + hex_off, sizeof(hex) - hex_off, "   ");
      }
    }

    ELOG("%4.4lx: %s%s", (long)i, hex, str);
  }
}

static void https_fetch_ctx_process_response(https_client_t *client,
                                             struct https_fetch_ctx *ctx)
{
  CURLcode res = 0;
  long long_resp = 0;
  char *str_resp = NULL;
  int faulty_response = 1;

  if ((res = curl_easy_getinfo(
        ctx->curl, CURLINFO_RESPONSE_CODE, &long_resp)) != CURLE_OK) {
    ELOG("CURLINFO_RESPONSE_CODE: %s", curl_easy_strerror(res));
  } else {
    if (long_resp == 200) {
      faulty_response = 0;
    } else {
      ELOG("curl response code: %d, content length: %zu", long_resp, ctx->buflen);
      if (ctx->buflen >= 0) {
        https_log_response_content(ctx->buf, ctx->buflen);
      }
    }
  }

  if (logging_debug_enabled() || faulty_response || ctx->buflen == 0) {
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_REDIRECT_URL, &str_resp)) != CURLE_OK) {
      ELOG("CURLINFO_REDIRECT_URL: %s", curl_easy_strerror(res));
    } else if (str_resp != NULL) {
      ELOG("Request would be redirected to: %s", str_resp);
      if (strcmp(str_resp, client->opt->resolver_url)) {
        ELOG("Please update Resolver URL to avoid redirection!");
      }
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_SSL_VERIFYRESULT, &long_resp)) != CURLE_OK) {
      ELOG("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(res));
    } else if (long_resp != CURLE_OK) {
      ELOG("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(long_resp));
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_OS_ERRNO, &long_resp)) != CURLE_OK) {
      ELOG("CURLINFO_OS_ERRNO: %s", curl_easy_strerror(res));
    } else if (long_resp != 0) {
      ELOG("CURLINFO_OS_ERRNO: %d %s", long_resp, strerror(long_resp));
      if (long_resp == ENETUNREACH && !client->opt->ipv4) {
        ELOG("Try to run application with -4 argument!");
      }
    }
  }

  if (logging_debug_enabled()) {
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_EFFECTIVE_URL, &str_resp)) != CURLE_OK) {
      ELOG("CURLINFO_EFFECTIVE_URL: %s", curl_easy_strerror(res));
    } else {
      DLOG("CURLINFO_EFFECTIVE_URL: %s", str_resp);
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_HTTP_VERSION, &long_resp)) != CURLE_OK) {
      ELOG("CURLINFO_HTTP_VERSION: %s", curl_easy_strerror(res));
    } else {
      switch (long_resp) {
        case CURL_HTTP_VERSION_1_0:
          DLOG("CURLINFO_HTTP_VERSION: 1.0");
          break;
        case CURL_HTTP_VERSION_1_1:
          DLOG("CURLINFO_HTTP_VERSION: 1.1");
          break;
        case CURL_HTTP_VERSION_2_0:
          DLOG("CURLINFO_HTTP_VERSION: 2");
          break;
        default:
          DLOG("CURLINFO_HTTP_VERSION: %d", long_resp);
      }
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_PROTOCOL, &long_resp)) != CURLE_OK) {
      ELOG("CURLINFO_PROTOCOL: %s", curl_easy_strerror(res));
    } else if (long_resp != CURLPROTO_HTTPS) {
      DLOG("CURLINFO_PROTOCOL: %d", long_resp);
    }

    double namelookup_time = NAN;
    double connect_time = NAN;
    double appconnect_time = NAN;
    double pretransfer_time = NAN;
    double starttransfer_time = NAN;
    double total_time = NAN;
    if (curl_easy_getinfo(ctx->curl,
                          CURLINFO_NAMELOOKUP_TIME, &namelookup_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_CONNECT_TIME, &connect_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_APPCONNECT_TIME, &appconnect_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_PRETRANSFER_TIME, &pretransfer_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_STARTTRANSFER_TIME, &starttransfer_time) != CURLE_OK ||
        curl_easy_getinfo(ctx->curl,
                          CURLINFO_TOTAL_TIME, &total_time) != CURLE_OK) {
      ELOG("Error getting timing");
    } else {
      DLOG("Times: %lf, %lf, %lf, %lf, %lf, %lf",
           namelookup_time, connect_time, appconnect_time, pretransfer_time,
           starttransfer_time, total_time);
    }
  }

  ctx->cb(ctx->cb_data, ctx->buf, ctx->buflen);
}

static void https_fetch_ctx_cleanup(https_client_t *client,
                                    struct https_fetch_ctx *ctx) {
  struct https_fetch_ctx *last = NULL;
  struct https_fetch_ctx *cur = client->fetches;
  while (cur) {
    if (cur == ctx) {
      CURLMcode code = curl_multi_remove_handle(client->curlm, ctx->curl);
      if (code != CURLM_OK) {
        FLOG("curl_multi_remove_handle error %d: %s", code, curl_multi_strerror(code));
      }
      https_fetch_ctx_process_response(client, ctx);
      curl_easy_cleanup(ctx->curl);
      free(cur->buf);
      if (last) {
        last->next = cur->next;
      } else {
        client->fetches = cur->next;
      }
      free(cur);
      return;
    }
    last = cur;
    cur = cur->next;
  }
}

static void check_multi_info(https_client_t *c) {
  CURLMsg *msg = NULL;
  int msgs_left = 0;
  while ((msg = curl_multi_info_read(c->curlm, &msgs_left))) {
    if (msg->msg == CURLMSG_DONE) {
      struct https_fetch_ctx *n = c->fetches;
      while (n) {
        if (n->curl == msg->easy_handle) {
          https_fetch_ctx_cleanup(c, n);
          break;
        }
        n = n->next;
      }
    }
  }
}

static void sock_cb(struct ev_loop __attribute__((unused)) *loop,
                    struct ev_io *w, int revents) {
  https_client_t *c = (https_client_t *)w->data;
  if (c == NULL) {
    FLOG("c is NULL");
  }
  CURLMcode code = curl_multi_socket_action(
      c->curlm, w->fd, (revents & EV_READ ? CURL_CSELECT_IN : 0) |
                       (revents & EV_WRITE ? CURL_CSELECT_OUT : 0),
      &c->still_running);
  if (code != CURLM_OK) {
    FLOG("curl_multi_socket_action error %d: %s", code, curl_multi_strerror(code));
  }
  check_multi_info(c);
}

static void timer_cb(struct ev_loop __attribute__((unused)) *loop,
                     struct ev_timer *w, int __attribute__((unused)) revents) {
  https_client_t *c = (https_client_t *)w->data;
  CURLMcode code = curl_multi_socket_action(c->curlm, CURL_SOCKET_TIMEOUT, 0,
                                          &c->still_running);
  if (code != CURLM_OK) {
    FLOG("curl_multi_socket_action error %d: %s", code, curl_multi_strerror(code));
  }
  check_multi_info(c);
}

static struct ev_io * get_io_event(struct ev_io io_events[], curl_socket_t sock) {
  for (int i = 0; i < MAX_TOTAL_CONNECTIONS; i++) {
    if (io_events[i].fd == sock) {
      return &io_events[i];
    }
  }
  return NULL;
}

static int multi_sock_cb(CURL *curl, curl_socket_t sock, int what,
                         void *userp, void __attribute__((unused)) *sockp) {
  https_client_t *c = (https_client_t *)userp;
  if (!curl) {
    FLOG("Unexpected NULL pointer for CURL");
  }
  if (!c) {
    FLOG("Unexpected NULL pointer for https_client_t");
  }
  // stop and release used event
  struct ev_io *io_event_ptr = get_io_event(c->io_events, sock);
  if (io_event_ptr) {
    ev_io_stop(c->loop, io_event_ptr);
    io_event_ptr->fd = 0;
    DLOG("Released used io event: %p", io_event_ptr);
  }
  if (what == CURL_POLL_REMOVE) {
    return 0;
  }
  // reserve and start new event on unused slot
  io_event_ptr = get_io_event(c->io_events, 0);
  if (!io_event_ptr) {
    FLOG("curl needed more event, than max connection!");
  }
  DLOG("Reserved new io event: %p", io_event_ptr);
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_io_init(io_event_ptr, sock_cb, sock,
             ((what & CURL_POLL_IN) ? EV_READ : 0) |
             ((what & CURL_POLL_OUT) ? EV_WRITE : 0));
  ev_io_start(c->loop, io_event_ptr);
  return 0;
}

static int multi_timer_cb(CURLM __attribute__((unused)) *multi,
                          long timeout_ms, void *userp) {
  https_client_t *c = (https_client_t *)userp;
  ev_timer_stop(c->loop, &c->timer);
  if (timeout_ms > 0) {
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    ev_timer_init(&c->timer, timer_cb, timeout_ms / 1000.0, 0);
    ev_timer_start(c->loop, &c->timer);
  } else {
    timer_cb(c->loop, &c->timer, 0);
  }
  return 0;
}

void https_client_init(https_client_t *c, options_t *opt, struct ev_loop *loop) {
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memset(c, 0, sizeof(*c));
  c->loop = loop;
  c->curlm = curl_multi_init(); // if fails, first setopt will fail
  c->header_list = curl_slist_append(curl_slist_append(NULL,
    "Accept: application/dns-message"),
    "Content-Type: application/dns-message");
  c->fetches = NULL;
  c->timer.data = c;
  for (int i = 0; i < MAX_TOTAL_CONNECTIONS; i++) {
    c->io_events[i].data = c;
  }
  c->opt = opt;

  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_PIPELINING,
                           c->opt->use_http_1_1 ?
                           CURLPIPE_HTTP1 :
                           CURLPIPE_MULTIPLEX);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_MAX_TOTAL_CONNECTIONS, MAX_TOTAL_CONNECTIONS);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_SOCKETDATA, c);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_SOCKETFUNCTION, multi_sock_cb);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_TIMERDATA, c);
  ASSERT_CURL_MULTI_SETOPT(c->curlm, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
}

void https_client_fetch(https_client_t *c, const char *url,
                        const char* postdata, size_t postdata_len,
                        struct curl_slist *resolv, https_response_cb cb,
                        void *data) {
  struct https_fetch_ctx *new_ctx =
      (struct https_fetch_ctx *)calloc(1, sizeof(struct https_fetch_ctx));
  if (!new_ctx) {
    FLOG("Out of mem");
  }
  https_fetch_ctx_init(c, new_ctx, url, postdata, postdata_len, resolv, cb, data);
}

void https_client_reset(https_client_t *c) {
  options_t *opt = c->opt;
  struct ev_loop *loop = c->loop;
  https_client_cleanup(c);
  https_client_init(c, opt, loop);
}

void https_client_cleanup(https_client_t *c) {
  while (c->fetches) {
    https_fetch_ctx_cleanup(c, c->fetches);
  }
  curl_slist_free_all(c->header_list);
  curl_multi_cleanup(c->curlm);
}
