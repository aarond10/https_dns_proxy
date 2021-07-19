#include <ctype.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <errno.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <ev.h>            // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <math.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <netinet/in.h>    // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <stdio.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/socket.h>    // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>

#include "https_client.h"
#include "logging.h"
#include "options.h"

#define DOH_CONTENT_TYPE "application/dns-message"

// the following macros require to have ctx pointer to https_fetch_ctx structure
// else: compilation failure will occur
#define LOG_REQ(level, format, args...) LOG(level, "%04hX: " format, ctx->id, ## args)
#define DLOG_REQ(format, args...) DLOG("%04hX: " format, ctx->id, ## args)
#define ILOG_REQ(format, args...) ILOG("%04hX: " format, ctx->id, ## args)
#define WLOG_REQ(format, args...) WLOG("%04hX: " format, ctx->id, ## args)
#define ELOG_REQ(format, args...) ELOG("%04hX: " format, ctx->id, ## args)
#define FLOG_REQ(format, args...) FLOG("%04hX: " format, ctx->id, ## args)

#define ASSERT_CURL_MULTI_SETOPT(curlm, option, param) \
  do { \
    CURLMcode code = curl_multi_setopt((curlm), (option), (param)); \
    if (code != CURLM_OK) { \
      FLOG(#option " error %d: %s", code, curl_multi_strerror(code)); \
    } \
  } while(0);

#define ASSERT_CURL_EASY_SETOPT(ctx, option, param) \
  do { \
    CURLcode code = curl_easy_setopt((ctx)->curl, (option), (param)); \
    if (code != CURLE_OK) { \
      FLOG_REQ(#option " error %d: %s", code, curl_easy_strerror(code)); \
    } \
  } while(0);

static size_t write_buffer(void *buf, size_t size, size_t nmemb, void *userp) {
  struct https_fetch_ctx *ctx = (struct https_fetch_ctx *)userp;
  char *new_buf = (char *)realloc(
      ctx->buf, ctx->buflen + size * nmemb + 1);
  if (new_buf == NULL) {
    ELOG_REQ("Out of memory!");
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
  https_client_t *client = (https_client_t *)clientp;

  curl_socket_t sock = socket(addr->family, addr->socktype, addr->protocol);

  DLOG("curl opened socket: %d", sock);

  if (client->stat) {
    stat_connection_opened(client->stat);
  }

#if defined(IP_TOS)
  if (purpose != CURLSOCKTYPE_IPCXN) {
    return sock;
  }

  if (sock != -1) {
    if (addr->family == AF_INET) {
        setsockopt(sock, IPPROTO_IP, IP_TOS,
                   &client->opt->dscp, sizeof(client->opt->dscp));
    }
#if defined(IPV6_TCLASS)
    else if (addr->family == AF_INET6) {
        setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS,
                   &client->opt->dscp, sizeof(client->opt->dscp));
    }
#endif
  }
#endif

  return sock;
}

static int closesocket_callback(void __attribute__((unused)) *clientp, curl_socket_t sock)
{
  https_client_t *client = (https_client_t *)clientp;

  if (close(sock) == 0) {
    DLOG("curl closed socket: %d", sock);
  } else {
    FLOG("Could not close curl socket %d:%s", errno, strerror(errno));
  }

  if (client->stat) {
    stat_connection_closed(client->stat);
  }

  return 0;
}

static void https_log_data(enum LogSeverity level, struct https_fetch_ctx *ctx,
                           char *ptr, size_t size)
{
  const size_t width = 0x10;

  for (size_t i = 0; i < size; i += width) {
    char hex[3 * width + 1];
    char str[width + 1];
    size_t hex_off = 0;
    size_t str_off = 0;
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memset(hex, 0, sizeof(hex));
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    memset(str, 0, sizeof(str));

    for (size_t c = 0; c < width; c++) {
      if (i+c < size) {
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        hex_off += snprintf(hex + hex_off, sizeof(hex) - hex_off,
                            "%02x ", (unsigned char)ptr[i+c]);
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        str_off += snprintf(str + str_off, sizeof(str) - str_off,
                            "%c", isprint(ptr[i+c]) ? ptr[i+c] : '.');
      } else {
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        hex_off += snprintf(hex + hex_off, sizeof(hex) - hex_off, "   ");
      }
    }

    LOG_REQ(level, "%4.4lx: %s%s", (long)i, hex, str);
  }
}

static
int https_curl_debug(CURL * __attribute__((unused)) handle, curl_infotype type,
                     char *data, size_t size, void *userp)
{
  struct https_fetch_ctx *ctx = (struct https_fetch_ctx *)userp;
  const char *prefix = "";

  switch (type) {
    case CURLINFO_TEXT:
      prefix = "* ";
      break;
    case CURLINFO_HEADER_OUT:
      prefix = "> ";
      break;
    case CURLINFO_HEADER_IN:
      prefix = "< ";
      break;
    // not dumping DNS packets because of privacy
    case CURLINFO_DATA_OUT:
    case CURLINFO_DATA_IN:
      // uncomment, to dump
      /* DLOG_REQ("data %s", type == CURLINFO_DATA_IN ? "IN" : "OUT");
       * https_log_data(LOG_DEBUG, ctx, data, size);
       * return 0; */
    // uninformative
    case CURLINFO_SSL_DATA_OUT:
    case CURLINFO_SSL_DATA_IN:
      return 0;
    default:
      WLOG("Unhandled curl info type: %d", type);
      return 0;
  }

  // for extra debugging purpose
  // if (type != CURLINFO_TEXT) {
  //   https_log_data(LOG_DEBUG, ctx, data, size);
  // }

  // process lines one-by one
  char *start = NULL; // start position of currently processed line
  for (char *pos = data; pos <= (data + size); pos++) {
    // tokenize by end of string and line splitting characters
    if (pos == (data + size) || *pos == '\r' || *pos == '\n') {
      // skip empty string and curl info Expire
      if (start != NULL && (pos - start) > 0 &&
          strncmp(start, "Expire", sizeof("Expire") - 1) != 0) {
        // https_log_data(LOG_DEBUG, ctx, start, pos - start);
        DLOG_REQ("%s%.*s", prefix, pos - start, start);
        start = NULL;
      }
    } else if (start == NULL) {
      start = pos;
    }
  }
  return 0;
}

static void https_fetch_ctx_init(https_client_t *client,
                                 struct https_fetch_ctx *ctx, const char *url,
                                 const char* data, size_t datalen,
                                 struct curl_slist *resolv, uint16_t id,
                                 https_response_cb cb, void *cb_data) {
  ctx->curl = curl_easy_init(); // if fails, first setopt will fail
  ctx->id = id;
  ctx->cb = cb;
  ctx->cb_data = cb_data;
  ctx->buf = NULL;
  ctx->buflen = 0;
  ctx->next = client->fetches;
  client->fetches = ctx;

  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_RESOLVE, resolv);

  DLOG_REQ("Requesting HTTP/1.1: %d", client->opt->use_http_1_1);
  CURLcode easy_code = curl_easy_setopt(ctx->curl, CURLOPT_HTTP_VERSION,
                                        client->opt->use_http_1_1 ?
                                        CURL_HTTP_VERSION_1_1 :
                                        CURL_HTTP_VERSION_2_0);
  if (easy_code != CURLE_OK) {
    ELOG_REQ("CURLOPT_HTTP_VERSION error %d: %s",
             easy_code, curl_easy_strerror(easy_code));
    if (!client->opt->use_http_1_1) {
      ELOG("Try to run application with -x argument! Forcing HTTP/1.1 version.");
      client->opt->use_http_1_1 = 1;
    }
  }

  if (logging_debug_enabled()) {
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_VERBOSE, 1L);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_DEBUGFUNCTION, https_curl_debug);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_DEBUGDATA, ctx);
  }
  if (logging_debug_enabled() || client->stat || client->opt->dscp) {
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_OPENSOCKETDATA, client);
  }
  if (logging_debug_enabled() || client->stat) {
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_CLOSESOCKETFUNCTION, closesocket_callback);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_CLOSESOCKETDATA, client);
  }
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_URL, url);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_HTTPHEADER, client->header_list);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_POSTFIELDSIZE, datalen);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_POSTFIELDS, data);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_WRITEFUNCTION, &write_buffer);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_WRITEDATA, ctx);
#ifdef CURLOPT_MAXAGE_CONN
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_TCP_KEEPALIVE, 1L);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_TCP_KEEPIDLE, 50L);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_TCP_KEEPINTVL, 50L);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_MAXAGE_CONN, 300L);
#endif
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_USERAGENT, "dns-to-https-proxy/0.2");
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_FOLLOWLOCATION, 0);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_NOSIGNAL, 0);
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_TIMEOUT, 10 /* seconds */);
  // We know Google supports this, so force it.
  ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
  if (client->opt->curl_proxy) {
    DLOG_REQ("Using curl proxy: %s", client->opt->curl_proxy);
    ASSERT_CURL_EASY_SETOPT(ctx, CURLOPT_PROXY, client->opt->curl_proxy);
  }
  CURLMcode multi_code = curl_multi_add_handle(client->curlm, ctx->curl);
  if (multi_code != CURLM_OK) {
    FLOG_REQ("curl_multi_add_handle error %d: %s",
             multi_code, curl_multi_strerror(multi_code));
  }
}

static int https_fetch_ctx_process_response(https_client_t *client,
                                            struct https_fetch_ctx *ctx)
{
  CURLcode res = 0;
  long long_resp = 0;
  char *str_resp = NULL;
  int faulty_response = 1;

  if ((res = curl_easy_getinfo(
        ctx->curl, CURLINFO_RESPONSE_CODE, &long_resp)) != CURLE_OK) {
    ELOG_REQ("CURLINFO_RESPONSE_CODE: %s", curl_easy_strerror(res));
  } else {
    if (long_resp == 200) {
      faulty_response = 0;
    } else if (long_resp == 0) {
      // in case of HTTP/1.1 this can happen very often depending on DNS query frequency
      // example: server side closes the connection or curl force closes connections
      // that have been opened a long time ago (if CURLOPT_MAXAGE_CONN can not be increased
      // it is 118 seconds)
      WLOG_REQ("No response (probably connection has been closed or timed out)");
    } else {
      ELOG_REQ("curl response code: %d, content length: %zu", long_resp, ctx->buflen);
      if (ctx->buflen >= 0) {
        https_log_data(LOG_ERROR, ctx, ctx->buf, ctx->buflen);
      }
    }
  }

  if (!faulty_response)
  {
    if ((res = curl_easy_getinfo(
          ctx->curl, CURLINFO_CONTENT_TYPE, &str_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_CONTENT_TYPE: %s", curl_easy_strerror(res));
    } else {
      if (str_resp == NULL ||
          strncmp(str_resp, DOH_CONTENT_TYPE, sizeof(DOH_CONTENT_TYPE) - 1) != 0) {  // at least, start with it
        ELOG_REQ("Invalid response Content-Type: %s", str_resp ? str_resp : "UNSET");
        faulty_response = 1;
      }
    }
  }

  if (logging_debug_enabled() || faulty_response || ctx->buflen == 0) {
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_REDIRECT_URL, &str_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_REDIRECT_URL: %s", curl_easy_strerror(res));
    } else if (str_resp != NULL) {
      ELOG_REQ("Request would be redirected to: %s", str_resp);
      if (strcmp(str_resp, client->opt->resolver_url) != 0) {
        ELOG("Please update Resolver URL to avoid redirection!");
      }
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_SSL_VERIFYRESULT, &long_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(res));
    } else if (long_resp != CURLE_OK) {
      ELOG_REQ("CURLINFO_SSL_VERIFYRESULT: %s", curl_easy_strerror(long_resp));
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_OS_ERRNO, &long_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_OS_ERRNO: %s", curl_easy_strerror(res));
    } else if (long_resp != 0) {
      ELOG_REQ("CURLINFO_OS_ERRNO: %d %s", long_resp, strerror(long_resp));
      if (long_resp == ENETUNREACH && !client->opt->ipv4) {
        ELOG("Try to run application with -4 argument!");
      }
    }
  }

  if (logging_debug_enabled() || client->stat) {
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_NUM_CONNECTS , &long_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_NUM_CONNECTS: %s", curl_easy_strerror(res));
    } else {
      DLOG_REQ("CURLINFO_NUM_CONNECTS: %d", long_resp);
      if (long_resp == 0 && client->stat) {
        stat_connection_reused(client->stat);
      }
    }
  }

  if (logging_debug_enabled()) {
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_EFFECTIVE_URL, &str_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_EFFECTIVE_URL: %s", curl_easy_strerror(res));
    } else {
      DLOG_REQ("CURLINFO_EFFECTIVE_URL: %s", str_resp);
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_HTTP_VERSION, &long_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_HTTP_VERSION: %s", curl_easy_strerror(res));
    } else {
      switch (long_resp) {
        case CURL_HTTP_VERSION_1_0:
          DLOG_REQ("CURLINFO_HTTP_VERSION: 1.0");
          break;
        case CURL_HTTP_VERSION_1_1:
          DLOG_REQ("CURLINFO_HTTP_VERSION: 1.1");
          break;
        case CURL_HTTP_VERSION_2_0:
          DLOG_REQ("CURLINFO_HTTP_VERSION: 2");
          break;
        default:
          DLOG_REQ("CURLINFO_HTTP_VERSION: %d", long_resp);
      }
    }
    if ((res = curl_easy_getinfo(
            ctx->curl, CURLINFO_PROTOCOL, &long_resp)) != CURLE_OK) {
      ELOG_REQ("CURLINFO_PROTOCOL: %s", curl_easy_strerror(res));
    } else if (long_resp != CURLPROTO_HTTPS) {
      DLOG_REQ("CURLINFO_PROTOCOL: %d", long_resp);
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
      ELOG_REQ("Error getting timing");
    } else {
      DLOG_REQ("Times: %lf, %lf, %lf, %lf, %lf, %lf",
               namelookup_time, connect_time, appconnect_time, pretransfer_time,
               starttransfer_time, total_time);
    }
  }

  return faulty_response;
}

static void https_fetch_ctx_cleanup(https_client_t *client,
                                    struct https_fetch_ctx *ctx) {
  struct https_fetch_ctx *last = NULL;
  struct https_fetch_ctx *cur = client->fetches;
  while (cur) {
    if (cur == ctx) {
      CURLMcode code = curl_multi_remove_handle(client->curlm, ctx->curl);
      if (code != CURLM_OK) {
        FLOG_REQ("curl_multi_remove_handle error %d: %s", code, curl_multi_strerror(code));
      }
      if (https_fetch_ctx_process_response(client, ctx) != 0) {
        ILOG_REQ("Response was faulty, skipping DNS reply.");
        free(ctx->buf);
        ctx->buf = NULL;
        ctx->buflen = 0;
      }
      // callback must be called to avoid memleak
      ctx->cb(ctx->cb_data, ctx->buf, ctx->buflen);
      curl_easy_cleanup(ctx->curl);
      free(ctx->buf);
      if (last) {
        last->next = ctx->next;
      } else {
        client->fetches = ctx->next;
      }
      free(ctx);
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
    FLOG("curl needed more event, than max connections: %d", MAX_TOTAL_CONNECTIONS);
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
  if (timeout_ms >= 0) {
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    ev_timer_init(&c->timer, timer_cb, timeout_ms / 1000.0, 0);
    ev_timer_start(c->loop, &c->timer);
  }
  return 0;
}

void https_client_init(https_client_t *c, options_t *opt,
                       stat_t *stat, struct ev_loop *loop) {
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memset(c, 0, sizeof(*c));
  c->loop = loop;
  c->curlm = curl_multi_init(); // if fails, first setopt will fail
  c->header_list = curl_slist_append(curl_slist_append(NULL,
    "Accept: " DOH_CONTENT_TYPE),
    "Content-Type: " DOH_CONTENT_TYPE);
  c->fetches = NULL;
  c->timer.data = c;
  for (int i = 0; i < MAX_TOTAL_CONNECTIONS; i++) {
    c->io_events[i].data = c;
  }
  c->opt = opt;
  c->stat = stat;

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
                        struct curl_slist *resolv, uint16_t id,
                        https_response_cb cb, void *data) {
  struct https_fetch_ctx *ctx =
      (struct https_fetch_ctx *)calloc(1, sizeof(struct https_fetch_ctx));
  if (!ctx) {
    FLOG("Out of mem");
  }
  https_fetch_ctx_init(c, ctx, url, postdata, postdata_len, resolv, id, cb, data);
}

void https_client_reset(https_client_t *c) {
  options_t *opt = c->opt;
  stat_t *stat = c->stat;
  struct ev_loop *loop = c->loop;
  https_client_cleanup(c);
  https_client_init(c, opt, stat, loop);
}

void https_client_cleanup(https_client_t *c) {
  while (c->fetches) {
    https_fetch_ctx_cleanup(c, c->fetches);
  }
  curl_slist_free_all(c->header_list);
  curl_multi_cleanup(c->curlm);
}
