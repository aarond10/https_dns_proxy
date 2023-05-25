// Simple UDP-to-HTTPS DNS Proxy
// (C) 2016 Aaron Drew

#include <ctype.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <errno.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <grp.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <pwd.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/types.h>     // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "dns_poller.h"
#include "dns_server.h"
#include "https_client.h"
#include "logging.h"
#include "options.h"
#include "stat.h"

// Holds app state required for dns_server_cb.
// NOLINTNEXTLINE(altera-struct-pack-align)
typedef struct {
  https_client_t *https_client;
  struct curl_slist *resolv;
  const char *resolver_url;
  stat_t *stat;
  uint8_t using_dns_poller;
} app_state_t;

// NOLINTNEXTLINE(altera-struct-pack-align)
typedef struct {
  dns_server_t *dns_server;
  char* dns_req;
  stat_t *stat;
  ev_tstamp start_tstamp;
  uint16_t tx_id;
  struct sockaddr_storage raddr;
} request_t;

// Very very basic hostname parsing.
// Note: Performs basic checks to see if last digit is non-alpha.
// Non-alpha hostnames are assumed to be IP addresses. e.g. foo.1
// Returns non-zero on success, zero on failure.
static int hostname_from_uri(const char* uri,
                             char* hostname, int hostname_len) {
  if (strncmp(uri, "https://", 8) != 0) { return 0; }  // not https://
  uri += 8;
  const char *end = uri;
  while (*end && *end != '/') { end++; }
  if (end - uri >= hostname_len) {
    return 0;
  }
  if (end == uri) { return 0; }  // empty string.
  if (!isalpha(*(end - 1))) { return 0; }  // last digit non-alpha.

  // If using basic authentication in URL, chop off prefix.
  char *tmp = NULL;
  if ((tmp = strchr(uri, '@'))) {
    tmp++;
    if (tmp < end) {
      uri = tmp;
    }
  }

  strncpy(hostname, uri, end - uri); // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  hostname[end - uri] = 0;
  return 1;
}

static void signal_shutdown_cb(struct ev_loop *loop,
                               ev_signal __attribute__((__unused__)) *w,
                               int __attribute__((__unused__)) revents) {
  ILOG("Shutting down gracefully. To force exit, send signal again.");
  ev_break(loop, EVBREAK_ALL);
}

static void sigpipe_cb(struct ev_loop __attribute__((__unused__)) *loop,
                       ev_signal __attribute__((__unused__)) *w,
                       int __attribute__((__unused__)) revents) {
  ELOG("Received SIGPIPE. Ignoring.");
}

static void https_resp_cb(void *data, char *buf, size_t buflen) {
  request_t *req = (request_t *)data;
  DLOG("Received response for id: %hX, len: %zu", req->tx_id, buflen);
  if (req == NULL) {
    FLOG("%04hX: data NULL", req->tx_id);
  }
  free((void*)req->dns_req);
  if (buf != NULL) { // May be NULL for timeout, DNS failure, or something similar.
    if (buflen < (int)sizeof(uint16_t)) {
      WLOG("%04hX: Malformed response received (too short)", req->tx_id);
    } else {
      uint16_t response_id = ntohs(*((uint16_t*)buf));
      if (req->tx_id != response_id) {
        WLOG("DNS request and response IDs are not matching: %hX != %hX",
             req->tx_id, response_id);
      } else {
        dns_server_respond(req->dns_server, (struct sockaddr*)&req->raddr, buf, buflen);
        if (req->stat) {
          stat_request_end(req->stat, buflen, ev_now(req->dns_server->loop) - req->start_tstamp);
        }
      }
    }
  }
  free(req);
}

static void dns_server_cb(dns_server_t *dns_server, void *data,
                          struct sockaddr* addr, uint16_t tx_id,
                          char *dns_req, size_t dns_req_len) {
  app_state_t *app = (app_state_t *)data;

  DLOG("Received request for id: %hX, len: %d", tx_id, dns_req_len);

  // If we're not yet bootstrapped, don't answer. libcurl will fall back to
  // gethostbyname() which can cause a DNS loop due to the nameserver listed
  // in resolv.conf being or depending on https_dns_proxy itself.
  if(app->using_dns_poller && (app->resolv == NULL || app->resolv->data == NULL)) {
    WLOG("%04hX: Query received before bootstrapping is completed, discarding.", tx_id);
    free(dns_req);
    return;
  }

  request_t *req = (request_t *)calloc(1, sizeof(request_t));
  if (req == NULL) {
    FLOG("%04hX: Out of mem", tx_id);
  }
  req->tx_id = tx_id;
  memcpy(&req->raddr, addr, dns_server->addrlen);  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  req->dns_server = dns_server;
  req->dns_req = dns_req; // To free buffer after https request is complete.
  req->start_tstamp = ev_now(dns_server->loop);
  req->stat = app->stat;

  if (req->stat) {
    stat_request_begin(app->stat, dns_req_len);
  }
  https_client_fetch(app->https_client, app->resolver_url,
                     dns_req, dns_req_len, app->resolv, req->tx_id, https_resp_cb, req);
}

static int addr_list_reduced(const char* full_list, const char* list) {
  const char *pos = list;
  const char *end = list + strlen(list);
  while (pos < end) {
    char current[50];
    const char *comma = strchr(pos, ',');
    size_t ip_len = comma ? comma - pos : end - pos;
    strncpy(current, pos, ip_len); // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    current[ip_len] = '\0';

    const char *match_begin = strstr(full_list, current);
    if (!match_begin ||
        !(match_begin == full_list || *(match_begin - 1) == ',') ||
        !(*(match_begin + ip_len) == ',' || *(match_begin + ip_len) == '\0')) {
      DLOG("IP address missing: %s", current);
      return 1;
    }

    pos += ip_len + 1;
  }
  return 0;
}

static void dns_poll_cb(const char* hostname, void *data,
                        const char* addr_list) {
  app_state_t *app = (app_state_t *)data;
  char buf[255 + (sizeof(":443:") - 1) + POLLER_ADDR_LIST_SIZE];
  memset(buf, 0, sizeof(buf)); // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  if (strlen(hostname) > 254) { FLOG("Hostname too long."); }
  int ip_start = snprintf(buf, sizeof(buf) - 1, "%s:443:", hostname);  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  snprintf(buf + ip_start, sizeof(buf) - 1 - ip_start, "%s", addr_list); // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  if (app->resolv && app->resolv->data) {
    char * old_addr_list = strstr(app->resolv->data, ":443:");
    if (old_addr_list) {
      old_addr_list += sizeof(":443:") - 1;
      if (!addr_list_reduced(addr_list, old_addr_list)) {
        DLOG("DNS server IP address unchanged (%s).", buf + ip_start);
        free((void*)addr_list);
        return;
      }
    }
  }
  free((void*)addr_list);
  DLOG("Received new DNS server IP '%s'", buf + ip_start);
  curl_slist_free_all(app->resolv);
  app->resolv = curl_slist_append(NULL, buf);
  // Resets curl or it gets in a mess due to IP of streaming connection not
  // matching that of configured DNS.
  https_client_reset(app->https_client);
}

static int proxy_supports_name_resolution(const char *proxy)
{
  size_t i = 0;
  const char *ptypes[] = {"http:", "https:", "socks4a:", "socks5h:"};

  if (proxy == NULL) {
    return 0;
  }
  for (i = 0; i < sizeof(ptypes) / sizeof(*ptypes); i++) {
    if (strncasecmp(proxy, ptypes[i], strlen(ptypes[i])) == 0) {
      return 1;
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  struct Options opt;
  options_init(&opt);
  if (options_parse_args(&opt, argc, argv)) {
    options_show_usage(argc, argv);
    exit(1);
  }

  logging_init(opt.logfd, opt.loglevel);

  ILOG("Version: %s", options_sw_version());
  ILOG("Built: " __DATE__ " " __TIME__);
  ILOG("System c-ares: %s", ares_version(NULL));
  ILOG("System libcurl: %s", curl_version());

  // Note: curl intentionally uses uninitialized stack variables and similar
  // tricks to increase it's entropy pool. This confuses valgrind and leaks
  // through to errors about use of uninitialized values in our code. :(
  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl_version_info_data *curl_ver = curl_version_info(CURLVERSION_NOW);
  if (!(curl_ver->features & CURL_VERSION_HTTP2)) {
    WLOG("HTTP/2 is not supported by current libcurl");
  }
#ifdef CURL_VERSION_HTTP3
  if (!(curl_ver->features & CURL_VERSION_HTTP3))
  {
    WLOG("HTTP/3 is not supported by current libcurl");
  }
#else
  WLOG("HTTP/3 was not available at build time, it will not work at all");
#endif
  if (!(curl_ver->features & CURL_VERSION_IPV6)) {
    WLOG("IPv6 is not supported by current libcurl");
  }

  // Note: This calls ev_default_loop(0) which never cleans up.
  //       valgrind will report a leak. :(
  struct ev_loop *loop = EV_DEFAULT;

  stat_t stat;
  stat_init(&stat, loop, opt.stats_interval);

  https_client_t https_client;
  https_client_init(&https_client, &opt, (opt.stats_interval ? &stat : NULL), loop);

  app_state_t app;
  app.https_client = &https_client;
  app.resolv = NULL;
  app.resolver_url = opt.resolver_url;
  app.using_dns_poller = 0;
  app.stat = (opt.stats_interval ? &stat : NULL);

  dns_server_t dns_server;
  dns_server_init(&dns_server, loop, opt.listen_addr, opt.listen_port,
                  dns_server_cb, &app);

  if (opt.gid != (uid_t)-1 && setgroups(1, &opt.gid)) {
    FLOG("Failed to set groups");
  }
  if (opt.gid != (uid_t)-1 && setgid(opt.gid)) {
    FLOG("Failed to set gid");
  }
  if (opt.uid != (uid_t)-1 && setuid(opt.uid)) {
    FLOG("Failed to set uid");
  }

  if (opt.daemonize) {
    // daemon() is non-standard. If needed, see OpenSSH openbsd-compat/daemon.c
    if (daemon(0, 0) == -1) {
      FLOG("daemon failed: %s", strerror(errno));
    }
  }

  ev_signal sigpipe;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_signal_init(&sigpipe, sigpipe_cb, SIGPIPE);
  ev_signal_start(loop, &sigpipe);

  ev_signal sigint;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_signal_init(&sigint, signal_shutdown_cb, SIGINT);
  ev_signal_start(loop, &sigint);

  ev_signal sigterm;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_signal_init(&sigterm, signal_shutdown_cb, SIGTERM);
  ev_signal_start(loop, &sigterm);

  logging_flush_init(loop);

  dns_poller_t dns_poller;
  char hostname[255];  // Domain names shouldn't exceed 253 chars.
  if (!proxy_supports_name_resolution(opt.curl_proxy)) {
    if (hostname_from_uri(opt.resolver_url, hostname, 254)) {
      app.using_dns_poller = 1;
      dns_poller_init(&dns_poller, loop, opt.bootstrap_dns,
                      opt.bootstrap_dns_polling_interval, hostname,
                      opt.ipv4 ? AF_INET : AF_UNSPEC,
                      dns_poll_cb, &app);
      ILOG("DNS polling initialized for '%s'", hostname);
    } else {
      ILOG("Resolver prefix '%s' doesn't appear to contain a "
           "hostname. DNS polling disabled.", opt.resolver_url);
    }
  }

  ev_run(loop, 0);
  DLOG("loop breaked");

  if (app.using_dns_poller) {
    dns_poller_cleanup(&dns_poller);
  }
  curl_slist_free_all(app.resolv);

  logging_flush_cleanup(loop);
  ev_signal_stop(loop, &sigterm);
  ev_signal_stop(loop, &sigint);
  ev_signal_stop(loop, &sigpipe);
  dns_server_stop(&dns_server);
  stat_stop(&stat);

  DLOG("re-entering loop");
  ev_run(loop, 0);
  DLOG("loop finished all events");

  dns_server_cleanup(&dns_server);
  https_client_cleanup(&https_client);
  stat_cleanup(&stat);

  ev_loop_destroy(loop);
  DLOG("loop destroyed");

  curl_global_cleanup();
  logging_cleanup();
  options_cleanup(&opt);

  return 0;
}
