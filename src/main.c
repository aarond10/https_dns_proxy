// Simple UDP-to-HTTPS DNS Proxy
// (C) 2016 Aaron Drew

#include <ctype.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <errno.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <grp.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <pwd.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/types.h>     // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)

#if HAS_LIBSYSTEMD == 1
#include <systemd/sd-daemon.h> // NOLINT(llvmlibc-restrict-system-libc-headers)
#endif

#include "dns_poller.h"
#include "dns_server.h"
#include "dns_server_tcp.h"
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
  socklen_t addrlen;
} app_state_t;

// NOLINTNEXTLINE(altera-struct-pack-align)
typedef struct {
  void *dns_server;
  uint8_t is_tcp;
  char* dns_req;
  size_t dns_req_len;
  stat_t *stat;
  ev_tstamp start_tstamp;
  uint16_t tx_id;
  struct sockaddr_storage raddr;
} request_t;

static int is_ipv4_address(char *str) {
    struct in6_addr addr;
    return inet_pton(AF_INET, str, &addr) == 1;
}

static int hostname_from_url(const char* url_in,
                             char* hostname, const size_t hostname_len) {
  int res = 0;
  CURLU *url = curl_url();
  if (url != NULL) {
    CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_in, 0);
    if (rc == CURLUE_OK) {
      char *host = NULL;
      rc = curl_url_get(url, CURLUPART_HOST, &host, 0);
      const size_t host_len = strlen(host);
      if (rc == CURLUE_OK && host_len < hostname_len &&
          host[0] != '[' && host[host_len-1] != ']' && // skip IPv6 address
          !is_ipv4_address(host)) {
        strncpy(hostname, host, hostname_len-1); // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        hostname[hostname_len-1] = '\0';
        res = 1; // success
      }
      curl_free(host);
    }
    curl_url_cleanup(url);
  }
  return res;
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
  if (buf != NULL) { // May be NULL for timeout, DNS failure, or something similar.
    if (buflen < DNS_HEADER_LENGTH) {
      WLOG("%04hX: Malformed response received, too short: %u", req->tx_id, buflen);
    } else {
      const uint16_t response_id = ntohs(*((uint16_t*)buf));
      if (req->tx_id != response_id) {
        WLOG("DNS request and response IDs are not matching: %hX != %hX",
             req->tx_id, response_id);
      } else {
        if (req->is_tcp) {
          dns_server_tcp_respond((dns_server_tcp_t *)req->dns_server, (struct sockaddr*)&req->raddr, buf, buflen);
        } else {
          dns_server_respond((dns_server_t *)req->dns_server, (struct sockaddr*)&req->raddr,
            req->dns_req, req->dns_req_len, buf, buflen);
        }
        if (req->stat) {
          stat_request_end(req->stat, buflen, ev_now(req->stat->loop) - req->start_tstamp, req->is_tcp);
        }
      }
    }
  }
  free((void*)req->dns_req);
  free(req);
}

static void dns_server_cb(void *dns_server, uint8_t is_tcp, void *data,
                          struct sockaddr* tmp_remote_addr,
                          char *dns_req, size_t dns_req_len) {
  app_state_t *app = (app_state_t *)data;

  uint16_t tx_id = ntohs(*((uint16_t*)dns_req));
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
  memcpy(&req->raddr, tmp_remote_addr, app->addrlen);  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  req->dns_server = dns_server;
  req->is_tcp = is_tcp;
  req->dns_req = dns_req;  // To free buffer after https request is complete.
  req->dns_req_len = dns_req_len;
  req->stat = app->stat;

  if (req->stat) {
    req->start_tstamp = ev_now(app->stat->loop);
    stat_request_begin(app->stat, dns_req_len, is_tcp);
  }
  https_client_fetch(app->https_client, app->resolver_url,
                     req->dns_req, dns_req_len, app->resolv, req->tx_id, https_resp_cb, req);
}

static void systemd_notify_ready(void) {
#if HAS_LIBSYSTEMD == 1
  static uint8_t called_once = 0;
  if (called_once != 0) {
    DLOG("Systemd notify already called once!");
    return;
  }
  called_once = 1;
  const int result = sd_notify(0, "READY=1");
  if (result > 0) {
    DLOG("Systemd notify succeeded, service is ready!");
  } else if (result == 0) {
    WLOG("Systemd notify called, but NOTIFY_SOCKET not set. Running manually?");
  } else {
    ELOG("Systemd notify failed with: %s", strerror(result));
  }
#else
  DLOG("Systemd notify skipped, not compiled with libsystemd!");
#endif
}

static int addr_list_reduced(const char* full_list, const char* list) {
  const char *pos = list;
  const char *end = list + strlen(list);
  while (pos < end) {
    char current[50];
    const char *comma = strchr(pos, ',');
    size_t ip_len = (size_t)(comma ? comma - pos : end - pos);
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
  if (ip_start < 0) {
    abort();  // must be impossible
  }
  (void)snprintf(buf + ip_start, sizeof(buf) - 1 - (uint32_t)ip_start, "%s", addr_list); // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  if (app->resolv == NULL) {
    systemd_notify_ready();
  }
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

static struct addrinfo * get_listen_address(const char *listen_addr) {
  struct addrinfo *ai = NULL;
  struct addrinfo hints;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memset(&hints, 0, sizeof(struct addrinfo));
  /* prevent DNS lookups if leakage is our worry */
  hints.ai_flags = AI_NUMERICHOST;

  int res = getaddrinfo(listen_addr, NULL, &hints, &ai);
  if (res != 0) {
    FLOG("Error parsing listen address %s, getaddrinfo error: %s",
         listen_addr, gai_strerror(res));
  }

  return ai;
}

static const char * sw_version(void) {
#ifdef SW_VERSION
  return SW_VERSION;
#else
  return "2025.8.26-atLeast";  // update date sometimes, like 1-2 times a year
#endif
}

int main(int argc, char *argv[]) {
  struct Options opt;
  options_init(&opt);
  switch (options_parse_args(&opt, argc, argv)) {
    case OPR_SUCCESS:
      break;
    case OPR_HELP:
      options_show_usage(argc, argv);
      exit(0);  // asking for help is not a problem
    case OPR_VERSION: {
      printf("%s\n", sw_version());
      CURLcode init_res = curl_global_init(CURL_GLOBAL_DEFAULT);
      curl_version_info_data *curl_ver = curl_version_info(CURLVERSION_NOW);
      if (init_res == CURLE_OK && curl_ver != NULL) {
        printf("Using: ev/%d.%d c-ares/%s %s\n",
               ev_version_major(), ev_version_minor(),
               ares_version(NULL), curl_version());
        printf("Features: %s%s%s%s\n",
               curl_ver->features & CURL_VERSION_HTTP2 ? "HTTP2 " : "",
               curl_ver->features & CURL_VERSION_HTTP3 ? "HTTP3 " : "",
               curl_ver->features & CURL_VERSION_HTTPS_PROXY ? "HTTPS-proxy " : "",
               curl_ver->features & CURL_VERSION_IPV6 ? "IPv6" : "");
        exit(0);
      } else {
        printf("\nFailed to get curl version info!\n");
        exit(1);
      }
    }
    case OPR_PARSING_ERROR:
      printf("Failed to parse options!\n");
      __attribute__((fallthrough));
    case OPR_OPTION_ERROR:
      printf("\n");
      options_show_usage(argc, argv);
      exit(1);
    default:
      abort();  // must not happen
  }

  logging_init(opt.logfd, opt.loglevel, (uint32_t)opt.flight_recorder_size);

  ILOG("Version: %s", sw_version());
  ILOG("Built: " __DATE__ " " __TIME__);
  ILOG("System ev library: %d.%d", ev_version_major(), ev_version_minor());
  ILOG("System c-ares library: %s", ares_version(NULL));
  ILOG("System curl library: %s", curl_version());

  // Note: curl intentionally uses uninitialized stack variables and similar
  // tricks to increase it's entropy pool. This confuses valgrind and leaks
  // through to errors about use of uninitialized values in our code. :(
  CURLcode code = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (code != CURLE_OK) {
    FLOG("Failed to initialize curl, error code %d: %s",
         code, curl_easy_strerror(code));
  }

  curl_version_info_data *curl_ver = curl_version_info(CURLVERSION_NOW);
  if (curl_ver == NULL) {
    FLOG("Failed to get curl version info!");
  }
  if (!(curl_ver->features & CURL_VERSION_HTTP2)) {
    WLOG("HTTP/2 is not supported by current libcurl");
  }
  if (!(curl_ver->features & CURL_VERSION_HTTP3)) {
    WLOG("HTTP/3 is not supported by current libcurl");
  }
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

  struct addrinfo *listen_addrinfo = get_listen_address(opt.listen_addr);

  if (listen_addrinfo->ai_family == AF_INET) {
    ((struct sockaddr_in*) listen_addrinfo->ai_addr)->sin_port = htons((uint16_t)opt.listen_port);
  } else if (listen_addrinfo->ai_family == AF_INET6) {
    ((struct sockaddr_in6*) listen_addrinfo->ai_addr)->sin6_port = htons((uint16_t)opt.listen_port);
  }

  app_state_t app;
  app.https_client = &https_client;
  app.resolv = NULL;
  app.resolver_url = opt.resolver_url;
  app.using_dns_poller = 0;
  app.stat = (opt.stats_interval ? &stat : NULL);
  app.addrlen = listen_addrinfo->ai_addrlen;

  dns_server_t dns_server;
  dns_server_init(&dns_server, loop, listen_addrinfo, dns_server_cb, &app);

  dns_server_tcp_t * dns_server_tcp = NULL;
  if (opt.tcp_client_limit > 0) {
    dns_server_tcp = dns_server_tcp_create(loop, listen_addrinfo, dns_server_cb, &app, (uint16_t)opt.tcp_client_limit);
  }

  freeaddrinfo(listen_addrinfo);
  listen_addrinfo = NULL;

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

  logging_events_init(loop);

  dns_poller_t dns_poller;
  char hostname[255] = {0};  // Domain names shouldn't exceed 253 chars.
  if (!proxy_supports_name_resolution(opt.curl_proxy)) {
    if (hostname_from_url(opt.resolver_url, hostname, sizeof(hostname))) {
      app.using_dns_poller = 1;
      dns_poller_init(&dns_poller, loop, opt.bootstrap_dns,
                      opt.bootstrap_dns_polling_interval, hostname,
                      opt.ipv4 ? AF_INET : AF_UNSPEC,
                      dns_poll_cb, &app);
      ILOG("DNS polling initialized for '%s'", hostname);
    } else {
      ILOG("Resolver prefix '%s' doesn't appear to contain a "
           "hostname. DNS polling disabled.", opt.resolver_url);

      systemd_notify_ready();
    }
  }

  ev_run(loop, 0);
  DLOG("loop breaked");

  if (app.using_dns_poller) {
    dns_poller_cleanup(&dns_poller);
  }
  curl_slist_free_all(app.resolv);

  logging_events_cleanup(loop);
  ev_signal_stop(loop, &sigterm);
  ev_signal_stop(loop, &sigint);
  ev_signal_stop(loop, &sigpipe);
  dns_server_stop(&dns_server);
  if (dns_server_tcp != NULL) {
    dns_server_tcp_stop(dns_server_tcp);
  }
  stat_stop(&stat);

  DLOG("re-entering loop");
  ev_run(loop, 0);
  DLOG("loop finished all events");

  dns_server_cleanup(&dns_server);
  if (dns_server_tcp != NULL) {
    dns_server_tcp_cleanup(dns_server_tcp);
    free(dns_server_tcp);
    dns_server_tcp = NULL;
  }
  https_client_cleanup(&https_client);
  stat_cleanup(&stat);

  ev_loop_destroy(loop);
  DLOG("loop destroyed");

  curl_global_cleanup();
  logging_cleanup();
  options_cleanup(&opt);

  return 0;
}
