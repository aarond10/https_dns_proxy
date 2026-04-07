// Simple UDP-to-HTTPS DNS Proxy
// (C) 2016 Aaron Drew

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if HAS_LIBSYSTEMD == 1
#include <systemd/sd-daemon.h>
#endif

#include "dns_listener.h"
#include "dns_listener_tcp.h"
#include "dns_listener_udp.h"
#include "dns_poller.h"
#include "doh_proxy.h"
#include "https_client.h"
#include "logging.h"
#include "options.h"
#include "stat.h"

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
      if (rc == CURLUE_OK && host != NULL) {
        const size_t host_len = strlen(host);
        if (hostname_len > 0 &&
            host_len < hostname_len &&
            host[0] != '[' && host[host_len-1] != ']' && // skip IPv6 address
            !is_ipv4_address(host)) {
          strncpy(hostname, host, hostname_len-1);
          hostname[hostname_len-1] = '\0';
          res = 1; // success
        }
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

static void systemd_notify_ready(void __attribute__((__unused__)) *unused) {
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
      CURLcode init_res = curl_global_init(CURL_GLOBAL_DEFAULT);  // needed to ensure, that curl_version*() calls will work properly!
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
        curl_global_cleanup();
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
  stat_t *stat_ptr = (opt.stats_interval ? &stat : NULL);

  https_client_t https_client;
  https_client_init(&https_client, &opt, stat_ptr, loop);

  doh_proxy_t *proxy = doh_proxy_create(loop, &https_client,
                                        opt.resolver_url, stat_ptr);

  struct addrinfo *listen_addrinfo = get_listen_address(opt.listen_addr);

  if (listen_addrinfo->ai_family == AF_INET) {
    ((struct sockaddr_in*) listen_addrinfo->ai_addr)->sin_port = htons((uint16_t)opt.listen_port);
  } else if (listen_addrinfo->ai_family == AF_INET6) {
    ((struct sockaddr_in6*) listen_addrinfo->ai_addr)->sin6_port = htons((uint16_t)opt.listen_port);
  }

  dns_listener_t *udp_listener =
      dns_udp_listener_create(loop, listen_addrinfo,
                              doh_proxy_handle_request, proxy);

  dns_listener_t *tcp_listener = NULL;
  if (opt.tcp_client_limit > 0) {
    tcp_listener = dns_tcp_listener_create(loop, listen_addrinfo,
                                           (uint16_t)opt.tcp_client_limit,
                                           doh_proxy_handle_request, proxy);
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
  ev_signal_init(&sigpipe, sigpipe_cb, SIGPIPE);
  ev_signal_start(loop, &sigpipe);

  ev_signal sigint;
  ev_signal_init(&sigint, signal_shutdown_cb, SIGINT);
  ev_signal_start(loop, &sigint);

  ev_signal sigterm;
  ev_signal_init(&sigterm, signal_shutdown_cb, SIGTERM);
  ev_signal_start(loop, &sigterm);

  logging_events_init(loop);

  dns_poller_t * dns_poller = NULL;
  if (!proxy_supports_name_resolution(opt.curl_proxy)) {
    char hostname[255] = {0};  // Domain names shouldn't exceed 253 chars.
    if (hostname_from_url(opt.resolver_url, hostname, sizeof(hostname))) {
      dns_poller = (dns_poller_t *)calloc(1, sizeof(dns_poller_t));
      doh_proxy_await_bootstrap(proxy);
      doh_proxy_set_on_ready(proxy, systemd_notify_ready, NULL);
      dns_poller_init(dns_poller, loop, opt.bootstrap_dns,
                      opt.bootstrap_dns_polling_interval, opt.source_addr,
                      hostname,
                      opt.ipv4 ? AF_INET : AF_UNSPEC,
                      doh_proxy_handle_resolver_update, proxy);
      ILOG("DNS polling initialized for '%s'", hostname);
    } else {
      ILOG("Resolver prefix '%s' doesn't appear to contain a "
           "hostname. DNS polling disabled.", opt.resolver_url);
      systemd_notify_ready(NULL);
    }
  } else {
    systemd_notify_ready(NULL);
  }

  ev_run(loop, 0);
  DLOG("loop breaked");

  if (dns_poller != NULL) {
    dns_poller_cleanup(dns_poller);
    free(dns_poller);
    dns_poller = NULL;
  }

  logging_events_cleanup(loop);
  ev_signal_stop(loop, &sigterm);
  ev_signal_stop(loop, &sigint);
  ev_signal_stop(loop, &sigpipe);
  udp_listener->stop(udp_listener);
  if (tcp_listener != NULL) {
    tcp_listener->stop(tcp_listener);
  }
  stat_stop(&stat);

  DLOG("re-entering loop");
  ev_run(loop, 0);
  DLOG("loop finished all events");

  udp_listener->destroy(udp_listener);
  if (tcp_listener != NULL) {
    tcp_listener->destroy(tcp_listener);
  }
  // The CURLOPT_RESOLVE list owned by the proxy must outlive in-flight curl
  // easy handles, which is why https_client_cleanup runs first.
  https_client_cleanup(&https_client);
  doh_proxy_destroy(proxy);
  stat_cleanup(&stat);

  ev_loop_destroy(loop);
  DLOG("loop destroyed");

  curl_global_cleanup();
  logging_cleanup();
  options_cleanup(&opt);

  return 0;
}
