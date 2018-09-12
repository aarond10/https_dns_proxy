// Simple UDP-to-HTTPS DNS Proxy
//
// (C) 2016 Aaron Drew
//
// Intended for use with Google's Public-DNS over HTTPS service
// (https://developers.google.com/speed/public-dns/docs/dns-over-https)
#include <sys/socket.h>
#include <sys/types.h>


#include <ares.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <ev.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dns_poller.h"
#include "dns_server.h"
#include "https_client.h"
#include "json_to_dns.h"
#include "logging.h"
#include "options.h"

// Holds app state required for dns_server_cb.
typedef struct {
  https_client_t *https_client;
  struct curl_slist *resolv;
  const char *resolver_url_prefix;
  uint8_t using_dns_poller;
  // currently only used for edns_client_subnet, if specified.
  const char *extra_request_args;
} app_state_t;

typedef struct {
  uint16_t tx_id;
  struct sockaddr_in raddr;
  dns_server_t *dns_server;
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
  strncpy(hostname, uri, end - uri);
  hostname[end - uri] = 0;
  return 1;
}

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents) {
  ev_break(loop, EVBREAK_ALL);
}

static void sigpipe_cb(struct ev_loop *loop, ev_signal *w, int revents) {
  ELOG("Received SIGPIPE. Ignoring.");
}

static void https_resp_cb(void *data, unsigned char *buf, unsigned int buflen) {
  DLOG("buflen %u\n", buflen);
  if (buf == NULL) { // Timeout, DNS failure, or something similar.
    return;
  }
  request_t *req = (request_t *)data;
  if (req == NULL) {
    FLOG("data NULL");
  }
  char *bufcpy = (char *)calloc(1, buflen + 1);
  if (bufcpy == NULL) {
    FLOG("Out of mem");
  }
  memcpy(bufcpy, buf, buflen);

  DLOG("Received response for id %04x: %.*s", req->tx_id, buflen, bufcpy);

  const int obuf_size = 1500;
  char obuf[obuf_size];
  int r;
  if ((r = json_to_dns(req->tx_id, bufcpy,
                       (unsigned char *)obuf, obuf_size)) <= 0) {
    ELOG("Failed to decode JSON.");
  } else {
    dns_server_respond(req->dns_server, req->raddr, obuf, r);
  }
  free(bufcpy);
  free(req);
}

static void dns_server_cb(dns_server_t *dns_server, void *data,
                          struct sockaddr_in addr, uint16_t tx_id,
                          uint16_t flags, const char *name, int type) {
  app_state_t *app = (app_state_t *)data;

  DLOG("Received request for '%s' id: %04x, type %d, flags %04x", name, tx_id,
       type, flags);

  // If we're not yet bootstrapped, don't answer. libcurl will fall back to
  // gethostbyname() which can cause a DNS loop due to the nameserver listed
  // in resolv.conf being or depending on https_dns_proxy itself.
  if(app->using_dns_poller && (app->resolv == NULL || app->resolv->data == NULL)) {
    WLOG("Query received before bootstrapping is completed, discarding.");
    return;
  }

  // Build URL
  int cd_bit = flags & (1 << 4);
  char *escaped_name = curl_escape(name, strlen(name));
  char url[1500] = "";
  snprintf(url, sizeof(url) - 1,
           "%sname=%s&type=%d%s%s",
           app->resolver_url_prefix,
           escaped_name, type, (cd_bit != 0) ? "&cd=true" : "",
           app->extra_request_args);
  curl_free(escaped_name);

  request_t *req = (request_t *)calloc(1, sizeof(request_t));
  if (req == NULL) {
    FLOG("Out of mem");
  }
  req->tx_id = tx_id;
  req->raddr = addr;
  req->dns_server = dns_server;
  https_client_fetch(app->https_client, url, app->resolv, https_resp_cb, req);
}

static void dns_poll_cb(const char* hostname, void *data, struct sockaddr_in *addr) {
  struct curl_slist **resolv = (struct curl_slist **)data;
  char buf[280];
  memset(buf, 0, sizeof(buf));
  if (strlen(hostname) > 254) { FLOG("Hostname too long."); }
  snprintf(buf, sizeof(buf) - 1, "%s:443:", hostname);
  char *pos = buf + strlen(buf);
  ares_inet_ntop(AF_INET, addr, pos, buf + sizeof(buf) - 1 - pos);
  DLOG("Received new IP '%s'", pos);
  curl_slist_free_all(*resolv);
  *resolv = curl_slist_append(NULL, buf);
}

static int proxy_supports_name_resolution(const char *proxy)
{
  int i;
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

  ILOG("Built "__DATE__" "__TIME__".");
  ILOG("System c-ares: %s", ares_version(NULL));
  ILOG("System libcurl: %s", curl_version());

  // Note: curl intentionally uses uninitialized stack variables and similar
  // tricks to increase it's entropy pool. This confuses valgrind and leaks
  // through to errors about use of uninitialized values in our code. :(
  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Note: This calls ev_default_loop(0) which never cleans up.
  //       valgrind will report a leak. :(
  struct ev_loop *loop = EV_DEFAULT;

  https_client_t https_client;
  https_client_init(&https_client, &opt, loop);

  app_state_t app;
  app.https_client = &https_client;
  app.resolv = NULL;
  app.resolver_url_prefix = opt.resolver_url_prefix;
  app.using_dns_poller = 0;

  if (opt.edns_client_subnet[0]) {
    static char buf[200];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "&edns_client_subnet=%s",
             opt.edns_client_subnet);
    app.extra_request_args = buf;
  } else {
    app.extra_request_args = "";
  }

  dns_server_t dns_server;
  dns_server_init(&dns_server, loop, opt.listen_addr, opt.listen_port,
                  dns_server_cb, &app);

  if (opt.gid != -1 && setgid(opt.gid)) {
    FLOG("Failed to set gid.");
  }
  if (opt.uid != -1 && setuid(opt.uid)) {
    FLOG("Failed to set uid.");
  }

  if (opt.daemonize) {
    // daemon() is non-standard. If needed, see OpenSSH openbsd-compat/daemon.c
    daemon(0, 0);
  }

  ev_signal sigpipe;
  ev_signal_init(&sigpipe, sigpipe_cb, SIGPIPE);
  ev_signal_start(loop, &sigpipe);

  ev_signal sigint;
  ev_signal_init(&sigint, sigint_cb, SIGINT);
  ev_signal_start(loop, &sigint);

  logging_flush_init(loop);

  dns_poller_t dns_poller;
  char hostname[255];  // Domain names shouldn't exceed 253 chars.
  if (!proxy_supports_name_resolution(opt.curl_proxy)) {
    if (hostname_from_uri(opt.resolver_url_prefix, hostname, 254)) {
      app.using_dns_poller = 1;
      dns_poller_init(&dns_poller, loop, opt.bootstrap_dns, hostname,
                      dns_poll_cb, &app.resolv);
      ILOG("DNS polling initialized for '%s'", hostname);
    } else {
      ILOG("Resolver prefix '%s' doesn't appear to contain a "
           "hostname. DNS polling disabled.", opt.resolver_url_prefix);
    }
  }

  ev_run(loop, 0);

  if (!proxy_supports_name_resolution(opt.curl_proxy)) {
    dns_poller_cleanup(&dns_poller);
}

  curl_slist_free_all(app.resolv);

  ev_signal_stop(loop, &sigint);
  dns_server_cleanup(&dns_server);
  https_client_cleanup(&https_client);

  ev_loop_destroy(loop);

  curl_global_cleanup();
  logging_cleanup();
  options_cleanup(&opt);

  return EXIT_SUCCESS;
}
