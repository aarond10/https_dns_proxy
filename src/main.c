// Simple UDP-to-HTTPS DNS Proxy
//
// (C) 2016 Aaron Drew
//
// Intended for use with Google's Public-DNS over HTTPS service
// (https://developers.google.com/speed/public-dns/docs/dns-over-https)
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ares.h>
#include <ev.h>
#include "dns_server.h"
#include "dns_poller.h"
#include "https_client.h"
#include "json_to_dns.h"
#include "options.h"
#include "logging.h"

// Holds app state required for dns_server_cb.
typedef struct {
  https_client_t *https_client;
  struct curl_slist *resolv;
} app_state_t;

typedef struct {
  uint16_t tx_id;
  struct sockaddr_in raddr;
  dns_server_t *dns_server;
} request_t;

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents) {
  ev_break(loop, EVBREAK_ALL);
}

static int is_printable(int ch) {
  return (ch >= '0' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}
static void debug_dump(unsigned char *buf, unsigned int buflen) {
  unsigned char *end = buf + buflen;
  int i;
  for (i = 0; buf < end; i++, buf++) {
    if (i && !(i % 16)) {
      printf(" ");
      for (int j = 0; j < 16; j++)
        printf("%c", is_printable(buf[j - 16]) ? buf[j - 16] : '.');
      printf("\n");
    }
    printf("%02x ", *buf);
  }
  while ((i % 16)) {
    printf("   ");
    buf++;
    i++;
  }
  printf(" ");
  buf -= 16;
  while (buf < end) {
    printf("%c", is_printable(*buf) ? *buf : '.');
    buf++;
  }
  printf("\n");
}

static void https_resp_cb(void *data, unsigned char *buf, unsigned int buflen) {
  request_t *req = (request_t *)data;
  if (strlen(buf) > buflen)
    FLOG("Buffer overflow! Wat?!");

  DLOG("Received response for id %04x: %s", req->tx_id, buf);

  const int obuf_size = 1500;
  char obuf[obuf_size];
  int r;
  if ((r = json_to_dns(req->tx_id, buf, obuf, obuf_size)) <= 0) {
    ELOG("Failed to decode JSON.");
  } else {
    // debug_dump(obuf, r);
    dns_server_respond(req->dns_server, req->raddr, obuf, r);
  }
  free(req);
}

static void dns_server_cb(dns_server_t *dns_server, void *data,
                          struct sockaddr_in addr, uint16_t tx_id,
                          uint16_t flags, const char *name, int type) {
  app_state_t *app = (app_state_t *)data;

  DLOG("Received request for '%s' id: %04x, type %d, flags %04x", name, tx_id,
       type, flags);

  // Build URL
  int cd_bit = flags & (1 << 4);
  char *escaped_name = curl_escape(name, strlen(name));
  char url[1500] = {};
  snprintf(url, sizeof(url) - 1,
           "https://dns.google.com/resolve?name=%s&type=%d%s", escaped_name,
           type, cd_bit ? "&cd=true" : "");
  curl_free(escaped_name);

  request_t *req = (request_t *)malloc(sizeof(request_t));
  req->tx_id = tx_id;
  req->raddr = addr;
  req->dns_server = dns_server;
  https_client_fetch(app->https_client, url, app->resolv, https_resp_cb, req);
}

static void dns_poll_cb(void *data, struct sockaddr_in *addr) {
  struct curl_slist **resolv = (struct curl_slist **)data;
  char buf[128] = "dns.google.com:443:";
  char *end = &buf[128];
  char *pos = buf + strlen(buf);
  ares_inet_ntop(AF_INET, addr, pos, end - pos);
  DLOG("Received new IP '%s'", pos);
  curl_slist_free_all(*resolv);
  *resolv = curl_slist_append(NULL, buf);
}

int main(int argc, char *argv[]) {
  struct ev_loop *loop = EV_DEFAULT;
  struct curl_slist *resolv = NULL;

  struct Options opt;
  options_init(&opt);
  if (options_parse_args(&opt, argc, argv)) {
    options_show_usage(argc, argv);
    exit(1);
  }

  logging_init(opt.logfd, opt.loglevel);
  curl_global_init(CURL_GLOBAL_DEFAULT);

  https_client_t https_client;
  https_client_init(&https_client, loop);

  app_state_t app;
  app.https_client = &https_client;
  app.resolv = resolv;

  dns_server_t dns_server;
  dns_server_init(&dns_server, loop, opt.listen_addr, opt.listen_port,
                  dns_server_cb, &app);

  if (opt.daemonize) {
    if (setgid(opt.gid))
      FLOG("Failed to set gid.");
    if (setuid(opt.uid))
      FLOG("Failed to set uid.");
    // daemon() is non-standard. If needed, see OpenSSH openbsd-compat/daemon.c
    daemon(0, 0);
  }

  ev_signal sigint;
  ev_signal_init(&sigint, sigint_cb, SIGINT);
  ev_signal_start(loop, &sigint);

  dns_poller_t dns_poller;
  dns_poller_init(&dns_poller, loop, opt.bootstrap_dns, "dns.google.com",
                  120 /* seconds */, dns_poll_cb, &resolv);

  ev_run(loop, 0);

  dns_poller_cleanup(&dns_poller);

  curl_slist_free_all(resolv);

  ev_signal_stop(loop, &sigint);
  dns_server_cleanup(&dns_server);
  https_client_cleanup(&https_client);

  curl_global_cleanup();
  logging_cleanup();
  options_cleanup(&opt);
  return EXIT_SUCCESS;
}
