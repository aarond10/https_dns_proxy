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
#include "dns_packet.h"
#include "options.h"
#include "logging.h"
#include "request.h"

// So we can quit gracefully on Ctrl-C...
static sig_atomic_t g_keep_running = 1;
static void SigHandler(int sig) {
  if (sig == SIGINT) g_keep_running = 0; 
}

// rand() is used for tx_id selection in outgoing DNS requests.
// This is probably overkill but seed the PRNG with a decent
// source to minimize chance of sequence prediction.
static void prng_init() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srand(tv.tv_sec);
  srand(rand() + tv.tv_usec);
}

// Called when c-ares has a DNS response or error for a lookup of
// dns.google.com.
static void AresCallback(void *arg, int status, int timeouts,
                         struct hostent *hostent) {
  if (status != ARES_SUCCESS) {
    WLOG("DNS lookup failed: %d", status);
  }
  if (!hostent || hostent->h_length < 1) {
    WLOG("No hosts.");
    return;
  }
  char buf[128] = "dns.google.com:443:";
  char *p = buf + strlen(buf);
  int l = sizeof(buf) - strlen(buf);
  ares_inet_ntop(AF_INET, hostent->h_addr_list[0], p, l);
  DLOG("Received new IP '%s'", p);

  // Update libcurl's resolv cache (we pass these cache injection entries in on
  // every request)
  struct curl_slist **p_client_resolv = (struct curl_slist**)arg;
  curl_slist_free_all(*p_client_resolv);
  *p_client_resolv = curl_slist_append(NULL, buf);
}

// Multiplexes three things, forever:
//  1. Listening socket for incoming DNS requests.
//  2. Outgoing sockets for HTTPS requests.
//  3. Outgoing socket for periodic DNS client query for dns.google.com.
static void RunSelectLoop(const struct Options* opt, int listen_sock) {
  CURLM *curlm = curl_multi_init();
  curl_multi_setopt(curlm, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  // Note: I don't bother sorting this, so O(n) cost in number of concurrent
  // requests. I assume this won't hurt much given typical concurrency levels.
  const int max_reqs = 1024;
  struct Request reqs[max_reqs];
  int num_reqs = 0;

  // DNS client.
  ares_channel ares;
  if (ares_init(&ares) != ARES_SUCCESS) {
    FLOG("Failed to init c-ares channel");
  }
  if (ares_set_servers_csv(ares, opt->bootstrap_dns) != ARES_SUCCESS) {
    FLOG("Failed to set DNS servers to '%s'.", opt->bootstrap_dns);
  }
  // 60 seconds poll. Rely on c-ares to honor DNS TTL.
  const time_t client_req_interval = 60; 
  time_t last_client_req_time = 0;
  struct curl_slist *client_resolv = NULL;

  while (g_keep_running) {
    fd_set rfd, wfd, efd;
    int max_fd = 0;
    FD_ZERO(&rfd); FD_ZERO(&wfd); FD_ZERO(&efd);

    // If we need to, send off a DNS request.
    if (last_client_req_time + client_req_interval < time(NULL)) {
      DLOG("Sending DNS request for dns.google.com");
      last_client_req_time = time(NULL);
      ares_gethostbyname(ares, "dns.google.com", AF_INET, 
          &AresCallback, &client_resolv);
    }

    // Curl tells us how long select should wait.
    long curl_timeo;
    struct timeval tv;
    curl_multi_timeout(curlm, &curl_timeo);
    if(curl_timeo < 0) curl_timeo = 1000;
    tv.tv_sec = curl_timeo / 1000;
    tv.tv_usec = (curl_timeo % 1000) * 1000;

    CURLMcode err;
    if ((err = curl_multi_fdset(
         curlm, &rfd, &wfd, &efd, &max_fd)) != CURLM_OK) {
      FLOG("CURL error: %s", curl_multi_strerror(err));
    }

    FD_SET(listen_sock, &rfd);
    max_fd = max_fd > listen_sock ? max_fd : listen_sock;

    int ares_max_fd = ares_fds(ares, &rfd, &wfd) - 1;
    max_fd = max_fd > ares_max_fd ? max_fd : ares_max_fd;

    int r = select(max_fd + 1,  &rfd, &wfd, &efd, &tv);
    if (r < 0) continue; // Signal.
    if (r == 0) continue; // Timeout.

    // DNS request
    if (FD_ISSET(listen_sock, &rfd)) {
      unsigned char buf[1500];  // A whole MTU. We don't do TCP so any bigger is a waste.
      struct sockaddr_in raddr;
      socklen_t raddr_size = sizeof(raddr);
      int len = recvfrom(listen_sock, buf, sizeof(buf), 0, 
                         (struct sockaddr *)&raddr, &raddr_size);
      if (len < 0) {
        WLOG("recvfrom failed: %s", strerror(errno));
        continue;
      }

      if (num_reqs >= max_reqs) {
        WLOG("Too many requests in flight. Ignoring.");
        continue;
      }

      unsigned char *p = buf;
      uint16_t tx_id = ntohs(*(uint16_t*)p); p += 2;
      uint16_t flags = ntohs(*(uint16_t*)p); p += 2;
      uint16_t num_q = ntohs(*(uint16_t*)p); p += 2;
      uint16_t num_rr = ntohs(*(uint16_t*)p); p += 2;
      uint16_t num_arr = ntohs(*(uint16_t*)p); p += 2;
      uint16_t num_xrr = ntohs(*(uint16_t*)p); p += 2;
      if (num_q != 1) {
        DLOG("Malformed request received.");
        continue;
      };
      char *domain_name;
      long enc_len;
      if (ares_expand_name(p, buf, len, 
                           &domain_name, &enc_len) != ARES_SUCCESS) {
        DLOG("Malformed request received.");
        continue;
      }
      p += enc_len;
      uint16_t type = ntohs(*(uint16_t*)p); p += 2;
        
      int cd_bit = flags & (1 << 4);
      char *escaped_name = curl_escape(domain_name, strlen(domain_name));
      ares_free_string(domain_name);
      char url[1500] = {};
      snprintf(url, sizeof(url)-1,
          "https://dns.google.com/resolve?name=%s&type=%d%s",
          escaped_name, type, cd_bit ? "&cd=true" : "");
      curl_free(escaped_name);
      request_init(&reqs[num_reqs], tx_id, url, raddr, client_resolv);
      curl_multi_add_handle(curlm, reqs[num_reqs].curl);
      num_reqs++;
    }
    // DNS response
    ares_process(ares, &rfd, &wfd);
    // CURL transfers
    if (r >= 0) {
      int running_https = 0;
      if ((err = curl_multi_perform(curlm, &running_https)) != CURLM_OK) {
        FLOG("CURL error: %s", curl_multi_strerror(err));
      }
      CURLMsg *m;
      int msgq = 0;
      while (m = curl_multi_info_read(curlm, &msgq)) {
        if(m->msg == CURLMSG_DONE) {
          for (int i = 0; i < num_reqs; i++) {
            if (reqs[i].curl == m->easy_handle) {
              request_send_response(&reqs[i], listen_sock);
              curl_multi_remove_handle(curlm, m->easy_handle);
              request_cleanup(&reqs[i]);
              reqs[i] = reqs[--num_reqs];
              break;
            }
          }
        }
      }
    }
  }

  WLOG("Shutting down.");

  // Cancel all pending requests.
  for (int i = 0; i < num_reqs; i++) {
    curl_multi_remove_handle(curlm, reqs[i].curl);
    request_cleanup(&reqs[i]);
  }
  curl_multi_cleanup(curlm);
  ares_destroy(ares);
  curl_slist_free_all(client_resolv);
  close(listen_sock);
}

int main(int argc, char *argv[]) {
  prng_init();

  struct Options opt;
  options_init(&opt);
  if (options_parse_args(&opt, argc, argv)) {
    options_show_usage(argc, argv);
    exit(1);
  }
  logging_init(opt.logfd, opt.loglevel);
  ares_library_init(ARES_LIB_INIT_ALL);
  curl_global_init(CURL_GLOBAL_DEFAULT);

  struct sockaddr_in laddr, raddr;
  memset(&laddr, 0, sizeof(laddr));
  laddr.sin_family = AF_INET;
  laddr.sin_port = htons(opt.listen_port);
  laddr.sin_addr.s_addr = inet_addr(opt.listen_addr);

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    FLOG("Error creating socket");
  }
  if(bind(sock, (struct sockaddr*)&laddr, sizeof(laddr)) < 0) {
    FLOG("Error binding %s:%d", opt.listen_addr, opt.listen_port);
  }

  ILOG("Listening on %s:%d", opt.listen_addr, opt.listen_port);
  if (opt.daemonize) {
    if (setgid(opt.gid)) FLOG("Failed to set gid.");
    if (setuid(opt.uid)) FLOG("Failed to set uid.");
    // Note: This is non-standard. If needed, see OpenSSH openbsd-compat/daemon.c
    daemon(0, 0);
  }

  if (signal(SIGINT, SigHandler) == SIG_ERR) {
    FLOG("Can't set signal handler.");
  }

  RunSelectLoop(&opt, sock);

  curl_global_cleanup();
  ares_library_cleanup();
  logging_cleanup();
  options_cleanup(&opt);
  return EXIT_SUCCESS;
}
