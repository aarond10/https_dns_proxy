// Simple UDP-to-HTTPS DNS Proxy
//
// (C) 2016 Aaron Drew
// 
// Intended for use with Google's Public-DNS over HTTPS service
// (https://developers.google.com/speed/public-dns/docs/dns-over-https)

#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#include "dns_client.h"
#include "dns_packet.h"
#include "options.h"
#include "logging.h"

using namespace std;

namespace {
sig_atomic_t gKeepRunning = 1;
// Quit gracefully on Ctrl-C
void SigHandler(int sig) {
  if (sig == SIGINT) {
    WLOG("SIGINT received. Shutting down.");
    gKeepRunning = 0; 
  }
}

// Forks and drops to a regular user if running as root.
void Daemonize(const Options& opt) {
  uid_t uid = 0;
  gid_t gid = 0;
  if (getuid() == 0) {
    WLOG("Dropping to %s:%s", opt.user, opt.group);
    struct passwd *p;
    if (!(p = getpwnam(opt.user)) || !p->pw_uid) {
      FLOG("Username (%s) invalid.", opt.user);
    } else {
      uid = p->pw_uid;
    }
    struct group *g;
    if (!(g = getgrnam(opt.group)) || !g->gr_gid) {
      FLOG("Group (%s) invalid.", opt.group);
    } else {
      gid = g->gr_gid;
    }
  }
  if(fork() != 0) { exit(0); }
  if(fork() != 0) { exit(0); }
  if (uid) setuid(uid);
  if (gid) setgid(gid);
}

class Request {
 public:
  Request(uint16_t tx_id, const char *url, 
          sockaddr_in raddr, curl_slist *resolv) {
    curl_ = curl_easy_init();
    tx_id_ = tx_id;
    buf_ = NULL;
    len_ = 0;
    raddr_ = raddr;
    resolv_ = resolv;

    CURLcode res;
    if ((res = curl_easy_setopt(curl_, CURLOPT_RESOLVE, resolv_)) != CURLE_OK) {
      FLOG("CURLOPT_RESOLV error: %s", curl_easy_strerror(res));
    }
    curl_easy_setopt(curl_, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl_, CURLOPT_URL, url);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT_MS, 3000);
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, &WriteBuffer);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, (void *)this);
    curl_easy_setopt(curl_, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl_, CURLOPT_USERAGENT, "dns-to-https-proxy/0.1");
    DLOG("Req %04x: %s", tx_id_, url);
  }

  CURL *easy_handle() { return curl_; }

  void SendResponse(int listen_sock) {
    DNSPacket r;
    if (!r.ReadJson(tx_id_, buf_)) {
      WLOG("Failed to interpret JSON '%s'. Skipping.", buf_);
      return;
    }

    char ret[4096];
    int len = 0;
    if (!r.WriteDNS(ret, ret + sizeof(ret), &len)) {
      DLOG("Failed to write DNS response to buffer. Skipping.");
      return;
    }
    if (len > 0) {
      sendto(listen_sock, ret, len, 0, (sockaddr *)&raddr_, sizeof(raddr_));
    }
    DLOG("Resp %04x", tx_id_);
  }

  ~Request() {
    curl_easy_cleanup(curl_);
    free(buf_);
  }

 private:
  CURL *curl_;
  uint16_t tx_id_;
  char *buf_;
  int len_;
  sockaddr_in raddr_;
  curl_slist *resolv_;

  static size_t WriteBuffer(
      void *contents, size_t size, size_t nmemb, void *userp) {
    Request *req = (Request *)userp;
    req->buf_ = (char *)realloc(req->buf_, req->len_ + size * nmemb + 1);
    if(req->buf_ == NULL) {
      ELOG("Out of memory!");
      return 0;
    }
    memcpy(&(req->buf_[req->len_]), contents, size * nmemb);
    req->len_ += size * nmemb;
    req->buf_[req->len_] = 0;
    return size * nmemb;
  }

};

// Multiplexes three things, forever:
//  1. Listening socket for incoming DNS requests.
//  2. Outgoing sockets for HTTPS requests.
//  3. Outgoing socket for periodic DNS client query for dns.google.com.
void RunSelectLoop(const Options& opt, int listen_sock) {
  CURLM *curlm = curl_multi_init();

  curl_multi_setopt(curlm, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  // Avoid C++ map, etc for symbol bloat.
  // We don't bother sorting this, so O(n) cost in number of concurrent
  // requests. I assume this won't hurt much.
  Request* reqs[4096];
  int num_reqs = 0;

  // DNS client state.
  TrivialDNSClient client(opt.bootstrap_dns, "dns.google.com");
  const time_t client_req_interval = 300; // 5 minutes.
  time_t last_client_req_time = 0;
  curl_slist *client_resolv = NULL;

  while (gKeepRunning) {
    DLOG("tick");
    fd_set rfd, wfd, efd;
    int max_fd;

    // If we need to, send off a DNS request.
    if (last_client_req_time + client_req_interval < time(NULL)) {
      DLOG("Sending DNS request for dns.google.com");
      last_client_req_time = time(NULL);
      client.Send();
    }

    // Curl tells us how long select should wait.
    long curl_timeo;
    timeval timeout;
    curl_multi_timeout(curlm, &curl_timeo);
    if(curl_timeo < 0) curl_timeo = 1000;
    timeout.tv_sec = curl_timeo / 1000;
    timeout.tv_usec = (curl_timeo % 1000) * 1000;

    FD_ZERO(&rfd); FD_ZERO(&wfd); FD_ZERO(&efd);  max_fd = 0;
    CURLMcode err;
    if ((err = curl_multi_fdset(curlm, &rfd, &wfd, &efd, &max_fd)) != CURLM_OK) {
      FLOG("CURL error: %s", curl_multi_strerror(err));
    }

    FD_SET(listen_sock, &rfd);
    max_fd = max_fd > listen_sock ? max_fd : listen_sock;
    FD_SET(client.sock(), &rfd);
    max_fd = max_fd > client.sock() ? max_fd : client.sock();

    int r = select(max_fd + 1,  &rfd, &wfd, &efd, &timeout);

    if (r < 0) continue; // signal?

    if (r == 0) {
      // Timeout. Try again.
      continue;
    }

    // DNS request
    if (FD_ISSET(listen_sock, &rfd)) {
      char buf[2048];
      sockaddr_in raddr;
      socklen_t raddr_size = sizeof(raddr);
      int len = recvfrom(listen_sock, buf, sizeof(buf), 0, (sockaddr *)&raddr, &raddr_size);
      if (len < 0) {
        WLOG("recvfrom failed: %s", strerror(errno));
        continue;
      }
      DNSPacket p;
      if (!p.ReadDNS(buf, buf + len)) {
        DLOG("Failed to decode packet.");
        continue;
      }
      if (p.num_q == 1) {
        bool cd_bit = p.flags & (1 << 4);
        char *escaped_name = curl_escape(p.q[0].name, strlen(p.q[0].name));
        char url[1500] = {};
        snprintf(url, sizeof(url)-1,
            "https://dns.google.com/resolve?name=%s&type=%d%s",
            escaped_name, p.q[0].type, cd_bit ? "&cd=true" : "");
        curl_free(escaped_name);
        Request *req = new Request(p.tx_id, url, raddr, client_resolv);
        reqs[num_reqs++] = req;
        curl_multi_add_handle(curlm, req->easy_handle());
      }
    }
    // DNS response
    if (FD_ISSET(client.sock(), &rfd)) {
      if (client.Recv()) {
        // Update libcurl's resolv cache (done on each request)
        curl_slist_free_all(client_resolv);
        char entry[256] = {};
        snprintf(entry, sizeof(entry)-1, "dns.google.com:443:%s",
                 client.ip());
        client_resolv = curl_slist_append(NULL, entry);
        DLOG("dns.google.com at %s", client.ip());
      }
    }
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
            if (reqs[i]->easy_handle() == m->easy_handle) {
              Request *req = reqs[i];
              req->SendResponse(listen_sock);
              reqs[i] = reqs[--num_reqs];
              curl_multi_remove_handle(curlm, m->easy_handle);
              delete req;
              break;
            }
          }
        }
      }
    }
  }

  // Cancel all pending requests.
  for (int i = 0; i < num_reqs; i++) {
    curl_multi_remove_handle(curlm, reqs[i]->easy_handle());
    delete reqs[i];
  }
  curl_multi_cleanup(curlm);
  curl_slist_free_all(client_resolv);
  close(listen_sock);
}
}  // namespace

int main(int argc, char *argv[]) {
  Options opt;
  if (!opt.ParseArgs(argc, argv)) {
    opt.ShowUsage(argc, argv);
    exit(1);
  }

  sockaddr_in laddr, raddr;
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

  curl_global_init(CURL_GLOBAL_DEFAULT);
  ILOG("Listening on %s:%d", opt.listen_addr, opt.listen_port);
  if (opt.daemonize) Daemonize(opt);

  if (signal(SIGINT, SigHandler) == SIG_ERR) {
    FLOG("Can't set signal handler.");
  }

  srand(time(0));  // PRNG used for tx_id when we query for dns.google.com.

  RunSelectLoop(opt, sock);

  curl_global_cleanup();
  return 0;
}


