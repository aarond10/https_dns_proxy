// Holds options that can be supplied via commandline.
#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include <stdint.h>

struct Options {
  const char *listen_addr;
  uint16_t listen_port;

  // Logfile.
  const char *logfile;
  int logfd;
  int loglevel;

  // Whether to fork into background.
  int daemonize;

  // User/group to drop permissions to if root.
  // Not used if running as non-root.
  const char *user;
  const char *group;

  // Derived from the above.
  uid_t uid;
  gid_t gid;

  // DNS servers to look up resolver host (e.g. dns.google.com)
  const char *bootstrap_dns;

  // Resolver URL prefix to use. Must start with https://.
  const char *resolver_url_prefix;

  // Google DNS can accept an edns_client_subnet option.
  // (https://tools.ietf.org/html/draft-ietf-dnsop-edns-client-subnet-08)
  // This can be used to localize DNS responses to the clients region to (say)
  // return the lowest latency CDN endpoint for some content.
  // It could also be used for geo-blocking and privacy invading user tracking.
  // If an IPv4 subnet is specified here, all requests will be made as if from
  // this address for supported domain resolvers.
  const char *edns_client_subnet;

  // Optional http proxy if required.
  // e.g. "socks5://127.0.0.1:1080"
  const char *curl_proxy;

  // Hack to fix OpenWRT issues due to dropping of HTTP/2 support from libcurl.
  int use_http_1_1;
};
typedef struct Options options_t;

#ifdef __cplusplus
extern "C" {
#endif
void options_init(struct Options *opt);
int options_parse_args(struct Options *opt, int argc, char **argv);
void options_show_usage(int argc, char **argv);
void options_cleanup(struct Options *opt);
#ifdef __cplusplus
}
#endif

#endif // _OPTIONS_H_
