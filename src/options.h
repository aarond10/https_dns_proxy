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

  // DNS servers to look up resolver host (e.g. dns.google)
  const char *bootstrap_dns;

  int bootstrap_dns_polling_interval;

  int ipv4;  // if non-zero, will only use AF_INET addresses.

  int dscp; // mark packet with DSCP

  // Resolver URL prefix to use. Must start with https://.
  const char *resolver_url;

  // Optional http proxy if required.
  // e.g. "socks5://127.0.0.1:1080"
  const char *curl_proxy;

  // 1 = Use only HTTP/1.1 for limited OpenWRT libcurl (which is not built with HTTP/2 support)
  // 2 = Use only HTTP/2 default
  // 3 = Use only HTTP/3 QUIC
  int use_http_version;

  int max_idle_time;

  // Print statistic interval
  int stats_interval;

  // Path to a file containing CA certificates
  const char *ca_info;

  // Number of logs to be kept by flight recorder
  uint32_t flight_recorder_size;
} __attribute__((aligned(128)));
typedef struct Options options_t;

enum OptionsParseResult {
    OPR_SUCCESS,
    OPR_HELP,
    OPR_VERSION,
    OPR_OPTION_ERROR,
    OPR_PARSING_ERROR
};

#ifdef __cplusplus
extern "C" {
#endif
void options_init(struct Options *opt);
enum OptionsParseResult options_parse_args(struct Options *opt, int argc, char **argv);
void options_show_usage(int argc, char **argv);
void options_cleanup(struct Options *opt);
#ifdef __cplusplus
}
#endif

#endif // _OPTIONS_H_
