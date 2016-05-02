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

  // DNS servers to look up dns.google.com
  const char *bootstrap_dns;
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
