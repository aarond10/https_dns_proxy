#include <fcntl.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <grp.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <pwd.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <stdio.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <string.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/stat.h>      // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/types.h>     // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "logging.h"
#include "options.h"

// Hack for platforms that don't support O_CLOEXEC.
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define DEFAULT_HTTP_VERSION 2

void options_init(struct Options *opt) {
  opt->listen_addr = "127.0.0.1";
  opt->listen_port = 5053;
  opt->logfile = "-";
  opt->logfd = -1;
  opt->loglevel = LOG_ERROR;
  opt->daemonize = 0;
  opt->dscp = 0;
  opt->user = NULL;
  opt->group = NULL;
  opt->uid = (uid_t)-1;
  opt->gid = (uid_t)-1;
  //new as from https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
  opt->bootstrap_dns = "8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1,145.100.185.15,145.100.185.16,185.49.141.37";
  opt->bootstrap_dns_polling_interval = 120;
  opt->ipv4 = 0;
  opt->resolver_url = "https://dns.google/dns-query";
  opt->curl_proxy = NULL;
  opt->use_http_version = DEFAULT_HTTP_VERSION;
  opt->stats_interval = 0;
  opt->ca_info = NULL;
}

int options_parse_args(struct Options *opt, int argc, char **argv) {
  int c = 0;
  while ((c = getopt(argc, argv, "a:c:p:du:g:b:i:4r:e:t:l:vxqs:C:hV")) != -1) {
    switch (c) {
    case 'a': // listen_addr
      opt->listen_addr = optarg;
      break;
    case 'c': // DSCP codepoint
      opt->dscp = atoi(optarg);
      break;
    case 'p': // listen_port
      opt->listen_port = atoi(optarg);
      break;
    case 'd': // daemonize
      opt->daemonize = 1;
      break;
    case 'u': // user
      opt->user = optarg;
      break;
    case 'g': // group
      opt->group = optarg;
      break;
    case 'b': // bootstrap dns servers
      opt->bootstrap_dns = optarg;
      break;
    case 'i': // bootstrap dns servers polling interval
      opt->bootstrap_dns_polling_interval = atoi(optarg);
      break;
    case '4': // ipv4 mode - don't use v6 addresses.
      opt->ipv4 = 1;
      break;
    case 'r': // resolver url prefix
      opt->resolver_url = optarg;
      break;
    case 't': // curl http proxy
      opt->curl_proxy = optarg;
      break;
    case 'l': // logfile
      opt->logfile = optarg;
      break;
    case 'v': // verbose
      if (opt->loglevel) {
        opt->loglevel--;
      }
      break;
    case 'x': // http/1.1 fallthrough
    case 'q': // http/3
      if (opt->use_http_version == DEFAULT_HTTP_VERSION) {
        opt->use_http_version = (c == 'x' ? 1 : 3);
      } else {
        printf("HTTP version already set to: HTTP/%s\n",
               opt->use_http_version == 1 ? "1.1" : "3");
        return -1;
      }
      break;
    case 's': // stats interval
      opt->stats_interval = atoi(optarg);
      break;
    case 'C': // CA info
      opt->ca_info = optarg;
      break;
    case '?':
      printf("Unknown option '-%c'\n", c);
      // fallthrough
    case 'h':
      return -1;
    case 'V': // version
      printf("%s\n", GIT_VERSION);
      exit(0);
    default:
      printf("Unknown state!");
      exit(EXIT_FAILURE);
    }
  }
  if (opt->user) {
    struct passwd *p = NULL;
    if (!(p = getpwnam(opt->user)) || !p->pw_uid) {
      printf("Username (%s) invalid.\n", opt->user);
      return -1;
    }
    opt->uid = p->pw_uid;
  }
  if (opt->group) {
    struct group *g = NULL;
    if (!(g = getgrnam(opt->group)) || !g->gr_gid) {
      printf("Group (%s) invalid.\n", opt->group);
      return -1;
    }
    opt->gid = g->gr_gid;
  }
  if (opt->dscp < 0 || opt->dscp >63) {
      printf("DSCP code (%d) invalid:[0-63]\n", opt->dscp);
      return -1;
  }
  opt->dscp <<= 2;
  // Get noisy about bad security practices.
  if (getuid() == 0 && (!opt->user || !opt->group)) {
    printf("----------------------------\n"
           "WARNING: Running as root without dropping privileges "
           "is NOT recommended.\n"
           "----------------------------\n");
    sleep(1);
  }
  if (opt->logfile == NULL ||
      !strcmp(opt->logfile, "-")) {
    opt->logfd = STDOUT_FILENO;
  } else if ((opt->logfd = open(opt->logfile,
                                O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC,
                                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) <= 0) {
    printf("Logfile '%s' is not writable.\n", opt->logfile);
  }
  if (opt->resolver_url == NULL ||
      strncmp(opt->resolver_url, "https://", 8) != 0) {
    printf("Resolver prefix (%s) must be a https:// address.\n",
           opt->resolver_url);
    return -1;
  }
  if (opt->bootstrap_dns_polling_interval < 5 ||
      opt->bootstrap_dns_polling_interval > 3600) {
    printf("DNS servers polling interval must be between 5 and 3600.\n");
    return -1;
  }
  if (opt->stats_interval < 0 || opt->stats_interval > 3600) {
    printf("Statistic interval must be between 0 and 3600.\n");
    return -1;
  }
  return 0;
}

void options_show_usage(int __attribute__((unused)) argc, char **argv) {
  struct Options defaults;
  options_init(&defaults);
  printf("Usage: %s [-a <listen_addr>] [-p <listen_port>]\n", argv[0]);
  printf("        [-d] [-u <user>] [-g <group>] [-b <dns_servers>]\n");
  printf("        [-i <polling_interval>] [-4] [-r <resolver_url>]\n");
  printf("        [-t <proxy_server>] [-l <logfile>] [-c <dscp_codepoint>]\n");
  printf("        [-x] [-q] [-s <statistic_interval>] [-v]+ [-V] [-h]\n\n");
  printf("  -a listen_addr         Local IPv4/v6 address to bind to. (%s)\n",
         defaults.listen_addr);
  printf("  -p listen_port         Local port to bind to. (%d)\n",
         defaults.listen_port);
  printf("  -d                     Daemonize.\n");
  printf("  -u user                Optional user to drop to if launched as root.\n");
  printf("  -g group               Optional group to drop to if launched as root.\n");
  printf("  -b dns_servers         Comma-separated IPv4/v6 addresses and ports (addr:port)\n");
  printf("                         of DNS servers to resolve resolver host (e.g. dns.google).\n"\
         "                         When specifying a port for IPv6, enclose the address in [].\n"\
         "                         (%s)\n",
         defaults.bootstrap_dns);
  printf("  -i polling_interval    Optional polling interval of DNS servers.\n"\
         "                         (Default: %d, Min: 5, Max: 3600)\n",
         defaults.bootstrap_dns_polling_interval);
  printf("  -4                     Force IPv4 hostnames for DNS resolvers non IPv6 networks.\n");
  printf("  -r resolver_url        The HTTPS path to the resolver URL. Default: %s\n",
         defaults.resolver_url);
  printf("  -t proxy_server        Optional HTTP proxy. e.g. socks5://127.0.0.1:1080\n");
  printf("                         Remote name resolution will be used if the protocol\n");
  printf("                         supports it (http, https, socks4a, socks5h), otherwise\n");
  printf("                         initial DNS resolution will still be done via the\n");
  printf("                         bootstrap DNS servers.\n");
  printf("  -l logfile             Path to file to log to. (\"%s\")\n",
         defaults.logfile);
  printf("  -c dscp_codepoint      Optional DSCP codepoint[0-63] to set on upstream DNS server\n");
  printf("                         connections.\n");
  printf("  -x                     Use HTTP/1.1 instead of HTTP/2. Useful with broken\n"
         "                         or limited builds of libcurl. (false)\n");
  printf("  -q                     Use HTTP/3 (QUIC) only. (false)\n");
  printf("  -s statistic_interval  Optional statistic printout interval.\n"\
         "                         (Default: %d, Disabled: 0, Min: 1, Max: 3600)\n",
         defaults.stats_interval);
  printf("  -C path                Optional file containing CA certificates.\n");
  printf("  -v                     Increase logging verbosity. (Default: error)\n");
  printf("                         Levels: fatal, stats, error, warning, info, debug\n");
  printf("                         Request issues are logged on warning level.\n");
  printf("  -V                     Print version and exit.\n");
  printf("  -h                     Print help and exit.\n");
  options_cleanup(&defaults);
}

void options_cleanup(struct Options *opt) {
  if (opt->logfd > 0) {
    close(opt->logfd);
  }
}
