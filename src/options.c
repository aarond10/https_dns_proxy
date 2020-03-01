#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "options.h"

// Hack for platforms that don't support O_CLOEXEC.
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

void options_init(struct Options *opt) {
  opt->listen_addr = "127.0.0.1";
  opt->listen_port = 5053;
  opt->logfile = "-";
  opt->logfd = -1;
  opt->loglevel = LOG_DEBUG;
  opt->daemonize = 0;
  opt->user = NULL;
  opt->group = NULL;
  opt->uid = -1;
  opt->gid = -1;
  //new as from https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers
  opt->bootstrap_dns = "8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1,145.100.185.15,145.100.185.16,185.49.141.37";
  opt->ipv4 = 0;
  opt->resolver_url = "https://dns.google/dns-query";
  opt->curl_proxy = NULL;
  opt->use_http_1_1 = 0;
}

int options_parse_args(struct Options *opt, int argc, char **argv) {
  int c;
  while ((c = getopt(argc, argv, "a:p:du:g:b:4r:e:t:l:vx")) != -1) {
    switch (c) {
    case 'a': // listen_addr
      opt->listen_addr = optarg;
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
    case 'x': // http/1.1
      opt->use_http_1_1 = 1;
      break;
    case '?':
      printf("Unknown option '-%c'", c);
      return -1;
    default:
      printf("Unknown state!");
      exit(EXIT_FAILURE);
    }
  }
  if (opt->user) {
    struct passwd *p;
    if (!(p = getpwnam(opt->user)) || !p->pw_uid) {
      printf("Username (%s) invalid.\n", opt->user);
      return -1;
    }
    opt->uid = p->pw_uid;
  }
  if (opt->group) {
    struct group *g;
    if (!(g = getgrnam(opt->group)) || !g->gr_gid) {
      printf("Group (%s) invalid.\n", opt->group);
      return -1;
    }
    opt->gid = g->gr_gid;
  }
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
  return 0;
}

void options_show_usage(int argc, char **argv) {
  struct Options defaults;
  options_init(&defaults);
  printf("Usage: %s [-a <listen_addr>] [-p <listen_port>]\n", argv[0]);
  printf("        [-d] [-u <user>] [-g <group>] [-b <dns_servers>]\n");
  printf("        [-r <resolver_url>] [-e <subnet_addr>]\n");
  printf("        [-t <proxy_server>] [-l <logfile>] [-x] [-v]+\n\n");
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
  printf("  -4                     Force IPv4 hostnames for DNS resolvers non IPv6 networks.\n");
  printf("  -r resolver_url        The HTTPS path to the resolver URL. default: %s\n",
         defaults.resolver_url);
  printf("  -t proxy_server        Optional HTTP proxy. e.g. socks5://127.0.0.1:1080\n");
  printf("                         Remote name resolution will be used if the protocol\n");
  printf("                         supports it (http, https, socks4a, socks5h), otherwise\n");
  printf("                         initial DNS resolution will still be done via the\n");
  printf("                         bootstrap DNS servers.\n");
  printf("  -l logfile             Path to file to log to. (\"%s\")\n",
         defaults.logfile);
  printf("  -x                     Use HTTP/1.1 instead of HTTP/2. Useful with broken\n"
         "                         or limited builds of libcurl. (false)\n");
  printf("  -v                     Increase logging verbosity. (INFO)\n");
  options_cleanup(&defaults);
}

void options_cleanup(struct Options *opt) {
  if (opt->logfd > 0) {
    close(opt->logfd);
  }
}
