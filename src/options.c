#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "logging.h"
#include "options.h"


bool Options::ParseArgs(int argc, char **argv) {
  int ix, c;
  while((c = getopt(argc, argv, "a:p:du:g:b:l:")) != -1) {
    switch(c) {
      case 'a':  // listen_addr
        listen_addr = optarg;
        break;
      case 'p':  // listen_port
        listen_port = atoi(optarg);
        break;
      case 'd':  // daemonize
        daemonize = true;
        break;
      case 'u':  // user
        user = optarg;
        break;
      case 'g':  // group
        group = optarg;
        break;
      case 'b':  // bootstrap dns servers
        bootstrap_dns = optarg;
        break;
      case 'l':  // logfile
        logfile = optarg;
        break;
      case '?':
        ELOG("Unknown option '-%c'", c);
        return false;
      default:
        ELOG("Unknown state!");
        exit(1);
    }
  }
  struct passwd *p;
  if (!(p = getpwnam(user)) || !p->pw_uid) {
    printf("Username (%s) invalid.\n", user);
    return false;
  }
  uid = p->pw_uid;
  struct group *g;
  if (!(g = getgrnam(group)) || !g->gr_gid) {
    printf("Group (%s) invalid.\n", group);
    return false;
  }
  gid = g->gr_gid;
  if ((logfd = open(logfile, O_CREAT | O_WRONLY | O_APPEND,
                    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)) <= 0) {
    printf("Logfile '%s' is not writable.\n", logfile);
  }
  return true;
}

Options::~Options() {
  if (logfd > 0) close(logfd);
}

void Options::ShowUsage(int argc, char **argv) {
  Options defaults;
  printf("Usage: %s [-a <listen_addr>] [-p <listen_port>]\n", argv[0]);
  printf("        [-d] [-u <user>] [-g <group>] [-b <dns_servers>]\n");
  printf("        [-l <logfile>]\n\n");
  printf("  -a listen_addr    Local address to bind to. (%s)\n",
         defaults.listen_addr);
  printf("  -p listen_port    Local port to bind to (%d).\n", 
         defaults.listen_port);
  printf("  -d             Daemonize\n");
  printf("  -u user           User to drop to launched as root (%s).\n",
         defaults.user);
  printf("  -g group          Group to drop to launched as root (%s).\n",
         defaults.group);
  printf("  -b dns_servers    Comma separated IPv4 address of DNS servers\n");
  printf("                    to resolve dns.google.com (%s)\n",
         defaults.bootstrap_dns);
  printf("  -l logfile        Path to file to log to. (%s)\n",
         defaults.logfile);
}
