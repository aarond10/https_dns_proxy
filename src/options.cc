#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "logging.h"
#include "options.h"


bool Options::ParseArgs(int argc, char **argv) {
  int ix, c;
  while((c = getopt(argc, argv, "l:p:du:g:b:")) != -1) {
    switch(c) {
      case 'l':  // listen_addr
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
      case '?':
        ELOG("Unknown option '-%c'", c);
        return false;
      default:
        ELOG("Unknown state!");
        exit(1);
    }
  }
  return true;
}

void Options::ShowUsage(int argc, char **argv) {
  Options defaults;
  printf("Usage: %s [-l <listen_addr>] [-p <listen_port>]\n", argv[0]);
  printf("        [-d] [-u <user>] [-g <group>] [-b <dns_servers>]\n\n");
  printf("  -l listen_addr    Local address to bind to. (%s)\n",
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
}
