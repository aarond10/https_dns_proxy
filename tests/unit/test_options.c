#include <unistd.h>
#include <pwd.h>

#include "test_harness.h"

static uid_t effective_uid;

static uid_t test_geteuid(void) {
  return effective_uid;
}

static uid_t test_getuid(void) {
  return 1000;
}

static struct passwd *test_getpwnam(const char __attribute__((unused)) *name) {
  static struct passwd user = {
    .pw_name = "proxy",
    .pw_uid = 1000,
    .pw_gid = 1000
  };
  return &user;
}

#define getuid test_getuid
#define geteuid test_geteuid
#define getpwnam test_getpwnam
#define OUTBOUND_INTERFACE_TEST
#include "../../src/options.c"
#undef OUTBOUND_INTERFACE_TEST
#undef getpwnam
#undef getuid
#undef geteuid

static options_t options;

static void setUp(void) {
  options_init(&options);
  effective_uid = 1000;
  optind = 1;
#ifdef __APPLE__
  optreset = 1;
#endif
}

static void tearDown(void) {
  options_cleanup(&options);
}

static void test_parses_outbound_interface(void) {
  char *arguments[] = {
    "https_dns_proxy", "-S", "192.0.2.10",
    "--outbound-interface", "wg0", NULL
  };

  TEST_ASSERT(options_parse_args(&options, 5, arguments) == OPR_SUCCESS);
  TEST_ASSERT(options.source_addr != NULL);
  TEST_ASSERT(strcmp(options.source_addr, "192.0.2.10") == 0);
  TEST_ASSERT(options.outbound_interface != NULL);
  TEST_ASSERT(strcmp(options.outbound_interface, "wg0") == 0);
}

static void test_rejects_interface_with_internal_user_drop(void) {
  char *arguments[] = {
    "https_dns_proxy", "-u", "proxy", "-I", "wg0", NULL
  };

  TEST_ASSERT(options_parse_args(&options, 5, arguments) == OPR_OPTION_ERROR);
}

static void test_allows_interface_with_proxy(void) {
  char *arguments[] = {
    "https_dns_proxy", "-t", "socks5h://proxy.example", "-I", "wg0", NULL
  };

  TEST_ASSERT(options_parse_args(&options, 5, arguments) == OPR_SUCCESS);
}

static void test_interface_rejects_source_interface_or_hostname(void) {
  char *arguments[] = {"https_dns_proxy", "-I", "wg0", "-S", "eth0", NULL};
  TEST_ASSERT(options_parse_args(&options, 5, arguments) == OPR_OPTION_ERROR);
}

static void test_interface_accepts_ipv6_source(void) {
  char *arguments[] = {"https_dns_proxy", "-I", "wg0", "-S", "2001:db8::1", NULL};
  TEST_ASSERT(options_parse_args(&options, 5, arguments) == OPR_SUCCESS);
}

static void test_nonroot_user_does_not_request_group_reset(void) {
  char *arguments[] = {"https_dns_proxy", "-u", "proxy", NULL};
  TEST_ASSERT(options_parse_args(&options, 3, arguments) == OPR_SUCCESS);
  TEST_ASSERT(options.uid == 1000);
  TEST_ASSERT(options.gid == (gid_t)-1);
}

static void test_root_user_uses_primary_group(void) {
  effective_uid = 0;
  char *arguments[] = {"https_dns_proxy", "-u", "proxy", NULL};
  TEST_ASSERT(options_parse_args(&options, 3, arguments) == OPR_SUCCESS);
  TEST_ASSERT(options.uid == 1000);
  TEST_ASSERT(options.gid == 1000);
}

int main(void) {
  TEST_RUN(test_parses_outbound_interface);
  TEST_RUN(test_rejects_interface_with_internal_user_drop);
  TEST_RUN(test_allows_interface_with_proxy);
  TEST_RUN(test_interface_rejects_source_interface_or_hostname);
  TEST_RUN(test_interface_accepts_ipv6_source);
  TEST_RUN(test_nonroot_user_does_not_request_group_reset);
  TEST_RUN(test_root_user_uses_primary_group);
  return test_summary();
}
