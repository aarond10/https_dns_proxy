#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_harness.h"

static int setsockopt_calls;
static int setsockopt_result;
static int captured_socket;
static int captured_level;
static int captured_option;
static char captured_interface[IFNAMSIZ];

#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

static int test_setsockopt(int socket_fd, int level, int option,
                           const void *value, socklen_t value_length) {
  setsockopt_calls++;
  captured_socket = socket_fd;
  captured_level = level;
  captured_option = option;
  const size_t copy_length = value_length < sizeof(captured_interface)
      ? value_length : sizeof(captured_interface);
  memcpy(captured_interface, value, copy_length);
  if (setsockopt_result != 0) {
    errno = EPERM;
  }
  return setsockopt_result;
}

#define setsockopt test_setsockopt
#define OUTBOUND_INTERFACE_TEST
#include "../../src/outbound_interface.c"
#undef OUTBOUND_INTERFACE_TEST
#undef setsockopt

static void setUp(void) {
  setsockopt_calls = 0;
  setsockopt_result = 0;
  captured_socket = -1;
  captured_level = -1;
  captured_option = -1;
  memset(captured_interface, 0, sizeof(captured_interface));
}

static void tearDown(void) {
}

static void test_rejects_empty_interface(void) {
  TEST_ASSERT(outbound_interface_bind_socket(7, "") == -1);
  TEST_ASSERT(errno == EINVAL);
  TEST_ASSERT(setsockopt_calls == 0);
}

static void test_rejects_overlong_interface(void) {
  char interface_name[IFNAMSIZ + 1];
  memset(interface_name, 'a', sizeof(interface_name));
  interface_name[sizeof(interface_name) - 1] = '\0';

  TEST_ASSERT(outbound_interface_bind_socket(7, interface_name) == -1);
  TEST_ASSERT(errno == ENAMETOOLONG);
  TEST_ASSERT(setsockopt_calls == 0);
}

static void test_binds_socket_to_exact_interface(void) {
  TEST_ASSERT(outbound_interface_bind_socket(7, "wg0") == 0);
  TEST_ASSERT(setsockopt_calls == 1);
  TEST_ASSERT(captured_socket == 7);
  TEST_ASSERT(captured_level == SOL_SOCKET);
  TEST_ASSERT(captured_option == SO_BINDTODEVICE);
  TEST_ASSERT(strcmp(captured_interface, "wg0") == 0);
}

static void test_propagates_bind_permission_failure(void) {
  setsockopt_result = -1;
  TEST_ASSERT(outbound_interface_bind_socket(7, "wg0") == -1);
  TEST_ASSERT(errno == EPERM);
  TEST_ASSERT(setsockopt_calls == 1);
}

int main(void) {
  TEST_RUN(test_rejects_empty_interface);
  TEST_RUN(test_rejects_overlong_interface);
  TEST_RUN(test_binds_socket_to_exact_interface);
  TEST_RUN(test_propagates_bind_permission_failure);
  return test_summary();
}
