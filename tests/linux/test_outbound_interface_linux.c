#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_harness.h"
#include "outbound_interface.h"

static void setUp(void) {
}

static void tearDown(void) {
}

static void test_real_interface_binding(void) {
  TEST_ASSERT(geteuid() == 0);
  TEST_ASSERT(outbound_interface_validate("lo") == 0);
  TEST_ASSERT(outbound_interface_validate("hdp-no-such-if") == -1);
  TEST_ASSERT(errno == ENODEV);
}

int main(void) {
  if (getenv("HDP_RUN_PRIVILEGED_TEST") == NULL) {
    return 77;
  }
  TEST_RUN(test_real_interface_binding);
  return test_summary();
}
