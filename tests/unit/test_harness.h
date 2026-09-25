#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>

static unsigned test_count;
static unsigned test_failures;
static int test_failed;

static void test_fail(const char *file, int line, const char *expression) {
  (void)fprintf(stderr, "%s:%d: assertion failed: %s\n", file, line, expression);
  test_failed = 1;
}

#define TEST_ASSERT(condition) do { \
  if (!(condition)) { \
    test_fail(__FILE__, __LINE__, #condition); \
    return; \
  } \
} while (0)

#define TEST_ASSERT_EQUAL_PTR(expected, actual) do { \
  const void *expected_ptr = (expected); \
  const void *actual_ptr = (actual); \
  if (expected_ptr != actual_ptr) { \
    test_fail(__FILE__, __LINE__, #expected " == " #actual); \
    return; \
  } \
} while (0)

#define TEST_RUN(test) do { \
  test_failed = 0; \
  setUp(); \
  if (!test_failed) { \
    test(); \
  } \
  tearDown(); \
  test_count++; \
  if (test_failed) { \
    test_failures++; \
    (void)printf("FAIL: %s\n", #test); \
  } else { \
    (void)printf("PASS: %s\n", #test); \
  } \
} while (0)

static int test_summary(void) {
  (void)printf("%u tests, %u failures\n", test_count, test_failures);
  return test_failures == 0 ? 0 : 1;
}

#endif
