// Unit test for logging context
// This test demonstrates that multiple independent logging contexts work correctly
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "../../src/logging.h"

// Simple test framework
static int tests_run = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, message) do { \
    tests_run++; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s:%d - %s\n", __FILE__, __LINE__, message); \
        tests_failed++; \
    } else { \
        fprintf(stdout, "PASS: %s\n", message); \
    } \
} while(0)

// Test that we can create multiple independent logging contexts
void test_multiple_contexts(void) {
    char tempfile1[] = "/tmp/log1_XXXXXX";
    char tempfile2[] = "/tmp/log2_XXXXXX";

    int fd1 = mkstemp(tempfile1);
    int fd2 = mkstemp(tempfile2);

    TEST_ASSERT(fd1 >= 0, "Create temp file 1");
    TEST_ASSERT(fd2 >= 0, "Create temp file 2");

    // Create two independent logging contexts
    logging_context_t ctx1;
    logging_context_t ctx2;

    memset(&ctx1, 0, sizeof(ctx1));
    memset(&ctx2, 0, sizeof(ctx2));

    logging_context_init(&ctx1, dup(fd1), LOG_INFO, 0);
    logging_context_init(&ctx2, dup(fd2), LOG_DEBUG, 0);

    // Log to different contexts
    ILOG_CTX(&ctx1, "Message to context 1");
    ILOG_CTX(&ctx2, "Message to context 2");
    DLOG_CTX(&ctx2, "Debug message to context 2");

    // Cleanup
    logging_context_cleanup(&ctx1);
    logging_context_cleanup(&ctx2);

    // Read back and verify
    char buf1[1024] = {0};
    char buf2[1024] = {0};

    lseek(fd1, 0, SEEK_SET);
    lseek(fd2, 0, SEEK_SET);

    ssize_t n1 = read(fd1, buf1, sizeof(buf1) - 1);
    ssize_t n2 = read(fd2, buf2, sizeof(buf2) - 1);

    TEST_ASSERT(n1 > 0, "Context 1 wrote data");
    TEST_ASSERT(n2 > 0, "Context 2 wrote data");

    TEST_ASSERT(strstr(buf1, "Message to context 1") != NULL,
                "Context 1 contains correct message");
    TEST_ASSERT(strstr(buf2, "Message to context 2") != NULL,
                "Context 2 contains correct message");
    TEST_ASSERT(strstr(buf2, "Debug message to context 2") != NULL,
                "Context 2 contains debug message");

    // Debug messages should NOT be in context 1 (LOG_INFO level)
    TEST_ASSERT(strstr(buf1, "Debug") == NULL,
                "Context 1 does not contain debug messages");

    close(fd1);
    close(fd2);
    unlink(tempfile1);
    unlink(tempfile2);
}

// Test that default context still works (backwards compatibility)
void test_default_context(void) {
    char tempfile[] = "/tmp/log_default_XXXXXX";
    int fd = mkstemp(tempfile);

    TEST_ASSERT(fd >= 0, "Create temp file for default context");

    // Initialize default context
    logging_init(dup(fd), LOG_INFO, 0);

    // Use legacy macros
    ILOG("Legacy macro test message");

    logging_cleanup();

    // Read back and verify
    char buf[1024] = {0};
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, buf, sizeof(buf) - 1);

    TEST_ASSERT(n > 0, "Default context wrote data");
    TEST_ASSERT(strstr(buf, "Legacy macro test message") != NULL,
                "Default context contains message from legacy macro");

    close(fd);
    unlink(tempfile);
}

// Test debug enabled flag
void test_debug_enabled(void) {
    logging_context_t ctx_debug;
    logging_context_t ctx_info;

    memset(&ctx_debug, 0, sizeof(ctx_debug));
    memset(&ctx_info, 0, sizeof(ctx_info));

    int fd_null = open("/dev/null", O_WRONLY);

    logging_context_init(&ctx_debug, dup(fd_null), LOG_DEBUG, 0);
    logging_context_init(&ctx_info, dup(fd_null), LOG_INFO, 0);

    TEST_ASSERT(logging_context_debug_enabled(&ctx_debug) == 1,
                "Debug level context reports debug enabled");
    TEST_ASSERT(logging_context_debug_enabled(&ctx_info) == 0,
                "Info level context reports debug disabled");

    logging_context_cleanup(&ctx_debug);
    logging_context_cleanup(&ctx_info);
    close(fd_null);
}

// Test ring buffer integration
void test_flight_recorder(void) {
    char tempfile[] = "/tmp/log_recorder_XXXXXX";
    int fd = mkstemp(tempfile);

    TEST_ASSERT(fd >= 0, "Create temp file for flight recorder");

    logging_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Initialize with flight recorder (100 entries)
    logging_context_init(&ctx, dup(fd), LOG_ERROR, 100);

    // Log some debug messages (won't be written due to level, but will be recorded)
    DLOG_CTX(&ctx, "Debug message 1");
    DLOG_CTX(&ctx, "Debug message 2");

    // Now dump the flight recorder
    logging_context_flight_recorder_dump(&ctx);

    logging_context_cleanup(&ctx);

    // Read back and verify
    char buf[2048] = {0};
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, buf, sizeof(buf) - 1);

    TEST_ASSERT(n > 0, "Flight recorder wrote data");
    TEST_ASSERT(strstr(buf, "Debug message 1") != NULL,
                "Flight recorder contains debug message 1");
    TEST_ASSERT(strstr(buf, "Debug message 2") != NULL,
                "Flight recorder contains debug message 2");

    close(fd);
    unlink(tempfile);
}

int main(void) {
    printf("Running logging context tests...\n\n");

    test_multiple_contexts();
    test_default_context();
    test_debug_enabled();
    test_flight_recorder();

    printf("\n========================================\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_run - tests_failed);
    printf("Tests failed: %d\n", tests_failed);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
