#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "test_harness.h"
#include "../../src/dns_listener_tcp.c"

static struct tcp_client_s client;
static char *dns_request;

static void setUp(void) {
  memset(&client, 0, sizeof(client));
  client.input_buffer_size = 64;
  client.input_buffer = (char *)calloc(1, client.input_buffer_size);
  dns_request = NULL;
}

static void tearDown(void) {
  free(dns_request);
  free(client.input_buffer);
}

static void test_waits_for_complete_length_prefix(void) {
  client.input_buffer[0] = (char)UINT8_MAX;
  client.input_buffer_used = 1;
  uint16_t request_size = 0;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 0);
  TEST_ASSERT(dns_request == NULL);
  TEST_ASSERT(client.input_buffer_used == 1);
}

static void test_large_length_does_not_wrap_frame_size(void) {
  client.input_buffer[0] = (char)UINT8_MAX;
  client.input_buffer[1] = (char)UINT8_MAX;
  client.input_buffer_used = 2;
  uint16_t request_size = 0;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 0);
  TEST_ASSERT(request_size == UINT16_MAX);
  TEST_ASSERT(dns_request == NULL);
  TEST_ASSERT(client.input_buffer_used == 2);
}

static void test_rejects_zero_length_request_without_allocating(void) {
  client.input_buffer[0] = 0;
  client.input_buffer[1] = 0;
  client.input_buffer_used = sizeof(uint16_t);
  uint16_t request_size = UINT16_MAX;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 1);
  TEST_ASSERT(request_size == 0);
  TEST_ASSERT(dns_request == NULL);
  TEST_ASSERT(client.input_buffer_used == 0);
}

static void test_extracts_complete_request(void) {
  enum { REQUEST_SIZE = DNS_HEADER_LENGTH };
  client.input_buffer[0] = 0;
  client.input_buffer[1] = REQUEST_SIZE;
  for (size_t i = 0; i < REQUEST_SIZE; i++) {
    client.input_buffer[sizeof(uint16_t) + i] = (char)i;
  }
  client.input_buffer_used = sizeof(uint16_t) + REQUEST_SIZE;
  uint16_t request_size = 0;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 1);
  TEST_ASSERT(request_size == REQUEST_SIZE);
  TEST_ASSERT(client.input_buffer_used == 0);
  for (size_t i = 0; i < REQUEST_SIZE; i++) {
    TEST_ASSERT((uint8_t)dns_request[i] == i);
  }
}

int main(void) {
  TEST_RUN(test_waits_for_complete_length_prefix);
  TEST_RUN(test_large_length_does_not_wrap_frame_size);
  TEST_RUN(test_rejects_zero_length_request_without_allocating);
  TEST_RUN(test_extracts_complete_request);
  return test_summary();
}
