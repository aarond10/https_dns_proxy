#include <ares.h>
#include <stdint.h>
#include <string.h>

#include "dns_common.h"
#include "dns_truncate.h"
#include "test_harness.h"

enum {
  DNS_TEST_BUFFER_SIZE = 640,
  DNS_TEST_TXT_RDATA_SIZE = 512
};

static void setUp(void) {
}

static void tearDown(void) {
}

static void write_u16(uint8_t *buffer, size_t *offset, uint16_t value) {
  buffer[(*offset)++] = (uint8_t)(value >> 8);
  buffer[(*offset)++] = (uint8_t)value;
}

static void write_u32(uint8_t *buffer, size_t *offset, uint32_t value) {
  buffer[(*offset)++] = (uint8_t)(value >> 24);
  buffer[(*offset)++] = (uint8_t)(value >> 16);
  buffer[(*offset)++] = (uint8_t)(value >> 8);
  buffer[(*offset)++] = (uint8_t)value;
}

static void write_question(uint8_t *buffer, size_t *offset) {
  static const uint8_t question[] = {
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm', 0,
    0, (uint8_t)ARES_REC_TYPE_A,
    0, (uint8_t)ARES_CLASS_IN
  };
  memcpy(buffer + *offset, question, sizeof(question));
  *offset += sizeof(question);
}

static void write_opt(uint8_t *buffer, size_t *offset, uint16_t udp_size) {
  buffer[(*offset)++] = 0;
  write_u16(buffer, offset, (uint16_t)ARES_REC_TYPE_OPT);
  write_u16(buffer, offset, udp_size);
  write_u32(buffer, offset, 0);
  write_u16(buffer, offset, 0);
}

static size_t build_request(uint8_t *buffer, uint16_t udp_size) {
  memset(buffer, 0, DNS_TEST_BUFFER_SIZE);
  buffer[0] = 0x12;
  buffer[1] = 0x34;
  buffer[2] = 0x01;
  buffer[5] = 1;
  buffer[11] = 1;

  size_t offset = DNS_HEADER_LENGTH;
  write_question(buffer, &offset);
  write_opt(buffer, &offset, udp_size);
  return offset;
}

static size_t build_large_response(uint8_t *buffer) {
  memset(buffer, 0, DNS_TEST_BUFFER_SIZE);
  buffer[0] = 0x12;
  buffer[1] = 0x34;
  buffer[2] = 0x81;
  buffer[3] = 0x80;
  buffer[5] = 1;
  buffer[7] = 1;
  buffer[11] = 1;

  size_t offset = DNS_HEADER_LENGTH;
  write_question(buffer, &offset);

  buffer[offset++] = 0xc0;
  buffer[offset++] = 0x0c;
  write_u16(buffer, &offset, (uint16_t)ARES_REC_TYPE_TXT);
  write_u16(buffer, &offset, (uint16_t)ARES_CLASS_IN);
  write_u32(buffer, &offset, 60);
  write_u16(buffer, &offset, DNS_TEST_TXT_RDATA_SIZE);
  buffer[offset++] = UINT8_MAX;
  memset(buffer + offset, 'a', UINT8_MAX);
  offset += UINT8_MAX;
  buffer[offset++] = UINT8_MAX;
  memset(buffer + offset, 'b', UINT8_MAX);
  offset += UINT8_MAX;

  write_opt(buffer, &offset, DNS_SIZE_LIMIT);
  return offset;
}

static void test_response_within_512_bytes_is_unchanged(void) {
  uint8_t request[DNS_TEST_BUFFER_SIZE];
  const size_t request_len = build_request(request, 256);
  uint8_t response[DNS_TEST_BUFFER_SIZE];
  uint8_t original[DNS_TEST_BUFFER_SIZE];
  size_t response_len = 300;
  memset(response, 0xa5, response_len);
  memcpy(original, response, response_len);

  dns_truncate_for_udp((const char *)request, request_len,
                       (char *)response, &response_len);

  TEST_ASSERT(response_len == 300);
  TEST_ASSERT(memcmp(response, original, response_len) == 0);
}

static void test_response_within_edns_limit_is_unchanged(void) {
  uint8_t request[DNS_TEST_BUFFER_SIZE];
  const size_t request_len = build_request(request, 1232);
  uint8_t response[DNS_TEST_BUFFER_SIZE];
  uint8_t original[DNS_TEST_BUFFER_SIZE];
  size_t response_len = 600;
  memset(response, 0x5a, response_len);
  memcpy(original, response, response_len);

  dns_truncate_for_udp((const char *)request, request_len,
                       (char *)response, &response_len);

  TEST_ASSERT(response_len == 600);
  TEST_ASSERT(memcmp(response, original, response_len) == 0);
}

static void test_oversized_response_is_truncated(void) {
  uint8_t request[DNS_TEST_BUFFER_SIZE];
  const size_t request_len = build_request(request, 256);
  uint8_t response[DNS_TEST_BUFFER_SIZE];
  size_t response_len = build_large_response(response);
  const size_t original_len = response_len;

  dns_truncate_for_udp((const char *)request, request_len,
                       (char *)response, &response_len);

  TEST_ASSERT(response_len < original_len);
  TEST_ASSERT(response_len <= DNS_SIZE_LIMIT);
  TEST_ASSERT((response[2] & 0x02) != 0);

  ares_dns_record_t *record = NULL;
  const ares_status_t status = ares_dns_parse(response, response_len, 0, &record);
  const int parsed = status == ARES_SUCCESS && record != NULL;
  const size_t answer_count = parsed ?
      ares_dns_record_rr_cnt(record, ARES_SECTION_ANSWER) : 1;
  const size_t authority_count = parsed ?
      ares_dns_record_rr_cnt(record, ARES_SECTION_AUTHORITY) : 1;
  const size_t additional_count = parsed ?
      ares_dns_record_rr_cnt(record, ARES_SECTION_ADDITIONAL) : 0;
  const ares_dns_rr_t *additional = additional_count == 1 ?
      ares_dns_record_rr_get(record, ARES_SECTION_ADDITIONAL, 0) : NULL;
  const int opt_preserved = additional != NULL &&
      ares_dns_rr_get_type(additional) == ARES_REC_TYPE_OPT;
  if (record != NULL) {
    ares_dns_record_destroy(record);
  }

  TEST_ASSERT(parsed);
  TEST_ASSERT(answer_count == 0);
  TEST_ASSERT(authority_count == 0);
  TEST_ASSERT(additional_count == 1);
  TEST_ASSERT(opt_preserved);
}

int main(void) {
  TEST_RUN(test_response_within_512_bytes_is_unchanged);
  TEST_RUN(test_response_within_edns_limit_is_unchanged);
  TEST_RUN(test_oversized_response_is_truncated);
  return test_summary();
}
