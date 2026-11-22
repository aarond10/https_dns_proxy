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

static size_t build_padded_response(uint8_t *buffer, uint16_t answer_count,
                                    uint16_t padding_size) {
  memset(buffer, 0, DNS_TEST_BUFFER_SIZE);
  buffer[0] = 0x12;
  buffer[1] = 0x34;
  buffer[2] = 0x81;
  buffer[3] = 0x80;
  buffer[5] = 1;
  buffer[7] = (uint8_t)answer_count;
  buffer[11] = 1;

  size_t offset = DNS_HEADER_LENGTH;
  write_question(buffer, &offset);

  for (uint16_t i = 0; i < answer_count; i++) {
    buffer[offset++] = 0xc0;
    buffer[offset++] = 0x0c;
    write_u16(buffer, &offset, (uint16_t)ARES_REC_TYPE_A);
    write_u16(buffer, &offset, (uint16_t)ARES_CLASS_IN);
    write_u32(buffer, &offset, 60);
    write_u16(buffer, &offset, 4);
    buffer[offset++] = 192;
    buffer[offset++] = 0;
    buffer[offset++] = 2;
    buffer[offset++] = (uint8_t)(i + 1);
  }

  // OPT with an RFC 8467 PADDING option carrying padding_size bytes.
  const uint16_t rdata_length = (uint16_t)(4 + padding_size);
  buffer[offset++] = 0;
  write_u16(buffer, &offset, (uint16_t)ARES_REC_TYPE_OPT);
  write_u16(buffer, &offset, 4096);
  write_u32(buffer, &offset, 0);
  write_u16(buffer, &offset, rdata_length);
  write_u16(buffer, &offset, 12);  // PADDING option code
  write_u16(buffer, &offset, padding_size);
  memset(buffer + offset, 0, padding_size);
  offset += padding_size;
  return offset;
}

static size_t additional_record_count(const uint8_t *resp, size_t resp_len) {
  ares_dns_record_t *record = NULL;
  if (ares_dns_parse(resp, resp_len, 0, &record) != ARES_SUCCESS || record == NULL) {
    return SIZE_MAX;
  }
  const size_t count = ares_dns_record_rr_cnt(record, ARES_SECTION_ADDITIONAL);
  ares_dns_record_destroy(record);
  return count;
}

static int additional_records_are_all_opt(const uint8_t *resp, size_t resp_len) {
  ares_dns_record_t *record = NULL;
  if (ares_dns_parse(resp, resp_len, 0, &record) != ARES_SUCCESS || record == NULL) {
    return 0;
  }
  int all_opt = 1;
  const size_t count = ares_dns_record_rr_cnt(record, ARES_SECTION_ADDITIONAL);
  for (size_t i = 0; i < count; i++) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get(record, ARES_SECTION_ADDITIONAL, i);
    if (rr == NULL || ares_dns_rr_get_type(rr) != ARES_REC_TYPE_OPT) {
      all_opt = 0;
      break;
    }
  }
  ares_dns_record_destroy(record);
  return all_opt;
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

// A resolver may pad its response (RFC 8467) past the buffer the client
// advertised. Removing the answer records is not enough on its own, so the
// datagram handed back must still fit the limit the client asked for.
static void test_oversized_response_with_padding_fits_peer_buffer(void) {
  uint8_t request[DNS_TEST_BUFFER_SIZE];
  const size_t request_len = build_request(request, DNS_SIZE_LIMIT);
  uint8_t response[DNS_TEST_BUFFER_SIZE];
  // 470 bytes of padding plus 4 answers: stripping the answers leaves the
  // padded OPT record alone over the limit, so OPT has to be dropped too.
  const size_t original_len = build_padded_response(response, 4, 470);

  TEST_ASSERT(original_len > DNS_SIZE_LIMIT);
  TEST_ASSERT(original_len <= DNS_TEST_BUFFER_SIZE);

  size_t response_len = original_len;
  dns_truncate_for_udp((const char *)request, request_len,
                       (char *)response, &response_len);

  TEST_ASSERT(response_len <= DNS_SIZE_LIMIT);
  TEST_ASSERT((response[2] & 0x02) != 0);
  TEST_ASSERT(additional_record_count(response, response_len) == 0);
}

// With a small OPT the preserved record still fits, so RFC 6891 preservation
// holds and only the answers are dropped.
static void test_oversized_response_keeps_opt_when_it_still_fits(void) {
  uint8_t request[DNS_TEST_BUFFER_SIZE];
  const size_t request_len = build_request(request, DNS_SIZE_LIMIT);
  uint8_t response[DNS_TEST_BUFFER_SIZE];
  // 30 answers keep the message above the limit before truncation, while the
  // bare OPT record left afterwards is small enough to be preserved.
  const size_t original_len = build_padded_response(response, 30, 0);

  TEST_ASSERT(original_len > DNS_SIZE_LIMIT);
  TEST_ASSERT(original_len <= DNS_TEST_BUFFER_SIZE);

  size_t response_len = original_len;
  dns_truncate_for_udp((const char *)request, request_len,
                       (char *)response, &response_len);

  TEST_ASSERT(response_len <= DNS_SIZE_LIMIT);
  TEST_ASSERT((response[2] & 0x02) != 0);
  TEST_ASSERT(additional_record_count(response, response_len) == 1);
  TEST_ASSERT(additional_records_are_all_opt(response, response_len));
}

int main(void) {
  TEST_RUN(test_response_within_512_bytes_is_unchanged);
  TEST_RUN(test_response_within_edns_limit_is_unchanged);
  TEST_RUN(test_oversized_response_is_truncated);
  TEST_RUN(test_oversized_response_with_padding_fits_peer_buffer);
  TEST_RUN(test_oversized_response_keeps_opt_when_it_still_fits);
  return test_summary();
}
