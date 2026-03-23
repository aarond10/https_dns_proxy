#include <ares.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dns_common.h"
#include "dns_truncate.h"
#include "logging.h"

// Returns the size limit the request peer is willing to accept. Reads the
// EDNS0 OPT record from the request's additional section. Falls back to the
// RFC1035 4.2.1 default of 512 if the request can't be parsed or the OPT
// advertises a smaller size (RFC6891 4.3 mandates that values below 512
// MUST be treated as 512).
static uint16_t get_edns_udp_size(const char *dns_req, const size_t dns_req_len) {
  ares_dns_record_t *dnsrec = NULL;
  ares_status_t parse_status = ares_dns_parse((const unsigned char *)dns_req, dns_req_len, 0, &dnsrec);
  if (parse_status != ARES_SUCCESS) {
    WLOG("Failed to parse DNS request: %s", ares_strerror((int)parse_status));
    return DNS_SIZE_LIMIT;
  }
  const uint16_t tx_id = ares_dns_record_get_id(dnsrec);
  uint16_t udp_size = 0;
  const size_t record_count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);
  for (size_t i = 0; i < record_count; ++i) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, i);
    if (ares_dns_rr_get_type(rr) == ARES_REC_TYPE_OPT) {
      udp_size = ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE);
      if (udp_size > 0) {
        DLOG("%04hX: Found EDNS0 UDP buffer size: %u", tx_id, udp_size);
      }
      break;
    }
  }
  ares_dns_record_destroy(dnsrec);
  if (udp_size < DNS_SIZE_LIMIT) {
    DLOG("%04hX: EDNS0 UDP buffer size %u overruled to %d", tx_id, udp_size, DNS_SIZE_LIMIT);
    return DNS_SIZE_LIMIT;
  }
  return udp_size;
}

static void truncate_to_size_limit(char *buf, size_t *buflen, const uint16_t size_limit) {
  const size_t old_size = *buflen;
  buf[2] |= 0x02;  // anyway: set truncation flag

  ares_dns_record_t *dnsrec = NULL;
  ares_status_t status = ares_dns_parse((const unsigned char *)buf, *buflen, 0, &dnsrec);
  if (status != ARES_SUCCESS) {
    WLOG("Failed to parse DNS response: %s", ares_strerror((int)status));
    return;
  }
  const uint16_t tx_id = ares_dns_record_get_id(dnsrec);

  // NOTE: according to current c-ares implementation, removing first or last elements are the fastest!

  // remove every additional and authority record
  while (ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL) > 0) {
    status = ares_dns_record_rr_del(dnsrec, ARES_SECTION_ADDITIONAL, 0);
    if (status != ARES_SUCCESS) {
      WLOG("%04hX: Could not remove additional record: %s", tx_id, ares_strerror((int)status));
    }
  }
  while (ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY) > 0) {
    status = ares_dns_record_rr_del(dnsrec, ARES_SECTION_AUTHORITY, 0);
    if (status != ARES_SUCCESS) {
      WLOG("%04hX: Could not remove authority record: %s", tx_id, ares_strerror((int)status));
    }
  }

  // rough estimate to reach size limit
  size_t answers = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  size_t answers_to_keep = ((size_limit - DNS_HEADER_LENGTH) * answers) / old_size;
  answers_to_keep = answers_to_keep > 0 ? answers_to_keep : 1;  // try to keep 1 answer

  // remove answer records until fit size limit or running out of answers
  unsigned char *new_resp = NULL;
  size_t new_resp_len = 0;
  for (uint8_t g = 0; g < UINT8_MAX; ++g) {  // endless loop guard
    status = ares_dns_write(dnsrec, &new_resp, &new_resp_len);
    if (status != ARES_SUCCESS) {
      WLOG("%04hX: Failed to create truncated DNS response: %s", tx_id, ares_strerror((int)status));
      new_resp = NULL;  // just to be sure
      break;
    }
    if (new_resp_len < size_limit || answers == 0) {
      break;
    }
    if (new_resp_len >= old_size) {
      WLOG("%04hX: Truncated DNS response size larger or equal to original: %u >= %u",
           tx_id, new_resp_len, old_size);  // impossible?
    }
    ares_free_string(new_resp);
    new_resp = NULL;

    DLOG("%04hX: DNS response size truncated from %u to %u but to keep %u limit reducing answers from %u to %u",
         tx_id, old_size, new_resp_len, size_limit, answers, answers_to_keep);

    while (answers > answers_to_keep) {
      status = ares_dns_record_rr_del(dnsrec, ARES_SECTION_ANSWER, answers - 1);
      if (status != ARES_SUCCESS) {
        WLOG("%04hX: Could not remove answer record: %s", tx_id, ares_strerror((int)status));
        break;
      }
      --answers;
    }
    answers = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);  // update to be sure!
    answers_to_keep /= 2;
  }
  ares_dns_record_destroy(dnsrec);

  if (new_resp == NULL) {
    return;
  }

  if (new_resp_len < old_size) {
    memcpy(buf, new_resp, new_resp_len);
    *buflen = new_resp_len;
    buf[2] |= 0x02;  // set truncation flag
    ILOG("%04hX: DNS response size truncated from %u to %u to keep %u limit",
         tx_id, old_size, new_resp_len, size_limit);
  }

  ares_free_string(new_resp);
}

void dns_truncate_for_udp(const char *dns_req, size_t dns_req_len,
                          char *resp, size_t *resp_len) {
  if (*resp_len <= DNS_SIZE_LIMIT) {
    return;  // always fits
  }
  const uint16_t udp_size = get_edns_udp_size(dns_req, dns_req_len);
  if (*resp_len <= udp_size) {
    uint16_t tx_id = ntohs(*((uint16_t*)dns_req));
    DLOG("%04hX: DNS response size %zu larger than %d but EDNS0 UDP buffer size %u allows it",
         tx_id, *resp_len, DNS_SIZE_LIMIT, udp_size);
    return;
  }
  truncate_to_size_limit(resp, resp_len, udp_size);
}
