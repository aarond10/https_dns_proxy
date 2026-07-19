#include <ares.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dns_common.h"
#include "dns_truncate.h"
#include "logging.h"

// Returns the size limit the request peer is willing to accept. Reads the
// EDNS0 OPT record from the request's additional section. Falls back to the
// RFC1035 4.2.1 default of 512 if the request can't be parsed or the OPT
// advertises a smaller size (RFC6891 4.3 mandates that values below 512
// MUST be treated as 512).
// Using c-ares' DNS parser for convenience and robustness, since the client's
// request can not be trusted.
static uint16_t get_edns_udp_size(const char *dns_req, const size_t dns_req_len) {
  ares_dns_record_t *dnsrec = NULL;
  ares_status_t parse_status = ares_dns_parse((const unsigned char *)dns_req, dns_req_len,
                                              ARES_DNS_PARSE_AN_BASE_RAW | ARES_DNS_PARSE_NS_BASE_RAW,  // for faster parsing
                                              &dnsrec);
  if (parse_status != ARES_SUCCESS) {
    const uint16_t req_id = ntohs(*((uint16_t*)dns_req));
    WLOG("%04hX: Failed to parse DNS request: %s", req_id, ares_strerror((int)parse_status));
    return DNS_SIZE_LIMIT;
  }
  const uint16_t req_id = ares_dns_record_get_id(dnsrec);
  uint16_t udp_size = 0;
  const size_t record_count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);
  for (size_t i = 0; i < record_count; ++i) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, i);
    if (ares_dns_rr_get_type(rr) == ARES_REC_TYPE_OPT) {
      udp_size = ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE);
      if (udp_size > 0) {
        DLOG("%04hX: Found EDNS0 UDP buffer size: %u", req_id, udp_size);
      }
      break;
    }
  }
  ares_dns_record_destroy(dnsrec);
  if (udp_size < DNS_SIZE_LIMIT) {
    DLOG("%04hX: EDNS0 UDP buffer size %u overruled to %d", req_id, udp_size, DNS_SIZE_LIMIT);
    return DNS_SIZE_LIMIT;
  }
  return udp_size;
}

/*
 * @brief Truncates a DNS response in-place to a skeleton packet to force an immediate TCP fallback.
 *
 * @param buf         Pointer to the raw DNS message buffer.
 * @param buflen      The actual size of the data currently in the buffer.
 *                    Will be set to the new truncated size after processing.
 * @param size_limit  The desired maximum size (e.g. 512).
 *
 * @section reasoning Architectural Reasoning & RFC Compliance:
 *
 * 1. TC Bit Enforcement (RFC 1035):
 * Sets the Truncation bit (buf[2] |= 0x02) unconditionally when payload data is cleared.
 * According to RFC 1035, the primary directive given to a resolver when it catches a packet
 * with TC = 1 is that it must discard the UDP response data and immediately retry the query
 * over a reliable transport (TCP). Because the client throws away the packet anyway, returning
 * an empty data section completely satisfies the protocol's intent.
 *
 * 2. Total Section Cleardown (Deterministic Atomicity & RFC 2181):
 * RFC 2181, Section 5.2, introduces the concept of RRSet Atomicity, stating that all records
 * belonging to the same name, class, and type must be treated as a single cohesive unit.
 * Instead of complex, error-prone progressive backtracking loops that risk partial RRSet exposure
 * (which can cause intermediary resolvers to incorrectly cache incomplete data), this engine
 * clears the ANCount, NSCount, and non-OPT ARCount fields to 0. Wiping all records
 * uniformly ensures zero data corruption risk, as a set of 0 records cannot violate atomicity.
 *
 * 3. EDNS0/OPT Preservation (RFC 6891):
 * The OPT pseudo-RR (Type 41) is critical for extended error tracking, cookies, and DNSSEC signaling.
 * RFC 6891 mandates that OPT records should be preserved in truncated messages if they were present
 * in the request. This function scans the Additional section and removes every record except the
 * OPT one; re-serializing via c-ares then leaves the OPT record directly after the Question
 * section, preserving it in the truncated response stream.
 *
 * 4. Trusted Data Assumption:
 * DoH resolver response is considered trusted input, so assuming that it complies with RFCs
 * and is well-formed.
 *
 */
static void truncate_to_size_limit(uint8_t *buf, size_t *buflen, size_t size_limit) {
  const size_t old_size = *buflen;
  buf[2] |= 0x02;  // anyway: set truncation flag

  ares_dns_record_t *dnsrec = NULL;
  ares_status_t status = ares_dns_parse((const unsigned char *)buf, *buflen,
                                        ARES_DNS_PARSE_AN_BASE_RAW | ARES_DNS_PARSE_NS_BASE_RAW,  // for faster parsing
                                        &dnsrec);
  if (status != ARES_SUCCESS) {
    const uint16_t resp_id = ntohs(*((uint16_t*)buf));
    WLOG("%04hX: Failed to parse DNS response: %s", resp_id, ares_strerror((int)status));
    return;
  }
  const uint16_t resp_id = ares_dns_record_get_id(dnsrec);

  // NOTE: according to current c-ares implementation, removing last element is the fastest!

  // Remove every answer and authority record
  for (size_t i = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER); i > 0; i--) {
    status = ares_dns_record_rr_del(dnsrec, ARES_SECTION_ANSWER, i - 1);
    if (status != ARES_SUCCESS) {
      WLOG("%04hX: Could not remove answer record: %s", resp_id, ares_strerror((int)status));
    }
  }
  for (size_t i = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY); i > 0; i--) {
    status = ares_dns_record_rr_del(dnsrec, ARES_SECTION_AUTHORITY, i - 1);
    if (status != ARES_SUCCESS) {
      WLOG("%04hX: Could not remove authority record: %s", resp_id, ares_strerror((int)status));
    }
  }
  // Remove every additional record except OPT
  for (size_t i = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL); i > 0; i--) {
    const ares_dns_rr_t *rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, i - 1);
    if (ares_dns_rr_get_type(rr) == ARES_REC_TYPE_OPT) {
      continue;  // skip removing OPT, removing records before will be unoptimal
    }
    status = ares_dns_record_rr_del(dnsrec, ARES_SECTION_ADDITIONAL, i - 1);
    if (status != ARES_SUCCESS) {
      WLOG("%04hX: Could not remove additional record: %s", resp_id, ares_strerror((int)status));
    }
  }

  unsigned char *new_resp = NULL;
  size_t new_resp_len = 0;
  status = ares_dns_write(dnsrec, &new_resp, &new_resp_len);

  ares_dns_record_destroy(dnsrec);

  if (status != ARES_SUCCESS || new_resp == NULL || new_resp_len == 0) {
    WLOG("%04hX: Failed to create truncated DNS response: %s (new_resp=%p, new_resp_len=%zu)",
         resp_id, ares_strerror((int)status), new_resp, new_resp_len);
    return;
  }

  if (new_resp_len < old_size) {
    memcpy(buf, new_resp, new_resp_len);
    *buflen = new_resp_len;
    buf[2] |= 0x02;  // set truncation flag
    ILOG("%04hX: DNS response size truncated from %zu to %zu to keep %zu limit",
         resp_id, old_size, new_resp_len, size_limit);
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
    uint16_t req_id = ntohs(*((uint16_t*)dns_req));
    DLOG("%04hX: DNS response size %zu larger than %d but EDNS0 UDP buffer size %u allows it",
         req_id, *resp_len, DNS_SIZE_LIMIT, udp_size);
    return;
  }
  truncate_to_size_limit((uint8_t*)resp, resp_len, udp_size);
}
