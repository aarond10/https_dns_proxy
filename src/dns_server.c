#include <ares.h>            // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <ares_dns_record.h> // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <errno.h>           // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <stdint.h>
#include <string.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>          // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "dns_server.h"
#include "logging.h"


// Creates and bind a listening UDP socket for incoming requests.
static int get_listen_sock(struct addrinfo *listen_addrinfo) {
  int sock = socket(listen_addrinfo->ai_family, SOCK_DGRAM, 0);
  if (sock < 0) {
    FLOG("Error creating socket: %s (%d)", strerror(errno), errno);
  }

  uint16_t port = 0;
  char ipstr[INET6_ADDRSTRLEN];
  if (listen_addrinfo->ai_family == AF_INET) {
    port = ntohs(((struct sockaddr_in*) listen_addrinfo->ai_addr)->sin_port);
    inet_ntop(AF_INET, &((struct sockaddr_in *)listen_addrinfo->ai_addr)->sin_addr, ipstr, sizeof(ipstr));
  } else if (listen_addrinfo->ai_family == AF_INET6) {
    port = ntohs(((struct sockaddr_in6*) listen_addrinfo->ai_addr)->sin6_port);
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)listen_addrinfo->ai_addr)->sin6_addr, ipstr, sizeof(ipstr));
  } else {
    FLOG("Unknown address family: %d", listen_addrinfo->ai_family);
  }

  int res = bind(sock, listen_addrinfo->ai_addr, listen_addrinfo->ai_addrlen);
  if (res < 0) {
    FLOG("Error binding on %s:%d UDP: %s (%d)", ipstr, port,
         strerror(errno), errno);
  }

  ILOG("Listening on %s:%d UDP", ipstr, port);

  return sock;
}

static void watcher_cb(struct ev_loop __attribute__((unused)) *loop,
                       ev_io *w, int __attribute__((unused)) revents) {
  dns_server_t *d = (dns_server_t *)w->data;

  char tmp_buf[DNS_REQUEST_BUFFER_SIZE];
  struct sockaddr_storage tmp_raddr;
  socklen_t tmp_addrlen = d->addrlen;  // recvfrom can write to addrlen
  ssize_t len = recvfrom(w->fd, tmp_buf, DNS_REQUEST_BUFFER_SIZE, MSG_TRUNC,
                         (struct sockaddr*)&tmp_raddr, &tmp_addrlen);
  if (len < 0) {
    ELOG("recvfrom failed: %s", strerror(errno));
    return;
  }
  if (len > DNS_REQUEST_BUFFER_SIZE) {
    WLOG("Unsupported request received, too large: %d. Limit is: %d",
         len, DNS_REQUEST_BUFFER_SIZE);
    return;
  }

  if (len < DNS_HEADER_LENGTH) {
    WLOG("Malformed request received, too short: %d", len);
    return;
  }

  char *dns_req = (char *)malloc((size_t)len);  // To free buffer after https request is complete.
  if (dns_req == NULL) {
    FLOG("Out of mem");
  }
  memcpy(dns_req, tmp_buf, (size_t)len);  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)

  d->cb(d, 0, d->cb_data, (struct sockaddr*)&tmp_raddr, dns_req, (size_t)len);
}

void dns_server_init(dns_server_t *d, struct ev_loop *loop,
                     struct addrinfo *listen_addrinfo,
                     dns_req_received_cb cb, void *data) {
  d->loop = loop;
  d->sock = get_listen_sock(listen_addrinfo);
  d->addrlen = listen_addrinfo->ai_addrlen;
  d->cb = cb;
  d->cb_data = data;

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_io_init(&d->watcher, watcher_cb, d->sock, EV_READ);
  d->watcher.data = d;
  ev_io_start(d->loop, &d->watcher);
}

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
    return DNS_SIZE_LIMIT;  // RFC6891 4.3 "Values lower than 512 MUST be treated as equal to 512."
  }
  return udp_size;
}

static void truncate_dns_response(char *buf, size_t *buflen, const uint16_t size_limit) {
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
  size_t answers_to_keep = (size_limit - DNS_HEADER_LENGTH) / (old_size / answers);
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

  if (new_resp != NULL && new_resp_len < old_size) {
    memcpy(buf, new_resp, new_resp_len);  // NOLINT(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    *buflen = new_resp_len;
    buf[2] |= 0x02;  // set truncation flag
    ILOG("%04hX: DNS response size truncated from %u to %u to keep %u limit",
         tx_id, old_size, new_resp_len, size_limit);
    ares_free_string(new_resp);
  }
}

void dns_server_respond(dns_server_t *d, struct sockaddr *raddr,
    const char *dns_req, const size_t dns_req_len, char *dns_resp, size_t dns_resp_len) {
  if (dns_resp_len > DNS_SIZE_LIMIT) {
    const uint16_t udp_size = get_edns_udp_size(dns_req, dns_req_len);
    if (dns_resp_len > udp_size) {
      truncate_dns_response(dns_resp, &dns_resp_len, udp_size);
    } else {
      uint16_t tx_id = ntohs(*((uint16_t*)dns_req));
      DLOG("%04hX: DNS response size %u larger than %d but EDNS0 UDP buffer size %u allows it",
           tx_id, dns_resp_len, DNS_SIZE_LIMIT, udp_size);
    }
  }

  ssize_t len = sendto(d->sock, dns_resp, dns_resp_len, 0, raddr, d->addrlen);
  if(len == -1) {
    DLOG("sendto failed: %s", strerror(errno));
  }
}

void dns_server_stop(dns_server_t *d) {
  ev_io_stop(d->loop, &d->watcher);
}

void dns_server_cleanup(dns_server_t *d) {
  close(d->sock);
}
