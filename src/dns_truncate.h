#ifndef _DNS_TRUNCATE_H_
#define _DNS_TRUNCATE_H_

#include <sys/types.h>

// Fit a DNS response into the size limit advertised by the request.
//
// If `resp` exceeds the request's EDNS0 UDP buffer size (or RFC1035 4.2.1's
// 512-byte default when no EDNS0 OPT record is present), shrink it in place
// by dropping additional and authority records, then answer records, until
// it fits. The TC flag is set on truncation. A response that already fits
// is left untouched.
//
// Mutates `resp` and `*resp_len`. Caller retains ownership of both buffers.
//
// DNS-over-TCP has no per-message size cap and never needs this.
void dns_truncate_for_udp(const char *dns_req, size_t dns_req_len,
                          char *resp, size_t *resp_len);

#endif // _DNS_TRUNCATE_H_
