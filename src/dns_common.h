#ifndef _DNS_COMMON_H_
#define _DNS_COMMON_H_

// Constants from the DNS wire format, shared by both UDP and TCP listeners
// and by the DoH proxy core.

enum {
  DNS_HEADER_LENGTH = 12,         // RFC1035 4.1.1 header size
  DNS_SIZE_LIMIT = 512,           // RFC1035 4.2.1 traditional UDP payload limit
  DNS_REQUEST_BUFFER_SIZE = 4096  // EDNS default before DNS Flag Day 2020
};

#endif // _DNS_COMMON_H_
