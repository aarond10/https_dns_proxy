// A terrible but functional, tiny DNS encode/decode library.
#ifndef _DNSPACKET_H_
#define _DNSPACKET_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void DebugDump(char *p, int len);

// In-memory representation of a DNS packet.
struct DNSPacket {
  static const int kMaxNameLen = 255; // RFC1035 says 255 max.
  static const int kMaxDataLen = 1023; // RFC1035 says 512 for the whole packet.
  static const int kMaxQ = 1;
  static const int kMaxRR = 32;
  static const int kMaxARR = 32;
  static const int kMaxXRR = 32;

  struct Question {
    char name[kMaxNameLen+1];
    uint16_t type;
    uint16_t cls;
  };
  struct Response {
    char name[kMaxNameLen+1];
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    char data[kMaxDataLen+1];
  };
  uint16_t tx_id;
  uint16_t flags;
  int num_q, num_rr, num_arr, num_xrr;
  Question q[kMaxQ];
  Response rr[kMaxRR];
  Response arr[kMaxARR];
  Response xrr[kMaxXRR];

  void clear() {
    tx_id = flags = 0;
    num_q = num_rr = num_arr = num_xrr = 0;
    memset(q, 0, sizeof(q));
    memset(rr, 0, sizeof(rr));
    memset(arr, 0, sizeof(arr));
    memset(xrr, 0, sizeof(xrr));
  }

  // Methods to encode/decode to wire formats.
  bool WriteDNS(char *buf, char *end, int *size);
  bool ReadJson(uint16_t tx_id, char *json_str);

  const char *DebugString() const {
    static char buf[2048] = {};
    snprintf(buf, sizeof(buf)-1, "%s %04x %04x %d %d", 
             q[0].name, q[0].type, flags, num_q, num_rr);
    return buf;
  }
};

#endif  // _DNSPACKET_H_
