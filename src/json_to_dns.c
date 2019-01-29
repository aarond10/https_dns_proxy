#include <sys/select.h>
#include <sys/types.h>

#include <ares.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "constants.h"
#include "json_to_dns.h"
#include "logging.h"
#include "nxjson/nxjson.h"

// Simple htons with write to '*buf'.
static inline size_t _ns_put16(uint16_t s, uint8_t *buf) {
  *buf++ = s >> 8;
  *buf++ = s;
  return 2;
}

// Simple htonl with write to '*buf'.
static inline size_t _ns_put32(uint32_t s, uint8_t *buf) {
  *buf++ = s >> 24;
  *buf++ = s >> 16;
  *buf++ = s >> 8;
  *buf++ = s >> 0;
  return 4;
}

// Writes a string out, pascal style. limited to 63 bytes$
// (max length without compression for a domain segment).
// Returns the bytes written to 'out'.$
// Bytes consumed from source is always one less than that written.
static int dn_write_name(const char *name, uint8_t *out, size_t outlen) {
  int namelen = 0;
  while (name[namelen] && name[namelen] != '.') { namelen++; }
  if (namelen > 63 || outlen < (namelen + 1)) { return -1; }
  *out++ = namelen;
  memcpy(out, name, namelen);
  return namelen + 1;
}

// Returns 1 if 'str' is matches domain name 'pos', otherwise returns 0.
// Equlivalent to expanding label and doing a comparison on the result.
static int dn_match(const char *str, const uint8_t *pos, const uint8_t *pkt_start) {
  uint8_t len = *pos;
  while (len) {
    if ((len & 0xc0) == 0xc0) {
      uint16_t ofs = ntohs(*(uint16_t*)pos) & 0xbfff;
      if (pkt_start + ofs >= pos || ofs < 12) {
        DLOG("Bad offset (%d)", ofs);
        return 0;
      }
      DLOG("Following backref to offset %04x.", ofs);
      pos = pkt_start + ofs;
      continue;
    }
    pos++;
    if (strlen(str) < len) {
      // If domain is longer than the suffix we're checking, it's no match.
      return 0;
    }
    if (memcmp(str, pos, len) != 0) { return 0; }
    str += len;
    pos += len;
    len = *pos;
    if (*str && *str++ != '.') { return 0; }
  }
  int end_of_str = (!(*str));
  return end_of_str;
}

// Returns offset in 'a' at which string 'a' matches an encoded domain 'b'.
// Returns -1 if they don't match. Only checks '.' boundaries. i.e.
// aa.b.c and a.b.c match at offset of b.c, not a.b.c.
static int dn_suffix_match(const char *a, const uint8_t *b, const uint8_t *pkt_start) {
  const char *d = a;
  while (*d) {
    if (dn_match(d, b, pkt_start)) { return d - a; }
    while (*d && *d != '.') { d++; }
    if (*d) { d++; }
  }
  return -1;
}

// Searches 'dnptrs' for longest suffix match on 'name'.
// Returns the offset into 'name' at which the suffix starts, or strlen(name)$
// if no suffix found. *pkt_ofs points at the offset of the suffix from the$
// start of the packet if found, 0 otherwise.
static int dn_find_dnptr(const char *name,
                         const uint8_t **dnptrs, const uint8_t **lastdnptr,
                         uint16_t *pkt_ofs) {
  const char *npos = name;
  const char *nend = name + strlen(name);
  while (npos < nend) {
    const uint8_t **d = &dnptrs[1];
    while(*d && d < lastdnptr) {
      int name_ofs = dn_suffix_match(npos, *d, dnptrs[0]);
      if (name_ofs != -1) {
        *pkt_ofs = *d - dnptrs[0];
        return name_ofs;
      }
      d++;
    }
    while (npos < nend && *npos != '.') { npos++; }
    if (*npos) { npos++; }
  }
  *pkt_ofs = 0;
  return nend - name;
}

// Write null-terminated 'name' to 'out' buffer of at least 'outlen' length.
// dnptrs[0] should point to the start of the packet. dnptrs[1-n] point at$
// previous domain names. dnptrs[n] should be NULL. lastdnptr should be$
// &dnptrs[m] where m > n.
int dn_name_compress(const char *name, uint8_t *out, size_t outlen,
                     const uint8_t **dnptrs, const uint8_t **lastdnptr) {
  uint16_t out_ofs;
  uint16_t name_ofs = dn_find_dnptr(name, dnptrs, lastdnptr, &out_ofs);

  const char *npos = name;
  const char *nend = name + name_ofs;
  uint8_t *pos = out;
  uint8_t *end = out + outlen;
  while (npos < nend) {
    int r = dn_write_name(npos, pos, end - pos);
    if (r < 0) { return -1; }
    pos += r;
    npos += r - 1;
    if (*npos && *npos != '.') { return -1; }
    npos++;
  }
  if (out_ofs > 0) {
    if (end - pos < 2) { return -1; }
    *(uint16_t*)pos = htons(0xc000 | out_ofs); pos += 2;
  } else {
    if (end - pos < 1) { return -1; }
    *pos++ = 0;
  }
  if ((*out & 0xc0) != 0xc0) {  // Don't keep duplicate dnptrs.
    const uint8_t **d = &dnptrs[1];
    while (*d && d < lastdnptr) {
      d++;
    }
    if (d < lastdnptr) {
      *d++ = out;
      if (d < lastdnptr) { *d = NULL; }
    }
  }
  return pos - out;
}

// Encode null-terminated 'name' to 'out' buffer of at least 'outlen' length.
// Does NOT use domain-name compression (back referencing). For use with
// DNSSEC RRType only.
// Returns length of encoded name.
int dn_name_nocompress(char *name, uint8_t *out, size_t outlen) {
  char *savedptr = NULL;
  char *name_component = strtok_r(name, ".", &savedptr);
  char *pos = (char *)out;
  char *end = pos + outlen;
  while(name_component && name_component[0]) {
    if (end - pos < strlen(name_component) + 1) {
      ELOG("Buffer too small.");
      return -1;
    }
    size_t l = strlen(name_component);
    *pos++ = l;
    memcpy(pos, name_component, l);
    pos += l;
    name_component = strtok_r(NULL, ".", &savedptr);
  }
  *pos++ = 0;
  return pos - (char *)out;
}

// Either does a strcpy (in the case of an unquoted string) or lightly
// unescapes ('\' and '"' only) a quoted string.
// Returns a pointer to the character immediately after the quoted string.
// olen should contain the output buffer size and will be replaced with the
// length of the unescaped string stored in 'out'.
static const char* unescape(const char *in, char *out, size_t *olen) {
  const char *s = in;
  const char *e = s + strlen(in);
  char *o = out;
  char *oe = o + *olen;

  if (*s != '"') {
    // If unquoted, assume no escaping required. Return whole string.
    if ((e - s) < *olen) { *olen = e - s; }
    strncpy(o, s, *olen);
    return e;
  }
  s++;  // Skip '"'

  while (s < e && o < oe) {
    switch(*s) {
     case '\\':
      s++;
      if (s == e) {
        FLOG("Trailing escape char in '%s'", in);
      }
      if (*s >= '0' && *s <= '9') { // Octal
        FLOG("Octal sequence found. Implement me.");
      } else {
        *o++ = *s++;
      }
      break;
    case '"':  // String closed. We're done.
      *olen = o - out;
      // cloudflare-dns.com delimits <character-string> with whitespace. Google
      // doesn't so we just eat trailing whitespace as necessary.
      s++;
      while (*s == ' ') { s++; }
      return s;
    default:
      *o++ = *s++;
    }
  }
  FLOG("Unclosed quoted string '%s'", in);
}

// Takes the string version of an RRTYPE and returns it's integer ID.
// Returns -1 if string does not correspond to a known type.
int str_to_rrtype(const char* str) {
  if (!strcasecmp(str, "A6")) { return dns_t_a6; }
  if (!strcasecmp(str, "A")) { return dns_t_a; }
  if (!strcasecmp(str, "AAAA")) { return dns_t_aaaa; }
  if (!strcasecmp(str, "AFSDB")) { return dns_t_afsdb; }
  if (!strcasecmp(str, "ANY")) { return dns_t_any; }
  if (!strcasecmp(str, "APL")) { return dns_t_apl; }
  if (!strcasecmp(str, "ATMA")) { return dns_t_atma; }
  if (!strcasecmp(str, "AXFR")) { return dns_t_axfr; }
  if (!strcasecmp(str, "CERT")) { return dns_t_cert; }
  if (!strcasecmp(str, "CNAME")) { return dns_t_cname; }
  if (!strcasecmp(str, "DNAME")) { return dns_t_dname; }
  if (!strcasecmp(str, "DNSKEY")) { return dns_t_dnskey; }
  if (!strcasecmp(str, "DS")) { return dns_t_ds; }
  if (!strcasecmp(str, "EID")) { return dns_t_eid; }
  if (!strcasecmp(str, "GPOS")) { return dns_t_gpos; }
  if (!strcasecmp(str, "HINFO")) { return dns_t_hinfo; }
  if (!strcasecmp(str, "ISDN")) { return dns_t_isdn; }
  if (!strcasecmp(str, "IXFR")) { return dns_t_ixfr; }
  if (!strcasecmp(str, "KEY")) { return dns_t_key; }
  if (!strcasecmp(str, "KX")) { return dns_t_kx; }
  if (!strcasecmp(str, "LOC")) { return dns_t_loc; }
  if (!strcasecmp(str, "MAILA")) { return dns_t_maila; }
  if (!strcasecmp(str, "MAILB")) { return dns_t_mailb; }
  if (!strcasecmp(str, "MB")) { return dns_t_mb; }
  if (!strcasecmp(str, "MD")) { return dns_t_md; }
  if (!strcasecmp(str, "MF")) { return dns_t_mf; }
  if (!strcasecmp(str, "MG")) { return dns_t_mg; }
  if (!strcasecmp(str, "MINFO")) { return dns_t_minfo; }
  if (!strcasecmp(str, "MR")) { return dns_t_mr; }
  if (!strcasecmp(str, "MX")) { return dns_t_mx; }
  if (!strcasecmp(str, "NAPTR")) { return dns_t_naptr; }
  if (!strcasecmp(str, "NIMLOC")) { return dns_t_nimloc; }
  if (!strcasecmp(str, "NS")) { return dns_t_ns; }
  if (!strcasecmp(str, "NSAP")) { return dns_t_nsap; }
  if (!strcasecmp(str, "NSAP_PTR")) { return dns_t_nsap_ptr; }
  if (!strcasecmp(str, "NSEC")) { return dns_t_nsec; }
  if (!strcasecmp(str, "NSEC3")) { return dns_t_nsec3; }
  if (!strcasecmp(str, "NSEC3PARAM")) { return dns_t_nsec3param; }
  if (!strcasecmp(str, "NULL")) { return dns_t_null; }
  if (!strcasecmp(str, "NXT")) { return dns_t_nxt; }
  if (!strcasecmp(str, "OPT")) { return dns_t_opt; }
  if (!strcasecmp(str, "PTR")) { return dns_t_ptr; }
  if (!strcasecmp(str, "PX")) { return dns_t_px; }
  if (!strcasecmp(str, "RP")) { return dns_t_rp; }
  if (!strcasecmp(str, "RRSIG")) { return dns_t_rrsig; }
  if (!strcasecmp(str, "RT")) { return dns_t_rt; }
  if (!strcasecmp(str, "SIG")) { return dns_t_sig; }
  if (!strcasecmp(str, "SINK")) { return dns_t_sink; }
  if (!strcasecmp(str, "SOA")) { return dns_t_soa; }
  if (!strcasecmp(str, "SRV")) { return dns_t_srv; }
  if (!strcasecmp(str, "SSHFP")) { return dns_t_sshfp; }
  if (!strcasecmp(str, "TKEY")) { return dns_t_tkey; }
  if (!strcasecmp(str, "TSIG")) { return dns_t_tsig; }
  if (!strcasecmp(str, "TXT")) { return dns_t_txt; }
  if (!strcasecmp(str, "WKS")) { return dns_t_wks; }
  if (!strcasecmp(str, "X25")) { return dns_t_x25; }
  if (!strcasecmp(str, "MAX")) { return dns_t_max; }
  WLOG("Unknown rrtype '%s'", str);
  return -1;
}

// Decodes YYYYmmddHHMMSS to a unix timestamp.
uint32_t parse_time(const char *timestr) {
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  if (sscanf(timestr, "%04d%02d%02d%02d%02d%02d",
          &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
          &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
    return 0;
  }
  tzset();
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;
  // TODO: Confirm this is reasonable to do. Negative seconds work for me
  // but man page doesn't state whether this is allowed.
  tm.tm_sec -= timezone;
  time_t t = mktime(&tm);
  return t;
}

// Compact base32hex char decode.
// Returns zero for invalid chars.
uint8_t b32h_char(char in) {
  if (in < '0') { return 0; }
  if (in <= '9') { return in - '0'; } // [0..10)
  if (in < 'A') { return 0; }
  if (in <= 'V') { return in - 'A' + 10; }  // [10..32)
  if (in < 'a') { return 0; }
  if (in <= 'v') { return in - 'a' + 10; }  // [10..32)
  return 0;
}

// In-place base32hex (RFC4648) decoder. Padding optional.
// returns the length of the decoded string.
int b32hexdec(const char *buf, uint8_t *out, int outlen) {
  const char *s = buf;
  const char *e = s + strlen(buf);
  uint8_t *pos = out;
  while (e > (s + 1)) {
    // 5 + 3
    *pos++ = b32h_char(s[0]) << 3 | b32h_char(s[1]) >> 2;
    s += 1; if ((s + 2) >= e || s[1] == '=' || s[2] == '=') { break; }
    // 2 + 5 + 1
    *pos++ = b32h_char(s[0]) << 6 | b32h_char(s[1]) << 1 | b32h_char(s[2]) >> 4;
    s += 2; if ((s + 1) >= e || s[1] == '=') { break; }
    // 4 + 4
    *pos++ = b32h_char(s[0]) << 4 | b32h_char(s[1]) >> 1;
    s += 1; if ((s + 2) >= e || s[1] == '=' || s[2] == '=') { break; }
    // 1 + 5 + 2
    *pos++ = b32h_char(s[0]) << 7 | b32h_char(s[1]) << 2 | b32h_char(s[2]) >> 3;
    s += 2; if ((s + 1) >= e || s[1] == '=') { break; }
    // 3 + 5
    *pos++ = b32h_char(s[0]) << 5 | b32h_char(s[1]);
    s += 2;
  }
  *pos = 0;
  return pos - out;
}

// Compact b64 char decode.
// Returns zero for invalid chars.
uint8_t b64_char(char in) {
  if (in == '+') { return 62; }
  if (in == '/') { return 63; }
  if (in < '0') { return 0; }
  if (in <= '9') { return in - '0' + 52; }  // [52..62)
  if (in < 'A') { return 0; }
  if (in <= 'Z') { return in - 'A'; }  // [0..26)
  if (in < 'a') { return 0; }
  if (in <= 'z') { return in - 'a' + 26; } // [26..52)
  return 0;
}

// In-place base64 decoder.
// returns the length of the decoded string.
int b64dec(const char *buf, uint8_t *out, int outlen) {
  int len = strlen(buf);
  if (len % 4) {
    WLOG("Invalid b64 string.");
    return -1;
  }
  const char *s = buf;
  const char *e = s + len;
  uint8_t *pos = out;
  while (e > (s + 1)) {
    *pos++ = b64_char(s[0]) << 2 | b64_char(s[1]) >> 4;
    s += 1; if (e <= (s + 1) || s[1] == '=') { break; }
    *pos++ = b64_char(s[0]) << 4 | b64_char(s[1]) >> 2;
    s += 1; if (e <= (s + 1) || s[1] == '=') { break; }
    *pos++ = b64_char(s[0]) << 6 | b64_char(s[1]);
    s += 2;
  }
  //*pos = 0;
  return pos - out;
}

int hex_char(char ch) {
  if (ch < '0') { return -1; }
  if (ch <= '9') { return ch - '0'; }
  if (ch < 'A') { return -1; }
  if (ch <= 'Z') { return ch - 'A' + 10; }
  if (ch < 'a') { return -1; }
  if (ch <= 'z') { return ch - 'a' + 10; }
  return -1;
}

// in-place decode of hex string to raw values.
// returns length of decoded string.
int hexdec(const char *buf, uint8_t *out, int outlen) {
  int len = strlen(buf);
  if (len % 2) {
    WLOG("Invalid hex byte string.");
    return -1;
  }
  if (outlen < len / 2) {
    WLOG("Out buffer too small.");
    return -1;
  }
  const char *s = buf;
  const char *e = s + len;
  uint8_t *pos = out;
  while (e > (s + 1)) {
    int tmp[2];
    for (int i = 0; i < 2; i++) {
      tmp[i] = hex_char(s[i]);
      if (tmp[i] < 0) {
        WLOG("Invalid hex char 0x%x", s[i]);
        return -1;
      }
    }
    *pos++ = tmp[0] << 4 | tmp[1];
    s += 2;
  }
  return pos - out;
}

// Type bitmaps are defined in https://www.ietf.org/rfc/rfc4034.txt
// This function parses presentation format from 'buf' and writes
// out wire format to 'out'. Returns the number of bytes written.
int type_bitmap_dec(char *buf, uint8_t *out, int outlen) {
  uint8_t bits[65536 / 8]; // one bit per rrtype.
  uint8_t window_len[256]; // one len per low 8-bit.
  char *saveptr = NULL;
  char *rrtype_str = strtok_r(buf, " ", &saveptr);
  uint8_t *pos = out;
  const uint8_t *end = pos + outlen;
  memset(&bits[0], 0, sizeof(bits));
  memset(&window_len[0], 0, sizeof(window_len));
  while (rrtype_str) {
    int rrtype = str_to_rrtype(rrtype_str);
    if (rrtype < 0) {
      DLOG("Ignoring unknown rrtype '%s'", rrtype_str);
    } else {
      bits[rrtype / 8] |= (0x80 >> (rrtype % 8));
      if (((rrtype % 256) / 8 + 1) > window_len[rrtype / 256]) {
        window_len[rrtype / 256] = (rrtype % 256) / 8 + 1;
      }
    }
    rrtype_str = strtok_r(NULL, " ", &saveptr);
  }
  for (int i = 0; i < 256; i++) {
    if (window_len[i] == 0) { continue; }
    if (end - pos < window_len[i] + 2) {
      DLOG("Out of buffer space.");
      return -1;
    }
    *pos++ = i;
    *pos++ = window_len[i];
    memcpy(pos, &bits[i * 256 / 8], window_len[i]);
    pos += window_len[i];
  }
  return pos - out;
}

int json_to_rdata(uint16_t type, char *data, uint8_t *pos, uint8_t *end,
                  const uint8_t **dnptrs, const uint8_t **lastdnptr) {
  if ((end - pos) < 2) {
    DLOG("Out of buffer space in json_to_rdata.");
    return -1;
  }

  // Write a placeholder for length until we know it.
  uint8_t *enc_len_pos = pos;
  pos += _ns_put16(0xffff, pos);

  switch (type) {
  case dns_t_cname:
  case dns_t_ns:
  case dns_t_ptr: {
    int r = dn_name_compress(data, pos, end - pos, dnptrs, lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress name.");
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_mx: {
    if ((end - pos) < 2) {
      return -1;
    }
    char *saveptr = NULL;
    char *tok = strtok_r(data, " ", &saveptr);
    if (!tok) {
      return -1;
    }
    uint16_t prio = atoi(tok);
    pos += _ns_put16(prio, pos);
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok) {
      return -1;
    }
    int r = dn_name_compress(tok, pos, end - pos, dnptrs, lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress name.");
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_a: {
    size_t r = sizeof(struct in_addr);
    if (pos + r > end) {
      DLOG("%p > %p", pos + r, end);
      return -1;
    }
    if (ares_inet_pton(AF_INET, data, pos) != 1) {
      DLOG("inet_pton: %s", data);
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_aaaa: {
    size_t r = sizeof(struct in6_addr);
    if (pos + r > end) {
      DLOG("%p > %p", pos + r, end);
      return -1;
    }
    if (ares_inet_pton(AF_INET6, data, pos) != 1) {
      DLOG("inet_pton");
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_txt: {
    // RFC1035 states:
    //   <character-string> is treated as binary information, and can be up
    //   to 256 characters in length (including the length octet).
    // Also:
    //   <character-string> is expressed in one or two ways: as a contiguous set
    //   of characters without interior spaces, or as a string beginning with a
    //   " and ending with a ".
    //
    // TXT records are made of one or more <character-string> in a DATA block.
    // (https://tools.ietf.org/html/rfc4408#section-3.1.3)
    //
    // Google DNS looks like it escapes each TXT as if it were in the 'master
    // files'.
    // These strings are then concatenated (without delimiter) and escaped again
    // as part of the JSON encoding process. Fun!
    const char *s = data, *e = data + strlen(data);
    if ((end - pos) < (e - s + 254) / 255 * 256) {
      return -1;
    }
    while (s < e) {
      size_t len = end - pos;
      if (len > 255) { len = 255; }
      const char *next_str = unescape(s, (char *)pos + 1, &len);
      if (!next_str) {
        FLOG("Expected unescape of '%s'", s);
      }
      *(pos++) = len;
      pos += len;
      s = next_str;
    }
    break;
  }
  case dns_t_soa: {
    char *saveptr = NULL;
    int r = dn_name_compress(strtok_r(data, " ", &saveptr), pos, end - pos,
                             dnptrs, lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress mname.");
      return -1;
    }
    pos += r;
    r = dn_name_compress(strtok_r(NULL, " ", &saveptr), pos, end - pos, dnptrs,
                         lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress rname.");
      return -1;
    }
    pos += r;
    if ((end - pos) < 20) {
      DLOG("Buffer too small: %d < 20", end - pos);
      return -1;
    }
    pos += _ns_put32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // serial
    pos += _ns_put32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // refresh
    pos += _ns_put32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // retry
    pos += _ns_put32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // expire
    pos += _ns_put32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // min
    break;
  }
  case dns_t_srv: {
    char *saveptr = NULL;
    pos += _ns_put16(atoi(strtok_r(data, " ", &saveptr)), pos); // prio
    pos += _ns_put16(atoi(strtok_r(NULL, " ", &saveptr)), pos); // weight
    pos += _ns_put16(atoi(strtok_r(NULL, " ", &saveptr)), pos); // port
    int r = dn_name_compress(strtok_r(NULL, " ", &saveptr), pos, end - pos, dnptrs,
                         lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress rname.");
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_rrsig: {
    // See https://www.ietf.org/rfc/rfc4034.txt
    char *saveptr = NULL;
    pos += _ns_put16(str_to_rrtype(strtok_r(data, " ", &saveptr)), pos); // type
    *pos++ = atoi(strtok_r(NULL, " ", &saveptr)); // algo
    *pos++ = atoi(strtok_r(NULL, " ", &saveptr)); // labels
    pos += _ns_put32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // orig_ttl
    pos += _ns_put32(parse_time(strtok_r(NULL, " ", &saveptr)), pos); // sig_expiration
    pos += _ns_put32(parse_time(strtok_r(NULL, " ", &saveptr)), pos); // sig_inception
    pos += _ns_put16(atoi(strtok_r(NULL, " ", &saveptr)), pos); // key_tag
    // signer
    int r = dn_name_nocompress(strtok_r(NULL, " ", &saveptr), pos, end - pos);
    if (r < 0) {
      DLOG("Failed to encode signer.");
      return -1;
    }
    pos += r;
    // signature
    r = b64dec(strtok_r(NULL, " ", &saveptr), pos, end - pos);
    if (r < 0) {
      DLOG("Failed to encode signature.");
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_nsec: {
    // See https://www.ietf.org/rfc/rfc4034.txt
    // next domain name.
    char *saveptr = NULL;
    int r = dn_name_nocompress(strtok_r(data, " ", &saveptr), pos, end - pos);
    if (r < 0) {
      DLOG("Failed to encode next domain name.");
      return -1;
    }
    pos += r;
    // type bit map encoding
    r = type_bitmap_dec(strtok_r(NULL, "", &saveptr), pos, end - pos);
    if (r < 0) {
      DLOG("Failed type bitmap decode.");
      return -1;
    }
    pos += r;
    break;
  }
  case dns_t_nsec3: {
    // See https://tools.ietf.org/html/rfc5155
    char *saveptr = NULL;
    *pos++ = atoi(strtok_r(data, " ", &saveptr)); // hash algo
    *pos++ = atoi(strtok_r(NULL, " ", &saveptr)); // flags
    pos += _ns_put16(atoi(strtok_r(NULL, " ", &saveptr)), pos); // iterations
    char *salt = strtok_r(NULL, " ", &saveptr);
    *pos++ = strlen(salt) / 2;  // salt length
    if (salt[0] == '-' && salt[1] == 0) {
      // No salt.
    } else {
      int r = hexdec(salt, pos, end - pos);  // salt
      if (r < 0) {
        DLOG("Failed hex decode.");
        return -1;
      }
      pos += r;
    }
    char *hash = strtok_r(NULL, " ", &saveptr);
    uint8_t *plen = pos++;  // hash length
    int r = b32hexdec(hash, pos, end - pos);  // hash
    if (r < 0) {
      DLOG("Failed hex decode.");
      return -1;
    }
    *plen = r;
    pos += r;
    // type bit map encoding
    r = type_bitmap_dec(strtok_r(NULL, "", &saveptr), pos, end - pos);
    if (r < 0) {
      DLOG("Failed type bitmap decode.");
      return -1;
    }
    pos += r;
    break;
  }
  default:
    DLOG("Unexpected RR type: %d", type);
    return -1;
  };
  size_t r = pos - enc_len_pos - 2;
  pos += _ns_put16(r, enc_len_pos);
  return pos - enc_len_pos - 2;
}

int json_to_dns(uint16_t tx_id, char *in, uint8_t *out, int olen) {
  const nx_json *json = nx_json_parse_utf8(in);
  int i, j;

  if (!json) {
    DLOG("Parser fail.");
    return 1;
  }

  uint16_t flags = 1 << 15; // Response bit
  flags |= nx_json_get(json, "TR")->int_value ? (1 << 9) : 0;
  flags |= nx_json_get(json, "RD")->int_value ? (1 << 8) : 0;
  flags |= nx_json_get(json, "RA")->int_value ? (1 << 7) : 0;
  flags |= nx_json_get(json, "AD")->int_value ? (1 << 5) : 0;
  flags |= nx_json_get(json, "CD")->int_value ? (1 << 4) : 0;
  flags |= nx_json_get(json, "Status")->int_value & 0xf;

  uint8_t *pos = out;
  uint8_t *end = out + olen;

  pos += _ns_put16(tx_id, pos);
  pos += _ns_put16(flags, pos);
  pos += _ns_put16(nx_json_get(json, "Question")->length, pos);
  pos += _ns_put16(nx_json_get(json, "Answer")->length, pos);
  pos += _ns_put16(nx_json_get(json, "Authority")->length, pos);
  pos += _ns_put16(nx_json_get(json, "Additional")->length, pos);

  const uint8_t *dnptrs[256];
  const uint8_t **lastdnptr = &dnptrs[256];
  dnptrs[0] = out;
  dnptrs[1] = NULL;

  const nx_json *obj = nx_json_get(json, "Question");
  for (i = 0; i < obj->length; i++) {
    const nx_json *subobj = nx_json_item(obj, i);
    int r = dn_name_compress(nx_json_get(subobj, "name")->text_value, pos,
                             end - pos, dnptrs, lastdnptr);
    if (r < 0) {
      DLOG("Failed to encode question name.");
      return r;
    }
    pos += r;
    if ((end - pos) < 4) {
      DLOG("Insufficient space for question.");
      return -1;
    }
    pos += _ns_put16(nx_json_get(subobj, "type")->int_value, pos);
    pos += _ns_put16(ns_c_in, pos);
  }
  const char *rr_keys[] = {"Answer", "Authority", "Additional", NULL};
  for (i = 0; rr_keys[i]; i++) {
    obj = nx_json_get(json, rr_keys[i]);
    if (obj->type == NX_JSON_ARRAY) {
      for (j = 0; j < obj->length; j++) {
        // We drop RR we can't translate from JSON by restoring pos to this.
        uint8_t *saved_pos = pos;
        const nx_json *subobj = nx_json_item(obj, j);
        int r = dn_name_compress(nx_json_get(subobj, "name")->text_value, pos,
                                 end - pos, dnptrs, lastdnptr);
        if (r < 0) {
          DLOG("Failed to encode %s ix %d.", rr_keys[i], j);
          return r;
        }
        pos += r;
        if ((end - pos) < 8) {
          DLOG("Failed to encode %s ix %d.", rr_keys[i], j);
          return -1;
        }
        uint16_t type = nx_json_get(subobj, "type")->int_value;
        pos += _ns_put16(type, pos);
        pos += _ns_put16(ns_c_in, pos);
        pos += _ns_put32(nx_json_get(subobj, "TTL")->int_value, pos);
        // TODO: Don't drop const? This is probably safe but bad form.
        r = json_to_rdata(type, (char *)nx_json_get(subobj, "data")->text_value,
                          pos, end, dnptrs, lastdnptr);
        if (r < 0) {
          WLOG("Failed to encode %s ix %d.", rr_keys[i], j);
          pos = saved_pos;
        } else {
          pos += r;
        }
      }
    }
  }
  nx_json_free(json);
  return pos - out;
}
