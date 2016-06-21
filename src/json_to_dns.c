#include <sys/types.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>

#include <ares.h>
#include "json_to_dns.h"
#include "logging.h"
#include "nxjson.h"

// Writes a string out, pascal style. limited to 63 bytes$
// (max length without compression for a domain segment).
// Returns the bytes written to 'out'.$
// Bytes consumed from source is always one less than that written.
static int dn_write_name(const char *name, uint8_t *out, size_t outlen) {
  int namelen = 0;
  while (name[namelen] && name[namelen] != '.') namelen++;
  if (namelen > 63 || outlen < (namelen + 1)) return -1;
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
    if (memcmp(str, pos, len)) return 0;
    str += len;
    pos += len;
    len = *pos;
    if (*str && *str++ != '.') return 0;
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
    if (dn_match(d, b, pkt_start)) return d - a;
    while (*d && *d != '.') d++;
    if (*d) d++;
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
    while (npos < nend && *npos != '.') *npos++;
    if (*npos) *npos++;
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
    if (r < 0) return -1;
    pos += r;
    npos += r - 1;
    if (*npos && *npos != '.') return -1;
    npos++;
  }
  if (out_ofs > 0) {
    if (end - pos < 2) return -1;
    *(uint16_t*)pos = htons(0xc000 | out_ofs); pos += 2;
  } else {
    if (end - pos < 1) return -1;
    *pos++ = 0;
  }
  if ((*out & 0xc0) != 0xc0) {  // Don't keep duplicate dnptrs.
    const uint8_t **d = &dnptrs[1];
    while (*d && d < lastdnptr) d++;
    if (d < lastdnptr) {
      *d++ = out;
      if (d < lastdnptr) *d = NULL;
    }
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
  NS_PUT16(0xffff, pos);

  switch (type) {
  case ns_t_cname:
  case ns_t_ns:
  case ns_t_ptr: {
    int r = dn_name_compress(data, pos, end - pos, dnptrs, lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress name.");
      return -1;
    }
    pos += r;
    break;
  }
  case ns_t_mx: {
    if ((end - pos) < 2)
      return -1;
    char *saveptr = NULL;
    char *tok = strtok_r(data, " ", &saveptr);
    if (!tok)
      return -1;
    uint16_t prio = atoi(tok);
    NS_PUT16(prio, pos);
    tok = strtok_r(NULL, " ", &saveptr);
    if (!tok)
      return -1;
    int r = dn_name_compress(tok, pos, end - pos, dnptrs, lastdnptr);
    if (r < 0) {
      DLOG("Failed to compress name.");
      return -1;
    }
    pos += r;
    break;
  }
  case ns_t_a: {
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
  case ns_t_aaaa: {
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
  case ns_t_txt: {
    const char *s = data, *e = data + strlen(data);
    if ((end - pos) < (e - s + 254) / 255 * 256)
      return -1;
    while (s < e) {
      int l = e - s;
      if (l > 255)
        l = 255;
      *(u_char *)(pos++) = l;
      memcpy(pos, s, l);
      s += l;
      pos += l;
    }
    break;
  }
  case ns_t_soa: {
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
    NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // serial
    NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // refresh
    NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // retry
    NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // expire
    NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos); // min
    break;
  }
  default:
    DLOG("Unexpected RR type: %d", type);
    return -1;
  };
  size_t r = pos - enc_len_pos - 2;
  NS_PUT16(r, enc_len_pos);
  return r + 2;
}

int json_to_dns(uint16_t tx_id, char *in, uint8_t *out, int olen) {
  const nx_json *json = nx_json_parse_utf8(in);
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

  NS_PUT16(tx_id, pos);
  NS_PUT16(flags, pos);
  NS_PUT16(nx_json_get(json, "Question")->length, pos);
  NS_PUT16(nx_json_get(json, "Answer")->length, pos);
  NS_PUT16(nx_json_get(json, "Authority")->length, pos);
  NS_PUT16(nx_json_get(json, "Additional")->length, pos);

  const uint8_t *dnptrs[256];
  const uint8_t **lastdnptr = &dnptrs[256];
  dnptrs[0] = out;
  dnptrs[1] = NULL;

  const nx_json *obj = nx_json_get(json, "Question");
  for (int i = 0; i < obj->length; i++) {
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
    NS_PUT16(nx_json_get(subobj, "type")->int_value, pos);
    NS_PUT16(ns_c_in, pos);
  }
  const char *rr_keys[] = {"Answer", "Authority", "Additional", NULL};
  for (int i = 0; rr_keys[i]; i++) {
    obj = nx_json_get(json, rr_keys[i]);
    if (obj->type == NX_JSON_ARRAY) {
      for (int j = 0; j < obj->length; j++) {
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
        NS_PUT16(type, pos);
        NS_PUT16(ns_c_in, pos);
        NS_PUT32(nx_json_get(subobj, "TTL")->int_value, pos);
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
