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

#include "constants.h"
#include "json_to_dns.h"
#include "logging.h"
#include "nxjson/nxjson.h"
#include "utils.h"

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


ssize_t json_to_rdata(uint16_t type, char *data, uint8_t *pos, uint8_t *end,
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
    const char *s = data;
    const char *e = data + strlen(data);
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
  case dns_t_ds: {
    // See https://www.ietf.org/rfc/rfc3658.txt
    char *saveptr = NULL;
    pos += _ns_put16(atoi(strtok_r(data, " ", &saveptr)), pos); // key_tag
    *pos++ = atoi(strtok_r(NULL, " ", &saveptr)); // algorithm
    *pos++ = atoi(strtok_r(NULL, " ", &saveptr)); // digest_type
    int r = hexdec(strtok_r(NULL, "", &saveptr), pos, end - pos);  // digest
    if (r < 0) {
      DLOG("Failed decode.");
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

ssize_t json_to_dns(uint16_t tx_id, char *in, uint8_t *out, int olen) {
  const nx_json *json = nx_json_parse_utf8(in);
  int i;
  int j;

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
