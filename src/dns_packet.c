#include <sys/types.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>

#include "dns_packet.h"
#include "logging.h"
#include "nxjson.h"

int json_to_rdata(uint8_t type, char *data,
                  uint8_t *pos, uint8_t *end, 
                  const uint8_t **dnptrs, const uint8_t **lastdnptr) {
  if ((end - pos) < 2) {
    DLOG("Out of buffer space in json_to_rdata.");
    return -1;
  }

  // Write a placeholder for length until we know it.
  uint8_t *enc_len_pos = pos;
  NS_PUT16(0xffff, pos);

  switch(type) {
    case ns_t_cname:
    case ns_t_ns:
    case ns_t_ptr:
    {
      int r = ns_name_compress(data, pos, end - pos, dnptrs, lastdnptr);
      if (r < 0) {
        DLOG("Failed to compress name.");
        return -1;
      }
      pos += r;
      break;
    }
    case ns_t_mx:
    {
      if ((end - pos) < 2) return -1;
      char *saveptr = NULL;
      char *tok = strtok_r(data, " ", &saveptr);
      if (!tok) return -1;
      uint16_t prio = atoi(tok);
      NS_PUT16(prio, pos);
      tok = strtok_r(NULL, " ", &saveptr);
      if (!tok) return -1;
      int r = ns_name_compress(tok, pos, end - pos, dnptrs, lastdnptr);
      if (r < 0) {
        DLOG("Failed to compress name.");
        return -1;
      }
      pos += r;
      break;
    }
    case ns_t_a:
    {
      size_t r = sizeof(struct in_addr);
      if (pos + r > end) return -1;
      if (!inet_pton(AF_INET, data, pos)) return -1;
      pos += r;
      break;
    }
    case ns_t_aaaa:
    {
      size_t r = sizeof(struct in6_addr);
      if (pos + r > end) return -1;
      if (!inet_pton(AF_INET6, data, pos)) return -1;
      pos += r;
      break;
    }
    case ns_t_txt:
    {
      const char *s = data, *e = data + strlen(data);
      if ((end - pos) < (e - s + 254) / 255 * 256) return -1;
      while(s < e) {
        int l = e - s;
        if (l > 255) l = 255;
        *(u_char *)(pos++) = l;
        memcpy(pos, s, l);
        s += l;
        pos += l;
      }
      break;
    }
    case ns_t_soa:
    {
      char *saveptr = NULL;
      int r = ns_name_compress(
          strtok_r(data, " ", &saveptr), pos, end - pos, dnptrs, lastdnptr);
      if (r < 0) {
        DLOG("Failed to compress mname.");
        return -1;
      }
      pos += r;
      r = ns_name_compress(
          strtok_r(NULL, " ", &saveptr), pos, end - pos, dnptrs, lastdnptr);
      if (r < 0) {
        DLOG("Failed to compress rname.");
        return -1;
      }
      pos += r;
      if ((end - pos) < 20) return -1;
      NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos);  // serial
      NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos);  // refresh
      NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos);  // retry
      NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos);  // expire
      NS_PUT32(atoi(strtok_r(NULL, " ", &saveptr)), pos);  // min
      break;
    }
    default:
      DLOG("Unexpected RR type: %d", type);
      return -1;
  };
  size_t r = pos - enc_len_pos - 2;
  NS_PUT16(r, enc_len_pos);
  return r;
}

int json_to_dns(uint16_t tx_id, char *in, uint8_t *out, int olen) {
  const nx_json* json = nx_json_parse_utf8(in);
  if (!json) {
    DLOG("Parser fail.");
    return 1;
  }

  uint16_t flags = 1 << 15;  // Response bit
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

  const nx_json* obj = nx_json_get(json, "Question");
  for (int i = 0; i < obj->length; i++) {
    const nx_json *subobj = nx_json_item(obj, i);
    int r = ns_name_compress(nx_json_get(subobj, "name")->text_value,
                             pos, end - pos, dnptrs, lastdnptr);
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
  const char *rr_keys[] = { "Answer", "Authority", "Additional", NULL };
  for (int i = 0; rr_keys[i]; i++) {
    obj = nx_json_get(json, rr_keys[i]);
    if (obj->type == NX_JSON_ARRAY) {
      for (int j = 0; j < obj->length; j++) {
        const nx_json *subobj = nx_json_item(obj, j);
        int r = ns_name_compress(nx_json_get(subobj, "name")->text_value,
                                 pos, end - pos, dnptrs, lastdnptr);
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
        // TODO: Don't drop const!! This is probably safe but bad form.
        r = json_to_rdata(type, (char *)nx_json_get(subobj, "data")->text_value,
                          pos, end, dnptrs, lastdnptr);
        if (r < 0) {
          DLOG("Failed to encode %s ix %d.", rr_keys[i], j);
          return -1;
        }
        pos += r;
      }
    }
  }
  nx_json_free(json);
  return pos - out;
}
