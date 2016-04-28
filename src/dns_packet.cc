#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "dns_packet.h"
#include "logging.h"
#include "nxjson.h"
#include "ulibc_resolv_c.h"

void DebugDump(char *p, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02x ", *(uint8_t*)p++); if ((i % 16) == 15) printf("\n");
  }
  printf("\n");
}

namespace {
// Holds state relevant only during the writing of a packet
// such as an offset table for strings that appear previously.
struct Writer {
  Writer(char *s, char *e) : buf(s), end(e), pos(buf) {
    memset(dnptrs, 0, sizeof(dnptrs));
    dnptrs[0] = (u_char *)buf;
  }
  char *buf;
  char *end;
  char *pos;
  const u_char *dnptrs[256];

  // Write a name (sequence of strings) to a packet.
  bool WriteDomainName(const char *name) {
    int len = ns_name_compress(
        name, (u_char *)pos, end - pos, dnptrs, &dnptrs[256]);
    if (len < 0) {
      DLOG("Failed to compress '%s'", name);
      return false;
    }
    pos += len;
    return true;
  }

  bool WriteResponse(const DNSPacket::Response& r) {
    if (!WriteDomainName(r.name)) return false;
    NS_PUT16(r.type, pos);
    NS_PUT16(r.cls, pos);
    NS_PUT32(r.ttl, pos);

    // Write a placeholder for length until we know it.
    char *pos1 = pos;
    NS_PUT16(0xffff, pos);
    switch(r.type) {
      case ns_t_cname:
      case ns_t_ns:
      case ns_t_ptr:
      {
	if (!WriteDomainName(r.data)) return false;
	break;
      }
      case ns_t_mx:
      {
	int prio;
	char *name;
	if (sscanf(r.data, "%d %ms", &prio, &name) != 2) return false;
	NS_PUT16(prio, pos);
	if (!WriteDomainName(name)) return false;
	free(name);
	break;
      }
      case ns_t_a:
      {
	if (pos + 4 > end) return false;
	if (!inet_pton(AF_INET, r.data, pos)) return false;
	pos += 4;
	break;
      }
      case ns_t_aaaa:
      {
	if (pos + 16 > end) return false;
	if (!inet_pton(AF_INET6, r.data, pos)) return false;
	pos += 16;
	break;
      }
      case ns_t_txt:
      {
        const char *s = r.data, *e = r.data + strlen(r.data);
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
	char *mname, *rname;
	uint32_t serial, refresh, retry, expire, min;
	if (sscanf(r.data, "%ms %ms %u %u %u %u %u", 
		   &mname, &rname, &serial, &refresh, 
		   &retry, &expire, &min) != 7) 
	  return false;
	if (!WriteDomainName(mname)) return false;
	if (!WriteDomainName(rname)) return false;
	NS_PUT32(serial, pos);
	NS_PUT32(refresh, pos);
	NS_PUT32(retry, pos);
	NS_PUT32(expire, pos);
	NS_PUT32(min, pos);
	DLOG("Decoded SOA to: %s %s %d %d %d %d %d", 
	     mname, rname, serial, refresh, retry, expire, min);
	break;
      }
      // Unsupported
      default:
	DLOG("Ignoring unknown RRecord type: %d", r.type);
      case ns_t_key:
      case ns_t_sig:
      case ns_t_cert:
      case ns_t_opt:  // EDNS
        break;
    };
    // Go back and fill in size.
    NS_PUT16(pos - pos1 - sizeof(uint16_t), pos1);
    return true;
  }
  
};
}  // namespace

bool DNSPacket::WriteDNS(char *buf, char *end, int* size) {
  Writer writer(buf, end);
  NS_PUT16(tx_id, writer.pos);
  NS_PUT16(flags, writer.pos);
  NS_PUT16(num_q, writer.pos);
  NS_PUT16(num_rr, writer.pos);
  NS_PUT16(num_arr, writer.pos);
  NS_PUT16(num_xrr, writer.pos);
  for (int i = 0; i < num_q; i++) {
    if (!writer.WriteDomainName(q[i].name)) return false;
    NS_PUT16(q[i].type, writer.pos);
    NS_PUT16(q[i].cls, writer.pos);
  }
  for (int i = 0; i < num_rr; i++) {
    if (!writer.WriteResponse(rr[i])) return false;
  }
  for (int i = 0; i < num_arr; i++) {
    if (!writer.WriteResponse(arr[i])) return false;
  }
  for (int i = 0; i < num_xrr; i++) {
    if (!writer.WriteResponse(xrr[i])) return false;
  }
  *size = writer.pos - writer.buf;
  return true; 
}

bool DNSPacket::ReadJson(uint16_t id, char *str) {
  const nx_json* json = nx_json_parse_utf8(str);
  if (!json) {
    DLOG("Failed to parse.");
    return false;
  }

  tx_id = id;
  flags = 1 << 15;  // Response
  flags |= nx_json_get(json, "TR")->int_value ? (1 << 9) : 0;
  flags |= nx_json_get(json, "RD")->int_value ? (1 << 8) : 0;
  flags |= nx_json_get(json, "RA")->int_value ? (1 << 7) : 0;
  flags |= nx_json_get(json, "AD")->int_value ? (1 << 5) : 0;
  flags |= nx_json_get(json, "CD")->int_value ? (1 << 4) : 0;
  flags |= nx_json_get(json, "Status")->int_value & 0xf;

  const nx_json* obj = nx_json_get(json, "Question");
  if (obj->type == NX_JSON_ARRAY) {
    num_q = kMaxQ < obj->length ? kMaxQ : obj->length;
    for (int i = 0; i < num_q; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(q[i].name, nx_json_get(subobj, "name")->text_value, sizeof(q[i].name)-1);
      q[i].type = nx_json_get(subobj, "type")->int_value;
      q[i].cls = ns_c_in;
    }
  }
  obj = nx_json_get(json, "Answer");
  if (obj->type == NX_JSON_ARRAY) {
    num_rr = kMaxRR < obj->length ? kMaxRR : obj->length;
    for (int i = 0; i < num_rr; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(rr[i].name, nx_json_get(subobj, "name")->text_value, sizeof(rr[i].name)-1);
      rr[i].type = nx_json_get(subobj, "type")->int_value;
      rr[i].cls = ns_c_in;
      rr[i].ttl = nx_json_get(subobj, "TTL")->int_value;
      strncpy(rr[i].data, nx_json_get(subobj, "data")->text_value, sizeof(rr[i].data)-1);
    }
  }
  obj = nx_json_get(json, "Authority");
  if (obj->type == NX_JSON_ARRAY) {
    num_arr = kMaxARR < obj->length ? kMaxARR : obj->length;
    for (int i = 0; i < num_arr; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(arr[i].name, nx_json_get(subobj, "name")->text_value, sizeof(arr[i].name)-1);
      arr[i].type = nx_json_get(subobj, "type")->int_value;
      arr[i].cls = ns_c_in;
      arr[i].ttl = nx_json_get(subobj, "TTL")->int_value;
      strncpy(arr[i].data, nx_json_get(subobj, "data")->text_value, sizeof(arr[i].data)-1);
    }
  }
  obj = nx_json_get(json, "Additional");
  if (obj->type == NX_JSON_ARRAY) {
    num_xrr = kMaxXRR > obj->length ? kMaxXRR : obj->length;
    for (int i = 0; i < num_xrr; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(xrr[i].name, nx_json_get(subobj, "name")->text_value, sizeof(xrr[i].name)-1);
      xrr[i].type = nx_json_get(subobj, "type")->int_value;
      xrr[i].cls = ns_c_in;
      xrr[i].ttl = nx_json_get(subobj, "TTL")->int_value;
      strncpy(xrr[i].data, nx_json_get(subobj, "data")->text_value, sizeof(xrr[i].data)-1);
    }
  }
  nx_json_free(json);
  return true;
}
