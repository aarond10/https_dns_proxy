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

// Holds state relevant only during the parsing of a packet.
struct Reader {
  Reader(char *s, char *e) : pkt_start(s), pkt_end(e), pos(s) { 
    memset(dnptrs, 0, sizeof(dnptrs));
    dnptrs[0] = (u_char *)pkt_start;
  }
  char *pkt_start;
  char *pkt_end;
  char *pos;
  const u_char *dnptrs[256];

  // Read a name (sequence of strings) off the wire, append to *out.
  // Output must be at least DNSPacket::kMaxNameLen bytes.
  bool ReadDomainName(char *out) {
    int len = ns_name_uncompress(
        (u_char *)pkt_start, (u_char *)pkt_end, (u_char *)pos,
        out, DNSPacket::kMaxNameLen);
    if (len < 0) {
      DLOG("Failed to read domain name. ");
      return false;
    }
    pos += len; 
    return true;
  }

  bool ReadQuestion(DNSPacket::Question* q) {
    if (!ReadDomainName(q->name)) {
      DLOG("Unable to read question name.");
      return false;
    } 
    NS_GET16(q->type, pos);
    NS_GET16(q->cls, pos);
    if (q->cls != 1 /* IN */) {
      DLOG("Don't support classes other than 'IN': %d", q->cls);
      return false;
    }
    return true;
  }

  bool ReadResponse(DNSPacket::Response* r) {
    if (!ReadDomainName(r->name)) {
      DLOG("Unable to read name");
      return false;
    }
    NS_GET16(r->type, pos);
    NS_GET16(r->cls, pos);
    NS_GET32(r->ttl, pos);
    uint16_t len;
    NS_GET16(len, pos);
    if (pos + len > pkt_end) {
      DLOG("Invalid data length: %d", len);
      return false;
    }
    // Internally, store as strings in same format as JSON does, for convenience.
    switch(r->type) {
      case ns_t_cname:
      case ns_t_ns:
      case ns_t_ptr:
      {
	if (!ReadDomainName(r->data)) return false;
	break;
      }
      case ns_t_mx:
      {
	uint16_t prio;
	NS_GET16(prio, pos);
        snprintf(r->data, sizeof(r->data), "%d ", prio);
	if (!ReadDomainName(r->data + strlen(r->data))) return false;
	break;
      }
      case ns_t_a:
      {
	if (len != 4 || !inet_ntop(AF_INET, pos, r->data, sizeof(r->data))) {
	  DLOG("Bad IPv4 decode.");
	  return false;
	}
	break;
      }
      case ns_t_aaaa:
      {
	if (len != 16 || !inet_ntop(AF_INET6, pos, r->data, sizeof(r->data))) {
	  DLOG("Bad IPv6 decode.");
	  return false;
	}
	break;
      }
      case ns_t_txt:
      {
        if (len > DNSPacket::kMaxDataLen) {
          DLOG("data length exceeds buffer.");
          return false;
        }
	char *e = pos + len;
        r->data[0] = 0;
	while(pos < e) {
	  u_char len = *(u_char *)pos++;
	  if ((e - pos) < len) return false;
          memcpy(r->data + strlen(r->data), pos, len);
	  pos += len;
	}
	break;
      }
      case ns_t_soa:
      {
        char mname[DNSPacket::kMaxNameLen];
        char rname[DNSPacket::kMaxNameLen];
	if (!ReadDomainName(mname)) return false;  // mname
	if (!ReadDomainName(rname)) return false;  // rname
	uint32_t serial, refresh, retry, expire, min;
	NS_GET32(serial, pos);
	NS_GET32(refresh, pos);
	NS_GET32(retry, pos);
	NS_GET32(expire, pos);
	NS_GET32(min, pos);
        snprintf(r->data, sizeof(r->data),
                 "%s %s %d %d %d %d %d",
                 mname, rname, serial, refresh, retry, expire);
	DLOG("Encoded SOA to: '%s'", r->data);
	break;
      }
      // Unsupported
      case ns_t_key:
      case ns_t_sig:
      case ns_t_cert:
      default:
	ILOG("Ignoring unknown RRecord type: %d", r->type);
    }  
    pos += len;
    return true;
  }
};

}  // namespace

bool DNSPacket::ReadDNS(char *pkt_start, char *pkt_end) {
  Reader reader(pkt_start, pkt_end);
  NS_GET16(tx_id, reader.pos);
  NS_GET16(flags, reader.pos);
  NS_GET16(num_q, reader.pos);
  NS_GET16(num_rr, reader.pos);
  NS_GET16(num_arr, reader.pos);
  NS_GET16(num_xrr, reader.pos);
  if (num_q > DNSPacket::kMaxQ) return false;
  if (num_rr > DNSPacket::kMaxRR) return false;
  if (num_arr > DNSPacket::kMaxARR) return false;
  if (num_xrr > DNSPacket::kMaxXRR) return false;

  for (int i = 0; i < num_q; i++) {
    if (!reader.ReadQuestion(&q[i])) return false;
  }
  for (int i = 0; i < num_rr; i++) {
    if (!reader.ReadResponse(&rr[i])) return false;
  }
  for (int i = 0; i < num_arr; i++) {
    if (!reader.ReadResponse(&arr[i])) return false;
  }
  for (int i = 0; i < num_xrr; i++) {
    if (!reader.ReadResponse(&xrr[i])) return false;
  }
  if (reader.pos != reader.pkt_end) {
    DLOG("Trailing %d unprocessed bytes.", (reader.pkt_end - reader.pos));
    return false;
  }
  return true; 
}

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
      q[i].cls = 1 /* IN */;
    }
  }
  obj = nx_json_get(json, "Answer");
  if (obj->type == NX_JSON_ARRAY) {
    num_rr = kMaxRR < obj->length ? kMaxRR : obj->length;
    for (int i = 0; i < num_rr; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(rr[i].name, nx_json_get(subobj, "name")->text_value, sizeof(rr[i].name)-1);
      rr[i].type = nx_json_get(subobj, "type")->int_value;
      rr[i].cls = 1 /* IN */;
      rr[i].ttl = nx_json_get(subobj, "TTL")->int_value;
      strncpy(rr[i].data, nx_json_get(subobj, "data")->text_value, sizeof(rr[i].data)-1);
    }
  }
  obj = nx_json_get(json, "Authority");
  if (obj->type == NX_JSON_ARRAY) {
    num_arr = kMaxARR < obj->length ? kMaxARR : obj->length;
    for (int i = 0; i < num_arr; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(rr[i].name, nx_json_get(subobj, "name")->text_value, sizeof(rr[i].name)-1);
      rr[i].type = nx_json_get(subobj, "type")->int_value;
      rr[i].cls = 1 /* IN */;
      rr[i].ttl = nx_json_get(subobj, "TTL")->int_value;
      strncpy(rr[i].data, nx_json_get(subobj, "data")->text_value, sizeof(rr[i].data)-1);
    }
  }
  obj = nx_json_get(json, "Additional");
  if (obj->type == NX_JSON_ARRAY) {
    num_xrr = kMaxXRR > obj->length ? kMaxXRR : obj->length;
    for (int i = 0; i < num_xrr; i++) {
      const nx_json *subobj = nx_json_item(obj, i);
      strncpy(rr[i].name, nx_json_get(subobj, "name")->text_value, sizeof(rr[i].name)-1);
      rr[i].type = nx_json_get(subobj, "type")->int_value;
      rr[i].cls = 1 /* IN */;
      rr[i].ttl = nx_json_get(subobj, "TTL")->int_value;
      strncpy(rr[i].data, nx_json_get(subobj, "data")->text_value, sizeof(rr[i].data)-1);
    }
  }
  nx_json_free(json);
  return true;
}
