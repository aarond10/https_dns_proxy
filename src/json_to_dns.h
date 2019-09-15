// A simple JSON -> DNS packet converter.
#ifndef _JSON_TO_DNS_H_
#define _JSON_TO_DNS_H_

#ifdef __cplusplus
extern "C" {
#endif
// Creates a DNS packet from a JSON representation.
// 'tx_id' is the ID to use in the packet, 'in' is the JSON representation.
// (https://developers.google.com/speed/public-dns/docs/dns-over-https#dns_response_in_json)
// 'out' is a buffer to write the packet to. 'olen' is buffer length in bytes.
// Returns size of packet on success, -1 on failure.
ssize_t json_to_dns(uint16_t tx_id, char *in, uint8_t *out, int olen);
#ifdef __cplusplus
}
#endif

#endif // _JSON_TO_DNS_H_
