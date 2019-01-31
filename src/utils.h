#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <stdlib.h>

// Write null-terminated 'name' to 'out' buffer of at least 'outlen' length.
// dnptrs[0] should point to the start of the packet. dnptrs[1-n] point at$
// previous domain names. dnptrs[n] should be NULL. lastdnptr should be$
// &dnptrs[m] where m > n.
int dn_name_compress(const char *name, uint8_t *out, size_t outlen,
                     const uint8_t **dnptrs, const uint8_t **lastdnptr);

// Encode null-terminated 'name' to 'out' buffer of at least 'outlen' length.
// Does NOT use domain-name compression (back referencing). For use with
// DNSSEC RRType only.
// Returns length of encoded name.
int dn_name_nocompress(char *name, uint8_t *out, size_t outlen);

// Either does a strcpy (in the case of an unquoted string) or lightly
// unescapes ('\' and '"' only) a quoted string.
// Returns a pointer to the character immediately after the quoted string.
// olen should contain the output buffer size and will be replaced with the
// length of the unescaped string stored in 'out'.
const char* unescape(const char *in, char *out, size_t *olen);

// Takes the string version of an RRTYPE and returns it's integer ID.
// Returns -1 if string does not correspond to a known type.
int str_to_rrtype(const char* str);

// Decodes YYYYmmddHHMMSS to a unix timestamp.
uint32_t parse_time(const char *timestr);

// In-place base32hex (RFC4648) decoder. Padding optional.
// returns the length of the decoded string.
int b32hexdec(const char *buf, uint8_t *out, int outlen);

// In-place base64 decoder.
// returns the length of the decoded string.
int b64dec(const char *buf, uint8_t *out, int outlen);

// in-place decode of hex string to raw values.
// returns length of decoded string.
int hexdec(const char *buf, uint8_t *out, int outlen);

// Type bitmaps are defined in https://www.ietf.org/rfc/rfc4034.txt
// This function parses presentation format from 'buf' and writes
// out wire format to 'out'. Returns the number of bytes written.
int type_bitmap_dec(char *buf, uint8_t *out, int outlen);

#endif // _UTILS_H_
