#ifndef _ULIBC_RESOLV_C_H_
#define _ULIBC_RESOLV_C_H_

#include <errno.h>
/**
 * The following is modified but comes from ulibc's resolv.c file and 
 * arpa/nameser.h header file.
 *
 * It saves dealing with slightly varying interfaces on different platforms.
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

// arpa/nameser.h

/*
 * Define constants based on RFC 883, RFC 1034, RFC 1035
 */
#define NS_PACKETSZ	512	/* maximum packet size */
#define NS_MAXDNAME	1025	/* maximum domain name */
#define NS_MAXCDNAME	255	/* maximum compressed domain name */
#define NS_MAXLABEL	63	/* maximum length of domain label */
#define NS_HFIXEDSZ	12	/* #/bytes of fixed data in header */
#define NS_QFIXEDSZ	4	/* #/bytes of fixed data in query */
#define NS_RRFIXEDSZ	10	/* #/bytes of fixed data in r record */
#define NS_INT32SZ	4	/* #/bytes of data in a u_int32_t */
#define NS_INT16SZ	2	/* #/bytes of data in a u_int16_t */
#define NS_INT8SZ	1	/* #/bytes of data in a u_int8_t */
#define NS_INADDRSZ	4	/* IPv4 T_A */
#define NS_IN6ADDRSZ	16	/* IPv6 T_AAAA */
#define NS_CMPRSFLGS	0xc0	/* Flag bits indicating name compression. */
#define NS_DEFAULTPORT	53	/* For both TCP and UDP. */

#define NS_TYPE_ELT         0x40 /*%< EDNS0 extended label type */
#define 	DNS_LABELTYPE_BITSTRING   0x41

/*
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type {
	ns_t_invalid = 0,	/* Cookie. */
	ns_t_a = 1,		/* Host address. */
	ns_t_ns = 2,		/* Authoritative server. */
	ns_t_md = 3,		/* Mail destination. */
	ns_t_mf = 4,		/* Mail forwarder. */
	ns_t_cname = 5,		/* Canonical name. */
	ns_t_soa = 6,		/* Start of authority zone. */
	ns_t_mb = 7,		/* Mailbox domain name. */
	ns_t_mg = 8,		/* Mail group member. */
	ns_t_mr = 9,		/* Mail rename name. */
	ns_t_null = 10,		/* Null resource record. */
	ns_t_wks = 11,		/* Well known service. */
	ns_t_ptr = 12,		/* Domain name pointer. */
	ns_t_hinfo = 13,	/* Host information. */
	ns_t_minfo = 14,	/* Mailbox information. */
	ns_t_mx = 15,		/* Mail routing information. */
	ns_t_txt = 16,		/* Text strings. */
	ns_t_rp = 17,		/* Responsible person. */
	ns_t_afsdb = 18,	/* AFS cell database. */
	ns_t_x25 = 19,		/* X_25 calling address. */
	ns_t_isdn = 20,		/* ISDN calling address. */
	ns_t_rt = 21,		/* Router. */
	ns_t_nsap = 22,		/* NSAP address. */
	ns_t_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
	ns_t_sig = 24,		/* Security signature. */
	ns_t_key = 25,		/* Security key. */
	ns_t_px = 26,		/* X.400 mail mapping. */
	ns_t_gpos = 27,		/* Geographical position (withdrawn). */
	ns_t_aaaa = 28,		/* Ip6 Address. */
	ns_t_loc = 29,		/* Location Information. */
	ns_t_nxt = 30,		/* Next domain (security). */
	ns_t_eid = 31,		/* Endpoint identifier. */
	ns_t_nimloc = 32,	/* Nimrod Locator. */
	ns_t_srv = 33,		/* Server Selection. */
	ns_t_atma = 34,		/* ATM Address */
	ns_t_naptr = 35,	/* Naming Authority PoinTeR */
	ns_t_kx = 36,		/* Key Exchange */
	ns_t_cert = 37,		/* Certification record */
	ns_t_a6 = 38,		/* IPv6 address (deprecated, use ns_t_aaaa) */
	ns_t_dname = 39,	/* Non-terminal DNAME (for IPv6) */
	ns_t_sink = 40,		/* Kitchen sink (experimentatl) */
	ns_t_opt = 41,		/* EDNS0 option (meta-RR) */
	ns_t_tsig = 250,	/* Transaction signature. */
	ns_t_ixfr = 251,	/* Incremental zone transfer. */
	ns_t_axfr = 252,	/* Transfer zone of authority. */
	ns_t_mailb = 253,	/* Transfer mailbox records. */
	ns_t_maila = 254,	/* Transfer mail agent records. */
	ns_t_any = 255,		/* Wildcard match. */
	ns_t_zxfr = 256,	/* BIND-specific, nonstandard. */
	ns_t_max = 65536
} ns_type;

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
#define NS_GET16(s, cp) do { \
	register u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += 2; \
} while (0)

#define NS_GET32(l, cp) do { \
	register u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += 4; \
} while (0)

#define NS_PUT16(s, cp) do { \
	register u_int16_t t_s = (u_int16_t)(s); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += 2; \
} while (0)

#define NS_PUT32(l, cp) do { \
	register u_int32_t t_l = (u_int32_t)(l); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += 4; \
} while (0)

// resolv.c

/* Thinking in noninternationalized USASCII (per the DNS spec),
 * is this character visible and not a space when printed ?
 */
static int printable(int ch)
{
	return (ch > 0x20 && ch < 0x7f);
}
/* Thinking in noninternationalized USASCII (per the DNS spec),
 * is this characted special ("in need of quoting") ?
 */
static int special(int ch)
{
	switch (ch) {
		case 0x22: /* '"' */
		case 0x2E: /* '.' */
		case 0x3B: /* ';' */
		case 0x5C: /* '\\' */
			/* Special modifiers in zone files. */
		case 0x40: /* '@' */
		case 0x24: /* '$' */
			return 1;
		default:
			return 0;
	}
}

/*
 * ns_name_ntop(src, dst, dstsiz)
 *      Convert an encoded domain name to printable ascii as per RFC1035.
 * return:
 *      Number of bytes written to buffer, or -1 (with errno set)
 * notes:
 *      The root is returned as "."
 *      All other domains are returned in non absolute form
 */
static int ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)
{
	const u_char *cp;
	char *dn, *eom;
	u_char c;
	u_int n;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) != 0) {
			/* Some kind of compression pointer. */
			return -1;
		}
		if (dn != dst) {
			if (dn >= eom) {
				return -1;
			}
			*dn++ = '.';
		}
		if (dn + n >= eom) {
			return -1;
		}
		for (; n > 0; n--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					return -1;
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					return -1;
				}
				*dn++ = '\\';
				*dn++ = "0123456789"[c / 100];
				c = c % 100;
				*dn++ = "0123456789"[c / 10];
				*dn++ = "0123456789"[c % 10];
			} else {
				if (dn >= eom) {
					return -1;
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			return -1;
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		return -1;
	}
	*dn++ = '\0';
	return (dn - dst);
}

static int encode_bitstring(const char **bp, const char *end,
							unsigned char **labelp,
							unsigned char ** dst,
							unsigned const char
*eom)
{
	int afterslash = 0;
	const char *cp = *bp;
	unsigned char *tp;
	const char *beg_blen;
	int value = 0, count = 0, tbcount = 0, blen = 0;

	beg_blen = NULL;

	/* a bitstring must contain at least 2 characters */
	if (end - cp < 2)
		return EINVAL;

	/* XXX: currently, only hex strings are supported */
	if (*cp++ != 'x')
		return EINVAL;
	if (!(*cp >= '0' && *cp <= '9') &&
            !(*cp >= 'A' && *cp <= 'F') &&
            !(*cp >= 'a' && *cp <= 'f'))
		return EINVAL;

        bool break_out = false;
	for (tp = *dst + 1; !break_out && cp < end && tp < eom; cp++) {
		unsigned char c = *cp;

		switch (c) {
		case ']':       /*%< end of the bitstring */
			if (afterslash) {
				char *end_blen;
				if (beg_blen == NULL)
					return EINVAL;
				blen = (int)strtol(beg_blen, &end_blen, 10);
				if (*end_blen != ']')
					return EINVAL;
			}
			if (count)
				*tp++ = ((value << 4) & 0xff);
			cp++;   /*%< skip ']' */
                        break_out = true;
                        continue;
		case '/':
			afterslash = 1;
			break;
		default:
			if (afterslash) {
				if (c < '0' || c > '9')
					return EINVAL;
				if (beg_blen == NULL) {
					if (c == '0') {
						/* blen never begings with 0 */
						return EINVAL;
					}
					beg_blen = cp;
				}
			} else {
				if (c < '0' || c > '9') {
					c = c | 0x20; /* lowercase */
					c = c - 'a';
					if (c > 5) /* not a-f? */
						return EINVAL;
					c += 10 + '0';
				}
				value <<= 4;
				value += (c - '0');
				count += 4;
				tbcount += 4;
				if (tbcount > 256)
					return EINVAL;
				if (count == 8) {
					*tp++ = value;
					count = 0;
				}
			}
			break;
		}
	}
	if (cp >= end || tp >= eom)
		return -1;

	/*
	 * bit length validation:
	 * If a <length> is present, the number of digits in the <bit-data>
	 * MUST be just sufficient to contain the number of bits specified
	 * by the <length>. If there are insignificant bits in a final
	 * hexadecimal or octal digit, they MUST be zero.
	 * RFC2673, Section 3.2.
	 */
	if (blen > 0) {
		int traillen;

		if (((blen + 3) & ~3) != tbcount)
			return EINVAL;
		traillen = tbcount - blen; /*%< between 0 and 3 */
		if (((value << (8 - traillen)) & 0xff) != 0)
			return EINVAL;
	}
	else
		blen = tbcount;
	if (blen == 256)
		blen = 0;

	/* encode the type and the significant bit fields */
	**labelp = DNS_LABELTYPE_BITSTRING;
	**dst = blen;

	*bp = cp;
	*dst = tp;

	return 0;
}

static int ns_name_pton(const char *src, u_char *dst, size_t dstsiz)
{
	static const char digits[] = "0123456789";
	u_char *label, *bp, *eom;
	int c, n, escaped, e = 0;
	const char *cp;

	escaped = 0;
	bp = dst;
	eom = dst + dstsiz;
	label = bp++;

	while ((c = *src++) != 0) {
		if (escaped) {
			if (c == '[') { /*%< start a bit string label */
				cp = strchr(src, ']');
				if (cp == NULL) {
					errno = EINVAL; /*%< ??? */
					return -1;
				}
				e = encode_bitstring(&src, cp + 2,
							 &label, &bp, eom);
				if (e != 0) {
					errno = e;
					return -1;
				}
				escaped = 0;
				label = bp++;
				c = *src++;
				if (c == '\0')
					goto done;
				if (c != '.') {
					errno = EINVAL;
					return -1;
				}
				continue;
			}
			cp = strchr(digits, c);
			if (cp != NULL) {
				n = (cp - digits) * 100;
				c = *src++;
				if (c == '\0')
					return -1;
				cp = strchr(digits, c);
				if (cp == NULL)
					return -1;
				n += (cp - digits) * 10;
				c = *src++;
				if (c == '\0')
					return -1;
				cp = strchr(digits, c);
				if (cp == NULL)
					return -1;
				n += (cp - digits);
				if (n > 255)
					return -1;
				c = n;
			}
			escaped = 0;
		} else if (c == '\\') {
			escaped = 1;
			continue;
		} else if (c == '.') {
			c = (bp - label - 1);
			if ((c & NS_CMPRSFLGS) != 0) {  /*%< Label too big. */
				return -1;
			}
			if (label >= eom) {
				return -1;
			}
			*label = c;
			/* Fully qualified ? */
			if (*src == '\0') {
				if (c != 0) {
					if (bp >= eom) {
						return -1;
					}
					*bp++ = '\0';
				}
				if ((bp - dst) > NS_MAXCDNAME) {
					return -1;
				}

				return 1;
			}
			if (c == 0 || *src == '.') {
				return -1;
			}
			label = bp++;
			continue;
		}
		if (bp >= eom) {
			return -1;
		}
		*bp++ = (u_char)c;
	}
	c = (bp - label - 1);
	if ((c & NS_CMPRSFLGS) != 0) {	  /*%< Label too big. */
		return -1;
	}
 done:
	if (label >= eom) {
		return -1;
	}
	*label = c;
	if (c != 0) {
		if (bp >= eom) {
			return -1;
		}
		*bp++ = 0;
	}
	if ((bp - dst) > NS_MAXCDNAME) {   /*%< src too big */
		return -1;
	}

	return 0;
}

/*
 * ns_name_unpack(msg, eom, src, dst, dstsiz)
 *      Unpack a domain name from a message, source may be compressed.
 * return:
 *      -1 if it fails, or consumed octets if it succeeds.
 */
static int ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
               u_char *dst, size_t dstsiz)
{
	const u_char *srcp, *dstlim;
	u_char *dstp;
	int n, len, checked;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		return -1;
	}
	/* Fetch next label in domain name. */
	while ((n = *srcp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
			case 0:
				/* Limit checks. */
				if (dstp + n + 1 >= dstlim || srcp + n >= eom) {
					return -1;
				}
				checked += n + 1;
				*dstp++ = n;
				memcpy(dstp, srcp, n);
				dstp += n;
				srcp += n;
				break;

			case NS_CMPRSFLGS:
				if (srcp >= eom) {
					return -1;
				}
				if (len < 0)
					len = srcp - src + 1;
				srcp = msg + (((n & 0x3f) << 8) | (*srcp &
0xff));
				if (srcp < msg || srcp >= eom) {  /* Out of
range. */
					return -1;
				}
				checked += 2;
				/*
				 * Check for loops in the compressed name;
				 * if we've looked at the whole message,
				 * there must be a loop.
				 */
				if (checked >= eom - msg) {
					return -1;
				}
				break;

			default:
				return -1;                    /* flag error */
		}
	}
	*dstp = '\0';
	if (len < 0)
		len = srcp - src;
	return len;
}

static int labellen(const unsigned char *lp)
{
	unsigned bitlen;
	unsigned char l = *lp;

	if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
		/* should be avoided by the caller */
		return -1;
	}

	if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
		if (l == DNS_LABELTYPE_BITSTRING) {
			bitlen = lp[1];
			if (bitlen == 0)
				bitlen = 256;
			return ((bitlen + 7 ) / 8 + 1);
		}

		return -1;    /*%< unknwon ELT */
	}

	return l;
}

static int mklower(int ch)
{
	if (ch >= 0x41 && ch <= 0x5A)
		return (ch + 0x20);

	return ch;
}

static int dn_find(const unsigned char *domain,
				   const unsigned char *msg,
				   const unsigned char * const *dnptrs,
				   const unsigned char * const *lastdnptr)
{
	const unsigned char *dn, *cp, *sp;
	const unsigned char * const *cpp;
	u_int n;

	for (cpp = dnptrs; cpp < lastdnptr; cpp++) {
		sp = *cpp;
		/*
		 * terminate search on:
		 * root label
		 * compression pointer
		 * unusable offset
		 */
		while (*sp != 0 && (*sp & NS_CMPRSFLGS) == 0 &&
				(sp - msg) < 0x4000) {
			dn = domain;
			cp = sp;

			while ((n = *cp++) != 0) {
				/*
				 * check for indirection
				 */
				switch (n & NS_CMPRSFLGS) {
				case 0:	 /*%< normal case, n == len */
					n = labellen(cp - 1); /*%< XXX */
					if (n != *dn++)
						goto next;

					for (; n > 0; n--)
						if (mklower(*dn++) !=
						    mklower(*cp++))
							goto next;
					/* Is next root for both ? */
					if (*dn == '\0' && *cp == '\0')
						return (sp - msg);
					if (*dn)
						continue;
					goto next;
				case NS_CMPRSFLGS:      /*%< indirection */
					cp = msg + (((n & 0x3f) << 8) | *cp);
					break;

				default:	/*%< illegal type */
					errno = EMSGSIZE;
					return -1;
				}
			}
next:
			sp += *sp + 1;
		}
	}

	errno = ENOENT;
	return -1;
}

static int ns_name_pack(const unsigned char *src,
				 unsigned char *dst, int dstsiz,
				 const unsigned char **dnptrs,
				 const unsigned char **lastdnptr)
{
	unsigned char *dstp;
	const unsigned char **cpp, **lpp, *eob, *msg;
	const unsigned char *srcp;
	int n, l, first = 1;

	srcp = src;
	dstp = dst;
	eob = dstp + dstsiz;
	lpp = cpp = NULL;

	if (dnptrs != NULL) {
		msg = *dnptrs++;
		if (msg != NULL) {
			for (cpp = dnptrs; *cpp != NULL; cpp++)
				continue;

			lpp = cpp;      /*%< end of list to search */
		}
	} else {
		msg = NULL;
	}

	/* make sure the domain we are about to add is legal */
	l = 0;
	do {
		int l0;

		n = *srcp;
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			errno = EMSGSIZE;
			return -1;
		}

		l0 = labellen(srcp);
		if (l0 < 0) {
			errno = EINVAL;
			return -1;
		}

		l += l0 + 1;
		if (l > NS_MAXCDNAME) {
			errno = EMSGSIZE;
			return -1;
		}

		srcp += l0 + 1;
	} while (n != 0);

	/* from here on we need to reset compression pointer array on error */
	srcp = src;

	do {
		/* Look to see if we can use pointers. */
		n = *srcp;

		if (n != 0 && msg != NULL) {
			l = dn_find(srcp, msg, (const unsigned char * const *)
dnptrs,
						(const unsigned char * const *)
lpp);
			if (l >= 0) {
				if (dstp + 1 >= eob) {
					goto cleanup;
				}

				*dstp++ = ((u_int32_t)l >> 8) | NS_CMPRSFLGS;
				*dstp++ = l % 256;
				return (dstp - dst);
			}

			/* Not found, save it. */
			if (lastdnptr != NULL && cpp < lastdnptr - 1 &&
				(dstp - msg) < 0x4000 && first) {
				*cpp++ = dstp;
				*cpp = NULL;
				first = 0;
			}
		}

		/* copy label to buffer */
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Should not happen. */
			goto cleanup;
		}

		n = labellen(srcp);
		if (dstp + 1 + n >= eob) {
			goto cleanup;
		}

		memcpy(dstp, srcp, (size_t)(n + 1));
		srcp += n + 1;
		dstp += n + 1;
	} while (n != 0);

	if (dstp > eob) {
cleanup:
		if (msg != NULL)
			*lpp = NULL;

			errno = EMSGSIZE;
			return -1;
	}

	return dstp - dst;
}

static int ns_name_compress(const char *src,
					 unsigned char *dst, size_t dstsiz,
					 const unsigned char **dnptrs,
					 const unsigned char **lastdnptr)
{
	unsigned char tmp[NS_MAXCDNAME];

	if (ns_name_pton(src, tmp, sizeof(tmp)) == -1)
		return -1;

	return ns_name_pack(tmp, dst, dstsiz, dnptrs, lastdnptr);
}

/*
 * ns_name_uncompress(msg, eom, src, dst, dstsiz)
 *      Expand compressed domain name to presentation format.
 * return:
 *      Number of bytes read out of `src', or -1 (with errno set).
 * note:
 *      Root domain returns as "." not "".
 */
static int ns_name_uncompress(const u_char *msg, const u_char *eom,
		const u_char *src, char *dst, size_t dstsiz)
{
	u_char tmp[NS_MAXCDNAME];
	int n;

	n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp);
	if (n == -1)
		return -1;
	if (ns_name_ntop(tmp, dst, dstsiz) == -1)
		return -1;
	return n;
}


#endif  // _ULIBC_RESOLV_C_H_
