/*
 * This file is modified from curl 8.11.1,
 * Some of the structures are modified to adapt this project.
 * The main purpose of this file is to provide `curl_url_xx` series
 *   functions that introduced in curl 7.62.0.
 * With curlite.c/curlite.h, this project is able to compile with
 *   libcurl 7.55.0.
 * When the libcurl version is equal or above 7.62.0, it will use the
 *   new library or this file is compiled to prvoide missing functions.
 * Lower the libcur dependency extended this project's adaptable scenarios,
 *   some of old systems, OpenWRT for example, is usually shipped
 *   with old version of libcurl.
 */
#ifndef _CURLITE_H__
#define _CURLITE_H__
#ifdef USE_CURLITE
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>

#ifndef TRUE
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif

#ifdef UNITTESTS
#define UNITTEST
#else
#define UNITTEST static
#endif

/* This should be undefined once we need bit 32 or higher */
#define PROTO_TYPE_SMALL
#ifndef PROTO_TYPE_SMALL
typedef curl_off_t curl_prot_t;
#else
typedef unsigned int curl_prot_t;
#endif

/*
 * Max integer data types that mprintf.c is capable
 */

#ifdef HAVE_LONG_LONG_TYPE
#  define mp_intmax_t LONG_LONG_TYPE
#  define mp_uintmax_t unsigned LONG_LONG_TYPE
#else
#  define mp_intmax_t long
#  define mp_uintmax_t unsigned long
#endif

/* A convenience macro to provide both the string literal and the length of
   the string literal in one go, useful for functions that take "string,len"
   as their argument */
#define STRCONST(x) x,sizeof(x)-1

#if !defined(FALLTHROUGH)
#if (defined(__GNUC__) && __GNUC__ >= 7) || \
    (defined(__clang__) && __clang_major__ >= 10)
#  define FALLTHROUGH()  __attribute__((fallthrough))
#else
#  define FALLTHROUGH()  do {} while (0)
#endif
#endif

#define OUTCHAR(x)                                      \
  do {                                                  \
    if(!stream((unsigned char)x, userp))                \
      done++;                                           \
    else                                                \
      return done; /* return on failure */              \
  } while(0)
  
/* MS-DOS/Windows style drive prefix, optionally with
 * a '|' instead of ':', followed by a slash or NUL */
#define STARTS_WITH_URL_DRIVE_PREFIX(str) \
  ((('a' <= (str)[0] && (str)[0] <= 'z') || \
    ('A' <= (str)[0] && (str)[0] <= 'Z')) && \
   ((str)[1] == ':' || (str)[1] == '|') && \
   ((str)[2] == '/' || (str)[2] == '\\' || (str)[2] == 0))

#define strcasecompare(a,b) curl_strequal(a,b)
#define strncasecompare(a,b,c) curl_strnequal(a,b,c)
#define aprintf curl_maprintf
#define vaprintf curl_mvaprintf
#define msnprintf curl_msnprintf
/* checkprefix() is a shorter version of the above, used when the first
   argument is the string literal */
#define checkprefix(a,b)    curl_strnequal(b, STRCONST(a))
#define ZERO_NULL NULL
/* Dynamic buffer max sizes */
#define DYN_DOH_RESPONSE    3000
#define DYN_DOH_CNAME       256
#define DYN_PAUSE_BUFFER    (64 * 1024 * 1024)
#define DYN_HAXPROXY        2048
#define DYN_HTTP_REQUEST    (1024*1024)
#define DYN_APRINTF         8000000
#define DYN_RTSP_REQ_HEADER (64*1024)
#define DYN_TRAILERS        (64*1024)
#define DYN_PROXY_CONNECT_HEADERS 16384
#define DYN_QLOG_NAME       1024
#define DYN_H1_TRAILER      4096
#define DYN_PINGPPONG_CMD   (64*1024)
#define DYN_IMAP_CMD        (64*1024)
#define DYN_MQTT_RECV       (64*1024)
/*
 * Parse the format string.
 *
 * Create two arrays. One describes the inputs, one describes the outputs.
 *
 * Returns zero on success.
 */
#define PFMT_OK          0
#define PFMT_DOLLAR      1 /* bad dollar for main param */
#define PFMT_DOLLARWIDTH 2 /* bad dollar use for width */
#define PFMT_DOLLARPREC  3 /* bad dollar use for precision */
#define PFMT_MANYARGS    4 /* too many input arguments used */
#define PFMT_PREC        5 /* precision overflow */
#define PFMT_PRECMIX     6 /* bad mix of precision specifiers */
#define PFMT_WIDTH       7 /* width overflow */
#define PFMT_INPUTGAP    8 /* gap in arguments */
#define PFMT_WIDTHARG    9 /* attempted to use same arg twice, for width */
#define PFMT_PRECARG    10 /* attempted to use same arg twice, for prec */
#define PFMT_MANYSEGS   11 /* maxed out output segments */
/* (1<<9) was PROTOPT_STREAM, now free */
#define PROTOPT_URLOPTIONS (1<<10) /* allow options part in the userinfo field
                                      of the URL */
/* convert CURLcode to CURLUcode */
#define cc2cu(x) ((x) == CURLE_TOO_LARGE ? CURLUE_TOO_LARGE :   \
                  CURLUE_OUT_OF_MEMORY)
#define ISLOWHEXALHA(x) (((x) >= 'a') && ((x) <= 'f'))
#define ISUPHEXALHA(x) (((x) >= 'A') && ((x) <= 'F'))

#define ISLOWCNTRL(x) ((unsigned char)(x) <= 0x1f)
#define IS7F(x) ((x) == 0x7f)

#define ISLOWPRINT(x) (((x) >= 9) && ((x) <= 0x0d))

#define ISPRINT(x)  (ISLOWPRINT(x) || (((x) >= ' ') && ((x) <= 0x7e)))
#define ISGRAPH(x)  (ISLOWPRINT(x) || (((x) > ' ') && ((x) <= 0x7e)))
#define ISCNTRL(x) (ISLOWCNTRL(x) || IS7F(x))
#define ISALPHA(x) (ISLOWER(x) || ISUPPER(x))
#define ISXDIGIT(x) (ISDIGIT(x) || ISLOWHEXALHA(x) || ISUPHEXALHA(x))
#define ISALNUM(x)  (ISDIGIT(x) || ISLOWER(x) || ISUPPER(x))
#define ISUPPER(x)  (((x) >= 'A') && ((x) <= 'Z'))
#define ISLOWER(x)  (((x) >= 'a') && ((x) <= 'z'))
#define ISDIGIT(x)  (((x) >= '0') && ((x) <= '9'))
#define ISBLANK(x)  (((x) == ' ') || ((x) == '\t'))
#define ISSPACE(x)  (ISBLANK(x) || (((x) >= 0xa) && ((x) <= 0x0d)))
#define ISURLPUNTCS(x) (((x) == '-') || ((x) == '.') || ((x) == '_') || \
                        ((x) == '~'))
#define ISUNRESERVED(x) (ISALNUM(x) || ISURLPUNTCS(x))
/*
 * Decide whether a character in a URL must be escaped.
 */
#define urlchar_needs_escaping(c) (!(ISCNTRL(c) || ISSPACE(c) || ISGRAPH(c)))
/*
 * Curl_safefree defined as a macro to allow MemoryTracking feature
 * to log free() calls at same location where Curl_safefree is used.
 * This macro also assigns NULL to given pointer when free'd.
 */

#define Curl_safefree(ptr) \
  do { free((ptr)); (ptr) = NULL;} while(0)

#define IN6ADDRSZ       16
#define INADDRSZ         4
#define INT16SZ          2
#define CURLE_TOO_LARGE 100
#define MERR_OK        0
#define MERR_MEM       1
#define MERR_TOO_LARGE 2
#define HOST_ERROR   -1 /* out of memory */
#define HOST_NAME    1
#define HOST_IPV4    2
#define HOST_IPV6    3
/* scheme is not URL encoded, the longest libcurl supported ones are... */
#define MAX_SCHEME_LEN 40
#define MAX_SEGMENTS   128 /* number of output segments */
#define BUFFSIZE 326 /* buffer for long-to-str and float-to-str calcs, should
                        fit negative DBL_MAX (317 letters) */
#define MAX_PARAMETERS 128 /* number of input arguments */
#define CURLU_DEFAULT_PORT (1<<0)       /* return default port number */
#define CURLU_NO_DEFAULT_PORT (1<<1)    /* act as if no port number was set,
                                           if the port number matches the
                                           default for the scheme */
#define CURLU_DEFAULT_SCHEME (1<<2)     /* return default scheme if
                                           missing */
#define CURLU_NON_SUPPORT_SCHEME (1<<3) /* allow non-supported scheme */
#define CURLU_PATH_AS_IS (1<<4)         /* leave dot sequences */
#define CURLU_DISALLOW_USER (1<<5)      /* no user+password allowed */
#define CURLU_URLDECODE (1<<6)          /* URL decode on get */
#define CURLU_URLENCODE (1<<7)          /* URL encode on set */
#define CURLU_APPENDQUERY (1<<8)        /* append a form style part */
#define CURLU_GUESS_SCHEME (1<<9)       /* legacy curl-style guessing */
#define CURLU_NO_AUTHORITY (1<<10)      /* Allow empty authority when the
                                           scheme is unknown. */
#define CURLU_ALLOW_SPACE (1<<11)       /* Allow spaces in the URL */
#define CURLU_PUNYCODE (1<<12)          /* get the hostname in punycode */
#define CURLU_PUNY2IDN (1<<13)          /* punycode => IDN conversion */
#define CURLU_GET_EMPTY (1<<14)         /* allow empty queries and fragments
                                           when extracting the URL or the
                                           components */
#define CURLU_NO_GUESS_SCHEME (1<<15)   /* for get, do not accept a guess */

#undef DEBUGASSERT
#if defined(DEBUGBUILD)
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do { } while(0)
#endif

/* The CURLPROTO_ defines below are for the **deprecated** CURLOPT_*PROTOCOLS
   options. Do not use. */
#define CURLPROTO_HTTP   (1<<0)
#define CURLPROTO_HTTPS  (1<<1)
#define CURLPROTO_FTP    (1<<2)
#define CURLPROTO_FTPS   (1<<3)
#define CURLPROTO_SCP    (1<<4)
#define CURLPROTO_SFTP   (1<<5)
#define CURLPROTO_TELNET (1<<6)
#define CURLPROTO_LDAP   (1<<7)
#define CURLPROTO_LDAPS  (1<<8)
#define CURLPROTO_DICT   (1<<9)
#define CURLPROTO_FILE   (1<<10)
#define CURLPROTO_TFTP   (1<<11)
#define CURLPROTO_IMAP   (1<<12)
#define CURLPROTO_IMAPS  (1<<13)
#define CURLPROTO_POP3   (1<<14)
#define CURLPROTO_POP3S  (1<<15)
#define CURLPROTO_SMTP   (1<<16)
#define CURLPROTO_SMTPS  (1<<17)
#define CURLPROTO_RTSP   (1<<18)
#define CURLPROTO_RTMP   (1<<19)
#define CURLPROTO_RTMPT  (1<<20)
#define CURLPROTO_RTMPE  (1<<21)
#define CURLPROTO_RTMPTE (1<<22)
#define CURLPROTO_RTMPS  (1<<23)
#define CURLPROTO_RTMPTS (1<<24)
#define CURLPROTO_GOPHER (1<<25)
#define CURLPROTO_SMB    (1<<26)
#define CURLPROTO_SMBS   (1<<27)
#define CURLPROTO_MQTT   (1<<28)
#define CURLPROTO_GOPHERS (1<<29)
#define CURLPROTO_ALL    (~0) /* enable everything */

#define PROTOPT_NONE 0             /* nothing extra */
#define PROTOPT_SSL (1<<0)         /* uses SSL */
#define PROTOPT_DUAL (1<<1)        /* this protocol uses two connections */
#define PROTOPT_CLOSEACTION (1<<2) /* need action before socket close */
/* some protocols will have to call the underlying functions without regard to
   what exact state the socket signals. IE even if the socket says "readable",
   the send function might need to be called while uploading, or vice versa.
*/
#define PROTOPT_DIRLOCK (1<<3)
#define PROTOPT_NONETWORK (1<<4)   /* protocol does not use the network! */
#define PROTOPT_NEEDSPWD (1<<5)    /* needs a password, and if none is set it
                                      gets a default */
#define PROTOPT_NOURLQUERY (1<<6)   /* protocol cannot handle
                                       URL query strings (?foo=bar) ! */
#define PROTOPT_CREDSPERREQUEST (1<<7) /* requires login credentials per
                                          request instead of per connection */
#define PROTOPT_ALPN (1<<8) /* set ALPN for this */
/* (1<<9) was PROTOPT_STREAM, now free */
#define PROTOPT_URLOPTIONS (1<<10) /* allow options part in the userinfo field
                                      of the URL */
#define PROTOPT_PROXY_AS_HTTP (1<<11) /* allow this non-HTTP scheme over a
                                         HTTP proxy as HTTP proxies may know
                                         this protocol and act as a gateway */
#define PROTOPT_WILDCARD (1<<12) /* protocol supports wildcard matching */
#define PROTOPT_USERPWDCTRL (1<<13) /* Allow "control bytes" (< 32 ASCII) in
                                       username and password */
#define PROTOPT_NOTCPPROXY (1<<14) /* this protocol cannot proxy over TCP */

#define PORT_FTP 21
#define PORT_FTPS 990
#define PORT_TELNET 23
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_DICT 2628
#define PORT_LDAP 389
#define PORT_LDAPS 636
#define PORT_TFTP 69
#define PORT_SSH 22
#define PORT_IMAP 143
#define PORT_IMAPS 993
#define PORT_POP3 110
#define PORT_POP3S 995
#define PORT_SMB 445
#define PORT_SMBS 445
#define PORT_SMTP 25
#define PORT_SMTPS 465 /* sometimes called SSMTP */
#define PORT_RTSP 554
#define PORT_RTMP 1935
#define PORT_RTMPT PORT_HTTP
#define PORT_RTMPS PORT_HTTPS
#define PORT_GOPHER 70
#define PORT_MQTT 1883

/*
 * Portable error number symbolic names defined to Winsock error codes.
 */

#ifdef USE_WINSOCK
#undef  EBADF            /* override definition in errno.h */
#define EBADF            WSAEBADF
#undef  EINTR            /* override definition in errno.h */
#define EINTR            WSAEINTR
#undef  EINVAL           /* override definition in errno.h */
#define EINVAL           WSAEINVAL
#undef  EWOULDBLOCK      /* override definition in errno.h */
#define EWOULDBLOCK      WSAEWOULDBLOCK
#undef  EINPROGRESS      /* override definition in errno.h */
#define EINPROGRESS      WSAEINPROGRESS
#undef  EALREADY         /* override definition in errno.h */
#define EALREADY         WSAEALREADY
#undef  ENOTSOCK         /* override definition in errno.h */
#define ENOTSOCK         WSAENOTSOCK
#undef  EDESTADDRREQ     /* override definition in errno.h */
#define EDESTADDRREQ     WSAEDESTADDRREQ
#undef  EMSGSIZE         /* override definition in errno.h */
#define EMSGSIZE         WSAEMSGSIZE
#undef  EPROTOTYPE       /* override definition in errno.h */
#define EPROTOTYPE       WSAEPROTOTYPE
#undef  ENOPROTOOPT      /* override definition in errno.h */
#define ENOPROTOOPT      WSAENOPROTOOPT
#undef  EPROTONOSUPPORT  /* override definition in errno.h */
#define EPROTONOSUPPORT  WSAEPROTONOSUPPORT
#define ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#undef  EOPNOTSUPP       /* override definition in errno.h */
#define EOPNOTSUPP       WSAEOPNOTSUPP
#define EPFNOSUPPORT     WSAEPFNOSUPPORT
#undef  EAFNOSUPPORT     /* override definition in errno.h */
#define EAFNOSUPPORT     WSAEAFNOSUPPORT
#undef  EADDRINUSE       /* override definition in errno.h */
#define EADDRINUSE       WSAEADDRINUSE
#undef  EADDRNOTAVAIL    /* override definition in errno.h */
#define EADDRNOTAVAIL    WSAEADDRNOTAVAIL
#undef  ENETDOWN         /* override definition in errno.h */
#define ENETDOWN         WSAENETDOWN
#undef  ENETUNREACH      /* override definition in errno.h */
#define ENETUNREACH      WSAENETUNREACH
#undef  ENETRESET        /* override definition in errno.h */
#define ENETRESET        WSAENETRESET
#undef  ECONNABORTED     /* override definition in errno.h */
#define ECONNABORTED     WSAECONNABORTED
#undef  ECONNRESET       /* override definition in errno.h */
#define ECONNRESET       WSAECONNRESET
#undef  ENOBUFS          /* override definition in errno.h */
#define ENOBUFS          WSAENOBUFS
#undef  EISCONN          /* override definition in errno.h */
#define EISCONN          WSAEISCONN
#undef  ENOTCONN         /* override definition in errno.h */
#define ENOTCONN         WSAENOTCONN
#define ESHUTDOWN        WSAESHUTDOWN
#define ETOOMANYREFS     WSAETOOMANYREFS
#undef  ETIMEDOUT        /* override definition in errno.h */
#define ETIMEDOUT        WSAETIMEDOUT
#undef  ECONNREFUSED     /* override definition in errno.h */
#define ECONNREFUSED     WSAECONNREFUSED
#undef  ELOOP            /* override definition in errno.h */
#define ELOOP            WSAELOOP
#ifndef ENAMETOOLONG     /* possible previous definition in errno.h */
#define ENAMETOOLONG     WSAENAMETOOLONG
#endif
#define EHOSTDOWN        WSAEHOSTDOWN
#undef  EHOSTUNREACH     /* override definition in errno.h */
#define EHOSTUNREACH     WSAEHOSTUNREACH
#ifndef ENOTEMPTY        /* possible previous definition in errno.h */
#define ENOTEMPTY        WSAENOTEMPTY
#endif
#define EPROCLIM         WSAEPROCLIM
#define EUSERS           WSAEUSERS
#define EDQUOT           WSAEDQUOT
#define ESTALE           WSAESTALE
#define EREMOTE          WSAEREMOTE
#endif

#ifndef CURL_DISABLE_WEBSOCKETS
/* CURLPROTO_GOPHERS (29) is the highest publicly used protocol bit number,
 * the rest are internal information. If we use higher bits we only do this on
 * platforms that have a >= 64-bit type and then we use such a type for the
 * protocol fields in the protocol handler.
 */
#define CURLPROTO_WS     (1<<30)
#define CURLPROTO_WSS    ((curl_prot_t)1<<31)
#else
#define CURLPROTO_WS 0
#define CURLPROTO_WSS 0
#endif

#define MIN_FIRST_ALLOC 32
#define DYNINIT 0xbee51da /* random pattern */
#define DEFAULT_SCHEME "https"
#define CURL_MAX_INPUT_LENGTH 8000000

struct dynbuf {
  char *bufr;    /* point to a null-terminated allocated buffer */
  size_t leng;   /* number of bytes *EXCLUDING* the null-terminator */
  size_t allc;   /* size of the current allocation */
  size_t toobig; /* size limit for the buffer */
#ifdef DEBUGBUILD
  int init;     /* detect API usage mistakes */
#endif
};

struct nsprintf {
  char *buffer;
  size_t length;
  size_t max;
};

struct asprintf {
  struct dynbuf *b;
  char merr;
};

/* the error codes for the URL API */
typedef enum {
  CURLUE_OK,
  CURLUE_BAD_HANDLE,          /* 1 */
  CURLUE_BAD_PARTPOINTER,     /* 2 */
  CURLUE_MALFORMED_INPUT,     /* 3 */
  CURLUE_BAD_PORT_NUMBER,     /* 4 */
  CURLUE_UNSUPPORTED_SCHEME,  /* 5 */
  CURLUE_URLDECODE,           /* 6 */
  CURLUE_OUT_OF_MEMORY,       /* 7 */
  CURLUE_USER_NOT_ALLOWED,    /* 8 */
  CURLUE_UNKNOWN_PART,        /* 9 */
  CURLUE_NO_SCHEME,           /* 10 */
  CURLUE_NO_USER,             /* 11 */
  CURLUE_NO_PASSWORD,         /* 12 */
  CURLUE_NO_OPTIONS,          /* 13 */
  CURLUE_NO_HOST,             /* 14 */
  CURLUE_NO_PORT,             /* 15 */
  CURLUE_NO_QUERY,            /* 16 */
  CURLUE_NO_FRAGMENT,         /* 17 */
  CURLUE_NO_ZONEID,           /* 18 */
  CURLUE_BAD_FILE_URL,        /* 19 */
  CURLUE_BAD_FRAGMENT,        /* 20 */
  CURLUE_BAD_HOSTNAME,        /* 21 */
  CURLUE_BAD_IPV6,            /* 22 */
  CURLUE_BAD_LOGIN,           /* 23 */
  CURLUE_BAD_PASSWORD,        /* 24 */
  CURLUE_BAD_PATH,            /* 25 */
  CURLUE_BAD_QUERY,           /* 26 */
  CURLUE_BAD_SCHEME,          /* 27 */
  CURLUE_BAD_SLASHES,         /* 28 */
  CURLUE_BAD_USER,            /* 29 */
  CURLUE_LACKS_IDN,           /* 30 */
  CURLUE_TOO_LARGE,           /* 31 */
  CURLUE_LAST
} CURLUcode;

typedef enum {
  CURLUPART_URL,
  CURLUPART_SCHEME,
  CURLUPART_USER,
  CURLUPART_PASSWORD,
  CURLUPART_OPTIONS,
  CURLUPART_HOST,
  CURLUPART_PORT,
  CURLUPART_PATH,
  CURLUPART_QUERY,
  CURLUPART_FRAGMENT,
  CURLUPART_ZONEID /* added in 7.65.0 */
} CURLUPart;

/* conversion and display flags */
enum {
  FLAGS_SPACE      = 1 << 0,
  FLAGS_SHOWSIGN   = 1 << 1,
  FLAGS_LEFT       = 1 << 2,
  FLAGS_ALT        = 1 << 3,
  FLAGS_SHORT      = 1 << 4,
  FLAGS_LONG       = 1 << 5,
  FLAGS_LONGLONG   = 1 << 6,
  FLAGS_LONGDOUBLE = 1 << 7,
  FLAGS_PAD_NIL    = 1 << 8,
  FLAGS_UNSIGNED   = 1 << 9,
  FLAGS_OCTAL      = 1 << 10,
  FLAGS_HEX        = 1 << 11,
  FLAGS_UPPER      = 1 << 12,
  FLAGS_WIDTH      = 1 << 13, /* '*' or '*<num>$' used */
  FLAGS_WIDTHPARAM = 1 << 14, /* width PARAMETER was specified */
  FLAGS_PREC       = 1 << 15, /* precision was specified */
  FLAGS_PRECPARAM  = 1 << 16, /* precision PARAMETER was specified */
  FLAGS_CHAR       = 1 << 17, /* %c story */
  FLAGS_FLOATE     = 1 << 18, /* %e or %E */
  FLAGS_FLOATG     = 1 << 19, /* %g or %G */
  FLAGS_SUBSTR     = 1 << 20  /* no input, only substring */
};

/* Data type to read from the arglist */
typedef enum {
  FORMAT_STRING,
  FORMAT_PTR,
  FORMAT_INTPTR,
  FORMAT_INT,
  FORMAT_LONG,
  FORMAT_LONGLONG,
  FORMAT_INTU,
  FORMAT_LONGU,
  FORMAT_LONGLONGU,
  FORMAT_DOUBLE,
  FORMAT_LONGDOUBLE,
  FORMAT_WIDTH,
  FORMAT_PRECISION
} FormatType;

enum urlreject {
  REJECT_NADA = 2,
  REJECT_CTRL,
  REJECT_ZERO
};
enum {
  DOLLAR_UNKNOWN,
  DOLLAR_NOPE,
  DOLLAR_USE
};

/* Internal representation of CURLU. Point to URL-encoded strings. */
struct Curl_URL {
  char *scheme;
  char *user;
  char *password;
  char *options; /* IMAP only? */
  char *host;
  char *zoneid; /* for numerical IPv6 addresses */
  char *port;
  char *path;
  char *query;
  char *fragment;
  unsigned short portnum; /* the numerical version (if 'port' is set) */
  char query_present;    /* to support blank */
  char fragment_present; /* to support blank */
  char guessed_scheme;   /* when a URL without scheme is parsed */
};

/*
 * Describes an input va_arg type and hold its value.
 */
struct va_input {
  FormatType type; /* FormatType */
  union {
    char *str;
    void *ptr;
    mp_intmax_t nums; /* signed */
    mp_uintmax_t numu; /* unsigned */
    double dnum;
  } val;
};

/*
 * Describes an output segment.
 */
struct outsegment {
  int width;     /* width OR width parameter number */
  int precision; /* precision OR precision parameter number */
  unsigned int flags;
  unsigned int input; /* input argument array index */
  char *start;      /* format string start to output */
  size_t outlen;     /* number of bytes from the format string to output */
};

// We just fake Curl_easy/connectdata structures to erase warnnings during compile time
// It is safe, because we dont realy invoke the callback, these structures wont be accessed
struct Curl_easy {
  char useless;
};
struct connectdata {
  char useless;
};
/*
 * Specific protocol handler.
 */
struct Curl_handler {
  const char *scheme;        /* URL scheme name in lowercase */

  /* Complement to setup_connection_internals(). This is done before the
     transfer "owns" the connection. */
  CURLcode (*setup_connection)(struct Curl_easy *,
                               struct connectdata *);

  /* These two functions MUST be set to be protocol dependent */
  CURLcode (*do_it)(struct Curl_easy *, bool *done);
  CURLcode (*done)(struct Curl_easy *, CURLcode, bool);

  /* If the curl_do() function is better made in two halves, this
   * curl_do_more() function will be called afterwards, if set. For example
   * for doing the FTP stuff after the PASV/PORT command.
   */
  CURLcode (*do_more)(struct Curl_easy *, int *);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * after the connect() and everything is done, as a step in the connection.
   * The 'done' pointer points to a bool that should be set to TRUE if the
   * function completes before return. If it does not complete, the caller
   * should call the ->connecting() function until it is.
   */
  CURLcode (*connect_it)(struct Curl_easy *, bool *done);

  /* See above. */
  CURLcode (*connecting)(struct Curl_easy *, bool *done);
  CURLcode (*doing)(struct Curl_easy *, bool *done);

  /* Called from the multi interface during the PROTOCONNECT phase, and it
     should then return a proper fd set */
  int (*proto_getsock)(struct Curl_easy *,
                       struct connectdata *, curl_socket_t *);

  /* Called from the multi interface during the DOING phase, and it should
     then return a proper fd set */
  int (*doing_getsock)(struct Curl_easy *,
                       struct connectdata *, curl_socket_t *);

  /* Called from the multi interface during the DO_MORE phase, and it should
     then return a proper fd set */
  int (*domore_getsock)(struct Curl_easy *,
                        struct connectdata *, curl_socket_t *);

  /* Called from the multi interface during the DO_DONE, PERFORM and
     WAITPERFORM phases, and it should then return a proper fd set. Not setting
     this will make libcurl use the generic default one. */
  int (*perform_getsock)(struct Curl_easy *,
                         struct connectdata *, curl_socket_t *);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * by the curl_disconnect(), as a step in the disconnection. If the handler
   * is called because the connection has been considered dead,
   * dead_connection is set to TRUE. The connection is (again) associated with
   * the transfer here.
   */
  CURLcode (*disconnect)(struct Curl_easy *, struct connectdata *,
                         bool dead_connection);

  /* If used, this function gets called from transfer.c to
     allow the protocol to do extra handling in writing response to
     the client. */
  CURLcode (*write_resp)(struct Curl_easy *, const char *buf, size_t blen,
                         bool is_eos);

  /* If used, this function gets called from transfer.c to
     allow the protocol to do extra handling in writing a single response
     header line to the client. */
  CURLcode (*write_resp_hd)(struct Curl_easy *data,
                            const char *hd, size_t hdlen, bool is_eos);

  /* This function can perform various checks on the connection. See
     CONNCHECK_* for more information about the checks that can be performed,
     and CONNRESULT_* for the results that can be returned. */
  unsigned int (*connection_check)(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   unsigned int checks_to_perform);

  /* attach() attaches this transfer to this connection */
  void (*attach)(struct Curl_easy *data, struct connectdata *conn);

  int defport;            /* Default port. */
  curl_prot_t protocol;  /* See CURLPROTO_* - this needs to be the single
                            specific protocol bit */
  curl_prot_t family;    /* single bit for protocol family; basically the
                            non-TLS name of the protocol this is */
  unsigned int flags;     /* Extra particular characteristics, see PROTOPT_* */

};

typedef struct Curl_URL CURLU;
	
static const char hexdigits[] = "0123456789abcdef";
/* Lower-case digits.  */
static const char lower_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
/* Upper-case digits.  */
static const char upper_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const unsigned char hextable[] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,       /* 0x30 - 0x3f */
  0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40 - 0x4f */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,       /* 0x50 - 0x5f */
  0, 10, 11, 12, 13, 14, 15                             /* 0x60 - 0x66 */
};

/* the input is a single hex digit */
#define onehex2dec(x) hextable[x - '0']

CURLU *curl_url(void);
CURLUcode curl_url_set(CURLU *u, CURLUPart what,
                       const char *part, unsigned int flags);
CURLUcode curl_url_get(const CURLU *u, CURLUPart what,
                       char **part, unsigned int flags);
void curl_url_cleanup(CURLU *u);
#endif
#endif
