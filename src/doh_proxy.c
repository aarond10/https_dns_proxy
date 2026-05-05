#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "dns_common.h"
#include "doh_proxy.h"
#include "logging.h"

struct doh_proxy {
  struct ev_loop *loop;
  https_client_t *client;
  const char *resolver_url;
  stat_t *stat;

  // CURLOPT_RESOLVE entries (one slist node, "host:443:ip1,ip2,..."). NULL
  // until the first successful resolver update arrives.
  struct curl_slist *resolv;

  // True until the first successful resolver update completes. While set,
  // inbound DNS requests are dropped (we'd otherwise leak through libcurl's
  // fallback resolver and risk a recursion through our own listener).
  uint8_t awaiting_bootstrap;

  doh_proxy_ready_fn on_ready;
  void *on_ready_ctx;
  uint8_t on_ready_fired;
};

// Per-request transient state. Lives from doh_proxy_handle_request to
// https_resp_cb, when the response (or failure) returns from libcurl.
// NOLINTNEXTLINE(altera-struct-pack-align)
typedef struct {
  doh_proxy_t *proxy;
  dns_listener_t *listener;
  uint16_t tx_id;
  ev_tstamp start_tstamp;
  struct sockaddr_storage raddr;
  char *dns_req;
  size_t dns_req_len;
} doh_request_t;

doh_proxy_t * doh_proxy_create(struct ev_loop *loop,
                               https_client_t *client,
                               const char *resolver_url,
                               stat_t *stat) {
  doh_proxy_t *p = (doh_proxy_t *)calloc(1, sizeof(doh_proxy_t));
  if (p == NULL) {
    FLOG("Out of mem");
  }
  p->loop = loop;
  p->client = client;
  p->resolver_url = resolver_url;
  p->stat = stat;
  return p;
}

void doh_proxy_await_bootstrap(doh_proxy_t *p) {
  p->awaiting_bootstrap = 1;
}

void doh_proxy_set_on_ready(doh_proxy_t *p, doh_proxy_ready_fn cb, void *cb_ctx) {
  p->on_ready = cb;
  p->on_ready_ctx = cb_ctx;
}

static void fire_on_ready(doh_proxy_t *p) {
  if (p->on_ready_fired || !p->on_ready) {
    return;
  }
  p->on_ready_fired = 1;
  p->on_ready(p->on_ready_ctx);
}

// Returns 1 if `addr_list` is a (possibly equal, possibly proper) subset of
// `full_list`, where both are comma-separated IP literals. Used to decide
// whether a fresh poll result actually changed anything; if every IP in the
// new list is already in the old list, we skip the curl reset.
static int addr_list_reduced(const char* full_list, const char* list) {
  const char *pos = list;
  const char *end = list + strlen(list);
  while (pos < end) {
    char current[50];
    const char *comma = strchr(pos, ',');
    size_t ip_len = (size_t)(comma ? comma - pos : end - pos);
    if (ip_len >= sizeof(current)) {
      DLOG("IP address too long: %zu bytes", ip_len);
      return 1;
    }
    strncpy(current, pos, ip_len);
    current[ip_len] = '\0';

    const char *match_begin = strstr(full_list, current);
    if (!match_begin ||
        !(match_begin == full_list || *(match_begin - 1) == ',') ||
        !(*(match_begin + ip_len) == ',' || *(match_begin + ip_len) == '\0')) {
      DLOG("IP address missing: %s", current);
      return 1;
    }

    pos += ip_len + 1;
  }
  return 0;
}

void doh_proxy_handle_resolver_update(const char *hostname, void *ctx,
                                      const char *addr_list) {
  doh_proxy_t *p = (doh_proxy_t *)ctx;

  if (addr_list == NULL) {
    WLOG("DNS poll for '%s' returned no usable addresses, will retry.", hostname);
    return;
  }

  char buf[255 + (sizeof(":443:") - 1) + POLLER_ADDR_LIST_SIZE];
  memset(buf, 0, sizeof(buf));
  if (strlen(hostname) > 254) { FLOG("Hostname too long."); }
  int ip_start = snprintf(buf, sizeof(buf) - 1, "%s:443:", hostname);
  if (ip_start < 0) {
    abort();  // must be impossible
  }
  (void)snprintf(buf + ip_start, sizeof(buf) - 1 - (uint32_t)ip_start, "%s", addr_list);

  if (p->resolv && p->resolv->data) {
    char *old_addr_list = strstr(p->resolv->data, ":443:");
    if (old_addr_list) {
      old_addr_list += sizeof(":443:") - 1;
      if (!addr_list_reduced(addr_list, old_addr_list)) {
        DLOG("DNS server IP address unchanged (%s).", buf + ip_start);
        free((void*)addr_list);
        return;
      }
    }
  }
  free((void*)addr_list);
  DLOG("Received new DNS server IP '%s'", buf + ip_start);
  curl_slist_free_all(p->resolv);
  p->resolv = curl_slist_append(NULL, buf);

  // Reset libcurl: in-flight connections were aimed at the old IP, and curl
  // gets confused if we leave them around with a different CURLOPT_RESOLVE.
  https_client_reset(p->client);

  if (p->awaiting_bootstrap) {
    p->awaiting_bootstrap = 0;
    fire_on_ready(p);
  }
}

static void doh_response_cb(void *data, char *buf, size_t buflen) {
  doh_request_t *req = (doh_request_t *)data;
  if (req == NULL) {
    FLOG("Request data is NULL (buflen: %zu)", buflen);
    return;
  }
  doh_proxy_t *p = req->proxy;
  DLOG("Received response for id: %hX, len: %zu", req->tx_id, buflen);

  if (buf != NULL) {  // NULL on timeout / DNS failure / similar.
    if (buflen < DNS_HEADER_LENGTH) {
      WLOG("%04hX: Malformed response received, too short: %u", req->tx_id, buflen);
    } else {
      const uint16_t response_id = ntohs(*((uint16_t*)buf));
      if (req->tx_id != response_id) {
        WLOG("DNS request and response IDs are not matching: %hX != %hX",
             req->tx_id, response_id);
      } else {
        req->listener->respond(req->listener, (struct sockaddr*)&req->raddr,
                               req->dns_req, req->dns_req_len, buf, buflen);
        if (p->stat) {
          stat_request_end(p->stat, buflen,
                           ev_now(p->stat->loop) - req->start_tstamp,
                           req->listener->transport == DNS_TRANSPORT_TCP);
        }
      }
    }
  }

  free((void*)req->dns_req);
  free(req);
}

void doh_proxy_handle_request(void *ctx, dns_listener_t *listener,
                              struct sockaddr *raddr,
                              char *dns_req, size_t dns_req_len) {
  doh_proxy_t *p = (doh_proxy_t *)ctx;

  uint16_t tx_id = ntohs(*((uint16_t*)dns_req));
  DLOG("Received request for id: %hX, len: %zu", tx_id, dns_req_len);

  if (p->awaiting_bootstrap) {
    WLOG("%04hX: Query received before bootstrapping is completed, discarding.", tx_id);
    free(dns_req);
    return;
  }

  doh_request_t *req = (doh_request_t *)calloc(1, sizeof(doh_request_t));
  if (req == NULL) {
    FLOG("%04hX: Out of mem", tx_id);
  }
  req->proxy = p;
  req->listener = listener;
  req->tx_id = tx_id;
  req->dns_req = dns_req;
  req->dns_req_len = dns_req_len;
  // raddr length depends on family; sockaddr_storage holds either. Copy what
  // the address actually has, not more.
  socklen_t raddr_len = (raddr->sa_family == AF_INET6)
      ? sizeof(struct sockaddr_in6)
      : sizeof(struct sockaddr_in);
  memcpy(&req->raddr, raddr, raddr_len);

  if (p->stat) {
    req->start_tstamp = ev_now(p->stat->loop);
    stat_request_begin(p->stat, dns_req_len,
                       listener->transport == DNS_TRANSPORT_TCP);
  }

  https_client_fetch(p->client, p->resolver_url, req->dns_req, dns_req_len,
                     p->resolv, req->tx_id, doh_response_cb, req);
}

void doh_proxy_destroy(doh_proxy_t *p) {
  if (p == NULL) {
    return;
  }
  curl_slist_free_all(p->resolv);
  free(p);
}
