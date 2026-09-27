#include <stdlib.h>
#include <string.h>

#include "test_harness.h"
#include "../../src/doh_proxy.c"

static https_client_t client;
static doh_proxy_t *proxy;
static unsigned reset_calls;

void https_client_reset(https_client_t *unused_client) {
  (void)unused_client;
  reset_calls++;
}

void https_client_fetch(https_client_t *unused_client, const char *url,
                        const char *postdata, size_t postdata_len,
                        struct curl_slist *resolv, uint16_t id,
                        https_response_cb cb, void *data) {
  (void)unused_client;
  (void)url;
  (void)postdata;
  (void)postdata_len;
  (void)resolv;
  (void)id;
  (void)cb;
  (void)data;
}

void stat_request_begin(stat_t *stat, size_t request_len, uint8_t is_tcp) {
  (void)stat;
  (void)request_len;
  (void)is_tcp;
}

void stat_request_end(stat_t *stat, size_t response_len,
                      ev_tstamp latency, uint8_t is_tcp) {
  (void)stat;
  (void)response_len;
  (void)latency;
  (void)is_tcp;
}

static void setUp(void) {
  memset(&client, 0, sizeof(client));
  reset_calls = 0;
  proxy = doh_proxy_create(NULL, &client, "https://resolver.test/dns-query", NULL);
  doh_proxy_set_resolv(proxy, "resolver.test:443:192.0.2.1,192.0.2.2");
}

static void tearDown(void) {
  doh_proxy_destroy(proxy);
  proxy = NULL;
}

static void update_resolver(const char *addresses) {
  char *owned_addresses = strdup(addresses);
  if (owned_addresses == NULL) {
    test_fail(__FILE__, __LINE__, "strdup(addresses)");
    return;
  }
  doh_proxy_handle_resolver_update("resolver.test", proxy, owned_addresses);
}

static void test_new_address_triggers_resolver_update(void) {
  update_resolver("192.0.2.1,192.0.2.2,192.0.2.3");

  TEST_ASSERT(reset_calls == 1);
  TEST_ASSERT(strcmp(proxy->resolv->data,
                     "resolver.test:443:192.0.2.1,192.0.2.2,192.0.2.3") == 0);
}

static void test_removed_address_triggers_resolver_update(void) {
  update_resolver("192.0.2.1");

  TEST_ASSERT(reset_calls == 1);
  TEST_ASSERT(strcmp(proxy->resolv->data,
                     "resolver.test:443:192.0.2.1") == 0);
}

static void test_exact_address_match_after_prefix_match(void) {
  curl_slist_free_all(proxy->resolv);
  proxy->resolv = NULL;
  doh_proxy_set_resolv(proxy, "resolver.test:443:192.0.2.10,192.0.2.1");

  update_resolver("192.0.2.1,192.0.2.10");

  TEST_ASSERT(reset_calls == 0);
  TEST_ASSERT(strcmp(proxy->resolv->data,
                     "resolver.test:443:192.0.2.10,192.0.2.1") == 0);
}

int main(void) {
  TEST_RUN(test_new_address_triggers_resolver_update);
  TEST_RUN(test_removed_address_triggers_resolver_update);
  TEST_RUN(test_exact_address_match_after_prefix_match);
  return test_summary();
}
