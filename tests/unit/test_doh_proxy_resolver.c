#include <stdlib.h>
#include <string.h>

#include "test_harness.h"
#include "../../src/doh_proxy.c"

static https_client_t client;
static doh_proxy_t *proxy;
static unsigned reset_calls;
static https_response_cb pending_response_cb;
static void *pending_response_data;
static uint64_t response_connection_id;
static uint64_t completion_connection_id;
static unsigned response_calls;
static unsigned completion_calls;
static const char *expected_resolver_during_reset;
static int reset_saw_expected_resolver;

void https_client_reset(https_client_t *unused_client) {
  (void)unused_client;
  reset_calls++;
  if (expected_resolver_during_reset != NULL &&
      proxy != NULL && proxy->resolv != NULL &&
      strcmp(proxy->resolv->data, expected_resolver_during_reset) == 0) {
    reset_saw_expected_resolver = 1;
  }
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
  pending_response_cb = cb;
  pending_response_data = data;
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
  pending_response_cb = NULL;
  pending_response_data = NULL;
  response_connection_id = 0;
  completion_connection_id = 0;
  response_calls = 0;
  completion_calls = 0;
  expected_resolver_during_reset = NULL;
  reset_saw_expected_resolver = 0;
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
  expected_resolver_during_reset =
      "resolver.test:443:192.0.2.1,192.0.2.2";
  update_resolver("192.0.2.1,192.0.2.2,192.0.2.3");

  TEST_ASSERT(reset_calls == 1);
  TEST_ASSERT(reset_saw_expected_resolver);
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

static void record_response(dns_listener_t *unused_listener,
                            struct sockaddr *unused_address,
                            uint64_t connection_id,
                            const char *unused_request, size_t unused_request_len,
                            char *unused_response, size_t unused_response_len) {
  (void)unused_listener;
  (void)unused_address;
  (void)unused_request;
  (void)unused_request_len;
  (void)unused_response;
  (void)unused_response_len;
  response_connection_id = connection_id;
  response_calls++;
}

static void record_completion(dns_listener_t *unused_listener,
                              struct sockaddr *unused_address,
                              uint64_t connection_id) {
  (void)unused_listener;
  (void)unused_address;
  completion_connection_id = connection_id;
  completion_calls++;
}

static void test_preserves_connection_identity_through_proxy_callbacks(void) {
  dns_listener_t listener = {
    .respond = record_response,
    .request_complete = record_completion,
    .transport = DNS_TRANSPORT_TCP
  };
  struct sockaddr_in address = {.sin_family = AF_INET};
  for (unsigned attempt = 0; attempt < 2; attempt++) {
    char *request = calloc(1, DNS_HEADER_LENGTH);
    TEST_ASSERT(request != NULL);
    const uint64_t connection_id = 100 + attempt;
    doh_proxy_handle_request(proxy, &listener, (struct sockaddr *)&address,
                             connection_id, request, DNS_HEADER_LENGTH);
    TEST_ASSERT(pending_response_cb != NULL);
    TEST_ASSERT(completion_calls == attempt);
    char response[DNS_HEADER_LENGTH] = {0};
    pending_response_cb(pending_response_data, attempt == 0 ? response : NULL,
                         attempt == 0 ? sizeof(response) : 0);
    TEST_ASSERT(completion_calls == attempt + 1);
    TEST_ASSERT(completion_connection_id == connection_id);
    TEST_ASSERT(response_calls == 1);
    TEST_ASSERT(response_connection_id == 100);
  }
}

static void test_listener_without_completion_callback(void) {
  dns_listener_t listener = {
    .respond = record_response,
    .transport = DNS_TRANSPORT_UDP
  };
  struct sockaddr_in address = {.sin_family = AF_INET};
  for (unsigned attempt = 0; attempt < 3; attempt++) {
    char *request = calloc(1, DNS_HEADER_LENGTH);
    TEST_ASSERT(request != NULL);
    pending_response_cb = NULL;
    if (attempt == 2) {
      doh_proxy_await_bootstrap(proxy, NULL);
    }
    doh_proxy_handle_request(proxy, &listener, (struct sockaddr *)&address,
                             0, request, DNS_HEADER_LENGTH);
    if (attempt == 2) {
      TEST_ASSERT(pending_response_cb == NULL);
    } else {
      TEST_ASSERT(pending_response_cb != NULL);
      char response[DNS_HEADER_LENGTH] = {0};
      pending_response_cb(pending_response_data, attempt == 0 ? response : NULL,
                           attempt == 0 ? sizeof(response) : 0);
    }
    TEST_ASSERT(response_calls == 1);
    TEST_ASSERT(completion_calls == 0);
  }
}

int main(void) {
  TEST_RUN(test_new_address_triggers_resolver_update);
  TEST_RUN(test_removed_address_triggers_resolver_update);
  TEST_RUN(test_exact_address_match_after_prefix_match);
  TEST_RUN(test_preserves_connection_identity_through_proxy_callbacks);
  TEST_RUN(test_listener_without_completion_callback);
  return test_summary();
}
