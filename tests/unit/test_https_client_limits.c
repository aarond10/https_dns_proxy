#include <curl/curl.h>
#include <ev.h>
#include <stdint.h>
#include <string.h>

#include "dns_common.h"
#include "https_client.h"
#include "test_harness.h"

typedef struct {
  size_t calls;
  size_t failures;
} callback_state_t;

static struct ev_loop *loop;
static https_client_t client;
static options_t options;
static callback_state_t callback_state;

static void response_cb(void *data, char *buf, size_t buflen) {
  callback_state_t *state = (callback_state_t *)data;
  state->calls++;
  if (buf == NULL && buflen == 0) {
    state->failures++;
  }
}

static void setUp(void) {
  memset(&client, 0, sizeof(client));
  memset(&options, 0, sizeof(options));
  memset(&callback_state, 0, sizeof(callback_state));
  options.use_http_version = 1;
  options.max_idle_time = 118;
  options.conn_loss_time = 15;
  loop = ev_loop_new(0);
  if (loop == NULL) {
    test_fail(__FILE__, __LINE__, "ev_loop_new(0)");
    return;
  }
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    test_fail(__FILE__, __LINE__, "curl_global_init");
    return;
  }
  https_client_init(&client, &options, NULL, loop);
}

static void tearDown(void) {
  if (client.curlm != NULL) {
    https_client_cleanup(&client);
  }
  curl_global_cleanup();
  if (loop != NULL) {
    ev_loop_destroy(loop);
    loop = NULL;
  }
}

static void test_rejects_requests_above_fetch_limit(void) {
  static const char request[DNS_HEADER_LENGTH] = {0};

  for (size_t i = 0; i < HTTPS_FETCH_LIMIT; i++) {
    https_client_fetch(&client, "https://127.0.0.1/dns-query",
                       request, sizeof(request), NULL, (uint16_t)i,
                       response_cb, &callback_state);
  }

  TEST_ASSERT(client.fetch_count == HTTPS_FETCH_LIMIT);
  TEST_ASSERT(callback_state.calls == 0);

  https_client_fetch(&client, "https://127.0.0.1/dns-query",
                     request, sizeof(request), NULL, UINT16_MAX,
                     response_cb, &callback_state);

  TEST_ASSERT(client.fetch_count == HTTPS_FETCH_LIMIT);
  TEST_ASSERT(callback_state.calls == 1);
  TEST_ASSERT(callback_state.failures == 1);
}

int main(void) {
  TEST_RUN(test_rejects_requests_above_fetch_limit);
  return test_summary();
}
