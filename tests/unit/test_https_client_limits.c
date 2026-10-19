#include <curl/curl.h>
#include <ev.h>
#include <stdint.h>
#include <string.h>

#include "dns_common.h"
#include "https_client.h"
#include "test_harness.h"
#include "../../src/https_client.c"

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

typedef struct {
  size_t fetch_count;
  size_t listed_fetches;
} replacement_state_t;

static void submit_replacement_request(void *data, char *buf, size_t buflen) {
  (void)buf;
  (void)buflen;
  replacement_state_t *state = data;
  state->fetch_count = client.fetch_count;
  for (struct https_fetch_ctx *ctx = client.fetches; ctx != NULL; ctx = ctx->next) {
    state->listed_fetches++;
  }
  static const char request[DNS_HEADER_LENGTH] = {0};
  https_client_fetch(&client, "https://127.0.0.1/dns-query",
                     request, sizeof(request), NULL, UINT16_MAX,
                     response_cb, &callback_state);
}

static void test_completion_callback_can_replace_request_at_fetch_limit(void) {
  static const char request[DNS_HEADER_LENGTH] = {0};
  for (size_t i = 0; i < HTTPS_FETCH_LIMIT; i++) {
    https_client_fetch(&client, "https://127.0.0.1/dns-query",
                       request, sizeof(request), NULL, (uint16_t)i,
                       response_cb, &callback_state);
  }
  TEST_ASSERT(client.fetch_count == HTTPS_FETCH_LIMIT);
  replacement_state_t state = {0};
  struct https_fetch_ctx *prev = client.fetches;
  struct https_fetch_ctx *completed = prev->next;
  completed->cb = submit_replacement_request;
  completed->cb_data = &state;

  https_fetch_ctx_cleanup(&client, prev, completed, -1);

  TEST_ASSERT(state.fetch_count == HTTPS_FETCH_LIMIT - 1);
  TEST_ASSERT(state.listed_fetches == HTTPS_FETCH_LIMIT - 1);
  TEST_ASSERT(callback_state.calls == 0);
  TEST_ASSERT(client.fetch_count == HTTPS_FETCH_LIMIT);
  size_t listed_fetches = 0;
  for (struct https_fetch_ctx *ctx = client.fetches; ctx != NULL; ctx = ctx->next) {
    listed_fetches++;
  }
  TEST_ASSERT(listed_fetches == client.fetch_count);
}

static void test_socket_watchers_grow_and_support_fd_zero(void) {
  CURL *fake_easy_handle = (CURL *)(uintptr_t)1;
  enum { WATCHER_COUNT = 16 };

  for (curl_socket_t fd = 0; fd < WATCHER_COUNT; fd++) {
    TEST_ASSERT(multi_sock_cb(fake_easy_handle, fd, CURL_POLL_IN,
                              &client, NULL) == 0);
    struct ev_io *watcher = get_io_event(client.io_events, fd);
    TEST_ASSERT(watcher != NULL);
    TEST_ASSERT(watcher->fd == fd);
    TEST_ASSERT(ev_is_active(watcher));
  }

  struct ev_io *fd_zero_watcher = get_io_event(client.io_events, 0);
  TEST_ASSERT(fd_zero_watcher != NULL);
  TEST_ASSERT(multi_sock_cb(fake_easy_handle, 0, CURL_POLL_REMOVE,
                            &client, NULL) == 0);
  TEST_ASSERT(get_io_event(client.io_events, 0) == NULL);
  TEST_ASSERT(!ev_is_active(fd_zero_watcher));

  TEST_ASSERT(multi_sock_cb(fake_easy_handle, WATCHER_COUNT,
                            CURL_POLL_OUT, &client, NULL) == 0);
  TEST_ASSERT(get_io_event(client.io_events, WATCHER_COUNT) == fd_zero_watcher);
}

static void test_aborted_multi_action_schedules_client_reset(void) {
  TEST_ASSERT(!ev_is_active(&client.reset_timer));

  TEST_ASSERT(handle_multi_action_result(
                  &client, CURLM_ABORTED_BY_CALLBACK) == -1);

  TEST_ASSERT(ev_is_active(&client.reset_timer));
}

static void test_rejects_socket_when_interface_binding_fails(void) {
  struct curl_sockaddr address;
  memset(&address, 0, sizeof(address));
  address.family = AF_INET;
  address.socktype = SOCK_STREAM;
  options.outbound_interface = "";

  TEST_ASSERT(opensocket_callback(&client, CURLSOCKTYPE_IPCXN, &address) ==
              CURL_SOCKET_BAD);
  TEST_ASSERT(client.connections == 0);
}

int main(void) {
  TEST_RUN(test_rejects_requests_above_fetch_limit);
  TEST_RUN(test_completion_callback_can_replace_request_at_fetch_limit);
  TEST_RUN(test_socket_watchers_grow_and_support_fd_zero);
  TEST_RUN(test_aborted_multi_action_schedules_client_reset);
  TEST_RUN(test_rejects_socket_when_interface_binding_fails);
  return test_summary();
}
