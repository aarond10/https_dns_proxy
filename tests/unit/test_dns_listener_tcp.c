#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_harness.h"
#include "../../src/dns_listener_tcp.c"

static struct tcp_client_s client;
static dns_listener_tcp_t listener;
static char *dns_request;
static int sockets[2];

static void setUp(void) {
  memset(&client, 0, sizeof(client));
  memset(&listener, 0, sizeof(listener));
  sockets[0] = -1;
  sockets[1] = -1;
  client.input_buffer_size = 64;
  client.input_buffer = (char *)calloc(1, client.input_buffer_size);
  dns_request = NULL;

  listener.loop = ev_loop_new(0);
  listener.clients = &client;
  client.d = &listener;
  if (listener.loop == NULL || socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
    test_fail(__FILE__, __LINE__, "test socket setup");
    return;
  }
  client.sock = sockets[0];
  client.addr_len = sizeof(struct sockaddr);
  client.raddr.ss_family = AF_UNIX;
  ev_io_init(&client.read_watcher, read_cb, client.sock, EV_READ);
  client.read_watcher.data = &client;
  ev_io_init(&client.write_watcher, write_cb, client.sock, EV_WRITE);
  client.write_watcher.data = &client;
  ev_timer_init(&client.timer_watcher, timer_cb, IDLE_TIMEOUT_S, IDLE_TIMEOUT_S);
  client.timer_watcher.data = &client;
}

static void tearDown(void) {
  if (listener.clients != NULL && listener.clients != &client) {
    remove_client(listener.clients);
    sockets[0] = -1;
  }
  free(dns_request);
  free(client.input_buffer);
  free_output_queue(&client);
  if (listener.loop != NULL) {
    ev_io_stop(listener.loop, &client.read_watcher);
    ev_io_stop(listener.loop, &client.write_watcher);
    ev_timer_stop(listener.loop, &client.timer_watcher);
    ev_loop_destroy(listener.loop);
  }
  if (sockets[0] >= 0) {
    close(sockets[0]);
  }
  if (sockets[1] >= 0) {
    close(sockets[1]);
  }
}

static void test_waits_for_complete_length_prefix(void) {
  client.input_buffer[0] = (char)UINT8_MAX;
  client.input_buffer_used = 1;
  uint16_t request_size = 0;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 0);
  TEST_ASSERT(dns_request == NULL);
  TEST_ASSERT(client.input_buffer_used == 1);
}

static void test_large_length_does_not_wrap_frame_size(void) {
  client.input_buffer[0] = (char)UINT8_MAX;
  client.input_buffer[1] = (char)UINT8_MAX;
  client.input_buffer_used = 2;
  uint16_t request_size = 0;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 0);
  TEST_ASSERT(request_size == UINT16_MAX);
  TEST_ASSERT(dns_request == NULL);
  TEST_ASSERT(client.input_buffer_used == 2);
}

static void test_rejects_zero_length_request_without_allocating(void) {
  client.input_buffer[0] = 0;
  client.input_buffer[1] = 0;
  client.input_buffer_used = sizeof(uint16_t);
  uint16_t request_size = UINT16_MAX;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 1);
  TEST_ASSERT(request_size == 0);
  TEST_ASSERT(dns_request == NULL);
  TEST_ASSERT(client.input_buffer_used == 0);
}

static void test_extracts_complete_request(void) {
  enum { REQUEST_SIZE = DNS_HEADER_LENGTH };
  client.input_buffer[0] = 0;
  client.input_buffer[1] = REQUEST_SIZE;
  for (size_t i = 0; i < REQUEST_SIZE; i++) {
    client.input_buffer[sizeof(uint16_t) + i] = (char)i;
  }
  client.input_buffer_used = sizeof(uint16_t) + REQUEST_SIZE;
  uint16_t request_size = 0;

  const int received = get_dns_request(&client, &dns_request, &request_size);

  TEST_ASSERT(received == 1);
  TEST_ASSERT(request_size == REQUEST_SIZE);
  TEST_ASSERT(client.input_buffer_used == 0);
  for (size_t i = 0; i < REQUEST_SIZE; i++) {
    TEST_ASSERT((uint8_t)dns_request[i] == i);
  }
}

static void test_large_partial_request_grows_without_exiting(void) {
  client.input_buffer_size = 32768;
  client.input_buffer = realloc(client.input_buffer, client.input_buffer_size);
  TEST_ASSERT(client.input_buffer != NULL);
  client.input_buffer_used = client.input_buffer_size;
  const uint16_t length = htons(60000);
  memcpy(client.input_buffer, &length, sizeof(length));
  char extra[1024] = {0};
  TEST_ASSERT(send(sockets[1], extra, sizeof(extra), 0) == sizeof(extra));
  read_cb(listener.loop, &client.read_watcher, EV_READ);
  TEST_ASSERT(client.input_buffer_size >= client.input_buffer_used);
  TEST_ASSERT(client.input_buffer_size <= TCP_DNS_MAX_FRAME);
  TEST_ASSERT(client.input_buffer_used == 32768 + sizeof(extra));
}

static void test_request_completion_resumes_client_reads(void) {
  client.pending_requests = TCP_CLIENT_REQUEST_LIMIT;

  tcp_request_complete(&listener.base, (struct sockaddr*)&client.raddr, client.id);

  TEST_ASSERT(client.pending_requests == TCP_CLIENT_REQUEST_LIMIT - 1);
  TEST_ASSERT(ev_is_active(&client.read_watcher));
}

static void consume_request(void *ctx, dns_listener_t *unused_listener,
                             struct sockaddr *unused_address,
                             uint64_t unused_id, char *request, size_t unused_length) {
  (void)unused_listener;
  (void)unused_address;
  (void)unused_id;
  (void)unused_length;
  unsigned *requests = ctx;
  (*requests)++;
  free(request);
}

static void test_resume_drains_buffer_before_reading_socket(void) {
  char frame[sizeof(uint16_t) + DNS_HEADER_LENGTH] = {0};
  const uint16_t length = htons(DNS_HEADER_LENGTH);
  memcpy(frame, &length, sizeof(length));
  memcpy(client.input_buffer, frame, sizeof(frame));
  memcpy(client.input_buffer + sizeof(frame), frame, sizeof(frame));
  client.input_buffer_used = 2 * sizeof(frame);
  client.pending_requests = TCP_CLIENT_REQUEST_LIMIT;
  unsigned requests = 0;
  listener.cb = consume_request;
  listener.cb_data = &requests;
  TEST_ASSERT(send(sockets[1], frame, sizeof(frame), 0) == sizeof(frame));

  tcp_request_complete(&listener.base, (struct sockaddr *)&client.raddr, client.id);
  read_cb(listener.loop, &client.read_watcher, EV_READ);

  TEST_ASSERT(requests == 1);
  TEST_ASSERT(client.pending_requests == TCP_CLIENT_REQUEST_LIMIT);
  TEST_ASSERT(client.input_buffer_used == sizeof(frame));
  TEST_ASSERT(!ev_is_active(&client.read_watcher));
  char unread[sizeof(frame)];
  TEST_ASSERT(recv(sockets[0], unread, sizeof(unread), MSG_DONTWAIT) == sizeof(frame));
  TEST_ASSERT(memcmp(unread, frame, sizeof(frame)) == 0);
}

static void test_read_respects_remaining_input_capacity(void) {
  client.input_buffer_size = TCP_DNS_MAX_FRAME;
  client.input_buffer = realloc(client.input_buffer, client.input_buffer_size);
  TEST_ASSERT(client.input_buffer != NULL);
  client.input_buffer_used = TCP_DNS_MAX_FRAME - 8;
  const uint16_t length = htons(UINT16_MAX);
  memcpy(client.input_buffer, &length, sizeof(length));
  unsigned requests = 0;
  listener.cb = consume_request;
  listener.cb_data = &requests;
  char extra[16] = {0};
  TEST_ASSERT(send(sockets[1], extra, sizeof(extra), 0) == sizeof(extra));
  read_cb(listener.loop, &client.read_watcher, EV_READ);
  TEST_ASSERT(requests == 1);
  TEST_ASSERT(client.input_buffer_used == 0);
  TEST_ASSERT(recv(sockets[0], extra, sizeof(extra), MSG_DONTWAIT) == 8);
}

static void test_old_connection_cannot_complete_or_respond_to_new_client(void) {
  client.id = 2;
  client.pending_requests = TCP_CLIENT_REQUEST_LIMIT;
  tcp_request_complete(&listener.base, (struct sockaddr *)&client.raddr, 1);
  TEST_ASSERT(client.pending_requests == TCP_CLIENT_REQUEST_LIMIT);
  TEST_ASSERT(!ev_is_active(&client.read_watcher));

  char response[DNS_HEADER_LENGTH] = {0};
  tcp_respond(&listener.base, (struct sockaddr *)&client.raddr,
              1, NULL, 0, response, sizeof(response));
  TEST_ASSERT(client.output_head == NULL);
  TEST_ASSERT(client.output_bytes == 0);
  char received[DNS_HEADER_LENGTH];
  TEST_ASSERT(recv(sockets[1], received, sizeof(received), MSG_DONTWAIT) == -1);
  TEST_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);
}

static void test_queues_response_without_blocking_event_loop(void) {
  const int flags = fcntl(sockets[0], F_GETFL, 0);
  TEST_ASSERT(flags >= 0);
  TEST_ASSERT(fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) == 0);

  char fill[4096] = {0};
  while (send(sockets[0], fill, sizeof(fill), MSG_NOSIGNAL) > 0) {
  }
  TEST_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);

  char response_one[DNS_HEADER_LENGTH];
  char response_two[DNS_HEADER_LENGTH];
  memset(response_one, 0x11, sizeof(response_one));
  memset(response_two, 0x22, sizeof(response_two));
  response_one[0] = 0x12;
  response_one[1] = 0x34;
  response_two[0] = 0x56;
  response_two[1] = 0x78;
  tcp_respond(&listener.base, (struct sockaddr *)&client.raddr,
              client.id, NULL, 0, response_one, sizeof(response_one));
  tcp_respond(&listener.base, (struct sockaddr *)&client.raddr,
              client.id, NULL, 0, response_two, sizeof(response_two));

  TEST_ASSERT(client.output_head != NULL);
  TEST_ASSERT(client.output_bytes ==
              2 * (sizeof(uint16_t) + sizeof(response_one)));
  TEST_ASSERT(ev_is_active(&client.write_watcher));

  const int peer_flags = fcntl(sockets[1], F_GETFL, 0);
  TEST_ASSERT(peer_flags >= 0);
  TEST_ASSERT(fcntl(sockets[1], F_SETFL, peer_flags | O_NONBLOCK) == 0);
  while (recv(sockets[1], fill, sizeof(fill), 0) > 0) {
  }
  TEST_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);

  write_cb(listener.loop, &client.write_watcher, EV_WRITE);

  char wire_data[2 * (sizeof(uint16_t) + DNS_HEADER_LENGTH)];
  size_t received = 0;
  while (received < sizeof(wire_data)) {
    const ssize_t bytes = recv(sockets[1], wire_data + received,
                               sizeof(wire_data) - received, 0);
    TEST_ASSERT(bytes > 0);
    received += (size_t)bytes;
  }

  uint16_t frame_size = 0;
  memcpy(&frame_size, wire_data, sizeof(frame_size));
  TEST_ASSERT(ntohs(frame_size) == sizeof(response_one));
  TEST_ASSERT(memcmp(wire_data + sizeof(frame_size),
                     response_one, sizeof(response_one)) == 0);
  const size_t second_frame = sizeof(frame_size) + sizeof(response_one);
  memcpy(&frame_size, wire_data + second_frame, sizeof(frame_size));
  TEST_ASSERT(ntohs(frame_size) == sizeof(response_two));
  TEST_ASSERT(memcmp(wire_data + second_frame + sizeof(frame_size),
                     response_two, sizeof(response_two)) == 0);

  TEST_ASSERT(client.output_head == NULL);
  TEST_ASSERT(client.output_tail == NULL);
  TEST_ASSERT(client.output_bytes == 0);
  TEST_ASSERT(!ev_is_active(&client.write_watcher));
}

static struct tcp_client_s *heap_client(void) {
  struct tcp_client_s *owned = malloc(sizeof(*owned));
  if (owned == NULL) {
    return NULL;
  }
  *owned = client;
  client.input_buffer = NULL;
  listener.clients = owned;
  listener.client_count = 1;
  listener.client_limit = 2;
  ev_io_init(&owned->read_watcher, read_cb, owned->sock, EV_READ);
  owned->read_watcher.data = owned;
  ev_io_start(listener.loop, &owned->read_watcher);
  ev_io_init(&owned->write_watcher, write_cb, owned->sock, EV_WRITE);
  owned->write_watcher.data = owned;
  ev_timer_init(&owned->timer_watcher, timer_cb, IDLE_TIMEOUT_S, IDLE_TIMEOUT_S);
  owned->timer_watcher.data = owned;
  return owned;
}

static void check_queued_response_drains(int stopping) {
  struct tcp_client_s *owned = heap_client();
  TEST_ASSERT(owned != NULL);
  TEST_ASSERT(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
  TEST_ASSERT(fcntl(sockets[1], F_SETFL, O_NONBLOCK) == 0);
  char fill[4096] = {0};
  while (send(sockets[0], fill, sizeof(fill), MSG_NOSIGNAL) > 0) {
  }
  TEST_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);
  char response[DNS_HEADER_LENGTH] = {0};
  tcp_respond(&listener.base, (struct sockaddr *)&owned->raddr,
              owned->id, NULL, 0, response, sizeof(response));
  TEST_ASSERT(owned->output_head != NULL);
  if (stopping) {
    tcp_stop(&listener.base);
    TEST_ASSERT(ev_is_active(&owned->timer_watcher));
    TEST_ASSERT(owned->timer_watcher.repeat == 0);
  } else {
    TEST_ASSERT(shutdown(sockets[1], SHUT_WR) == 0);
    read_cb(listener.loop, &owned->read_watcher, EV_READ);
  }
  TEST_ASSERT(listener.clients == owned);
  TEST_ASSERT(owned->read_eof);
  TEST_ASSERT(!ev_is_active(&owned->read_watcher));
  while (recv(sockets[1], fill, sizeof(fill), 0) > 0) {
  }
  write_cb(listener.loop, &owned->write_watcher, EV_WRITE);
  TEST_ASSERT(listener.clients == NULL);
  sockets[0] = -1;
  char frame[sizeof(uint16_t) + DNS_HEADER_LENGTH];
  TEST_ASSERT(recv(sockets[1], frame, sizeof(frame), 0) == sizeof(frame));
  uint16_t length;
  memcpy(&length, frame, sizeof(length));
  TEST_ASSERT(ntohs(length) == sizeof(response));
  TEST_ASSERT(memcmp(frame + sizeof(length), response, sizeof(response)) == 0);
  TEST_ASSERT(recv(sockets[1], frame, sizeof(frame), 0) == 0);
}

static void test_half_close_keeps_queued_response_until_drained(void) {
  check_queued_response_drains(0);
}

static void test_shutdown_keeps_queued_response_until_drained(void) {
  check_queued_response_drains(1);
}

static void test_shutdown_waits_for_pending_response(void) {
  struct tcp_client_s *owned = heap_client();
  TEST_ASSERT(owned != NULL);
  owned->pending_requests = TCP_CLIENT_REQUEST_LIMIT;
  listener.client_limit = 1;
  tcp_stop(&listener.base);
  TEST_ASSERT(listener.clients == owned);
  TEST_ASSERT(!ev_is_active(&owned->read_watcher));
  TEST_ASSERT(!ev_is_active(&listener.accept_watcher));
  const ev_tstamp deadline = owned->timer_watcher.at;
  char response[DNS_HEADER_LENGTH] = {0};
  tcp_respond(&listener.base, (struct sockaddr *)&owned->raddr,
              owned->id, NULL, 0, response, sizeof(response));
  tcp_request_complete(&listener.base, (struct sockaddr *)&owned->raddr, owned->id);
  TEST_ASSERT(!ev_is_active(&owned->read_watcher));
  TEST_ASSERT(ev_is_active(&owned->timer_watcher));
  TEST_ASSERT(owned->timer_watcher.at == deadline);
  TEST_ASSERT(owned->timer_watcher.repeat == 0);
  tcp_stop(&listener.base);
  TEST_ASSERT(owned->timer_watcher.at == deadline);
  char frame[sizeof(uint16_t) + DNS_HEADER_LENGTH];
  TEST_ASSERT(recv(sockets[1], frame, sizeof(frame), 0) == sizeof(frame));
  timer_cb(listener.loop, &owned->timer_watcher, EV_TIMER);
  sockets[0] = -1;
  TEST_ASSERT(listener.clients == NULL);
  TEST_ASSERT(!ev_is_active(&listener.accept_watcher));
}

static void test_shutdown_removes_idle_client(void) {
  TEST_ASSERT(heap_client() != NULL);
  listener.client_limit = 1;
  tcp_stop(&listener.base);
  sockets[0] = -1;
  TEST_ASSERT(listener.clients == NULL);
  TEST_ASSERT(!ev_is_active(&listener.accept_watcher));
}

static void test_half_close_waits_for_pending_request_completion(void) {
  struct tcp_client_s *owned = heap_client();
  TEST_ASSERT(owned != NULL);
  owned->pending_requests = 1;
  TEST_ASSERT(shutdown(sockets[1], SHUT_WR) == 0);
  read_cb(listener.loop, &owned->read_watcher, EV_READ);
  TEST_ASSERT(listener.clients == owned);
  TEST_ASSERT(owned->read_eof);
  struct sockaddr_storage address = owned->raddr;
  const uint64_t connection_id = owned->id;
  tcp_request_complete(&listener.base, (struct sockaddr *)&address, connection_id);
  TEST_ASSERT(listener.clients == NULL);
  sockets[0] = -1;
}

static void test_accepts_maximum_payload_request_and_response(void) {
  client.input_buffer_size = TCP_DNS_MAX_FRAME;
  client.input_buffer = realloc(client.input_buffer, client.input_buffer_size);
  TEST_ASSERT(client.input_buffer != NULL);
  memset(client.input_buffer, 0, client.input_buffer_size);
  const uint16_t length = htons(UINT16_MAX);
  memcpy(client.input_buffer, &length, sizeof(length));
  client.input_buffer_used = TCP_DNS_MAX_FRAME;
  uint16_t request_size = 0;
  TEST_ASSERT(get_dns_request(&client, &dns_request, &request_size) == 1);
  TEST_ASSERT(request_size == UINT16_MAX);
  TEST_ASSERT(client.input_buffer_used == 0);
  TEST_ASSERT(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
  tcp_respond(&listener.base, (struct sockaddr *)&client.raddr,
              client.id, NULL, 0, dns_request, request_size);
  size_t received = 0;
  char buffer[4096];
  while (received < TCP_DNS_MAX_FRAME) {
    const size_t remaining = TCP_DNS_MAX_FRAME - received;
    const ssize_t count = recv(sockets[1], buffer,
                               remaining < sizeof(buffer) ? remaining : sizeof(buffer), 0);
    TEST_ASSERT(count > 0);
    if (received == 0) {
      TEST_ASSERT(count >= (ssize_t)sizeof(length));
      TEST_ASSERT(memcmp(buffer, &length, sizeof(length)) == 0);
    }
    received += (size_t)count;
    write_cb(listener.loop, &client.write_watcher, EV_WRITE);
  }
  TEST_ASSERT(client.output_head == NULL);
}

int main(void) {
  TEST_RUN(test_waits_for_complete_length_prefix);
  TEST_RUN(test_large_length_does_not_wrap_frame_size);
  TEST_RUN(test_rejects_zero_length_request_without_allocating);
  TEST_RUN(test_extracts_complete_request);
  TEST_RUN(test_large_partial_request_grows_without_exiting);
  TEST_RUN(test_request_completion_resumes_client_reads);
  TEST_RUN(test_resume_drains_buffer_before_reading_socket);
  TEST_RUN(test_read_respects_remaining_input_capacity);
  TEST_RUN(test_old_connection_cannot_complete_or_respond_to_new_client);
  TEST_RUN(test_queues_response_without_blocking_event_loop);
  TEST_RUN(test_half_close_keeps_queued_response_until_drained);
  TEST_RUN(test_shutdown_keeps_queued_response_until_drained);
  TEST_RUN(test_shutdown_waits_for_pending_response);
  TEST_RUN(test_shutdown_removes_idle_client);
  TEST_RUN(test_half_close_waits_for_pending_request_completion);
  TEST_RUN(test_accepts_maximum_payload_request_and_response);
  return test_summary();
}
