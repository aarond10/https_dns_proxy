#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns_common.h"
#include "dns_listener_tcp.h"
#include "logging.h"

// Platform compatibility
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

// the following macros require to have client pointer to tcp_client_s structure
// else: compilation failure will occur
#define LOG_CLIENT(level, format, args...) LOG(level, "C-%u: " format, client->id, ## args)
#define DLOG_CLIENT(format, args...) DLOG("C-%u: " format, client->id, ## args)
#define ILOG_CLIENT(format, args...) ILOG("C-%u: " format, client->id, ## args)
#define WLOG_CLIENT(format, args...) WLOG("C-%u: " format, client->id, ## args)
#define ELOG_CLIENT(format, args...) ELOG("C-%u: " format, client->id, ## args)
#define FLOG_CLIENT(format, args...) FLOG("C-%u: " format, client->id, ## args)

enum {
  LISTEN_BACKLOG  =   5,
  IDLE_TIMEOUT_S  = 120,  // "two minutes" according to RFC1035 4.2.2
  TCP_DNS_MAX_PAYLOAD = UINT16_MAX,
  TCP_DNS_MAX_FRAME = TCP_DNS_MAX_PAYLOAD + sizeof(uint16_t),
  TCP_CLIENT_REQUEST_LIMIT = 16,
  TCP_CLIENT_OUTPUT_LIMIT = 2 * UINT16_MAX,
  TCP_WRITE_BUDGET = UINT16_MAX,
};

typedef struct dns_listener_tcp_s dns_listener_tcp_t;

struct tcp_response_s {
  struct tcp_response_s *next;
  size_t length;
  size_t sent;
  char data[];
};

struct tcp_client_s {
  dns_listener_tcp_t * d;

  uint64_t id;
  int sock;

  struct sockaddr_storage raddr;
  socklen_t addr_len;

  char * input_buffer;
  uint32_t input_buffer_size;
  uint32_t input_buffer_used;
  uint16_t pending_requests;
  int read_eof;

  ev_io read_watcher;
  ev_io write_watcher;
  ev_timer timer_watcher;

  struct tcp_response_s *output_head;
  struct tcp_response_s *output_tail;
  size_t output_bytes;

  struct tcp_client_s * next;
};

struct dns_listener_tcp_s {
  dns_listener_t base;

  struct ev_loop *loop;

  dns_request_fn cb;
  void *cb_data;

  int sock;
  socklen_t addrlen;
  ev_io accept_watcher;

  uint64_t client_id;
  uint16_t client_count;
  uint16_t client_limit;
  int stopping;
  struct tcp_client_s * clients;
};

static struct tcp_client_s *find_client(dns_listener_tcp_t *d,
                                        struct sockaddr *raddr, uint64_t connection_id) {
  for (struct tcp_client_s *client = d->clients; client != NULL; client = client->next) {
    if (client->id == connection_id &&
        memcmp(raddr, &client->raddr, client->addr_len) == 0) {
      return client;
    }
  }
  return NULL;
}

static void free_output_queue(struct tcp_client_s *client) {
  while (client->output_head != NULL) {
    struct tcp_response_s *response = client->output_head;
    client->output_head = response->next;
    free(response);
  }
  client->output_tail = NULL;
  client->output_bytes = 0;
}

static void remove_client(struct tcp_client_s * client) {
  dns_listener_tcp_t *d = client->d;

  DLOG_CLIENT("Removing client, socket %d", client->sock);

  if (!d->stopping && d->client_count == d->client_limit) {
    ev_io_start(d->loop, &d->accept_watcher);  // continue accepting new client connections
  }
  d->client_count--;

  ev_io_stop(d->loop, &client->read_watcher);
  ev_io_stop(d->loop, &client->write_watcher);
  ev_timer_stop(d->loop, &client->timer_watcher);

  free(client->input_buffer);
  free_output_queue(client);

  close(client->sock);

  if (d->clients == client) {
    d->clients = client->next;
  }
  else {
    for (struct tcp_client_s * cur = d->clients; cur != NULL; cur = cur->next) {
      if (cur->next == client) {
        cur->next = client->next;
        break;
      }
    }
  }

  free(client);
}

static int get_dns_request(struct tcp_client_s *client,
    char ** dns_req, uint16_t * req_size) {
  if (client->input_buffer_used < sizeof(uint16_t)) {
    return 0;  // Partial length prefix
  }

  // check if whole request is available
  memcpy(req_size, client->input_buffer, sizeof(*req_size));
  *req_size = ntohs(*req_size);
  const size_t data_size = sizeof(uint16_t) + (size_t)*req_size;
  if (data_size > client->input_buffer_used) {
    return 0;  // Partial request
  }
  // Extract the frame; the caller validates the DNS header. Avoid malloc(0)
  // for empty frames, since a NULL result is not an allocation failure.
  *dns_req = NULL;
  if (*req_size != 0) {
    *dns_req = (char *)malloc(*req_size);  // freed when DoH request completes
    if (*dns_req == NULL) {
      FLOG_CLIENT("Out of mem");
    }
    memcpy(*dns_req, client->input_buffer + sizeof(uint16_t), *req_size);
  }
  // move down data of next request(s) if any
  client->input_buffer_used -= (uint32_t)data_size;
  memmove(client->input_buffer, client->input_buffer + data_size, client->input_buffer_used);
  return 1;
}

static int dispatch_client_requests(struct tcp_client_s *client) {
  dns_listener_tcp_t *d = client->d;
  char *dns_req = NULL;
  uint16_t req_size = 0;
  int request_received = 0;
  while (client->pending_requests < TCP_CLIENT_REQUEST_LIMIT &&
         get_dns_request(client, &dns_req, &req_size)) {
    if (req_size < DNS_HEADER_LENGTH) {
      WLOG_CLIENT("Malformed request received, too short: %u, dropping client", req_size);
      free(dns_req);
      remove_client(client);
      return -1;
    }
    client->pending_requests++;
    if (client->pending_requests == TCP_CLIENT_REQUEST_LIMIT) {
      ev_io_stop(d->loop, &client->read_watcher);
    }
    d->cb(d->cb_data, &d->base, (struct sockaddr *)&client->raddr,
           client->id, dns_req, req_size);
    request_received = 1;
  }
  if (request_received) {
    ev_timer_again(d->loop, &client->timer_watcher);
  }
  return client->pending_requests == TCP_CLIENT_REQUEST_LIMIT;
}

static void read_cb(struct ev_loop __attribute__((unused)) *loop,
                    ev_io *w, int __attribute__((unused)) revents) {
  struct tcp_client_s *client = (struct tcp_client_s *)w->data;
  if (client->read_eof) {
    return;
  }
  if (dispatch_client_requests(client) != 0) {
    return;
  }

  // Receive data
  char buf[DNS_REQUEST_BUFFER_SIZE];  // if there would be more data, callback will be called again
  const size_t remaining = TCP_DNS_MAX_FRAME - client->input_buffer_used;
  if (remaining == 0) {
    WLOG_CLIENT("Request too large, dropping client");
    remove_client(client);
    return;
  }
  const size_t read_size = remaining < sizeof(buf) ? remaining : sizeof(buf);
  const ssize_t len = recv(w->fd, buf, read_size, 0);
  if (len == 0) {
    client->read_eof = 1;
    ev_io_stop(client->d->loop, &client->read_watcher);
    if (client->pending_requests == 0 && client->output_head == NULL) {
      remove_client(client);
    }
    return;
  }
  if (len < 0) {
    if (errno == ECONNRESET) {
      DLOG_CLIENT("TCP client closed connection");
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;  // Buffered requests were already dispatched before recv().
    } else {
      WLOG_CLIENT("Read error: %s (%d), dropping client", strerror(errno), errno);
    }
    remove_client(client);
    return;
  }

  // Append data into input buffer
  // Check for integer overflow and maximum message size
  if ((size_t)len > TCP_DNS_MAX_FRAME - client->input_buffer_used) {
    WLOG_CLIENT("Request too large, dropping client");
    remove_client(client);
    return;
  }
  const uint32_t free_space = client->input_buffer_size - client->input_buffer_used;
  const uint32_t needed_space = client->input_buffer_used + (uint32_t)len;
  // Limit buffer size to prevent memory exhaustion attacks
  if (needed_space > TCP_DNS_MAX_FRAME) {
    WLOG_CLIENT("Request too large, dropping client");
    remove_client(client);
    return;
  }
  DLOG_CLIENT("Received %d byte, free: %u", len, free_space);
  if (free_space < len) {
    for (client->input_buffer_size = 64;  // lower value does not make much sense
         client->input_buffer_size < needed_space;
         client->input_buffer_size *= 2) {
    }
    if (client->input_buffer_size > TCP_DNS_MAX_FRAME) {
      client->input_buffer_size = TCP_DNS_MAX_FRAME;
    }
    DLOG_CLIENT("Resize input buffer to %u", client->input_buffer_size);
    client->input_buffer = (char *) realloc((void*) client->input_buffer,  // NOLINT(bugprone-suspicious-realloc-usage) if realloc fails, program stops
                                            client->input_buffer_size);
    if (client->input_buffer == NULL) {
      FLOG_CLIENT("Out of mem");
    }
  }
  memcpy(client->input_buffer + client->input_buffer_used, buf, (size_t)len);
  client->input_buffer_used = needed_space;

  (void)dispatch_client_requests(client);
}

static void tcp_request_complete(dns_listener_t *self, struct sockaddr *raddr,
                                 uint64_t connection_id) {
  dns_listener_tcp_t *d = (dns_listener_tcp_t *)self;
  struct tcp_client_s *client = find_client(d, raddr, connection_id);
  if (client == NULL) {
    return;
  }
  if (client->pending_requests == 0) {
    WLOG_CLIENT("Completed request with no request pending");
    return;
  }

  const int resume_reads = client->pending_requests == TCP_CLIENT_REQUEST_LIMIT;
  client->pending_requests--;
  if (client->read_eof && client->pending_requests == 0 && client->output_head == NULL) {
    remove_client(client);
    return;
  }
  if (resume_reads && !client->read_eof) {
    ev_io_start(d->loop, &client->read_watcher);
    if (client->input_buffer_used > 0) {
      ev_feed_event(d->loop, &client->read_watcher, EV_READ);
    }
  }
}

static void timer_cb(struct ev_loop __attribute__((unused)) *loop,
                     ev_timer *w, int __attribute__((unused)) revents) {
  struct tcp_client_s *client = (struct tcp_client_s *)w->data;
  DLOG_CLIENT("TCP client timeouted");
  remove_client(client);
}

static int flush_client_output(struct tcp_client_s *client, int *made_progress) {
  size_t budget = TCP_WRITE_BUDGET;
  *made_progress = 0;

  while (client->output_head != NULL && budget > 0) {
    struct tcp_response_s *response = client->output_head;
    const size_t remaining = response->length - response->sent;
    const size_t send_size = remaining < budget ? remaining : budget;
    const ssize_t sent = send(client->sock, response->data + response->sent,
                              send_size, MSG_NOSIGNAL);
    if (sent > 0) {
      const size_t sent_size = (size_t)sent;
      response->sent += sent_size;
      client->output_bytes -= sent_size;
      budget -= sent_size;
      *made_progress = 1;
      if (response->sent == response->length) {
        client->output_head = response->next;
        if (client->output_head == NULL) {
          client->output_tail = NULL;
        }
        free(response);
      }
      continue;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;
    }
    WLOG_CLIENT("Send error: %s (%d), dropping client", strerror(errno), errno);
    return -1;
  }

  if (client->output_head == NULL) {
    ev_io_stop(client->d->loop, &client->write_watcher);
  } else {
    ev_io_start(client->d->loop, &client->write_watcher);
  }
  return 0;
}

static void write_cb(struct ev_loop __attribute__((unused)) *loop,
                     ev_io *w, int __attribute__((unused)) revents) {
  struct tcp_client_s *client = (struct tcp_client_s *)w->data;
  int made_progress = 0;
  if (flush_client_output(client, &made_progress) != 0) {
    remove_client(client);
    return;
  }
  if (made_progress && !client->d->stopping) {
    ev_timer_again(client->d->loop, &client->timer_watcher);
  }
  if (client->read_eof && client->pending_requests == 0 && client->output_head == NULL) {
    remove_client(client);
  }
}

static void accept_cb(struct ev_loop __attribute__((unused)) *loop,
                      ev_io *w, int __attribute__((unused)) revents) {
  dns_listener_tcp_t *d = (dns_listener_tcp_t *)w->data;

  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  // NOLINTNEXTLINE(android-cloexec-accept)
  const int client_sock = accept(w->fd, (struct sockaddr *)&client_addr, &client_addr_len);
  if (client_sock == -1) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      ELOG("Failed to accept TCP client: %s (%d)", strerror(errno), errno);
    }
    return;
  }

  // Set non-blocking mode for macOS compatibility (Linux accept4 does this atomically)
  const int flags = fcntl(client_sock, F_GETFL, 0);
  if (flags == -1) {
    ELOG("Error getting TCP client socket flags: %s (%d), dropping client",
         strerror(errno), errno);
    close(client_sock);
    return;
  }
  if (fcntl(client_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
    ELOG("Error setting TCP client socket to non-blocking: %s (%d), dropping client",
         strerror(errno), errno);
    close(client_sock);
    return;
  }

  d->client_id++;
  d->client_count++;
  if (d->client_count == d->client_limit) {
    ev_io_stop(d->loop, &d->accept_watcher);  // suspend accepting new client connections
  }

  struct tcp_client_s *client = (struct tcp_client_s *)calloc(1, sizeof(struct tcp_client_s));
  if (client == NULL) {
    FLOG("Out of mem");
  }
  client->d = d;
  client->id = d->client_id;
  client->sock = client_sock;
  memcpy(&client->raddr, &client_addr, client_addr_len);
  client->addr_len = client_addr_len;
  client->input_buffer = NULL;
  client->next = d->clients;
  d->clients = client;

  ev_io_init(&client->read_watcher, read_cb, client->sock, EV_READ);
  client->read_watcher.data = client;
  ev_io_start(d->loop, &client->read_watcher);

  ev_io_init(&client->write_watcher, write_cb, client->sock, EV_WRITE);
  client->write_watcher.data = client;

  ev_init(&client->timer_watcher, timer_cb);
  client->timer_watcher.repeat = IDLE_TIMEOUT_S;
  client->timer_watcher.data = client;
  ev_timer_again(d->loop, &client->timer_watcher);

  DLOG_CLIENT("Accepted client %u of %u, socket %d", d->client_count, d->client_limit, client->sock);
}

// Creates and binds a listening non-blocking TCP socket for incoming requests.
static int get_tcp_listen_sock(struct addrinfo *listen_addrinfo) {
  int sock = socket(listen_addrinfo->ai_family, SOCK_STREAM, 0);
  if (sock < 0) {
    FLOG("Error creating TCP socket: %s (%d)", strerror(errno), errno);
  }

  int yes = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    ELOG("Reuse address failed: %s (%d)", strerror(errno), errno);
  }

  uint16_t port = 0;
  char ipstr[INET6_ADDRSTRLEN];
  if (listen_addrinfo->ai_family == AF_INET) {
    port = ntohs(((struct sockaddr_in*) listen_addrinfo->ai_addr)->sin_port);
    inet_ntop(AF_INET, &((struct sockaddr_in *)listen_addrinfo->ai_addr)->sin_addr, ipstr, sizeof(ipstr));
  } else if (listen_addrinfo->ai_family == AF_INET6) {
    port = ntohs(((struct sockaddr_in6*) listen_addrinfo->ai_addr)->sin6_port);
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)listen_addrinfo->ai_addr)->sin6_addr, ipstr, sizeof(ipstr));
  } else {
    FLOG("Unknown address family: %d", listen_addrinfo->ai_family);
  }

  int res = bind(sock, listen_addrinfo->ai_addr, listen_addrinfo->ai_addrlen);
  if (res < 0) {
    FLOG("Error binding on %s:%d TCP: %s (%d)", ipstr, port,
         strerror(errno), errno);
  }

  if (listen(sock, LISTEN_BACKLOG) == -1) {
    FLOG("Error listening on %s:%d TCP: %s (%d)", ipstr, port,
         strerror(errno), errno);
  }

  int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    FLOG("Error getting TCP socket flags on %s:%d: %s (%d)", ipstr, port,
         strerror(errno), errno);
  }
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
    FLOG("Error setting TCP socket to non-blocking on %s:%d: %s (%d)", ipstr, port,
         strerror(errno), errno);
  }

  ILOG("Listening on %s:%d TCP", ipstr, port);

  return sock;
}

static void tcp_respond(dns_listener_t *self, struct sockaddr *raddr,
                        uint64_t connection_id,
                        const char __attribute__((unused)) *dns_req,
                        size_t __attribute__((unused)) dns_req_len,
                        char *resp, size_t resp_len) {
  dns_listener_tcp_t *d = (dns_listener_tcp_t *)self;

  if (resp_len < DNS_HEADER_LENGTH || resp_len > TCP_DNS_MAX_PAYLOAD) {
    WLOG("Malformed response received, invalid length: %zu", resp_len);
    return;
  }
  uint16_t response_id;
  memcpy(&response_id, resp, sizeof(response_id));
  response_id = ntohs(response_id);

  // find client data
  struct tcp_client_s *client = find_client(d, raddr, connection_id);
  if (client == NULL) {
    WLOG("Could not find client, can not send DNS response: %04hX", response_id);
    return;
  }

  const size_t frame_len = sizeof(uint16_t) + resp_len;
  if (frame_len > (TCP_CLIENT_OUTPUT_LIMIT - client->output_bytes)) {
    WLOG_CLIENT("Output queue limit exceeded, dropping client");
    remove_client(client);
    return;
  }

  struct tcp_response_s *response =
      (struct tcp_response_s *)malloc(sizeof(*response) + frame_len);
  if (response == NULL) {
    FLOG_CLIENT("Out of mem");
  }
  response->next = NULL;
  response->length = frame_len;
  response->sent = 0;
  const uint16_t response_size = htons((uint16_t)resp_len);
  memcpy(response->data, &response_size, sizeof(response_size));
  memcpy(response->data + sizeof(response_size), resp, resp_len);

  if (client->output_tail != NULL) {
    client->output_tail->next = response;
  } else {
    client->output_head = response;
  }
  client->output_tail = response;
  client->output_bytes += frame_len;

  DLOG_CLIENT("Queued %zu bytes, %zu bytes pending", resp_len, client->output_bytes);
  int made_progress = 0;
  if (flush_client_output(client, &made_progress) != 0) {
    remove_client(client);
    return;
  }
  if (made_progress) {
    DLOG_CLIENT("Responded %04hX", response_id);
    if (!d->stopping) {
      ev_timer_again(d->loop, &client->timer_watcher);
    }
  }
}

static void tcp_stop(dns_listener_t *self) {
  dns_listener_tcp_t *d = (dns_listener_tcp_t *)self;
  if (d->stopping) {
    return;
  }
  d->stopping = 1;
  ev_io_stop(d->loop, &d->accept_watcher);
  for (struct tcp_client_s *client = d->clients; client != NULL;) {
    struct tcp_client_s *next = client->next;
    client->read_eof = 1;
    ev_io_stop(d->loop, &client->read_watcher);
    if (client->pending_requests == 0 && client->output_head == NULL) {
      remove_client(client);
    } else {
      ev_timer_stop(d->loop, &client->timer_watcher);
      ev_timer_set(&client->timer_watcher, DNS_SHUTDOWN_TIMEOUT_S, 0);
      ev_timer_start(d->loop, &client->timer_watcher);
    }
    client = next;
  }
}

static void tcp_destroy(dns_listener_t *self) {
  dns_listener_tcp_t *d = (dns_listener_tcp_t *)self;
  while (d->clients != NULL) {
    remove_client(d->clients);
  }
  close(d->sock);
  free(d);
}

dns_listener_t * dns_tcp_listener_create(struct ev_loop *loop,
                                         struct addrinfo *listen_addrinfo,
                                         uint16_t client_limit,
                                         dns_request_fn cb, void *ctx) {
  dns_listener_tcp_t * d = (dns_listener_tcp_t *)calloc(1, sizeof(dns_listener_tcp_t));
  if (d == NULL) {
    FLOG("Out of mem");
  }
  d->base.respond = tcp_respond;
  d->base.request_complete = tcp_request_complete;
  d->base.stop = tcp_stop;
  d->base.destroy = tcp_destroy;
  d->base.transport = DNS_TRANSPORT_TCP;
  d->loop = loop;
  d->cb = cb;
  d->cb_data = ctx;
  d->sock = get_tcp_listen_sock(listen_addrinfo);
  d->addrlen = listen_addrinfo->ai_addrlen;
  d->client_limit = client_limit;

  ev_io_init(&d->accept_watcher, accept_cb, d->sock, EV_READ);
  d->accept_watcher.data = d;
  ev_io_start(d->loop, &d->accept_watcher);

  return &d->base;
}
