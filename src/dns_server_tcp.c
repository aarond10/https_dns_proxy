//NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _GNU_SOURCE  // needed for having accept4()

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "dns_server_tcp.h"
#include "logging.h"

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
  RESEND_DELAY_US = 500,  // 0.0005 sec
  TCP_DNS_MAX_PAYLOAD = UINT16_MAX - sizeof(uint16_t),  // Max after 2-byte length prefix
};

struct tcp_client_s {
  struct dns_server_tcp_s * d;

  uint64_t id;
  int sock;

  struct sockaddr_storage raddr;
  socklen_t addr_len;

  char * input_buffer;
  uint32_t input_buffer_size;
  uint32_t input_buffer_used;

  ev_io read_watcher;
  ev_timer timer_watcher;

  struct tcp_client_s * next;
} __attribute__((packed)) __attribute__((aligned(128)));

struct dns_server_tcp_s {
  struct ev_loop *loop;

  dns_req_received_cb cb;
  void *cb_data;

  int sock;
  socklen_t addrlen;
  ev_io accept_watcher;

  uint64_t client_id;
  uint16_t client_count;
  uint16_t client_limit;
  struct tcp_client_s * clients;
} __attribute__((packed)) __attribute__((aligned(128)));


static void remove_client(struct tcp_client_s * client) {
  dns_server_tcp_t *d = client->d;

  DLOG_CLIENT("Removing client, socket %d", client->sock);

  if (d->client_count == d->client_limit) {
    ev_io_start(d->loop, &d->accept_watcher);  // continue accepting new client connections
  }
  d->client_count--;

  ev_io_stop(d->loop, &client->read_watcher);
  ev_timer_stop(d->loop, &client->timer_watcher);

  free(client->input_buffer);

  close(client->sock);

  // Save next pointer before freeing. Safe because this is single-threaded
  // event loop - no callbacks can run during this function.
  struct tcp_client_s *next = client->next;

  if (d->clients == client) {
    d->clients = next;
  }
  else {
    for (struct tcp_client_s * cur = d->clients; cur != NULL; cur = cur->next) {
      if (cur->next == client) {
        cur->next = next;
        break;
      }
    }
  }

  free(client);
}

static int get_dns_request(struct tcp_client_s *client,
    char ** dns_req, uint16_t * req_size) {
  // check if whole request is available
  *req_size = ntohs(*((uint16_t*)client->input_buffer));
  uint16_t data_size = sizeof(uint16_t) + *req_size;
  if (data_size > client->input_buffer_used) {
    return 0;  // Partial request
  }
  // copy whole request
  *dns_req = (char *)malloc(*req_size);  // To free buffer after https request is complete.
  if (*dns_req == NULL) {
    FLOG_CLIENT("Out of mem");
  }
  memcpy(*dns_req, client->input_buffer + sizeof(uint16_t), *req_size);
  // move down data of next request(s) if any
  client->input_buffer_used -= data_size;
  memmove(client->input_buffer, client->input_buffer + data_size, client->input_buffer_used);
  return 1;
}

static void read_cb(struct ev_loop __attribute__((unused)) *loop,
                    ev_io *w, int __attribute__((unused)) revents) {
  struct tcp_client_s *client = (struct tcp_client_s *)w->data;
  dns_server_tcp_t *d = client->d;

  // Receive data
  char buf[DNS_REQUEST_BUFFER_SIZE];  // if there would be more data, callback will be called again
  ssize_t len = recv(w->fd, buf, DNS_REQUEST_BUFFER_SIZE, 0);
  if (len <= 0) {
    if (len == 0 || errno == ECONNRESET) {
      DLOG_CLIENT("Connection closed");
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;
    } else {
      WLOG_CLIENT("Read error: %s", strerror(errno));
    }
    remove_client(client);
    return;
  }

  // Append data into input buffer
  // Check for integer overflow and maximum message size
  if (len > UINT16_MAX || client->input_buffer_used > UINT16_MAX - (uint32_t)len) {
    WLOG_CLIENT("Request too large, dropping client");
    remove_client(client);
    return;
  }
  const uint32_t free_space = client->input_buffer_size - client->input_buffer_used;
  const uint32_t needed_space = client->input_buffer_used + (uint32_t)len;
  DLOG_CLIENT("Received %d byte, free: %u", len, free_space);
  if (free_space < len) {
    for (client->input_buffer_size = 64;  // lower value does not make much sense
         client->input_buffer_size < needed_space;
         client->input_buffer_size *= 2) {
      if (client->input_buffer_size > 2*UINT16_MAX) {
        FLOG_CLIENT("Unrealistic input buffer size: %u", client->input_buffer_size);
      }
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

  // Split requests
  char *dns_req = NULL;
  uint16_t req_size = 0;
  uint8_t request_received = 0;
  while (get_dns_request(client, &dns_req, &req_size)) {
    if (req_size < DNS_HEADER_LENGTH) {
      WLOG_CLIENT("Malformed request received, too short: %u", req_size);
      free(dns_req);
      remove_client(client);
      return;
    }

    d->cb(d, 1, d->cb_data, (struct sockaddr*)&client->raddr, dns_req, req_size);
    request_received = 1;
  }

  if (request_received) {
    ev_timer_again(d->loop, &client->timer_watcher);
  }
}

static void timer_cb(struct ev_loop __attribute__((unused)) *loop,
                     ev_timer *w, int __attribute__((unused)) revents) {
  struct tcp_client_s *client = (struct tcp_client_s *)w->data;
  DLOG_CLIENT("TCP client timeouted");
  remove_client(client);
}

static void accept_cb(struct ev_loop __attribute__((unused)) *loop,
                      ev_io *w, int __attribute__((unused)) revents) {
  dns_server_tcp_t *d = (dns_server_tcp_t *)w->data;

  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  int client_sock = accept4(w->fd, (struct sockaddr *)&client_addr,
                            &client_addr_len, SOCK_NONBLOCK);
  if (client_sock == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
    ELOG("Failed to accept TCP client: %s", strerror(errno));
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

  ev_init(&client->timer_watcher, timer_cb);
  client->timer_watcher.repeat = IDLE_TIMEOUT_S;
  client->timer_watcher.data = client;
  ev_timer_again(d->loop, &client->timer_watcher);

  DLOG_CLIENT("Accepted client %u of %u, socket %d", d->client_count, d->client_limit, client->sock);
}

// Creates and bind a listening non-blocking TCP socket for incoming requests.
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

dns_server_tcp_t * dns_server_tcp_create(
    struct ev_loop *loop, struct addrinfo *listen_addrinfo,
    dns_req_received_cb cb, void *data, uint16_t tcp_client_limit) {
  dns_server_tcp_t * d = (dns_server_tcp_t *) malloc(sizeof(dns_server_tcp_t));
  if (d == NULL) {
    FLOG("Out of mem");
  }
  d->loop = loop;
  d->cb = cb;
  d->cb_data = data;
  d->sock = get_tcp_listen_sock(listen_addrinfo);
  d->addrlen = listen_addrinfo->ai_addrlen;
  d->client_id = 0;
  d->client_count = 0;
  d->client_limit = tcp_client_limit;
  d->clients = NULL;

  ev_io_init(&d->accept_watcher, accept_cb, d->sock, EV_READ);
  d->accept_watcher.data = d;
  ev_io_start(d->loop, &d->accept_watcher);

  return d;
}

void dns_server_tcp_respond(dns_server_tcp_t *d,
    struct sockaddr *raddr, char *resp, size_t resp_len)
{
  // Limit response size to prevent overflow when accounting for the 2-byte
  // length prefix. The total on-wire size would be resp_len + sizeof(uint16_t).
  if (resp_len < DNS_HEADER_LENGTH || resp_len > TCP_DNS_MAX_PAYLOAD) {
    WLOG("Malformed response received, invalid length: %u", resp_len);
    return;
  }

  // find client data
  struct tcp_client_s *client = NULL;
  for (struct tcp_client_s * cur = d->clients; cur != NULL; cur = cur->next) {
    if (memcmp(raddr, &(cur->raddr), cur->addr_len) == 0) {
      client = cur;
      break;
    }
  }
  if (client == NULL) {
    uint16_t response_id = ntohs(*((uint16_t*)resp));
    WLOG("Could not find client, can not send DNS response: %04hX", response_id);
    return;
  }

  // NOTE: Single-threaded libev event loop ensures no TOCTOU race here.
  // No other callbacks can execute while this function runs, and usleep()
  // below is a blocking syscall (not an event loop yield). If remove_client()
  // is called due to send errors, the function returns immediately.

  DLOG_CLIENT("Sending %u bytes", resp_len);

  // send length of response
  uint16_t resp_size = htons((uint16_t)resp_len);
  ssize_t len = send(client->sock, &resp_size, sizeof(uint16_t), MSG_MORE | MSG_NOSIGNAL);
  if (len != sizeof(uint16_t)) {
    WLOG_CLIENT("Send error: %s, len: %d", strerror(errno), len);
    remove_client(client);
    return;
  }

  // send the response
  ssize_t sent = 0;
  int attempts = 0;
  for (; attempts < 50; ++attempts)  // 25ms max wait
  {
    len = send(client->sock, resp + sent, resp_len - (size_t)sent, MSG_NOSIGNAL);
    if (len < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        WLOG_CLIENT("Send error: %s", strerror(errno));
        remove_client(client);
        return;
      }
      // EAGAIN/EWOULDBLOCK - socket buffer full, retry after delay
      continue;
    }
    sent += len;
    if (sent == (ssize_t)resp_len) {
      break;
    }
    usleep(RESEND_DELAY_US);
  }
  if (sent != (ssize_t)resp_len) {
    WLOG_CLIENT("Send timeout after %d attempts, sent %zd/%zu bytes", attempts, sent, resp_len);
    remove_client(client);
    return;
  }

  ev_timer_again(d->loop, &client->timer_watcher);
}

void dns_server_tcp_stop(dns_server_tcp_t *d) {
  while (d->clients) {
    remove_client(d->clients);  //NOLINT(clang-analyzer-unix.Malloc) false use after free detection
  }
  ev_io_stop(d->loop, &d->accept_watcher);
}

void dns_server_tcp_cleanup(dns_server_tcp_t *d) {
  close(d->sock);
}
