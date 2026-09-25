#include <sys/socket.h>
#include <unistd.h>

#include "test_harness.h"
#include "../../src/dns_poller.c"

enum {
  TEST_SOCKET_COUNT = 40,
  TEST_FD_CAPACITY = 48
};

static dns_poller_t poller;
static struct ev_loop *loop;
static int poller_initialized;
static int tracked_fds[TEST_FD_CAPACITY];
static unsigned tracked_fd_count;

static void setUp(void) {
  poller_initialized = 0;
  tracked_fd_count = 0;
  loop = NULL;
  memset(&poller, 0, sizeof(poller));
  loop = ev_loop_new(0);
  if (!loop) {
    test_fail(__FILE__, __LINE__, "ev_loop_new(0)");
    return;
  }
  dns_poller_init(&poller, loop, "127.0.0.1,127.0.0.2", 60, NULL,
                  "example.com", AF_INET, NULL, NULL);
  poller_initialized = 1;
  ev_timer_stop(loop, &poller.timer);
}

static void tearDown(void) {
  if (poller_initialized) {
    dns_poller_cleanup(&poller);
    poller_initialized = 0;
  }
  for (unsigned i = 0; i < tracked_fd_count; i++) {
    close(tracked_fds[i]);
  }
  if (loop) {
    ev_loop_destroy(loop);
    loop = NULL;
  }
}

static int open_test_socket(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return fd;
  }
  if (tracked_fd_count >= TEST_FD_CAPACITY) {
    close(fd);
    return -1;
  }
  tracked_fds[tracked_fd_count++] = fd;
  return fd;
}

static int watcher_matches(ev_io *watcher, int fd, int events) {
  return watcher && ev_is_active(watcher) && !ev_is_pending(watcher) &&
         watcher->fd == fd && watcher->events == events &&
         watcher->data == &poller;
}

static void test_allocates_watchers_beyond_nameserver_count(void) {
  ev_io *first = NULL;
  int first_fd = ARES_SOCKET_BAD;

  for (int i = 0; i < TEST_SOCKET_COUNT; i++) {
    int fd = open_test_socket();
    TEST_ASSERT(fd >= 0);
    sock_state_cb(&poller, fd, 1, 0);
    TEST_ASSERT(watcher_matches(get_io_event(&poller, fd), fd, EV_READ));
    if (i == 0) {
      first = get_io_event(&poller, fd);
      first_fd = fd;
    }
    TEST_ASSERT_EQUAL_PTR(first, get_io_event(&poller, first_fd));
  }
}

static void test_reuses_released_watcher(void) {
  int fd = open_test_socket();
  TEST_ASSERT(fd >= 0);
  sock_state_cb(&poller, fd, 1, 0);
  ev_io *watcher = get_io_event(&poller, fd);
  TEST_ASSERT(watcher_matches(watcher, fd, EV_READ));

  sock_state_cb(&poller, fd, 0, 0);
  TEST_ASSERT(!get_io_event(&poller, fd));
  TEST_ASSERT(!ev_is_active(watcher));
  TEST_ASSERT(!ev_is_pending(watcher));
  TEST_ASSERT(watcher->fd == ARES_SOCKET_BAD);
  sock_state_cb(&poller, fd, 1, 1);
  TEST_ASSERT_EQUAL_PTR(watcher, get_io_event(&poller, fd));
  TEST_ASSERT(watcher_matches(watcher, fd, EV_READ | EV_WRITE));
}

static void test_fd_zero_does_not_alias_free_watcher(void) {
  sock_state_cb(&poller, 0, 1, 0);
  ev_io *fd_zero_watcher = get_io_event(&poller, 0);
  TEST_ASSERT(watcher_matches(fd_zero_watcher, 0, EV_READ));

  int fd = open_test_socket();
  TEST_ASSERT(fd > 0);
  sock_state_cb(&poller, fd, 1, 0);
  TEST_ASSERT(watcher_matches(get_io_event(&poller, fd), fd, EV_READ));
  TEST_ASSERT_EQUAL_PTR(fd_zero_watcher, get_io_event(&poller, 0));
  TEST_ASSERT(get_io_event(&poller, fd) != fd_zero_watcher);
}

static void test_cleanup_stops_active_watchers(void) {
  int fd = open_test_socket();
  TEST_ASSERT(fd >= 0);
  sock_state_cb(&poller, fd, 1, 0);
  ev_io *watcher = get_io_event(&poller, fd);
  TEST_ASSERT(watcher_matches(watcher, fd, EV_READ));
  ev_feed_event(loop, watcher, EV_READ);
  TEST_ASSERT(ev_is_pending(watcher));

  dns_poller_cleanup(&poller);
  poller_initialized = 0;
  TEST_ASSERT(!poller.io_events);
  TEST_ASSERT(ev_run(loop, EVRUN_NOWAIT) == 0);
}

int main(void) {
  TEST_RUN(test_allocates_watchers_beyond_nameserver_count);
  TEST_RUN(test_reuses_released_watcher);
  TEST_RUN(test_fd_zero_does_not_alias_free_watcher);
  TEST_RUN(test_cleanup_stops_active_watchers);
  return test_summary();
}
