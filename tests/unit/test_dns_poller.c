#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../../src/dns_poller.c"
int main(void) {
  dns_poller_t d = {0};
  struct ev_loop *loop = ev_loop_new(0);
  assert(loop);
  dns_poller_init(&d, loop, "127.0.0.1,127.0.0.2", 60, NULL,
                  "example.com", AF_INET, NULL, NULL);
  ev_timer_stop(loop, &d.timer);
  int fds[40];
  ev_io *first = NULL;
  for (int i = 0; i < 40; i++) {
    fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fds[i] >= 0);
    sock_state_cb(&d, fds[i], 1, 0);
    assert(get_io_event(&d, fds[i]));
    if (!i) first = get_io_event(&d, fds[i]);
    assert(get_io_event(&d, fds[0]) == first);
  }
  ev_io *reused = get_io_event(&d, fds[10]);
  sock_state_cb(&d, fds[10], 0, 0);
  assert(!get_io_event(&d, fds[10]));
  sock_state_cb(&d, fds[10], 1, 1);
  assert(get_io_event(&d, fds[10]) == reused);
  for (int i = 0; i < 40; i++) {
    sock_state_cb(&d, fds[i], 0, 0);
    close(fds[i]);
  }
  // Also exercise cleanup with a registered watcher still active.
  int remaining = socket(AF_INET, SOCK_DGRAM, 0);
  assert(remaining >= 0);
  sock_state_cb(&d, remaining, 1, 0);
  dns_poller_cleanup(&d);
  close(remaining);
  ev_run(loop, EVRUN_NOWAIT);
  ev_loop_destroy(loop);
  puts("PASS: 40 sockets / 2 servers; stable addresses; update/reuse/cleanup");
  return 0;
}
