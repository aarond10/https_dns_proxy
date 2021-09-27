#include "stat.h"
#include "logging.h"

static void reset_counters(stat_t *s) {
  s->requests_size = 0;
  s->responses_size = 0;
  s->requests = 0;
  s->responses = 0;
  s->query_times_sum = 0;
  s->connections_opened = 0;
  s->connections_closed = 0;
  s->connections_reused = 0;
}

static void stat_print(stat_t *s) {
  SLOG("%llu %llu %llu %zu %zu %llu %llu %llu",
       s->requests, s->responses, s->query_times_sum,
       s->requests_size, s->responses_size,
       s->connections_opened, s->connections_closed,
       s->connections_reused);
  reset_counters(s);
}

static void stat_timer_cb(struct ev_loop __attribute__((unused)) *loop,
                           ev_timer *w, int __attribute__((unused)) revents) {
  stat_t *s = (stat_t *)w->data;
  stat_print(s);
}

void stat_init(stat_t *s, struct ev_loop *loop, int stats_interval) {
  s->loop = loop;
  s->stats_interval = stats_interval;
  reset_counters(s);

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_timer_init(&s->stats_timer, stat_timer_cb,
                s->stats_interval, s->stats_interval);
  s->stats_timer.data = s;
  if (s->stats_interval > 0) {
    ev_timer_start(loop, &s->stats_timer);
    SLOG("RequestsCount ResponsesCount LatencyMilisecondsSummary "
         "RequestsSize ResponsesSize ConnectionsOpened ConnectionsClosed "
         "ConnectionsReused");
  }
}

void stat_request_begin(stat_t *s, size_t req_len)
{
    s->requests_size += req_len;
    s->requests++;
}

void stat_request_end(stat_t *s, size_t resp_len, ev_tstamp latency)
{
  if (resp_len) {
    s->responses_size += resp_len;
    s->responses++;
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    s->query_times_sum += (latency * 1000);
  }
}

void stat_connection_opened(stat_t *s)
{
  s->connections_opened++;
}

void stat_connection_closed(stat_t *s)
{
  s->connections_closed++;
}

void stat_connection_reused(stat_t *s)
{
  s->connections_reused++;
}

void stat_stop(stat_t *s) {
  ev_timer_stop(s->loop, &s->stats_timer);
}

void stat_cleanup(stat_t *s) {
  if (s->stats_interval > 0) {
    stat_print(s); // final one
  }
}
