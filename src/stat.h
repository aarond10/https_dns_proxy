// Statistics tracking
//
// Connection, request and latency statistics are accumulated in a struct
// and output periodically via a libev timer callback.
//
// stat_init() initializes this struct and starts the timer if required.
// stat_stop() stops the timer for shutdown.
// stat_cleanup() prints the final measurement.
// stat_request_(begin|end) and
// stat_connection_(open|closed|reused) update the tallies.
//

#ifndef _STAT_H_
#define _STAT_H_

#include <stdint.h>
#include <ev.h>

typedef struct {
  struct ev_loop *loop;
  int stats_interval;
  size_t requests_size;
  size_t responses_size;
  uint64_t requests;
  uint64_t responses;
  uint64_t query_times_sum;
  uint64_t connections_opened;
  uint64_t connections_closed;
  uint64_t connections_reused;
  ev_timer stats_timer;
} stat_t;

void stat_init(stat_t *s, struct ev_loop *loop, int stats_interval);

void stat_request_begin(stat_t *s, size_t req_len);

void stat_request_end(stat_t *s, size_t resp_len, ev_tstamp latency);

void stat_connection_opened(stat_t *s);

void stat_connection_closed(stat_t *s);

void stat_connection_reused(stat_t *s);

void stat_stop(stat_t *s);

void stat_cleanup(stat_t *s);

#endif // _STAT_H_
