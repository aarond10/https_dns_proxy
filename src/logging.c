#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "logging.h"
#include "ring_buffer.h"

// logs of this severity or higher are flushed immediately after write
#define LOG_FLUSH_LEVEL LOG_WARNING
enum {
LOG_LINE_SIZE = 2048  // Log line should be at least 100
};

static FILE *logfile = NULL;                         // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int loglevel = LOG_ERROR;                     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static ev_timer logging_timer;                       // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static ev_signal sigusr2;                            // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static ev_async flight_recorder_async;               // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static struct ev_loop *logging_loop = NULL;          // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static struct ring_buffer * flight_recorder = NULL;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static const char * const SeverityStr[] = {
  "[D]",
  "[I]",
  "[W]",
  "[E]",
  "[S]",
  "[F]"
};

void logging_timer_cb(struct ev_loop __attribute__((unused)) *loop,
    ev_timer __attribute__((unused)) *w,
    int __attribute__((unused)) revents) {
  if (logfile) {
    (void)fflush(logfile);
  }
}

void logging_flight_recorder_dump(void) {
  if (flight_recorder) {
    ILOG("Flight recorder dump");  // will be also at the end of the dump :)
    ring_buffer_dump(flight_recorder, logfile);
  } else {
    ILOG("Flight recorder is disabled");
  }
}

static void logging_flight_recorder_dump_async_cb(struct ev_loop __attribute__((unused)) *loop,
    ev_async __attribute__((__unused__)) *w,
    int __attribute__((__unused__)) revents) {
  logging_flight_recorder_dump();
}

static void logging_flight_recorder_dump_cb(struct ev_loop __attribute__((unused)) *loop,
    ev_signal __attribute__((__unused__)) *w,
    int __attribute__((__unused__)) revents) {
  // Signal handler: just trigger async watcher to defer to main loop
  // This ensures fprintf() is called outside of signal context
  ev_async_send(logging_loop, &flight_recorder_async);
}

void logging_events_init(struct ev_loop *loop) {
  logging_loop = loop;

  /* don't start timer if we will never write messages that are not flushed */
  if (loglevel < LOG_FLUSH_LEVEL) {
    DLOG("starting periodic log flush timer");
    ev_timer_init(&logging_timer, logging_timer_cb, 0, 10);
    ev_timer_start(loop, &logging_timer);
  }

  DLOG("starting SIGUSR2 handler");
  ev_async_init(&flight_recorder_async, logging_flight_recorder_dump_async_cb);
  ev_async_start(loop, &flight_recorder_async);
  ev_signal_init(&sigusr2, logging_flight_recorder_dump_cb, SIGUSR2);
  ev_signal_start(loop, &sigusr2);
}

void logging_events_cleanup(struct ev_loop *loop) {
  ev_timer_stop(loop, &logging_timer);
  ev_signal_stop(loop, &sigusr2);
  ev_async_stop(loop, &flight_recorder_async);
}

void logging_init(int fd, int level, uint32_t flight_recorder_size) {
  if (logfile) {
    (void)fclose(logfile);
    logfile = NULL;
  }
  logfile = fdopen(fd, "a");
  if (logfile == NULL) {
    // fdopen failed, can't log but we can still continue
    return;
  }
  loglevel = level;

  ring_buffer_init(&flight_recorder, flight_recorder_size);
}

void logging_cleanup(void) {
  if (flight_recorder) {
    ring_buffer_free(&flight_recorder);
    flight_recorder = NULL;
  }

  if (logfile) {
    (void)fclose(logfile);
  }
  logfile = NULL;
}

int logging_debug_enabled(void) {
  return loglevel <= LOG_DEBUG || flight_recorder;
}

// NOLINTNEXTLINE(misc-no-recursion) because of severity check
void _log(const char *file, int line, int severity, const char *fmt, ...) {
  if (severity < loglevel && !flight_recorder) {
    return;
  }
  if (severity < 0 || severity >= LOG_MAX) {
    FLOG("Unknown log severity: %d", severity);
  }
  if (!logfile) {
    logfile = fdopen(STDOUT_FILENO, "w");
  }

  struct timeval tv;
  gettimeofday(&tv, NULL);

  char buff[LOG_LINE_SIZE];
  uint32_t buff_pos = 0;
  int chars = snprintf(buff, LOG_LINE_SIZE, "%s %8"PRIu64".%06"PRIu64" %s:%d ",
                       SeverityStr[severity], (uint64_t)tv.tv_sec, (uint64_t)tv.tv_usec, file, line);
  if (chars < 0 || chars >= LOG_LINE_SIZE/2) {
    abort();  // must be impossible
  }
  buff_pos += (uint32_t)chars;

  va_list args;
  va_start(args, fmt);
  chars = vsnprintf(buff + buff_pos, LOG_LINE_SIZE - buff_pos, fmt, args);  // NOLINT(clang-diagnostic-format-nonliteral)
  va_end(args);

  if (chars < 0) {
    abort();  // must be impossible
  }
  buff_pos += (uint32_t)chars;
  if (buff_pos >= LOG_LINE_SIZE) {
    buff_pos = LOG_LINE_SIZE - 1;
    buff[buff_pos - 1] = '$'; // indicate truncation
  }

  if (flight_recorder) {
    ring_buffer_push_back(flight_recorder, buff, buff_pos);
  }

  if (severity < loglevel) {
    return;
  }
  (void)fprintf(logfile, "%s\n", buff);

  if (severity >= LOG_FLUSH_LEVEL) {
    (void)fflush(logfile);
  }
  if (severity == LOG_FATAL) {
    if (flight_recorder) {
      ring_buffer_dump(flight_recorder, logfile);
    }
#ifdef DEBUG
    abort();
#else
    exit(1);
#endif
  }
}
