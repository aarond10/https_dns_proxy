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

// Default global logging context for backwards compatibility
static logging_context_t g_default_context;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int g_default_initialized = 0;       // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static const char * const SeverityStr[] = {
  "[D]",
  "[I]",
  "[W]",
  "[E]",
  "[S]",
  "[F]"
};

// === Context-aware implementations ===

static void logging_timer_cb_ctx(struct ev_loop __attribute__((unused)) *loop,
    ev_timer *w, int __attribute__((unused)) revents) {
  logging_context_t *ctx = (logging_context_t *)w->data;
  if (ctx->logfile) {
    (void)fflush(ctx->logfile);
  }
}

static void logging_flight_recorder_dump_cb_ctx(struct ev_loop __attribute__((unused)) *loop,
    ev_signal *w, int __attribute__((__unused__)) revents) {
  logging_context_t *ctx = (logging_context_t *)w->data;
  logging_context_flight_recorder_dump(ctx);
}

void logging_context_init(logging_context_t *ctx, int fd, int level,
                          unsigned flight_recorder_size) {
  if (ctx->logfile) {
    (void)fclose(ctx->logfile);
  }
  ctx->logfile = fdopen(fd, "a");
  ctx->loglevel = level;
  ctx->loop = NULL;

  ring_buffer_init(&ctx->flight_recorder, flight_recorder_size);
}

void logging_context_events_init(logging_context_t *ctx, struct ev_loop *loop) {
  ctx->loop = loop;

  /* don't start timer if we will never write messages that are not flushed */
  if (ctx->loglevel < LOG_FLUSH_LEVEL) {
    ev_timer_init(&ctx->logging_timer, logging_timer_cb_ctx, 0, 10);
    ctx->logging_timer.data = ctx;
    ev_timer_start(loop, &ctx->logging_timer);
  }

  ev_signal_init(&ctx->sigusr2, logging_flight_recorder_dump_cb_ctx, SIGUSR2);
  ctx->sigusr2.data = ctx;
  ev_signal_start(loop, &ctx->sigusr2);
}

void logging_context_events_cleanup(logging_context_t *ctx) {
  if (ctx->loop) {
    ev_timer_stop(ctx->loop, &ctx->logging_timer);
    ev_signal_stop(ctx->loop, &ctx->sigusr2);
  }
}

void logging_context_cleanup(logging_context_t *ctx) {
  if (ctx->flight_recorder) {
    ring_buffer_free(&ctx->flight_recorder);
    ctx->flight_recorder = NULL;
  }

  if (ctx->logfile) {
    (void)fclose(ctx->logfile);
  }
  ctx->logfile = NULL;
  ctx->loop = NULL;
}

int logging_context_debug_enabled(logging_context_t *ctx) {
  return ctx->loglevel <= LOG_DEBUG || ctx->flight_recorder;
}

void logging_context_flight_recorder_dump(logging_context_t *ctx) {
  if (ctx->flight_recorder) {
    // Log using context to avoid recursion
    if (ctx->logfile) {
      fprintf(ctx->logfile, "[I] Flight recorder dump\n");
      fflush(ctx->logfile);
    }
    ring_buffer_dump(ctx->flight_recorder, ctx->logfile);
  }
}

// NOLINTNEXTLINE(misc-no-recursion) because of severity check
void logging_context_log(logging_context_t *ctx, const char *file, int line,
                         int severity, const char *fmt, ...) {
  if (severity < ctx->loglevel && !ctx->flight_recorder) {
    return;
  }
  if (severity < 0 || severity >= LOG_MAX) {
    // Can't use FLOG here due to recursion, just log error
    fprintf(stderr, "Unknown log severity: %d\n", severity);
    return;
  }
  if (!ctx->logfile) {
    ctx->logfile = fdopen(STDOUT_FILENO, "w");
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

  if (ctx->flight_recorder) {
    ring_buffer_push_back(ctx->flight_recorder, buff, buff_pos);
  }

  if (severity < ctx->loglevel) {
    return;
  }
  (void)fprintf(ctx->logfile, "%s\n", buff);

  if (severity >= LOG_FLUSH_LEVEL) {
    (void)fflush(ctx->logfile);
  }
  if (severity == LOG_FATAL) {
    if (ctx->flight_recorder) {
      ring_buffer_dump(ctx->flight_recorder, ctx->logfile);
    }
#ifdef DEBUG
    abort();
#else
    exit(1);
#endif
  }
}

// === Legacy API (uses default global context) ===

logging_context_t* logging_get_default_context(void) {
  return &g_default_context;
}

void logging_init(int fd, int level, unsigned flight_recorder_size) {
  logging_context_init(&g_default_context, fd, level, flight_recorder_size);
  g_default_initialized = 1;
}

void logging_events_init(struct ev_loop *loop) {
  if (!g_default_initialized) {
    // Initialize with default stderr if not already initialized
    logging_init(STDERR_FILENO, LOG_ERROR, 0);
  }
  logging_context_events_init(&g_default_context, loop);
}

void logging_events_cleanup(struct ev_loop *loop) {
  (void)loop; // Unused - kept for API compatibility
  logging_context_events_cleanup(&g_default_context);
}

void logging_cleanup(void) {
  logging_context_cleanup(&g_default_context);
  g_default_initialized = 0;
}

int logging_debug_enabled(void) {
  return logging_context_debug_enabled(&g_default_context);
}

void logging_flight_recorder_dump(void) {
  logging_context_flight_recorder_dump(&g_default_context);
}

// Keep original _log for backwards compatibility with existing macros
void _log(const char *file, int line, int severity, const char *fmt, ...) {
  if (!g_default_initialized) {
    // Auto-initialize to stderr if not already initialized
    logging_init(STDERR_FILENO, LOG_ERROR, 0);
  }

  if (severity < g_default_context.loglevel && !g_default_context.flight_recorder) {
    return;
  }

  // Forward to context-aware implementation
  va_list args;
  va_start(args, fmt);

  // Manually inline the logging logic since we can't forward va_list easily
  if (severity < 0 || severity >= LOG_MAX) {
    fprintf(stderr, "Unknown log severity: %d\n", severity);
    va_end(args);
    return;
  }

  if (!g_default_context.logfile) {
    g_default_context.logfile = fdopen(STDOUT_FILENO, "w");
  }

  struct timeval tv;
  gettimeofday(&tv, NULL);

  char buff[LOG_LINE_SIZE];
  uint32_t buff_pos = 0;
  int chars = snprintf(buff, LOG_LINE_SIZE, "%s %8"PRIu64".%06"PRIu64" %s:%d ",
                       SeverityStr[severity], (uint64_t)tv.tv_sec, (uint64_t)tv.tv_usec, file, line);
  if (chars < 0 || chars >= LOG_LINE_SIZE/2) {
    abort();
  }
  buff_pos += (uint32_t)chars;

  chars = vsnprintf(buff + buff_pos, LOG_LINE_SIZE - buff_pos, fmt, args);  // NOLINT(clang-diagnostic-format-nonliteral)
  va_end(args);

  if (chars < 0) {
    abort();
  }
  buff_pos += (uint32_t)chars;
  if (buff_pos >= LOG_LINE_SIZE) {
    buff_pos = LOG_LINE_SIZE - 1;
    buff[buff_pos - 1] = '$';
  }

  if (g_default_context.flight_recorder) {
    ring_buffer_push_back(g_default_context.flight_recorder, buff, buff_pos);
  }

  if (severity < g_default_context.loglevel) {
    return;
  }
  (void)fprintf(g_default_context.logfile, "%s\n", buff);

  if (severity >= LOG_FLUSH_LEVEL) {
    (void)fflush(g_default_context.logfile);
  }
  if (severity == LOG_FATAL) {
    if (g_default_context.flight_recorder) {
      ring_buffer_dump(g_default_context.flight_recorder, g_default_context.logfile);
    }
#ifdef DEBUG
    abort();
#else
    exit(1);
#endif
  }
}
