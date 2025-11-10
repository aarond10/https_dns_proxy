#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdio.h>
#include <stdlib.h>
#include <ev.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct ring_buffer;

// Logging context - allows multiple independent logging contexts
// Useful for testing and future multi-instance support
typedef struct logging_context {
  FILE *logfile;
  int loglevel;
  struct ring_buffer *flight_recorder;
  struct ev_loop *loop;
  ev_timer logging_timer;
  ev_signal sigusr2;
} logging_context_t;

// === Context-aware API (new) ===

// Initialize a logging context with specified parameters
void logging_context_init(logging_context_t *ctx, int fd, int level,
                          unsigned flight_recorder_size);

// Initialize periodic timer and signal handlers for a context
void logging_context_events_init(logging_context_t *ctx, struct ev_loop *loop);

// Cleanup events for a context
void logging_context_events_cleanup(logging_context_t *ctx);

// Cleanup a logging context
void logging_context_cleanup(logging_context_t *ctx);

// Check if debug logging is enabled for a context
int logging_context_debug_enabled(logging_context_t *ctx);

// Dump flight recorder for a context
void logging_context_flight_recorder_dump(logging_context_t *ctx);

// Log with explicit context
void logging_context_log(logging_context_t *ctx, const char *file, int line,
                         int severity, const char *fmt, ...);

// === Legacy API (backwards compatible) ===

// Get the default global logging context
logging_context_t* logging_get_default_context(void);

// Initializes default global logging context
// Writes logs to descriptor 'fd' for log levels above or equal to 'level'.
void logging_init(int fd, int level, unsigned flight_recorder_size);

// Initialize periodic timer to flush logs (uses default context)
void logging_events_init(struct ev_loop *loop);
void logging_events_cleanup(struct ev_loop *loop);

// Cleans up and flushes open logs (uses default context)
void logging_cleanup(void);

// Returns 1 if debug logging is enabled (uses default context)
int logging_debug_enabled(void);

// Dump flight recorder (uses default context)
void logging_flight_recorder_dump(void);

// Internal. Don't use directly - use macros below
void _log(const char *file, int line, int severity, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

enum LogSeverity {
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARNING,
  LOG_ERROR,
  LOG_STATS,
  LOG_FATAL,
  LOG_MAX
};

// === Legacy macros (use default global context) ===

#define LOG(level, ...) _log(__FILENAME__, __LINE__, level, __VA_ARGS__)
#define DLOG(...) _log(__FILENAME__, __LINE__, LOG_DEBUG, __VA_ARGS__)
#define ILOG(...) _log(__FILENAME__, __LINE__, LOG_INFO, __VA_ARGS__)
#define WLOG(...) _log(__FILENAME__, __LINE__, LOG_WARNING, __VA_ARGS__)
#define ELOG(...) _log(__FILENAME__, __LINE__, LOG_ERROR, __VA_ARGS__)
#define SLOG(...) _log(__FILENAME__, __LINE__, LOG_STATS, __VA_ARGS__)
#define FLOG(...) do { \
  _log(__FILENAME__, __LINE__, LOG_FATAL, __VA_ARGS__); \
  exit(1); /* for clang-tidy! */ \
} while(0)

// === Context-aware macros (new, opt-in) ===

#define LOG_CTX(ctx, level, ...) \
  logging_context_log(ctx, __FILENAME__, __LINE__, level, __VA_ARGS__)
#define DLOG_CTX(ctx, ...) \
  logging_context_log(ctx, __FILENAME__, __LINE__, LOG_DEBUG, __VA_ARGS__)
#define ILOG_CTX(ctx, ...) \
  logging_context_log(ctx, __FILENAME__, __LINE__, LOG_INFO, __VA_ARGS__)
#define WLOG_CTX(ctx, ...) \
  logging_context_log(ctx, __FILENAME__, __LINE__, LOG_WARNING, __VA_ARGS__)
#define ELOG_CTX(ctx, ...) \
  logging_context_log(ctx, __FILENAME__, __LINE__, LOG_ERROR, __VA_ARGS__)
#define SLOG_CTX(ctx, ...) \
  logging_context_log(ctx, __FILENAME__, __LINE__, LOG_STATS, __VA_ARGS__)
#define FLOG_CTX(ctx, ...) do { \
  logging_context_log(ctx, __FILENAME__, __LINE__, LOG_FATAL, __VA_ARGS__); \
  exit(1); /* for clang-tidy! */ \
} while(0)

#endif // _LOGGING_H_
