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

// Logging context - encapsulates all logging state
typedef struct logging_context {
  FILE *logfile;
  int loglevel;
  struct ring_buffer *flight_recorder;
  struct ev_loop *loop;
  ev_timer logging_timer;
  ev_signal sigusr2;
} logging_context_t;

enum LogSeverity {
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARNING,
  LOG_ERROR,
  LOG_STATS,
  LOG_FATAL,
  LOG_MAX
};

// Core logging function - logs to specified context
void logging_context_log(logging_context_t *ctx, const char *file, int line,
                         int severity, const char *fmt, ...);

// Context lifecycle management
void logging_context_init(logging_context_t *ctx, int fd, int level,
                          unsigned flight_recorder_size);
void logging_context_events_init(logging_context_t *ctx, struct ev_loop *loop);
void logging_context_events_cleanup(logging_context_t *ctx);
void logging_context_cleanup(logging_context_t *ctx);

// Context query functions
int logging_context_debug_enabled(logging_context_t *ctx);
void logging_context_flight_recorder_dump(logging_context_t *ctx);

// Default global context accessors
logging_context_t* logging_get_default_context(void);

// Convenience wrappers for default context
void logging_init(int fd, int level, unsigned flight_recorder_size);
void logging_events_init(struct ev_loop *loop);
void logging_events_cleanup(struct ev_loop *loop);
void logging_cleanup(void);
int logging_debug_enabled(void);
void logging_flight_recorder_dump(void);

#ifdef __cplusplus
}
#endif

// Logging macros - all use the default global context
#define LOG(level, ...) \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, level, __VA_ARGS__)
#define DLOG(...) \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, LOG_DEBUG, __VA_ARGS__)
#define ILOG(...) \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, LOG_INFO, __VA_ARGS__)
#define WLOG(...) \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, LOG_WARNING, __VA_ARGS__)
#define ELOG(...) \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, LOG_ERROR, __VA_ARGS__)
#define SLOG(...) \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, LOG_STATS, __VA_ARGS__)
#define FLOG(...) do { \
  logging_context_log(logging_get_default_context(), __FILENAME__, __LINE__, LOG_FATAL, __VA_ARGS__); \
  exit(1); \
} while(0)

#endif // _LOGGING_H_
