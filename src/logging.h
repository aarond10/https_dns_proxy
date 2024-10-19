#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdio.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <stdlib.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <ev.h>            // NOLINT(llvmlibc-restrict-system-libc-headers)

#ifdef __cplusplus
extern "C" {
#endif

// Initializes logging.
// Writes logs to descriptor 'fd' for log levels above or equal to 'level'.
void logging_init(int fd, int level);

// Initialize periodic timer to flush logs.
void logging_flush_init(struct ev_loop *loop);
void logging_flush_cleanup(struct ev_loop *loop);

// Cleans up and flushes open logs.
void logging_cleanup(void);

// Returns 1 if debug logging is enabled.
int logging_debug_enabled(void);

// Internal. Don't use.
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

#endif // _LOGGING_H_
