#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <ev.h>

#ifdef __cplusplus
extern "C" {
#endif
// Initializes logging.
// Writes logs to descriptor 'fd' for log levels above or equal to 'level'.
void logging_init(int fd, int level);

// Initialize periodic timer to flush logs.
void logging_flush_init(struct ev_loop *loop);

// Cleans up and flushes open logs.
void logging_cleanup();

// Internal. Don't use.
void _log(const char *file, int line, int severity, const char *fmt, ...);
#ifdef __cplusplus
}
#endif

enum _LogSeverity {
  LOG_DEBUG = 0,
  LOG_INFO = 1,
  LOG_WARNING = 2,
  LOG_ERROR = 3,
  LOG_FATAL = 4,
};

// Debug, Info, Warning, Error logging.
#define DLOG(...) _log(__FILE__, __LINE__, LOG_DEBUG, __VA_ARGS__)
#define ILOG(...) _log(__FILE__, __LINE__, LOG_INFO, __VA_ARGS__)
#define WLOG(...) _log(__FILE__, __LINE__, LOG_WARNING, __VA_ARGS__)
#define ELOG(...) _log(__FILE__, __LINE__, LOG_ERROR, __VA_ARGS__)
#define FLOG(...) do { \
  _log(__FILE__, __LINE__, LOG_FATAL, __VA_ARGS__); \
  exit(1); \
} while(0);

#endif // _LOGGING_H_
