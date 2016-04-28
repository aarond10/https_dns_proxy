#ifndef _LOGGING_H_
#define _LOGGING_H_

#ifdef __cplusplus
extern "C" {
#endif 
void log_init(int fd);
void _log(const char *filename, int line, int fd, const char *fmt, ...);
void log_destroy();
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
#define DLOG(...) _log(__FILENAME__, __LINE__, LOG_DEBUG, __VA_ARGS__)
#define ILOG(...) _log(__FILENAME__, __LINE__, LOG_INFO, __VA_ARGS__)
#define WLOG(...) _log(__FILENAME__, __LINE__, LOG_WARNING, __VA_ARGS__)
#define ELOG(...) _log(__FILENAME__, __LINE__, LOG_ERROR, __VA_ARGS__)
#define FLOG(...) _log(__FILENAME__, __LINE__, LOG_FATAL, __VA_ARGS__)

#ifdef NDEBUG
#undef DLOG
#undef ILOG
#define DLOG(...) do { } while(0);
#define ILOG(...) do { } while(0);
#endif

#endif  // _LOGGING_H_
