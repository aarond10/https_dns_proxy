#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>


#define _VARLOG(file, line, out, prefix, ...) \
{ fprintf((out), (prefix)); \
  timeval tv; \
  gettimeofday(&tv, NULL); \
  fprintf((out), "%8d.%06d ", tv.tv_sec, tv.tv_usec); \
  fprintf((out), "%s:%d ", (file), (line)); \
  fprintf((out), __VA_ARGS__); \
  fprintf((out), "\n"); }

// Debug, Info, Warning, Error logging.
#ifndef NDEBUG
#define DLOG(...) _VARLOG(__FILENAME__, __LINE__, stdout, "[D] ", __VA_ARGS__)
#define ILOG(...) _VARLOG(__FILENAME__, __LINE__, stdout, "[I] ", __VA_ARGS__)
#define WLOG(...) _VARLOG(__FILENAME__, __LINE__, stderr, "[W] ", __VA_ARGS__)
#define ELOG(...) _VARLOG(__FILENAME__, __LINE__, stderr, "[E] ", __VA_ARGS__)
#else
#define DLOG(...) do { } while(0);
#define ILOG(...) do { } while(0);
#define WLOG(...) _VARLOG(__FILENAME__, __LINE__, stderr, "[W] ", __VA_ARGS__)
#define ELOG(...) _VARLOG(__FILENAME__, __LINE__, stderr, "[E] ", __VA_ARGS__)
#endif

// Fatal logging.
#define FLOG(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0);

#endif
