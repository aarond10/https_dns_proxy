#include <stdarg.h>
#include <stdio.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/time.h>      // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "logging.h"

/* logs of this severity or higher are flushed immediately after write */
#define LOG_FLUSH_LEVEL LOG_WARNING

static FILE *logf = NULL;        // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int loglevel = LOG_ERROR; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static ev_timer logging_timer;   // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static const char *SeverityStr[] = {
  "[D]",
  "[I]",
  "[W]",
  "[E]",
  "[F]"
};

static void logging_timer_cb(struct ev_loop __attribute__((unused)) *loop,
                             ev_timer __attribute__((unused)) *w,
                             int __attribute__((unused)) revents) {
  if (logf) {
    fflush(logf);
  }
}

void logging_flush_init(struct ev_loop *loop) {
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  ev_timer_init(&logging_timer, logging_timer_cb, 0, 10);
  /* don't start timer if we will never write messages that are not flushed */
  if (loglevel >= LOG_FLUSH_LEVEL) {
    return;
  }
  DLOG("starting periodic log flush timer");
  ev_timer_start(loop, &logging_timer);
}

void logging_flush_cleanup(struct ev_loop *loop) {
  ev_timer_stop(loop, &logging_timer);
}

void logging_init(int fd, int level) {
  if (logf) {
    fclose(logf);
  }
  logf = fdopen(fd, "a");
  loglevel = level;
}

void logging_cleanup() {
  if (logf) {
    fclose(logf);
  }
  logf = NULL;
}

int logging_debug_enabled() {
  return loglevel <= LOG_DEBUG;
}

void _log(const char *file, int line, int severity, const char *fmt, ...) {
  if (severity < loglevel) {
    return;
  }
  if (severity < 0 || severity >= LOG_MAX) {
    FLOG("Unknown log severity: %d\n", severity);
  }
  if (!logf) {
    logf = fdopen(STDOUT_FILENO, "w");
  }

  struct timeval tv;
  gettimeofday(&tv, NULL);
  fprintf(logf, "%s %8ld.%06ld %s:%d ", SeverityStr[severity], tv.tv_sec,
          tv.tv_usec, file, line);

  va_list args;
  va_start(args, fmt);
  vfprintf(logf, fmt, args);
  va_end(args);
  fprintf(logf, "\n");

  if (severity >= LOG_FLUSH_LEVEL) {
    fflush(logf);
  }
  if (severity == LOG_FATAL) {
#ifdef DEBUG
    abort();
#else
    exit(1);
#endif
  }
}
