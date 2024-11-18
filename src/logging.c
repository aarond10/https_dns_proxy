#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>         // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <sys/time.h>      // NOLINT(llvmlibc-restrict-system-libc-headers)
#include <unistd.h>        // NOLINT(llvmlibc-restrict-system-libc-headers)

#include "logging.h"

/* logs of this severity or higher are flushed immediately after write */
#define LOG_FLUSH_LEVEL LOG_WARNING

static FILE *logfile = NULL;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static int loglevel = LOG_ERROR; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static ev_timer logging_timer;   // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

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
  if (logfile) {
    (void)fclose(logfile);
  }
  logfile = fdopen(fd, "a");
  loglevel = level;
}

void logging_cleanup(void) {
  if (logfile) {
    (void)fclose(logfile);
  }
  logfile = NULL;
}

int logging_debug_enabled(void) {
  return loglevel <= LOG_DEBUG;
}

// NOLINTNEXTLINE(misc-no-recursion) because of severity check
void _log(const char *file, int line, int severity, const char *fmt, ...) {
  if (severity < loglevel) {
    return;
  }
  if (severity < 0 || severity >= LOG_MAX) {
    FLOG("Unknown log severity: %d\n", severity);
  }
  if (!logfile) {
    logfile = fdopen(STDOUT_FILENO, "w");
  }

  struct timeval tv;
  gettimeofday(&tv, NULL);

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  (void)fprintf(logfile, "%s %8"PRIu64".%06"PRIu64" %s:%d ", SeverityStr[severity],
          (uint64_t)tv.tv_sec,
          (uint64_t)tv.tv_usec, file, line);

  va_list args;
  va_start(args, fmt);
  (void)vfprintf(logfile, fmt, args);
  va_end(args);

  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  (void)fprintf(logfile, "\n");

  if (severity >= LOG_FLUSH_LEVEL) {
    (void)fflush(logfile);
  }
  if (severity == LOG_FATAL) {
#ifdef DEBUG
    abort();
#else
    exit(1);
#endif
  }
}
