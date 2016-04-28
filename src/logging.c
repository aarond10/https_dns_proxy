#include <sys/time.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "logging.h"

static FILE *logf = NULL;

// Renders a severity as a short string.
static const char *SeverityStr(int severity) {
  switch(severity) {
   case LOG_DEBUG: return "[D]";
   case LOG_INFO: return "[I]";
   case LOG_WARNING: return "[W]";
   case LOG_ERROR: return "[E]";
   case LOG_FATAL: return "[F]";
   default:
    fprintf(logf, "Unknown log severity: %d\n", severity);
    exit(1);
  }
}

void log_init(int fd) {
  if (logf) fclose(logf);
  logf = fdopen(fd, "a");
  printf("logf now %p (fd %d)\n", logf, fd);
}

void log_destroy() {
  if (logf) fclose(logf);
  logf = NULL;
}

void _log(const char *file, int line, int severity, const char *fmt, ...) {
  if (!logf) logf = fdopen(STDOUT_FILENO, "w");

  struct timeval tv;
  gettimeofday(&tv, NULL);
  fprintf(logf, "%s %8d.%06d %s:%d ",
      SeverityStr(severity), tv.tv_sec, tv.tv_usec, file, line);

  va_list args;
    va_start(args, fmt);
  vfprintf(logf, fmt, args);
  va_end(args);
  fprintf(logf, "\n");

  if (severity >= LOG_WARNING) fflush(logf);
  if (severity == LOG_FATAL) exit(1);
}
