#include <sys/time.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "logging.h"

static FILE *logf = NULL;
static int loglevel = LOG_ERROR;

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
    exit(EXIT_FAILURE);
  }
}

void logging_init(int fd, int level) {
  if (logf) fclose(logf);
  logf = fdopen(fd, "a");
  loglevel = level;
}

void logging_cleanup() {
  if (logf) fclose(logf);
  logf = NULL;
}

void _log(const char *file, int line, int severity, const char *fmt, ...) {
  if (severity < loglevel) return;

  if (!logf) logf = fdopen(STDOUT_FILENO, "w");

  // We just want to log the filename, not the path.
  const char *filename = file + strlen(file);
  while (filename > file && *filename != '/') {
    filename--;
  }
  if (*filename == '/') filename++;

  struct timeval tv;
  gettimeofday(&tv, NULL);
  fprintf(logf, "%s %8d.%06d %s:%d ",
      SeverityStr(severity), tv.tv_sec, tv.tv_usec, filename, line);

  va_list args;
  va_start(args, fmt);
  vfprintf(logf, fmt, args);
  va_end(args);
  fprintf(logf, "\n");

  if (severity >= LOG_WARNING) fflush(logf);
  if (severity == LOG_FATAL) exit(1);
}
