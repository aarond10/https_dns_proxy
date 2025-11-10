# Logging API Documentation

## Overview

The https_dns_proxy logging system supports both legacy global logging (for backwards compatibility) and new context-aware logging (for testability and future multi-instance support).

## Basic Usage (Legacy API)

The legacy API uses a global logging context and is compatible with all existing code:

```c
#include "logging.h"

// Initialize logging (usually in main)
logging_init(STDERR_FILENO, LOG_INFO, 0);

// Use logging macros anywhere
DLOG("Debug message: %d", value);    // Debug level
ILOG("Info message");                 // Info level
WLOG("Warning: %s", message);         // Warning level
ELOG("Error occurred");               // Error level
SLOG("Statistics: %llu", count);      // Stats level
FLOG("Fatal error");                  // Fatal (exits program)
```

## Context-Aware API (New)

The context-aware API allows multiple independent logging contexts, useful for testing and future enhancements:

### Creating a Context

```c
#include "logging.h"

// Create and initialize a logging context
logging_context_t my_context;
memset(&my_context, 0, sizeof(my_context));

int logfd = open("mylog.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
logging_context_init(&my_context, logfd, LOG_DEBUG, 100);
```

### Using Context-Aware Macros

```c
// Log to specific context
DLOG_CTX(&my_context, "Debug message: %d", value);
ILOG_CTX(&my_context, "Info message");
WLOG_CTX(&my_context, "Warning: %s", message);
ELOG_CTX(&my_context, "Error occurred");
SLOG_CTX(&my_context, "Statistics: %llu", count);
FLOG_CTX(&my_context, "Fatal error");  // Exits program
```

### Event Loop Integration

If using libev for timers and signals:

```c
struct ev_loop *loop = EV_DEFAULT;

// Set up periodic flush and signal handlers
logging_context_events_init(&my_context, loop);

// ... run event loop ...

// Clean up before stopping
logging_context_events_cleanup(&my_context);
```

### Cleanup

```c
// Always cleanup when done
logging_context_cleanup(&my_context);
```

## Flight Recorder

The flight recorder feature stores recent log messages in memory and dumps them on fatal errors or SIGUSR2:

```c
// Initialize with flight recorder (store last 1000 messages)
logging_context_init(&ctx, logfd, LOG_ERROR, 1000);

// Even debug messages are recorded (though not written unless debug enabled)
DLOG_CTX(&ctx, "This is stored in memory");

// Manually dump flight recorder
logging_context_flight_recorder_dump(&ctx);
```

## Log Levels

From most verbose to least verbose:

1. `LOG_DEBUG` - Detailed debugging information
2. `LOG_INFO` - Informational messages
3. `LOG_WARNING` - Warning conditions
4. `LOG_ERROR` - Error conditions
5. `LOG_STATS` - Statistics output
6. `LOG_FATAL` - Fatal errors (program exits)

Messages at or above the configured level are written to the log file.

## API Reference

### Context Management

#### `void logging_context_init(logging_context_t *ctx, int fd, int level, unsigned flight_recorder_size)`

Initialize a logging context.

- `ctx`: Pointer to context structure (must be zeroed first)
- `fd`: File descriptor to write logs to (takes ownership)
- `level`: Minimum log level to write (LOG_DEBUG, LOG_INFO, etc.)
- `flight_recorder_size`: Number of messages to keep in memory (0 to disable)

#### `void logging_context_cleanup(logging_context_t *ctx)`

Clean up a logging context and free resources.

#### `void logging_context_events_init(logging_context_t *ctx, struct ev_loop *loop)`

Set up periodic flush timer and SIGUSR2 handler for flight recorder dumps.

#### `void logging_context_events_cleanup(logging_context_t *ctx)`

Stop timers and signal handlers.

### Utility Functions

#### `int logging_context_debug_enabled(logging_context_t *ctx)`

Returns 1 if debug logging is enabled for this context.

#### `void logging_context_flight_recorder_dump(logging_context_t *ctx)`

Manually dump the flight recorder contents to the log file.

#### `void logging_context_log(logging_context_t *ctx, const char *file, int line, int severity, const char *fmt, ...)`

Low-level logging function (use macros instead).

### Legacy API

#### `logging_context_t* logging_get_default_context(void)`

Get the default global logging context.

#### `void logging_init(int fd, int level, unsigned flight_recorder_size)`

Initialize the default global context (legacy API).

#### `void logging_cleanup(void)`

Clean up the default global context.

#### `int logging_debug_enabled(void)`

Check if debug is enabled on default context.

## Testing Example

The context-aware API makes testing easy:

```c
void test_my_function(void) {
    // Create isolated logging context for this test
    logging_context_t test_ctx;
    memset(&test_ctx, 0, sizeof(test_ctx));

    char tempfile[] = "/tmp/test_log_XXXXXX";
    int fd = mkstemp(tempfile);

    logging_context_init(&test_ctx, fd, LOG_DEBUG, 0);

    // Pass context to code under test
    my_function_with_logging(&test_ctx);

    // Verify log output
    logging_context_cleanup(&test_ctx);

    // Read and check tempfile contents
    // ...

    close(fd);
    unlink(tempfile);
}
```

## Migration Guide

### Existing Code

No changes needed! All existing code using DLOG(), ILOG(), etc. continues to work.

### New Code

For new code or when refactoring, consider using context-aware logging:

1. Add `logging_context_t *log_ctx` parameter to component structures
2. Use `*_CTX()` macros instead of legacy macros
3. Initialize context in component init functions
4. Clean up in component cleanup functions

This provides better testability and flexibility.

## Binary Size Impact

- Context struct: ~80 bytes per context
- New functions: ~600 bytes total
- Production build: **~600 bytes increase**
- Test builds: Additional test code (not in production binary)

## Performance

- Zero overhead for disabled log levels (early return)
- Flight recorder has minimal overhead (memory allocation only)
- Periodic flush reduces syscall frequency
- Context-aware macros have same performance as legacy macros
