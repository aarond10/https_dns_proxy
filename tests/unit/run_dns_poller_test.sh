#!/bin/sh
# Run from any directory; requires a C compiler and c-ares/libev development files.
set -eu
cd "$(dirname "$0")/../.."
binary=$(mktemp)
trap 'rm -f "$binary"' EXIT HUP INT TERM
"${CC:-cc}" -g -Wall -Wextra -I src -D__FILENAME__='"dns_poller_test"' \
    tests/unit/test_dns_poller.c src/logging.c src/ring_buffer.c \
    -lcares -lev -o "$binary"
"$binary"
