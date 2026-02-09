#!/usr/bin/env bash
set -euo pipefail

# Docker-based test runner for https_dns_proxy
#
# When to use:
# - Full regression testing before commits/PRs
# - CI/CD pipelines
# - Developing on macOS (proxy uses Linux-specific syscalls like accept4, MSG_MORE)
#
# Runtime: ~2-3 minutes

docker_bin="${DOCKER_BIN:-docker}"
if ! command -v "$docker_bin" >/dev/null 2>&1; then
  echo "docker not found; set DOCKER_BIN or install Docker." >&2
  exit 1
fi

image="https_dns_proxy_test:latest"

echo "==> Building Docker test image..."
"$docker_bin" build -t "$image" -f tests/docker/Dockerfile . -q

echo "==> Running tests..."
"$docker_bin" run --rm \
  --dns 1.1.1.1 --dns 8.8.8.8 \
  -v "$PWD":/src "$image"
