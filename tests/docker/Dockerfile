FROM ubuntu:24.04

# Install all build and test dependencies in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iproute2 \
    cmake \
    build-essential \
    libcurl4-openssl-dev \
    libc-ares-dev \
    libev-dev \
    libsystemd-dev \
    python3 \
    python3-pip \
    python3-venv \
    dnsutils \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# Install Robot Framework
RUN pip3 install --break-system-packages robotframework

WORKDIR /src

# Default command: build and run tests
# Symlink needed because Robot test expects binary at project root
CMD ["bash", "-c", "cmake -S . -B build && cmake --build build && ln -sf build/https_dns_proxy https_dns_proxy && ctest --test-dir build --output-on-failure"]
