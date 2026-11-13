# https-dns-proxy

`https_dns_proxy` is a light-weight DNS&lt;--&gt;HTTPS, non-caching translation
proxy for the [RFC 8484][rfc-8484] DNS-over-HTTPS standard. It receives
regular (UDP or TCP) DNS requests and issues them via DoH.

[Google's DNS-over-HTTPS][google-doh] service is default, but
[Cloudflare's service][cloudflare-doh] also works with trivial commandline flag
changes.

[cloudflare-doh]: https://developers.cloudflare.com/1.1.1.1/dns-over-https/wireformat/
[rfc-8484]: https://tools.ietf.org/html/rfc8484
[google-doh]: https://developers.google.com/speed/public-dns/docs/doh

### Using Google

```bash
# ./https_dns_proxy -u nobody -g nogroup -d -b 8.8.8.8,8.8.4.4 \
    -r "https://dns.google/dns-query"
```

### Using Cloudflare

```bash
# ./https_dns_proxy -u nobody -g nogroup -d -b 1.1.1.1,1.0.0.1 \
    -r "https://cloudflare-dns.com/dns-query"
```

## Why?

Using DNS over HTTPS makes eavesdropping and spoofing of DNS traffic between you
and the HTTPS DNS provider (Google/Cloudflare) much less likely. This of course 
only makes sense if you trust your DoH provider.

## Features

* Tiny Size (<30kiB) when linked against system libraries
  (the [portable build](#portable-binary-and-docker-image) is larger, see below).
* Uses curl for HTTP/2 and pipelining, keeping resolve latencies extremely low.
* Single-threaded, non-blocking select() server for use on resource-starved 
  embedded systems.
* Designed to sit in front of dnsmasq or similar caching resolver for
  transparent use.

## Build

Depends on `c-ares (>=1.11.0)`, `libcurl (>=7.66.0)`, `libev (>=4.25)`.

On Debian-derived systems those are libc-ares-dev,
libcurl4-{openssl,nss,gnutls}-dev and libev-dev respectively.
On Redhat-derived systems those are c-ares-devel, libcurl-devel and libev-devel.
On systems with systemd it is recommended to have libsystemd development package installed.

On MacOS, you may run into issues with curl headers. Others have had success when first installing curl with brew.
```
brew install curl --with-openssl --with-c-ares --with-libssh2 --with-nghttp2 --with-gssapi --with-libmetalink
brew link curl --force
```

On Ubuntu
```
apt-get install cmake libc-ares-dev libcurl4-openssl-dev libev-dev libsystemd-dev build-essential
```

If all pre-requisites are met, you should be able to build with:
```
$ cmake .
$ make
```

### Build with HTTP/3 support

* If system libcurl supports it by default nothing else has to be done

* If a custom build of libcurl supports HTTP/3 which is installed in a different location, that can be set when running cmake:
  ```
  $ cmake -D CUSTOM_LIBCURL_INSTALL_PATH=/absolute/path/to/custom/libcurl/install .
  ```

* Just to test HTTP/3 support for development purpose, simply run the following command and wait for a long time:
  ```
  $ ./development_build_with_http3.sh
  ```

## INSTALL

### Install built program

This method work fine on most Linux operating system, which uses systemd.  
Like: Raspberry Pi OS / Raspbian, Debian, Ubuntu, etc.

To install the program binary, systemd service and munin plugin (if munin is pre-installed),
simply execute the following after build:
```
$ sudo make install
```

To activate munin plugin, restart munin services:
```
$ sudo systemctl restart munin munin-node
```

To overwrite default service options use:
```
$ sudo systemctl edit https_dns_proxy.service
```
And re-define ExecStart with desired options:
```
[Service]
ExecStart=
ExecStart=/usr/local/bin/https_dns_proxy \
  -u nobody -g nogroup -r https://doh.opendns.com/dns-query
```

### Portable binary and Docker image

Every day a GitHub Action checks this repository for changes since the last
release. If there are any, it builds a new [release](../../releases/latest),
tagged with the build date (`YYYY.MM.DD`), with these files:

* `https_dns_proxy-linux-amd64` - portable, statically linked binary for Linux x86_64
* `https_dns_proxy.service` - systemd unit for it
* `SHA256SUMS` - checksums

It also publishes a [Docker image](../../pkgs/container/https_dns_proxy) with the
same binary at `ghcr.io/aarond10/https_dns_proxy` (tags: the release date and `latest`).
Forks with the workflow enabled publish to their own `ghcr.io/<owner>/https_dns_proxy`
and own releases.

The portable binary has HTTP/3 (QUIC) support (`-q`) and needs no libraries on the
target system. It runs on any Linux x86_64 distribution, regardless of its libc
or installed packages.

**Size:** the portable binary is about 8 MB instead of the <30 kiB of a regular
build. It is statically linked: libcurl, OpenSSL, ngtcp2, nghttp3, nghttp2, c-ares,
libev and the musl C library are all inside the executable, instead of being shared
with the rest of the system. For the same reason, security fixes in these libraries
reach the binary only through a new release, not through system package updates.

Other differences from a regular build:

* No systemd notify support (libsystemd has no static library), so the provided
  unit uses `Type=simple`.
* CA certificates are read from `/etc/ssl/certs/ca-certificates.crt`
  (Debian, Ubuntu, Alpine, Arch and others). On distributions that keep them
  elsewhere, use `-C`, for example `-C /etc/pki/tls/certs/ca-bundle.crt`
  on Fedora/RHEL.

Install with systemd:
```
$ curl -LO https://github.com/aarond10/https_dns_proxy/releases/latest/download/https_dns_proxy-linux-amd64
$ curl -LO https://github.com/aarond10/https_dns_proxy/releases/latest/download/https_dns_proxy.service
$ sudo install -m 755 https_dns_proxy-linux-amd64 /usr/local/bin/https_dns_proxy
$ sudo install -m 644 https_dns_proxy.service /etc/systemd/system/
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now https_dns_proxy
```
The unit runs the proxy with default options. To change them, use
`sudo systemctl edit https_dns_proxy.service` as shown above.

Run with Docker:
```
$ docker run -d --name https_dns_proxy \
    -p 127.0.0.1:5053:5053/udp -p 127.0.0.1:5053:5053/tcp \
    ghcr.io/aarond10/https_dns_proxy \
    -r https://cloudflare-dns.com/dns-query
```
The image contains only the binary and a CA certificate bundle, in a single layer
on an empty base image. It runs as an unprivileged user (65534) and listens on
`0.0.0.0:5053` inside the container. Arguments after the image name are passed
to `https_dns_proxy`.

To build both locally (needs Docker with buildx), run from the repository root:
```
$ docker buildx build -f portable/Dockerfile --target binary --output type=local,dest=./out .
$ docker buildx build -f portable/Dockerfile --target image -t https_dns_proxy .
```

### OpenWRT package install

There is a package in the [OpenWRT packages](https://github.com/openwrt/packages) repository as well.
You can install as follows:

```
root@OpenWrt:~# opkg update
root@OpenWrt:~# opkg install https-dns-proxy
root@OpenWrt:~# /etc/init.d/https-dns-proxy enable
root@OpenWrt:~# /etc/init.d/https-dns-proxy start
```

OpenWrt's init script automatically updates the `dnsmasq` config to include only DoH servers on its start and restores old settings on stop. Additional information on OpenWrt-specific configuration is available at the [README](https://github.com/openwrt/packages/blob/master/net/https-dns-proxy/files/README.md).

If you are using any other resolver on your router you will need to manually replace any previously used servers with entries like:

`127.0.0.1#5053`

You may also want to prevent your resolver from using /etc/resolv.conf DNS servers, leaving only our proxy server.

There's also a WebUI package available for OpenWrt (`luci-app-https-dns-proxy`) which contains the list of supported and tested DoH providers.

### archlinux package install

There is also an externally maintained [AUR package](https://aur.archlinux.org/packages/https-dns-proxy-git/) for latest git version. You can install as follows:
```
user@arch:~# yay -S https-dns-proxy-git
```

### Docker install

See [Portable binary and Docker image](#portable-binary-and-docker-image) for the
image built by this repository. There is also an externally maintained [Docker image](https://hub.docker.com/r/bwmoran/https-dns-proxy) for latest git version. Documentation, Dockerfile, and entrypoint script can be viewed on [GitHub](https://github.com/moranbw/https-dns-proxy-docker).  An example run:

```
### points towards AdGuard DNS, only use IPv4, increase logging ###

docker run --name "https-dns-proxy" -p 5053:5053/udp  \
  -e DNS_SERVERS="94.140.14.14,94.140.15.15" \
  -e RESOLVER_URL="https://dns.adguard.com/dns-query" \
  -d bwmoran/https-dns-proxy \
  -4 -vvv
```

## Usage

Just run it as a daemon and point traffic at it. Commandline flags are:

```
Usage: ./https_dns_proxy [-a <listen_addr>] [-p <listen_port>] [-T <tcp_client_limit>]
        [-b <dns_servers>] [-i <polling_interval>] [-4]
        [-r <resolver_url>] [-t <proxy_server>] [-S <source_addr>] [-x] [-q] [-C <ca_path>] [-c <dscp_codepoint>]
        [--outbound-interface <interface>]
        [-d] [-u <user>] [-g <group>]
        [-v]+ [-l <logfile>] [-s <statistic_interval>] [-F <log_limit>] [-V] [-h]

 DNS server
  -a listen_addr         Local IPv4/v6 address to bind to. (Default: 127.0.0.1)
  -p listen_port         Local port to bind to. (Default: 5053)
  -T tcp_client_limit    Number of TCP clients to serve.
                         (Default: 20, Disabled: 0, Min: 1, Max: 200)

 DNS client
  -b dns_servers         Comma-separated IPv4/v6 addresses and ports (addr:port)
                         of DNS servers to resolve resolver host (e.g. dns.google).
                         When specifying a port for IPv6, enclose the address in [].
                         (Default: 8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1,145.100.185.15,145.100.185.16,185.49.141.37)
  -i polling_interval    Optional polling interval of DNS servers.
                         (Default: 120, Min: 5, Max: 3600)
  -4                     Force IPv4 hostnames for DNS resolvers non IPv6 networks.

 HTTPS client
  -r resolver_url        The HTTPS path to the resolver URL. (Default: https://dns.google/dns-query)
  -t proxy_server        Optional HTTP proxy. e.g. socks5://127.0.0.1:1080
                         Remote name resolution will be used if the protocol
                         supports it (http, https, socks4a, socks5h), otherwise
                         initial DNS resolution will still be done via the
                         bootstrap DNS servers.
  -S source_addr         Source IPv4/v6 address for outbound HTTPS and bootstrap DNS.
                         (Default: system default)
  -I, --outbound-interface interface
                         Linux network interface for outbound HTTPS and bootstrap DNS.
                         Incompatible with -u; requires CAP_NET_RAW.
  -x                     Use HTTP/1.1 instead of HTTP/2. Useful with broken
                         or limited builds of libcurl.
  -q                     Use HTTP/3 (QUIC) only.
  -m max_idle_time       Maximum idle time in seconds allowed for reusing a HTTPS connection.
                         (Default: 118, Min: 0, Max: 3600)
  -L conn_loss_time      Seconds before resetting after a recoverable connection failure.
                         This option mitigates half-open TCP connection issue (e.g. WAN IP change).
                         (Default: 15, Min: 5, Max: 60)
  -C ca_path             Optional file containing CA certificates.
  -c dscp_codepoint      Optional DSCP codepoint to set on upstream HTTPS server
                         connections. (Min: 0, Max: 63)

 Process
  -d                     Daemonize.
  -u user                Optional user to drop to if launched as root.
                         Also uses the user's primary group unless -g is set.
  -g group               Optional group to drop to if launched as root.

 Logging
  -v                     Increase logging verbosity. (Default: error)
                         Levels: fatal, stats, error, warning, info, debug
                         Request issues are logged on warning level.
  -l logfile             Path to file to log to. (Default: standard output)
  -s statistic_interval  Optional statistic printout interval.
                         (Default: 0, Disabled: 0, Min: 1, Max: 3600)
  -F log_limit           Flight recorder: storing desired amount of logs from all levels
                         in memory and dumping them on fatal error or on SIGUSR2 signal.
                         (Default: 0, Disabled: 0, Min: 100, Max: 100000)
  -V                     Print versions and exit.
  -h                     Print help and exit.
```

`--outbound-interface` may be combined with `-S`, `-d`, and the HTTP version
options. When combined with `-I`, `-S` must be an IP literal.
It cannot be combined with the in-process `-u` privilege drop, which
clears Linux capabilities. When using `-t`, the proxy connection is bound to the
interface, but local resolution of a proxy hostname is not.

Interface binding is checked before daemonization and on every subsequently
created HTTPS and bootstrap DNS socket. Missing permissions, an absent
interface, or loss of the interface therefore fails closed.

### Interface-binding privileges

Linux requires `CAP_NET_RAW`. Grant it to the final service user through the
service manager rather than using `-u`. For example, a systemd override can use:

```ini
[Service]
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
```

## Testing

Functional tests can be executed using [Robot Framework](https://robotframework.org/).

dig and valgrind commands are expected to be available.

```
pip3 install robotframework
python3 -m robot.run tests/robot/functional_tests.robot
```

## Docker bootstrap DNS test

There is a repeatable Docker-based test suite for validating proxy behavior
including `-S` source address binding:

```
tests/docker/run_all_tests.sh
```

If your Docker CLI is not on `PATH`, you can set `DOCKER_BIN` to its full path.

## TODO

* Add some tests.
* Improve IPv6 handling and add automatic fallback to IPv4

## Authors

* Aaron Drew (aarond10@gmail.com): Original https_dns_proxy.
* Soumya ([github.com/soumya92](https://github.com/soumya92)): RFC 8484 implementation.
* baranyaib90 ([github.com/baranyaib90](https://github.com/baranyaib90)): fixes and improvements.
