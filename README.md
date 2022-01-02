# https-dns-proxy

`https_dns_proxy` is a light-weight DNS&lt;--&gt;HTTPS, non-caching translation
proxy for the [RFC 8484][rfc-8484] DNS-over-HTTPS standard. It receives
regular (UDP) DNS requests and issues them via DoH.

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

* Tiny Size (<30kiB).
* Uses curl for HTTP/2 and pipelining, keeping resolve latencies extremely low.
* Single-threaded, non-blocking select() server for use on resource-starved 
  embedded systems.
* Designed to sit in front of dnsmasq or similar caching resolver for
  transparent use.

## Build

Depends on `c-ares (>=1.11.0)`, `libcurl (>=7.64.0)`, `libev (>=4.25)`.

On Debian-derived systems those are libc-ares-dev,
libcurl4-{openssl,nss,gnutls}-dev and libev-dev respectively.
On Redhat-derived systems those are c-ares-devel, libcurl-devel and libev-devel.

On MacOS, you may run into issues with curl headers. Others have had success when first installing curl with brew.
```
brew install curl --with-openssl --with-c-ares --with-libssh2 --with-nghttp2 --with-gssapi --with-libmetalink
brew link curl --force
```

On Ubuntu
```
apt-get install cmake libc-ares-dev libcurl4-openssl-dev libev-dev build-essential
```

If all pre-requisites are met, you should be able to build with:
```
$ cmake .
$ make
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

There is also an externally maintained [Docker image](https://hub.docker.com/r/bwmoran/https-dns-proxy) for latest git version. Documentation, Dockerfile, and entrypoint script can be viewed on [GitHub](https://github.com/moranbw/https-dns-proxy-docker).  An example run:

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
Usage: ./https_dns_proxy [-a <listen_addr>] [-p <listen_port>]
        [-d] [-u <user>] [-g <group>] [-b <dns_servers>]
        [-i <polling_interval>] [-4] [-r <resolver_url>]
        [-t <proxy_server>] [-l <logfile>] [-c <dscp_codepoint>]
        [-x] [-q] [-s <statistic_interval>] [-v]+ [-V] [-h]

  -a listen_addr         Local IPv4/v6 address to bind to. (127.0.0.1)
  -p listen_port         Local port to bind to. (5053)
  -d                     Daemonize.
  -u user                Optional user to drop to if launched as root.
  -g group               Optional group to drop to if launched as root.
  -b dns_servers         Comma-separated IPv4/v6 addresses and ports (addr:port)
                         of DNS servers to resolve resolver host (e.g. dns.google).
                         When specifying a port for IPv6, enclose the address in [].
                         (8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1,145.100.185.15,145.100.185.16,185.49.141.37)
  -i polling_interval    Optional polling interval of DNS servers.
                         (Default: 120, Min: 5, Max: 3600)
  -4                     Force IPv4 hostnames for DNS resolvers non IPv6 networks.
  -r resolver_url        The HTTPS path to the resolver URL. Default: https://dns.google/dns-query
  -t proxy_server        Optional HTTP proxy. e.g. socks5://127.0.0.1:1080
                         Remote name resolution will be used if the protocol
                         supports it (http, https, socks4a, socks5h), otherwise
                         initial DNS resolution will still be done via the
                         bootstrap DNS servers.
  -l logfile             Path to file to log to. ("-")
  -c dscp_codepoint      Optional DSCP codepoint[0-63] to set on upstream DNS server
                         connections.
  -x                     Use HTTP/1.1 instead of HTTP/2. Useful with broken
                         or limited builds of libcurl. (false)
  -q                     Use HTTP/3 (QUIC) only. (false)
  -s statistic_interval  Optional statistic printout interval.
                         (Default: 0, Disabled: 0, Min: 1, Max: 3600)
  -v                     Increase logging verbosity. (Default: error)
                         Levels: fatal, stats, error, warning, info, debug
                         Request issues are logged on warning level.
  -V                     Print version and exit.
  -h                     Print help and exit.
```

## Testing

Functional tests can be executed using [Robot Framework](https://robotframework.org/).

dig command is expected to be available.

```
pip3 install robotframework
python3 -m robot.run tests/robot/functional_tests.robot
```

## TODO

* Add some tests.
* Improve IPv6 handling and add automatic fallback to IPv4

## Authors

* Aaron Drew (aarond10@gmail.com): Original https_dns_proxy.
* Soumya ([github.com/soumya92](https://github.com/soumya92)): RFC 8484 implementation.
* baranyaib90 ([github.com/baranyaib90](https://github.com/baranyaib90)): fixes and improvements.

