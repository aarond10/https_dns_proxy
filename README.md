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

Depends on `c-ares (>=1.11.0)`, `libcurl (>=7.66.0)`, `libev (>=4.25)`, `gtest`.

On Debian-derived systems those are libc-ares-dev,
libcurl4-{openssl,nss,gnutls}-dev, libev-dev and libgtest-dev respectively.
On Redhat-derived systems those are c-ares-devel, libcurl-devel, libev-devel and gtest-devel, .

On MacOS, you may run into issues with curl headers. Others have had success when first installing curl with brew.
```
brew install curl --with-openssl --with-c-ares --with-libssh2 --with-nghttp2 --with-gssapi --with-libmetalink
brew link curl --force
```

On Ubuntu
```
apt-get install cmake libc-ares-dev libcurl4-openssl-dev libev-dev
```

If all pre-requisites are met, you should be able to build with:
```
$ cmake .
$ make
```

## INSTALL

There is no installer at this stage - just run it.

### OpenWRT package install

I maintain a package in the [OpenWRT packages](https://github.com/openwrt/packages) repository as well.
You can install as follows:

```
root@OpenWrt:~# opkg update
root@OpenWrt:~# opkg install https_dns_proxy
root@OpenWrt:~# /etc/init.d/https_dns_proxy enable
root@OpenWrt:~# /etc/init.d/https_dns_proxy start
```

Replace any 'list server' lines in `/etc/config/dhcp` with:

`list server '127.0.0.1#5053'`

You may also want to add the line:

`noresolv '1'`

This prevents dnsmasq from using /etc/resolv.conf DNS servers, leaving only our proxy server.

### archlinux package install

There is also an externally maintained [AUR package](https://aur.archlinux.org/packages/https-dns-proxy-git/) for latest git version. You can install as follows:
```
user@arch:~# yaourt -S https-dns-proxy-git
```

## Usage

Just run it as a daemon and point traffic at it. Commandline flags are:

```
Usage: ./https_dns_proxy [-a <listen_addr>] [-p <listen_port>]
        [-d] [-u <user>] [-g <group>] [-b <dns_servers>]
        [-r <resolver_url>] [-e <subnet_addr>]
        [-t <proxy_server>] [-l <logfile>] [-x] [-v]+

  -a listen_addr         Local IPv4/v6 address to bind to. (127.0.0.1)
  -p listen_port         Local port to bind to. (5053)
  -d                     Daemonize.
  -u user                Optional user to drop to if launched as root.
  -g group               Optional group to drop to if launched as root.
  -b dns_servers         Comma-separated IPv4/v6 addresses and ports (addr:port)
                         of DNS servers to resolve resolver host (e.g. dns.google).
                         When specifying a port for IPv6, enclose the address in [].
                         (8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1,145.100.185.15,145.100.185.16,185.49.141.37)
  -4                     Force IPv4 hostnames for DNS resolvers non IPv6 networks.
  -r resolver_url        The HTTPS path to the resolver URL. default: https://dns.google/dns-query
  -e subnet_addr         An edns-client-subnet to use such as "203.31.0.0/16".
                         ("")
  -t proxy_server        Optional HTTP proxy. e.g. socks5://127.0.0.1:1080
                         Remote name resolution will be used if the protocol
                         supports it (http, https, socks4a, socks5h), otherwise
                         initial DNS resolution will still be done via the
                         bootstrap DNS servers.
  -l logfile             Path to file to log to. ("-")
  -x                     Use HTTP/1.1 instead of HTTP/2. Useful with broken
                         or limited builds of libcurl. (false)
  -v                     Increase logging verbosity. (INFO)
```

## TODO

* Add some tests.

## Authors

* Aaron Drew (aarond10@gmail.com): Original https_dns_proxy.
* Soumya ([github.com/soumya92](https://github.com/soumya92)): RFC 8484 implementation.

