# https-dns-proxy

https\_dns\_proxy is a light-weight DNS&lt;--&gt;HTTPS, non-caching translation
proxy for the emerging [DoH](https://datatracker.ietf.org/doc/charter-ietf-doh/)
DNS-over-HTTPS standard. It receives regular (UDP) DNS requests and issues them
via DoH.

Google's [DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https)
service is default, but [Cloudflare's
service](https://developers.cloudflare.com/1.1.1.1/dns-over-https/) also works
with trivial commandline flag changes.

### Using Google

```bash
# ./https_dns_proxy -u nobody -g nogroup -d -b 8.8.8.8,8.8.4.4 \
    -r "https://dns.google.com/resolve?"
```

### Using Cloudflare

```bash
# ./https_dns_proxy -u nobody -g nogroup -d -b 1.1.1.1,1.0.0.1 \
    -r "https://cloudflare-dns.com/dns-query?ct=application/dns-json&"
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

Depends on `c-ares`, `libcurl`, `libev`.

On Debian-derived systems those are libc-ares-dev,
libcurl4-{openssl,nss,gnutls}-dev and libev-dev respectively.
On Redhat-derived systems those are c-ares-devel, libcurl-devel and
libev-devel.

On MacOS, you may run into issues with curl headers. Others have had success when first installing curl with brew.
```
brew install curl --with-openssl --with-c-ares --with-libssh2 --with-nghttp2 --with-gssapi --with-libmetalink
brew link curl --force
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
        [-r <resolver_url_prefix>] [-e <subnet_addr>]
        [-t <proxy_server>] [-l <logfile>] [-x] [-v]+

  -a listen_addr         Local address to bind to. (127.0.0.1)
  -p listen_port         Local port to bind to. (5053)
  -d                     Daemonize.
  -u user                User to drop to launched as root. (nobody)
  -g group               Group to drop to launched as root. (nobody)
  -b dns_servers         Comma separated IPv4 address of DNS servers
                         to resolve resolver host (e.g. dns.google.com).  (8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1,145.100.185.15,145.100.185.16,185.49.141.37)
  -r resolver_url_prefix The HTTPS path to the JSON resolver URL.  (https://dns.google.com/resolve?)
  -e subnet_addr         An edns-client-subnet to use such as "203.31.0.0/16".  ()
  -t proxy_server        Optional HTTP proxy. e.g. socks5://127.0.0.1:1080
                         (Initial DNS resolution can't be done over this.)
  -l logfile             Path to file to log to. (-)
  -x                     Use HTTP/1.1 instead of HTTP/2. Useful with broken
                         or limited builds of libcurl (false).
  -v                     Increase logging verbosity. (INFO)
```

## TODO

* Test coverage could be better.

## Alternative protocols

The DoH standard is still evolving. Because responses are translated into
JSON, there is room for error in encoding and parsing response types -
particularly the less common ones.

For this reason, I tend to believe [DNS-over-TLS](https://developers.cloudflare.com/1.1.1.1/dns-over-tls/) is a better
long-term strategy for the industry, but proxy clients aren't yet
readily available. 

Note that fundamental differences (binary vs JSON encoding) mean this
software does not and will not support DNS-over-TLS.

## Authors

* Aaron Drew (aarond10@gmail.com)
