# https-dns-proxy

https\_dns\_proxy is a light-weight DNS&lt;--&gt;HTTPS, non-caching proxy for
Google's [DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https)
service.

Using DNS over HTTPS makes eavesdropping and spoofing of DNS traffic between you
and the HTTPS DNS provider (Google) much less likely. This of course only makes
sense if you trust Google as they're currently the only provider of such a
service.

Features:

* Tiny Size (<30kiB).
* Uses curl for HTTP/2 and pipelining, keeping resolve latencies extremely low.
* Single-threaded, non-blocking select() server for use on resource-starved 
  embedded systems.
* Designed to sit in front of dnsmasq or similar caching resolver for
  transparent use.

## BUILD

Depends on `c-ares`, `libcurl`, `libev`.

```
$ cmake .
$ make
```

## INSTALL

There is no installer at this stage - just run it.

```
# ./https_dns_proxy -u nobody -g nogroup -d
```

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

## TODO

* Test coverage could be better.
* Load tests (that don't tax Google's infrastructure) would be nice.

## AUTHORS

* Aaron Drew (aarond10@gmail.com)
