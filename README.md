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

### OpenWRT

I've got a pending pull request to add net/https-dns-proxy to the OpenWRT
package repository. My repo lives [here](https://github.com/aarond10/packages).

## TODO

* Test coverage could be better.
* Load tests (that don't tax Google's infrastructure) would be nice.

## AUTHORS

* Aaron Drew (aarond10@gmail.com)
