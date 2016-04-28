# https-dns-proxy

https\_dns\_proxy is a light-weight DNS&lt;--&gt;HTTPS, non-caching proxy for
Google's [DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https)
service.

Using DNS over HTTPS makes eavesdropping and spoofing of your DNS traffic 
almost impossible.

Features:

* Tiny Size (50kiB when linked against external libcurl)
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
$ ./https_dns_proxy -u nobody -g nogroup -p 5053 -d
```

### OpenWRT

I've got some basic OpenWRT packages I maintain in [a
separate](https://github.com/aarond10/https_dns_proxy_openwrt) repository so I
can avoid it being self-referential. :P

## TODO

* The whole binary here is extremely "alpha" in quality. Expect issues. That
  said, I've been running it successfully for a week now without any problems!
* The DNS client and DNS packet code is extremely rough and could do with much
  love.
* Test coverage could be better.
* Load tests (that don't tax Google's infrastructure) would be nice.

## AUTHORS

* Aaron Drew (aarond10@gmail.com)
