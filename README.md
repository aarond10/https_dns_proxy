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

```
$ cmake .
$ make
```

## INSTALL

There is no installer at this stage but OpenWRT packages are maintained in the
openwrt/ directory. Just copy the package definition into your openwrt build
directory with something like:

```
cp openwrt/packages ~/my_openwrt_build_dir/ -R
```

Then you should see `https_dns_proxy` show up under "Network services" when you
configure OpenWRT with something like `make menuconfig`

To set it up as a foward proxy for OpenWRT, add this to your 
`/etc/config/dhcp` file:

```
list server '127.0.0.1#5053'
<b># Remove all other list server lines</b>
```

You might also want to set up some iptables rules to block all forwarded outgoing port 53
traffic. (Note, you'll still need to allow localhost so `https_dns_proxy` can resolve
"dns.google.com".)

## TODO

* The DNS client and DNS packet code is extremely rough and could do with much
  love.
* Test coverage could be better.
* Load tests (that don't tax Google's infrastructure) would be nice.

## AUTHORS

Aaron Drew (aarond10@gmail.com)
