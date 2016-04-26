#ifndef _DNS_CLIENT_H_
#define _DNS_CLIENT_H_

#include <stdlib.h>
#include "dns_packet.h"
#include "logging.h"

// A bare-bones DNS client with almost no functionality.
class TrivialDNSClient {
 public:
  // Accepts comma separated list of IPs.
  TrivialDNSClient(const char *dns_servers, 
                   const char *domain_name) 
      : sock_(-1), len_(0), tx_id_(0), num_raddrs_(0), raddrs_ix_(0) {
    strncpy(domain_name_, domain_name, sizeof(domain_name_)-1);

    memset(buf_, 0, sizeof(buf_));
    memset(&raddr_, 0, sizeof(raddr_));
    memset(raddrs_, 0, sizeof(raddrs_));
    memset(result_, 0, sizeof(result_));

    // Create socket.
    sockaddr_in laddr;
    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) {
      ELOG("Socket error: %s", strerror(errno));
      exit(1);
    }
    if(bind(sock_, (sockaddr *)&laddr, sizeof(laddr)) < 0) {
      ELOG("Bind error: %s", strerror(errno));
      exit(1);
    }

    // Make list of sockaddr_in for sendto.
    char *dns_servers_copy = (char *)malloc(strlen(dns_servers) + 1);
    strcpy(dns_servers_copy, dns_servers);
    char *ip = strtok(dns_servers_copy, ",");
    while (ip) {
      sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      if (!inet_pton(AF_INET, ip, &addr.sin_addr)) {
        ELOG("Bad IP: %s", ip);
        exit(1);
      }
      addr.sin_family = AF_INET;
      addr.sin_port = htons(53);
      raddrs_[num_raddrs_++] = addr;
      ip = strtok(NULL, ",");
    }
    free(dns_servers_copy);
  
    // Build a DNS packet.
    DNSPacket p;
    p.tx_id = 0;  // Hack: we change this later.
    p.flags = 0x0100;  // Recursion Desired.
    DNSPacket::Question q;
    strncpy(q.name, domain_name, sizeof(q.name));
    q.type = 1 /* A */;  // No IPv6 for now.
    q.cls = 1 /* IN */;
    p.q[p.num_q++] = q;
    if (!p.WriteDNS(buf_, buf_ + sizeof(buf_), &len_)) {
      DLOG("Failed to build request packet.");
      exit(1);
    }
  }

  ~TrivialDNSClient() {
    close(sock_);
  }

  int sock() { return sock_; }

  const char *ip() const { return result_; }

  bool Recv() {
    char buf[2048];
    sockaddr_in raddr;
    socklen_t raddr_size = sizeof(raddr);
    int len = recvfrom(sock_, buf, sizeof(buf), 0, (sockaddr *)&raddr, &raddr_size);
    if (len <= 0) {
      DLOG("Failed DNS response: %s", strerror(errno));
      close(sock_);
      return false;
    }
    if (memcmp(&raddr, &raddr_, sizeof(raddr_)) != 0) {
      DLOG("Response from unexpected host.");
      return false;
    }
    DNSPacket resp;
    if (!resp.ReadDNS(buf, buf + len)) {
      DLOG("Bad DNS response. Ignoring.");
      return false;
    }
    if (resp.tx_id != tx_id_) {
      DLOG("Bad tx_id. Ignoring.");
      return false;
    }
    if (!(resp.flags & 0x8000) || resp.num_rr == 0) {
      DLOG("No responses.");
      return false;
    }
    if (resp.rr[0].type != 1 /* A */) {
      DLOG("Type is not an A record.");
      return false;
    }
    if (strcmp(resp.rr[0].name, domain_name_)) {
      DLOG("Names differ.");
      return false;
    }
    strncpy(result_, resp.rr[0].data, sizeof(result_)-1);
    return true;
  }
  
  bool Send() {
   tx_id_ = rand();
   *(uint16_t*)buf_ = htons(tx_id_);
   raddr_ = raddrs_[raddrs_ix_++ % num_raddrs_];
   if (sendto(sock_, buf_, len_, 0, 
       (sockaddr *)&raddr_, sizeof(raddr_)) != len_) {
     DLOG("Sendto error: %s", strerror(errno));
     return false;
   }
  }

 private:
  int sock_;
  char domain_name_[1024];  // Should only contain 'dns.google.com'
  char buf_[2048];
  int len_;
  uint16_t tx_id_;
  sockaddr_in raddr_;
  sockaddr_in raddrs_[4]; 
  int num_raddrs_;
  int raddrs_ix_;
  char result_[32];  // contains an IP address (max 16 bytes + null)
};


#endif  // _DNS_CLIENT_H_
