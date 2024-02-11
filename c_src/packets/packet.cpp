#include "packet.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ostream>
#include <pcap/pcap.h>

using namespace std;

Payload::Payload() {
  data = nullptr;
  length = 0;
}

Payload::Payload(u_char *d, size_t l) {
  data = d;
  length = l;
}

ostream &operator<<(ostream &os, const Payload &payload) {
  for (size_t i = 0; i < payload.length; i++) {
    os << payload.data[i];
  }
  return os;
}

Packet::Packet() {
  packet = nullptr;
  ip = nullptr;
  eth = nullptr;
}

Packet::Packet(const u_char *p) {
  packet = p;

  // Skip over the Ethernet header
  packet += Packet::ETHERNET_HEADER_LENGTH;

  /* Find start of IP header */
  ip = (struct ip *)(packet);

  // Advance to the transport layer header then parse and display
  // the fields based on the type of header: tcp, udp or icmp.
  packet += 4 * ip->ip_hl;
}

char *Packet::get_src_ip() const { return inet_ntoa(ip->ip_src); }

char *Packet::get_dst_ip() const { return inet_ntoa(ip->ip_dst); }

u_int8_t get_protocol(const u_char *packet) {
  struct ip *ip;
  ip = (struct ip *)(packet + 14);
  return ip->ip_p;
}

Packet PacketFactory::create(const u_char *packet) {
  switch (get_protocol(packet)) {
  case IPPROTO_TCP:
    cout << "Creating TCP packet" << endl;
    return TcpPacket(packet);
  case IPPROTO_UDP:
    cout << "Creating UDP packet" << endl;
    return UdpPacket(packet);
  case IPPROTO_ICMP:
    // return IcmpPacket(packet);
  default:
    cout << "Creating default packet" << endl;
    return Packet(packet);
  }
}