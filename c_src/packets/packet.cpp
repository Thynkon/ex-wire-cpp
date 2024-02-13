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
#include <string_view>

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
  this->packet = nullptr;
  this->ip = nullptr;
  this->eth = nullptr;
}

Packet::Packet(frame_data *packet, size_t ethernet_header_length) {
  this->packet = packet;
  this->ethernet_header_length = ethernet_header_length;

  // Skip over the Ethernet header
  this->packet += ethernet_header_length;

  /* Find start of IP header */
  this->ip = (struct ip *)(this->packet);

  // Advance to the transport layer header then parse and display
  // the fields based on the type of header: tcp, udp or icmp.
  this->packet += 4 * ip->ip_hl;
}

char *Packet::get_src_ip() const { return inet_ntoa(ip->ip_src); }

char *Packet::get_dst_ip() const { return inet_ntoa(ip->ip_dst); }

u_int8_t get_protocol(const u_char *packet) {
  struct ip *ip;
  ip = (struct ip *)(packet + 14);
  return ip->ip_p;
}

string_view Packet::get_payload() const {
  return string_view((char *)payload.data, payload.length);
}