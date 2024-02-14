module;

// #include "icmp.h"
//  #include "packet.h"
//  #include "tcp.h"
//  #include "udp.h"
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ostream>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

export module Packet;

using namespace std;

export namespace Packet {

using frame_data = const u_char;
using packet_data = frame_data;

enum class PacketType {
  Tcp,
  Udp,
  Icmp,
};

// export class Packet;

struct Payload {
  u_char *data;
  size_t length;

public:
  Payload() {
    data = nullptr;
    length = 0;
  }

  //  Payload(u_char *d, size_t l);
  Payload(u_char *d, size_t l) {
    data = d;
    length = l;
  }

  friend std::ostream &operator<<(std::ostream &os, const Payload &payload) {
    for (size_t i = 0; i < payload.length; i++) {
      os << payload.data[i];
    }
    return os;
  }
};

// Payload::Payload() {
//   data = nullptr;
//   length = 0;
// }

// Payload::Payload(u_char *d, size_t l) {
//   data = d;
//   length = l;
// }

// ostream &operator<<(ostream &os, const Payload &payload) {
//   for (size_t i = 0; i < payload.length; i++) {
//     os << payload.data[i];
//   }
//   return os;
// }

class Packet {
protected:
  ether_header *eth;
  // struct ip *ip;
  // struct ip *ip;
  ::ip *ip;
  packet_data *packet;
  Payload payload;
  PacketType type;
  size_t ethernet_header_length;

public:
  //  Packet();
  Packet() {
    this->packet = nullptr;
    this->ip = nullptr;
    this->eth = nullptr;
  }

  // Packet(frame_data *p, size_t ethernet_header_length);
  Packet(frame_data *packet, size_t ethernet_header_length) {
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

  char *get_src_ip() const { return inet_ntoa(ip->ip_src); }

  char *get_dst_ip() const { return inet_ntoa(ip->ip_dst); }

  PacketType get_type() const;

  // std::string_view get_payload() const;
  string_view get_payload() const {
    return string_view((char *)payload.data, payload.length);
  }
};

// Packet::Packet() {
//   this->packet = nullptr;
//   this->ip = nullptr;
//   this->eth = nullptr;
// }

// Packet::Packet(frame_data *packet, size_t ethernet_header_length) {
//   this->packet = packet;
//   this->ethernet_header_length = ethernet_header_length;

//   // Skip over the Ethernet header
//   this->packet += ethernet_header_length;

//   /* Find start of IP header */
//   this->ip = (struct ip *)(this->packet);

//   // Advance to the transport layer header then parse and display
//   // the fields based on the type of header: tcp, udp or icmp.
//   this->packet += 4 * ip->ip_hl;
// }

// char *Packet::get_src_ip() const { return inet_ntoa(ip->ip_src); }

// char *Packet::get_dst_ip() const { return inet_ntoa(ip->ip_dst); }

u_int8_t get_protocol(const u_char *packet) {
  struct ip *ip;
  ip = (struct ip *)(packet + 14);
  return ip->ip_p;
}

// string_view Packet::get_payload() const {
//   return string_view((char *)payload.data, payload.length);
// }

class TcpPacket : public Packet {
private:
  // struct tcphdr *tcp;
  ::tcphdr *tcp;

public:
  //  TcpPacket(const u_char *pkt, size_t ethernet_header_length);
  TcpPacket(const u_char *pkt, size_t ethernet_header_length)
      : Packet(pkt, ethernet_header_length) {
    type = PacketType::Tcp;
    tcp = (struct tcphdr *)packet;

    u_char *begin = (u_char *)(packet + (4 * tcp->th_off));
    size_t length = ntohs(ip->ip_len) - (4 * ip->ip_hl) - (4 * tcp->th_off);

    payload = Payload(begin, length);
  }

  //  PacketType get_type() const;
  PacketType get_type() const { return type; }

  // friend std::ostream &operator<<(std::ostream &os, const TcpPacket &packet);
  friend ostream &operator<<(ostream &os, const TcpPacket &packet) {
    char iphdrInfo[256];

    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(packet.ip->ip_id), packet.ip->ip_tos, packet.ip->ip_ttl,
            4 * packet.ip->ip_hl, ntohs(packet.ip->ip_len));

    os << "TCP  " << packet.get_src_ip() << ":" << ntohs(packet.tcp->th_sport)
       << " -> " << packet.get_dst_ip() << ":" << ntohs(packet.tcp->th_dport)
       << endl;
    os << iphdrInfo << endl;
    os << (packet.tcp->th_flags & TH_URG ? 'U' : '*')
       << (packet.tcp->th_flags & TH_ACK ? 'A' : '*')
       << (packet.tcp->th_flags & TH_PUSH ? 'P' : '*')
       << (packet.tcp->th_flags & TH_RST ? 'R' : '*')
       << (packet.tcp->th_flags & TH_SYN ? 'S' : '*')
       << (packet.tcp->th_flags & TH_SYN ? 'F' : '*')
       << ntohl(packet.tcp->th_seq) << ntohl(packet.tcp->th_ack)
       << ntohs(packet.tcp->th_win) << 4 * packet.tcp->th_off << endl;
    os << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
       << endl;
    os << "Payload: " << packet.get_payload()
       << ", length: " << packet.payload.length << endl;
    os << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
       << endl;
    return os;
  }
};

// TcpPacket::TcpPacket(const u_char *pkt, size_t ethernet_header_length)
//     : Packet(pkt, ethernet_header_length) {
//   type = PacketType::Tcp;
//   tcp = (struct tcphdr *)packet;

//   u_char *begin = (u_char *)(packet + (4 * tcp->th_off));
//   size_t length = ntohs(ip->ip_len) - (4 * ip->ip_hl) - (4 * tcp->th_off);

//   payload = Payload(begin, length);
// }

// PacketType TcpPacket::get_type() const { return type; }

/*
ostream &operator<<(ostream &os, const TcpPacket &packet) {
  char iphdrInfo[256];

  sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
          ntohs(packet.ip->ip_id), packet.ip->ip_tos, packet.ip->ip_ttl,
          4 * packet.ip->ip_hl, ntohs(packet.ip->ip_len));

  os << "TCP  " << packet.get_src_ip() << ":" << ntohs(packet.tcp->th_sport)
     << " -> " << packet.get_dst_ip() << ":" << ntohs(packet.tcp->th_dport)
     << endl;
  os << iphdrInfo << endl;
  os << (packet.tcp->th_flags & TH_URG ? 'U' : '*')
     << (packet.tcp->th_flags & TH_ACK ? 'A' : '*')
     << (packet.tcp->th_flags & TH_PUSH ? 'P' : '*')
     << (packet.tcp->th_flags & TH_RST ? 'R' : '*')
     << (packet.tcp->th_flags & TH_SYN ? 'S' : '*')
     << (packet.tcp->th_flags & TH_SYN ? 'F' : '*') << ntohl(packet.tcp->th_seq)
     << ntohl(packet.tcp->th_ack) << ntohs(packet.tcp->th_win)
     << 4 * packet.tcp->th_off << endl;
  os << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" << endl;
  os << "Payload: " << packet.get_payload()
     << ", length: " << packet.payload.length << endl;
  os << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+" << endl;
  return os;
}
*/

} // namespace Packet