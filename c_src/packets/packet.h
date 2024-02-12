#ifndef PACKET_H

#define PACKET_H

#include <iostream>
#include <netinet/ether.h>
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

using frame_data = const u_char;
using packet_data = frame_data;

enum class PacketType {
  Tcp,
  Udp,
  Icmp,
};

class Packet;

struct Payload {
  u_char *data;
  size_t length;

public:
  Payload();

  Payload(u_char *d, size_t l);

  friend std::ostream &operator<<(std::ostream &os, const Payload &payload);
};

class Packet {
protected:
  ether_header *eth;
  struct ip *ip;
  const u_char *packet;
  Payload payload;
  PacketType type;

  /* Header lengths in bytes */
  static size_t const ETHERNET_HEADER_LENGTH = 14;

public:
  Packet();

  Packet(frame_data *p);

  char *get_src_ip() const;

  char *get_dst_ip() const;
  PacketType get_type() const;
  std::string_view get_payload() const;
};

class PacketFactory {
public:
  static Packet create(const u_char *packet);
};

#endif