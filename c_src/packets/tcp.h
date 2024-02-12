#ifndef EXWIRE_PCAP_TCPPACKET_H
#define EXWIRE_PCAP_TCPPACKET_H

#include "packet.h"
#include <ostream>

class TcpPacket : public Packet {
private:
  struct tcphdr *tcp;

public:
  TcpPacket(const u_char *pkt);
  PacketType get_type() const;

  friend std::ostream &operator<<(std::ostream &os, const TcpPacket &packet);
};

#endif
