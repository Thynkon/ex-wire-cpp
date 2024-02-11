#ifndef EXWIRE_PCAP_UDP_H
#define EXWIRE_PCAP_UDP_H

#include "packet.h"

class UdpPacket : public Packet {
  /*
  friend ostream &operator<<(ostream &os, const UdpPacket &packet) {
    os << "UDP  " << srcip << ":" << ntohs(udp_header->uh_sport) << " -> "
       << dstip << ":" << ntohs(udp_header->uh_dport) << endl;
    os << iphdrInfo << endl;
    os << "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
       << endl;
    return os;
  }
  */
};

#endif // EXWIRE_PCAP_UDP_H
