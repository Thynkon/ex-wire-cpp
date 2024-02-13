#include "tcp.h"
#include <ostream>

using namespace std;

TcpPacket::TcpPacket(const u_char *pkt, size_t ethernet_header_length)
    : Packet(pkt, ethernet_header_length) {
  type = PacketType::Tcp;
  tcp = (struct tcphdr *)packet;

  u_char *begin = (u_char *)(packet + (4 * tcp->th_off));
  size_t length = ntohs(ip->ip_len) - (4 * ip->ip_hl) - (4 * tcp->th_off);

  payload = Payload(begin, length);
}

PacketType TcpPacket::get_type() const { return type; }

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