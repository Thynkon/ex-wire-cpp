module;

#include <format>
#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ostream>
#include <pcap.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <string_view>
#include <vector>

import Packet;
import Protocol;
import PcapWrapper;

export module Device;

using namespace std;

PcapWrapper pcap_wrapper{};

export namespace Device {
void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header,
                    Packet::frame_data *packet) {
  static size_t ethernet_header_length = pcap_wrapper.get_link_header_len();
  Packet::TcpPacket pkt(packet, ethernet_header_length);

  if (pkt.get_type() == Packet::PacketType::Tcp) {
    switch (Protocol::Protocol::detect(pkt)) {
    case Protocol::ProtocolType::HTTP: {
      Protocol::Http http{pkt};
      break;
    }

    default:
      break;
    }
  }
}

vector<string> list_all() {
  vector<string> result;
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    return result;
  }

  for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
    result.push_back(d->name);
  }

  pcap_freealldevs(alldevs);
  alldevs = nullptr;

  return result;
}

void capture(string_view device, string_view filter) {
  pcap_wrapper = PcapWrapper(device, filter);
  pcap_wrapper.init();

  // Get the type of link layer.
  if (!pcap_wrapper.get_link_header_len()) {
    cerr << "Unkown link layer" << endl;
    /* return -1; */
  }
  int count = 0;
  pcap_wrapper.set_loop_callback(packet_handler);
}

} // namespace Device
