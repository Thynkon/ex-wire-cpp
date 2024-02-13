#include "device.h"
#include "packets/icmp.h"
#include "packets/packet.h"
#include "packets/tcp.h"
#include "packets/udp.h"
#include "pcap_wrapper.h"
#include "protocols/protocol.h"
#include <format>
#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ostream>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <string_view>
#include <vector>

using namespace std;

PcapWrapper pcap_wrapper{};

void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header,
                    frame_data *packet) {
  static size_t ethernet_header_length = pcap_wrapper.get_link_header_len();
  TcpPacket pkt(packet, ethernet_header_length);

  if (pkt.get_type() == PacketType::Tcp) {
    switch (Protocol::detect(pkt)) {
    case ProtocolType::HTTP:
      // parse HTTP packet
      cout << "PACKET ==>" << pkt << endl;
      break;

    default:
      break;
    }
  }
}

namespace Device {

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
