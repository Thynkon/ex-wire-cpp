#include "device.h"
#include <format>
#include <ostream>

#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <string_view>
#include <vector>

#include "packets/icmp.h"
#include "packets/packet.h"
#include "packets/tcp.h"
#include "packets/udp.h"
#include "pcap_wrapper.h"
#include <signal.h>
#include <stdio.h>

pcap_t *handle;
int linkhdrlen;
int packets;

using namespace std;

void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header,
                    const u_char *packet) {
  TcpPacket packet1(packet);
  cout << "PACKET ==>" << packet1 << endl;
}

void stop_capture(int signo) {
  struct pcap_stat stats;

  printf("closing pcap handle\n");

  if (handle != NULL) {
    if (pcap_stats(handle, &stats) >= 0) {
      printf("\n%d packets captured\n", packets);
      printf("%d packets received\n", stats.ps_recv);
      printf("%d packets dropped\n\n", stats.ps_drop);
    }

    pcap_close(handle);
    handle = nullptr;
  }

  exit(0);
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
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = NULL;
  pcap_if_t *devices = NULL;
  struct bpf_program bpf;
  bpf_u_int32 netmask;
  bpf_u_int32 srcip;

  // Get network device source IP address and netmask.
  if (pcap_lookupnet(device.data(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
    cerr << "pcap_lookupnet: " << errbuf << endl;
  }

  // Open the device for live capture.
  handle = pcap_open_live(device.data(), BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    cerr << "pcap_open_live(): " << errbuf << endl;
  }

  // Convert the packet filter epxression into a packet filter binary.
  if (pcap_compile(handle, &bpf, filter.data(), 0, netmask) == PCAP_ERROR) {
    cerr << "pcap_compile(): " << pcap_geterr(handle) << endl;
  }

  // Bind the packet filter to the libpcap handle.
  if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
    cerr << "pcap_setfilter(): " << pcap_geterr(handle) << endl;
    throw format_error(pcap_geterr(handle));
  }

  int count = 0;

  // Create packet capture handle.
  handle = create_pcap_handle(device, filter);
  if (handle == NULL) {
    // return -1;
  }
  signal(SIGINT, stop_capture);
  signal(SIGTERM, stop_capture);
  signal(SIGQUIT, stop_capture);

  // Get the type of link layer.
  get_link_header_len(handle, linkhdrlen);
  if (linkhdrlen == 0) {
    /* return -1; */
  }

  // Start the packet capture with a set count or continually if the count is
  // 0.
  if (pcap_loop(handle, count, packet_handler, (u_char *)NULL) < 0) {
    fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
    /* return -1; */
  }
}

} // namespace Device
