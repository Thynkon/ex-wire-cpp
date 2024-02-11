
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <string_view>

using namespace std;

void get_link_header_len(pcap_t *handle, int &linkhdrlen) {
  int linktype;

  // Determine the datalink layer type.
  if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
    fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
    return;
  }

  // Set the datalink layer header size.
  switch (linktype) {
  case DLT_NULL:
    linkhdrlen = 4;
    break;

  case DLT_EN10MB:
    linkhdrlen = 14;
    break;

  case DLT_SLIP:
  case DLT_PPP:
    linkhdrlen = 24;
    break;

  default:
    printf("Unsupported datalink (%d)\n", linktype);
    linkhdrlen = 0;
  }
}

pcap_t *create_pcap_handle(string_view device, string_view filter) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = NULL;
  pcap_if_t *devices = NULL;
  struct bpf_program bpf;
  bpf_u_int32 netmask;
  bpf_u_int32 srcip;

  // Get network device source IP address and netmask.
  if (pcap_lookupnet(device.data(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
    fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
    return NULL;
  }

  // Open the device for live capture.
  handle = pcap_open_live(device.data(), BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
    return NULL;
  }

  // Convert the packet filter epxression into a packet filter binary.
  if (pcap_compile(handle, &bpf, filter.data(), 0, netmask) == PCAP_ERROR) {
    fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
    return NULL;
  }

  // Bind the packet filter to the libpcap handle.
  if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
    fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
    return NULL;
  }

  return handle;
}