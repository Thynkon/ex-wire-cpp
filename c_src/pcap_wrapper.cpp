#include "pcap_wrapper.h"
#include <format>
#include <iostream>
#include <memory>
#include <pcap/pcap.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <string_view>

using namespace std;

PcapWrapper::PcapWrapper() {
  this->packet_count = 0;
  this->handle.reset();
}

PcapWrapper::PcapWrapper(string_view device, string_view filter) {
  this->device = device;
  this->filter = filter;
  this->packet_count = 0;
}

PcapWrapper::PcapWrapper(const PcapWrapper &other) {
  this->handle = std::unique_ptr<pcap_t, decltype(&pcap_close)>(
      other.handle.get(), pcap_close);
  this->device = other.device;
  this->filter = other.filter;
  this->packet_count = other.packet_count;
}

bool PcapWrapper::is_closed() const { return this->handle == nullptr; }

int PcapWrapper::get_link_header_len() {
  if (this->handle == nullptr) {
    throw invalid_argument("Pcap handle was not initialized yet!");
  }

  int link_type;
  int link_header_length;

  // Determine the datalink layer type.
  if ((link_type = pcap_datalink(this->handle.get())) == PCAP_ERROR) {
    fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(this->handle.get()));
    throw format_error(pcap_geterr(this->handle.get()));
  }

  // Set the datalink layer header size.
  switch (link_type) {
  case DLT_NULL:
    link_header_length = 4;
    break;

  case DLT_EN10MB:
    link_header_length = 14;
    break;

  case DLT_SLIP:
  case DLT_PPP:
    link_header_length = 24;
    break;

  default:
    printf("Unsupported datalink (%d)\n", link_type);
    link_header_length = 0;
  }

  return link_header_length;
}

struct pcap_stat PcapWrapper::get_stats() const {
  struct pcap_stat stats;
  if (pcap_stats(this->handle.get(), &stats) < 0) {
    cerr << "pcap_stats(): " << pcap_geterr(this->handle.get()) << endl;
  }
  return stats;
}

void PcapWrapper::close() { this->~PcapWrapper(); }

void PcapWrapper::init() {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  bpf_u_int32 netmask;
  bpf_u_int32 srcip;
  pcap_t *h = nullptr;

  memset(&bpf, 0, sizeof(bpf));
  memset(&netmask, 0, sizeof(netmask));
  memset(&srcip, 0, sizeof(srcip));

  // Get network device source IP address and netmask.
  if (pcap_lookupnet(device.data(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
    throw invalid_argument(errbuf);
    cerr << "pcap_lookupnet: " << errbuf << endl;
  }

  // Open the device for live capture.
  h = pcap_open_live(device.data(), BUFSIZ, 1, 1000, errbuf);
  if (h == NULL) {
    cerr << "pcap_open_live(): " << errbuf << endl;
    throw invalid_argument(errbuf);
  }
  this->handle.reset(h);
  h = nullptr;

  // Convert the packet filter epxression into a packet filter binary.
  if (pcap_compile(this->handle.get(), &bpf, filter.data(), 0, netmask) ==
      PCAP_ERROR) {
    cerr << "pcap_compile(): " << pcap_geterr(this->handle.get()) << endl;
    throw invalid_argument(pcap_geterr(this->handle.get()));
  }

  // Bind the packet filter to the libpcap handle.
  if (pcap_setfilter(this->handle.get(), &bpf) == PCAP_ERROR) {
    cerr << "pcap_setfilter(): " << pcap_geterr(this->handle.get()) << endl;
    throw format_error(pcap_geterr(this->handle.get()));
  }
}

void PcapWrapper::set_loop_callback(pcap_handler callback) {
  if (pcap_loop(this->handle.get(), this->packet_count, callback,
                (u_char *)NULL) < 0) {
    fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(this->handle.get()));
  }
}

void PcapWrapper::swap(PcapWrapper &other) noexcept {
  using std::swap;

  swap(this->handle, other.handle);
  swap(this->device, other.device);
  swap(this->filter, other.filter);
  swap(this->packet_count, other.packet_count);
}

PcapWrapper &PcapWrapper::operator=(const PcapWrapper &other) {
  if (this == &other) {
    return *this;
  }

  PcapWrapper tmp{other};
  swap(tmp);

  return *this;
}

PcapWrapper::~PcapWrapper() {
  if (this->handle != nullptr) {
    pcap_close(this->handle.get());
    this->handle = nullptr;
  }
}