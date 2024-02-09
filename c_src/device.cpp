#include "device.h"

#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>

using namespace std;

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
} // namespace Device
