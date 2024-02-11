#ifndef _PCAP_WRAPPER_H_

#define _PCAP_WRAPPER_H_

#include <pcap.h>
#include <string_view>

void get_link_header_len(pcap_t *handle, int &linkhdrlen);

pcap_t *create_pcap_handle(std::string_view device, std::string_view filter);

#endif