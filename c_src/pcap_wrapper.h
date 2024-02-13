#ifndef _PCAP_WRAPPER_H_

#define _PCAP_WRAPPER_H_

#include <memory>
#include <pcap.h>
#include <string_view>

class PcapWrapper {
private:
  std::unique_ptr<pcap_t, decltype(&pcap_close)> handle{nullptr, pcap_close};
  std::string_view device;
  std::string_view filter;
  int packet_count;
  PcapWrapper(const PcapWrapper &other);

public:
  PcapWrapper();
  PcapWrapper(std::string_view device, std::string_view filter);

  int get_link_header_len();
  void init();
  void set_loop_callback(pcap_handler callback);
  bool is_closed() const;
  struct pcap_stat get_stats() const;
  void close();
  PcapWrapper &operator=(const PcapWrapper &other);
  void swap(PcapWrapper &other) noexcept;

  ~PcapWrapper();
};

#endif