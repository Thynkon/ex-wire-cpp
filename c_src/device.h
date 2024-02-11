#ifndef _DEVICE_H_

#define _DEVICE_H_

#include <pcap.h>
#include <string>
#include <string_view>
#include <vector>

namespace Device {
    std::vector<std::string> list_all();

    void capture(std::string_view iface, std::string_view filter);
};

#endif
