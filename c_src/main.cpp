#include "device.h"
#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>

int main() {
  std::vector<std::string> result;
  std::cout << "find all devs" << std::endl;
  result = Device::list_all();

  for (auto i = result.begin(); i != result.end(); ++i) {
    std::cout << *i << std::endl;
  }

  return 0;
}
