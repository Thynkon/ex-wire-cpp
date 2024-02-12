#include "protocol.h"
#include "http.h"
#include <iostream>

using namespace std;

auto begin(ProtocolType) { return ProtocolType::NONE; }
auto end(ProtocolType) { return ProtocolType::TELNET; }
ProtocolType operator++(ProtocolType &type) {
  return type = static_cast<ProtocolType>(static_cast<int>(type) + 1);
}
ProtocolType operator*(ProtocolType type) { return type; }

bool is_valid(const Packet &packet, ProtocolType type) {
  switch (type) {
  case ProtocolType::HTTP:
    return is_valid_http(packet);
    break;

  default:
    return false;
    break;
  }
}

bool is_valid_http(const Packet &packet) {
  auto payload = packet.get_payload();

  if (payload.empty()) {
    return false;
  }

  if (Http::get_message_type(packet) != HttpMessageType::UNKNOWN) {
    return true;
  }

  return false;
}

ProtocolType Protocol::detect(const Packet &packet) {
  for (const auto &protocol : ProtocolType()) {
    if (is_valid(packet, protocol)) {
      return protocol;
    }
  }

  return ProtocolType::NONE;
}