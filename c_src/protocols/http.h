#ifndef HTTP_H

#define HTTP_H

#include "../packets/packet.h"
#include "../protocols/protocol.h"
#include <string>

enum class HttpMessageType { REQUEST, RESPONSE, UNKNOWN };
enum class HttpMethod : int {
  GET,
  HEAD,
  POST,
  PUT,
  DELETE,
  CONNECT,
  OPTIONS,
  TRACE
};

std::string to_string(const HttpMethod &method);

auto begin(HttpMethod);
auto end(HttpMethod);
HttpMethod operator++(HttpMethod &method);
HttpMethod operator*(HttpMethod method);

class Http : public Protocol {
public:
  static HttpMessageType get_message_type(const Packet &packet);
};

#endif