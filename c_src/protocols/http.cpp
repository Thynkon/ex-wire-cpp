#include "http.h"

auto begin(HttpMethod) { return HttpMethod::GET; }
auto end(HttpMethod) { return HttpMethod::TRACE; }
HttpMethod operator++(HttpMethod &method) {
  return method = static_cast<HttpMethod>(static_cast<int>(method) + 1);
}
HttpMethod operator*(HttpMethod method) { return method; }

std::string to_string(const HttpMethod &method) {
  switch (method) {
  case HttpMethod::GET:
    return "GET";

  case HttpMethod::HEAD:
    return "HEAD";

  case HttpMethod::POST:
    return "POST";

  case HttpMethod::PUT:
    return "PUT";

  case HttpMethod::DELETE:
    return "DELETE";

  case HttpMethod::CONNECT:
    return "CONNECT";

  case HttpMethod::OPTIONS:
    return "OPTIONS";

  case HttpMethod::TRACE:
    return "TRACE";

  default:
    break;
  }
}

HttpMessageType Http::get_message_type(const Packet &packet) {
  auto payload = packet.get_payload();

  // Check if the payload starts with "HTTP/" to identify as a response
  if (payload.find("HTTP/") == 0) {
    return HttpMessageType::RESPONSE;
  }

  bool found = false;
  for (const auto &method : HttpMethod()) {
    // Check if the payload starts with an HTTP method to identify as a request
    if (payload.find(to_string(method)) == 0) {
      found = true;
      break;
    }
  }

  if (found) {
    return HttpMessageType::REQUEST;
  }

  // Unable to identify as request or response
  return HttpMessageType::UNKNOWN;
}