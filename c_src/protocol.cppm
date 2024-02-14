module;

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

import Packet;

export module Protocol;

using namespace std;

export namespace Protocol {

inline std::string trim(std::string &str) {
  str.erase(str.find_last_not_of(' ') + 1); // suffixing spaces
  str.erase(0, str.find_first_not_of(' ')); // prefixing spaces
  return str;
}
enum class MessageType { REQUEST, RESPONSE, UNKNOWN };

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

auto begin(HttpMethod) { return HttpMethod::GET; }
auto end(HttpMethod) { return HttpMethod::TRACE; }
HttpMethod operator++(HttpMethod &method) {
  return method = static_cast<HttpMethod>(static_cast<int>(method) + 1);
}
HttpMethod operator*(HttpMethod method) { return method; }

string to_string(const HttpMethod &method) {
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

enum class ProtocolType : int {
  NONE,
  DHCP,
  DNS,
  FTP,
  HTTP,
  ICMP,
  IMAP,
  POP3,
  SMTP,
  SSH,
  TELNET,
};

auto begin(ProtocolType) { return ProtocolType::NONE; }
auto end(ProtocolType) { return ProtocolType::TELNET; }
ProtocolType operator++(ProtocolType &type) {
  return type = static_cast<ProtocolType>(static_cast<int>(type) + 1);
}
ProtocolType operator*(ProtocolType type) { return type; }

bool is_valid_http(const Packet::Packet &packet);
bool is_valid(const Packet::Packet &packet, ProtocolType type);

class ProtocolInterface {
public:
  virtual bool is_valid(const Packet::Packet &packet) const = 0;
};

class Protocol {
public:
  static ProtocolType detect(const Packet::Packet &packet) {
    for (const auto &protocol : ProtocolType()) {
      if (is_valid(packet, protocol)) {
        return protocol;
      }
    }

    return ProtocolType::NONE;
  }
};

using header = std::pair<std::string, std::string>;

class Http : public Protocol {
private:
  MessageType type;
  std::vector<header> headers;
  u_char *body;
  std::string_view version;
  HttpMethod method;

  void parse_headers(const Packet::Packet &packet) {
    auto request = packet.get_payload();
    string buffer;
    stringstream ss(request.data());
    bool eoh = false;
    size_t pos = 0;
    size_t count_eol = 0;
    size_t length = 0;

    while (getline(ss, buffer)) {
      erase(buffer, '\r');
      if (!eoh) {
        string key{};
        string value{};

        pos = buffer.find(":");
        if (pos == string::npos) {
          // first line of request
          // TODO: should parse method
        } else {
          key = buffer.substr(0, pos);
          trim(key);
          value = buffer.substr(++pos, buffer.length());
          trim(value);
          this->headers.push_back(make_pair(key, value));
        }

        if (buffer.empty()) {
          ++count_eol;

          if (count_eol >= 2) {
            cout << "End of header section!" << endl;
            // end of header section
            eoh = true;
          }
        }
      } else {
        cout << "Adding to body" << endl;
      }
    }
  }

public:
  static MessageType get_type_from_packet(const Packet::Packet &packet) {
    auto payload = packet.get_payload();

    // Check if the payload starts with "HTTP/" to identify as a response
    if (payload.find("HTTP/") == 0) {
      return MessageType::RESPONSE;
    }

    bool found = false;
    for (const auto &method : HttpMethod()) {
      // Check if the payload starts with an HTTP method to identify as a
      // request
      if (payload.find(to_string(method)) == 0) {
        found = true;
        break;
      }
    }

    if (found) {
      return MessageType::REQUEST;
    }

    // Unable to identify as request or response
    return MessageType::UNKNOWN;
  }
  Http(const Packet::Packet &packet) {
    this->type = Http::get_type_from_packet(packet);
    this->parse_headers(packet);
  }
  MessageType get_type() const { return this->type; }
};

bool is_valid_http(const Packet::Packet &packet) {
  auto payload = packet.get_payload();

  if (payload.empty()) {
    return false;
  }

  if (Http::get_type_from_packet(packet) != MessageType::UNKNOWN) {
    return true;
  }

  return false;
}

bool is_valid(const Packet::Packet &packet, ProtocolType type) {
  switch (type) {
  case ProtocolType::HTTP:
    return is_valid_http(packet);
    break;

  default:
    return false;
    break;
  }
}
} // namespace Protocol