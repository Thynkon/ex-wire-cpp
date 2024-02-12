#ifndef PROTOCOL_H

#include "../packets/packet.h"
#include <cstddef>
#include <stdlib.h>

#define PROTOCOL_H

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

auto begin(ProtocolType);
auto end(ProtocolType);
ProtocolType operator++(ProtocolType &type);
ProtocolType operator*(ProtocolType type);

class ProtocolInterface {
public:
  virtual bool is_valid(const Packet &packet) const = 0;
};

class Protocol {
public:
  static ProtocolType detect(const Packet &packet);
};

bool is_valid(const Packet &packet, ProtocolType type);
bool is_valid_http(const Packet &packet);

class Ftp : public Protocol {};
class Ssh : public Protocol {};
class Telnet : public Protocol {};
class Smtp : public Protocol {};
class Snmp : public Protocol {};
class Icmp : public Protocol {};
class Dns : public Protocol {};

#endif