#pragma once
#include <string>
#include "ValueType.h"

class Peer {
private:
  std::string _ipaddress;
  ushort _port;

public:
  //Peer(std::string& ip, ushort p) {
  //  _ipaddress = ip;
  //  _port = p;
  //}

  Peer(std::string ip, ushort p) {
    _ipaddress = ip;
    _port = p;
  }

  Peer(const std::string& bin) {
    byte size = bin[0];
    if (bin.length() < 1 + size + sizeof(_port)) {
      _ipaddress = "";
      _port = 0;
      return;
    }

    _ipaddress.assign(bin.c_str() + 1, size);
    _port = *(ushort*)&(bin.c_str()[1 + size]);
  }

  const std::string& ipaddress() const { return _ipaddress; }
  const ushort& port() const { return _port; }

  std::string getUri() const {
    std::string uri("http://");
    uri.append(_ipaddress);
    uri.append(":");
    std::stringstream ss;
    ss << _port;
    uri.append(ss.str());
    return uri;
  }

  bool isInit() const {
    if (_ipaddress == "") return false;
    if (_port == 0) return false;
    return true;
  }

  bool operator<(const Peer& rhs) const {
    if (_ipaddress < rhs._ipaddress) return true;
    if (_ipaddress > rhs._ipaddress) return false;
    if (_port < _port) return true;
    return false;
  }

  std::string getBinary() const {
    byte size = _ipaddress.length();
    std::string bin((char*)&size, sizeof(size));
    bin.append(_ipaddress.begin(), _ipaddress.end());
    bin.append((char*)&_port, sizeof(_port));
    return bin;
  }
};