#pragma once
#include <string>
#include "ValueType.h"
#include "Status.h"
#include "Log.h"


class Parameters {
public:
  static const uint MAX_UNPN_COUNT;
private:
  ushort _listenPort;
  ushort _externalPort;
  std::string _userName;
  std::string _rpcPassword;
  std::string _loalIpAddress;
  std::string _globalIpAddress;

public:
  Parameters() {
    _loalIpAddress = "127.0.0.1";
    _globalIpAddress = "127.0.0.1";
    _listenPort = 1234;
    _externalPort = 1234;

    _userName = "sora";
    _rpcPassword = "password";
  }

  ~Parameters() {}

  const ushort& listenPort() const { return _listenPort; }
  const ushort& externalPort() const { return _externalPort; }
  const std::string& userName() const { return _userName; }
  const std::string& rpcPassword() const { return _rpcPassword; }
  const std::string& localIpAddress() const { return _loalIpAddress; }
  const std::string& globalIpAddress() const { return _globalIpAddress; }

  void setLocalIpAddress(const std::string& ip) { _loalIpAddress = ip; }
  void setGlobalIpAddress(const std::string& ip) { _globalIpAddress = ip; }

  void setListenPort(const ushort& port) { _listenPort = port; }
  void setExternalListenPort(const ushort& port) { _externalPort = port; }

  ResultStatus LoadConfig(std::string filePath);
};