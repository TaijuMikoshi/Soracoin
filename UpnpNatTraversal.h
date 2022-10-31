#pragma once

#include "lib/httplib.h"
#include "lib/rapidxml.hpp"

#include <vector>
#include <string>
#include <sstream>

std::wstring StringToWString(std::string oString);

class NetworkInfomation {
public:
  static std::string getDefautlGW();
  static void getNetworkAddr(const std::string& ip, unsigned char addr[4], const unsigned char mask[4]);
  static void getNetworkAddr(const std::string& ip, unsigned char addr[4], const std::string& mask);
  static std::string getIP(const std::string& gw);
};

inline std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) {
      elems.push_back(item);
    }
  }
  return elems;
}


class UpnpNatTraversal {
public:
  struct UPnPService {
    std::string serviceType;
    std::string serviceId;
    std::string SCPDURL;
    std::string controlURL;
    std::string eventSubURL;

    UPnPService() {}

    UPnPService(const UPnPService& s) {
      serviceType = s.serviceType;
      serviceId = s.serviceId;
      SCPDURL = s.SCPDURL;
      controlURL = s.controlURL;
      eventSubURL = s.eventSubURL;
    }
  };

  UpnpNatTraversal(){
    _cli = nullptr;
    _upnpInfo = nullptr;
    _gwIP = "";
    _localIP = "";
    _externalIP = "";
  }

  ~UpnpNatTraversal() {
    if(_cli != nullptr) delete _cli;
    if (_upnpInfo != nullptr) delete _upnpInfo;
  }

  UPnPService searchWANIPConnection();

  std::string GetExternalIPAddress();
  static void GetExternalIPAddress(httplib::Headers& header, std::string& body, const std::string& serviceType);

  static std::string getGwUpnpInfo(std::string& domain, std::string& path, std::string& port);

 // static UPnPService findServiceType(const rapidxml::xml_node<char>* device, const std::string& value);

  std::string getLocalIP();

  bool AddPortMapping(const std::string& internal_port) { return AddPortMapping(getLocalIP(), internal_port, internal_port);}

  bool AddPortMapping(const std::string& ip, const std::string& internal_port) { return AddPortMapping(ip, internal_port, internal_port); }

  bool AddPortMapping(const std::string& ip, const std::string& internal_port, const std::string& external_port);

  static void AddPortMapping(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& ip, const std::string& internal_port, const std::string& external_port);

  bool DeletePortMapping(const std::string& external_port);

  static void DeletePortMapping(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& external_port);

  std::string GetGenericPortMappingEntry(const std::string& index);

  static void GetGenericPortMappingEntry(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& index);

  std::string GetSpecificPortMappingEntry(const std::string& internal_port) { return GetSpecificPortMappingEntry(getLocalIP(), internal_port, internal_port); }

  std::string GetSpecificPortMappingEntry(const std::string& ip, const std::string& internal_port) { return GetSpecificPortMappingEntry(ip, internal_port, internal_port); }

  std::string GetSpecificPortMappingEntry(const std::string& ip, const std::string& internal_port, const std::string& external_port);

  static void GetSpecificPortMappingEntry(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& ip, const std::string& internal_port, const std::string& external_port);

private:
  httplib::Client* _cli;
  UPnPService* _upnpInfo;

  std::string _externalIP;

  std::string _gwIP;
  std::string _localIP;

  static void setActionHeader(std::string& body);
  static void setActionTrailer(std::string& body);

  static std::string getGwUpnpInfo_();
};

