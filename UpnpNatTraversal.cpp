#include "UpnpNatTraversal.h"

#include <assert.h>


#ifdef _MSC_VER
#include <Windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#else
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ioctl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

void UpnpNatTraversal::setActionHeader(std::string& body) {
  body.assign("<?xml version=\"1.0\"?>");
  body.append("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">");
  body.append("<SOAP-ENV:Body>");
}

void UpnpNatTraversal::setActionTrailer(std::string& body) {
  body.append("</SOAP-ENV:Body>");
  body.append("</SOAP-ENV:Envelope>");
}

std::string serachValue(const rapidxml::xml_node<char>* node, const std::string& tag) {
  if (node->name() == tag) {
    return node->value();
  }
  auto child = node->first_node();
  if (child) {
    return serachValue(child, tag);
  }

  auto sibling = node->next_sibling();
  while (sibling) {
    auto ip = serachValue(sibling, tag);
    if (ip != "") return ip;
  }

  return "";
}

bool hasTag(const rapidxml::xml_node<char>* node, const std::string& tag) {
  if (node->name() == tag) {
    return true;
  }
  auto child = node->first_node();
  if (child) {
    return hasTag(child, tag) ? true : false;
  }

  auto sibling = node->next_sibling();
  while (sibling) {
    if (hasTag(sibling, tag)) return true;
  }

  return false;
}

UpnpNatTraversal::UPnPService findServiceType(const rapidxml::xml_node<char>* device, const std::string& value) {
  auto serviceList = device->first_node("serviceList");

  auto service = serviceList->first_node("service");
  while (service) {
    auto type = service->first_node("serviceType");
    if (type->value() == value) {
      UpnpNatTraversal::UPnPService upnp;
      upnp.serviceType = service->first_node("serviceType")->value();
      upnp.serviceId = service->first_node("serviceId")->value();
      upnp.SCPDURL = service->first_node("SCPDURL")->value();
      upnp.controlURL = service->first_node("controlURL")->value();
      upnp.eventSubURL = service->first_node("eventSubURL")->value();
      return upnp;
    }
    service = service->next_sibling();
  }

  auto newDevice = device->first_node("deviceList")->first_node("device");
  return findServiceType(newDevice, value);
}

std::string UpnpNatTraversal::GetExternalIPAddress() {
  httplib::Headers header;
  std::string body;
  GetExternalIPAddress(header, body, _upnpInfo->serviceType);

  auto res = _cli->Post(_upnpInfo->controlURL.c_str(), header, body, "text/xml");

  rapidxml::xml_document<> doc;
  doc.parse<0>((char*)res->body.c_str());
  _externalIP = serachValue(doc.first_node(), "NewExternalIPAddress");

  return _externalIP;
}

void UpnpNatTraversal::GetExternalIPAddress(httplib::Headers& header, std::string& body, const std::string& serviceType) {
  const std::string action = "GetExternalIPAddress";

  header.emplace("SoapAction", serviceType + "#" + action);

  setActionHeader(body);
  body.append("<u:" + action + " xmlns:u=\"" + serviceType + "\">");
  body.append("</u:" + action + ">");
  setActionTrailer(body);
}

bool UpnpNatTraversal::AddPortMapping(const std::string& ip, const std::string& internal_port, const std::string& external_port) {
  httplib::Headers header;
  std::string body;
  AddPortMapping(header, body, _upnpInfo->serviceType, ip, internal_port, external_port);
  auto res = _cli->Post(_upnpInfo->controlURL.c_str(), header, body, "text/xml");

  rapidxml::xml_document<> doc;
  doc.parse<0>((char*)res->body.c_str());
  return hasTag(doc.first_node(), "u:AddPortMappingResponse");
}

void UpnpNatTraversal::AddPortMapping(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& ip, const std::string& internal_port, const std::string& external_port) {
  const std::string action = "AddPortMapping";

  header.emplace("SoapAction", serviceType + "#" + action);

  setActionHeader(body);
  body.append("<u:" + action + " xmlns:u=\"" + serviceType + "\">");
  body.append("<NewRemoteHost></NewRemoteHost>");
  body.append("<NewExternalPort>" + external_port + "</NewExternalPort>");
  body.append("<NewProtocol>TCP</NewProtocol>");
  body.append("<NewInternalPort>" + internal_port + "</NewInternalPort>");
  body.append("<NewInternalClient>" + ip + "</NewInternalClient>");
  body.append("<NewEnabled>1</NewEnabled>");
  body.append("<NewPortMappingDescription>UPnP " + internal_port + " port Mapping</NewPortMappingDescription>");
  body.append("<NewLeaseDuration>0</NewLeaseDuration>");
  body.append("</u:" + action + ">");
  setActionTrailer(body);
}

bool UpnpNatTraversal::DeletePortMapping(const std::string& external_port) {
  httplib::Headers header;
  std::string body;
  DeletePortMapping(header, body, _upnpInfo->serviceType, external_port);
  auto res = _cli->Post(_upnpInfo->controlURL.c_str(), header, body, "text/xml");

  rapidxml::xml_document<> doc;
  doc.parse<0>((char*)res->body.c_str());
  return hasTag(doc.first_node(), "u:DeletePortMappingResponse");
}

void UpnpNatTraversal::DeletePortMapping(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& external_port) {
  const std::string action = "DeletePortMapping";

  header.emplace("SoapAction", serviceType + "#" + action);

  setActionHeader(body);
  body.append("<u:" + action + " xmlns:u=\"" + serviceType + "\">");
  body.append("<NewRemoteHost></NewRemoteHost>");
  body.append("<NewExternalPort>" + external_port + "</NewExternalPort>");
  body.append("<NewProtocol>TCP</NewProtocol>");
  body.append("</u:" + action + ">");
  setActionTrailer(body);
}

std::string UpnpNatTraversal::GetGenericPortMappingEntry(const std::string& index) {
  httplib::Headers header;
  std::string body;
  GetGenericPortMappingEntry(header, body, _upnpInfo->serviceType, index);
  auto res = _cli->Post(_upnpInfo->controlURL.c_str(), header, body, "text/xml");

  rapidxml::xml_document<> doc;
  doc.parse<0>((char*)res->body.c_str());
  return hasTag(doc.first_node(), "u:GetGenericPortMappingEntryResponse") ? res->body : "";
}

void UpnpNatTraversal::GetGenericPortMappingEntry(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& index) {
  const std::string action = "GetGenericPortMappingEntry";

  header.emplace("SoapAction", serviceType + "#" + action);

  setActionHeader(body);
  body.append("<u:" + action + " xmlns:u=\"" + serviceType + "\">");
  body.append("<NewPortMappingIndex>" + index + "</NewPortMappingIndex>");
  body.append("</u:" + action + ">");
  setActionTrailer(body);
}

std::string UpnpNatTraversal::GetSpecificPortMappingEntry(const std::string& ip, const std::string& internal_port, const std::string& external_port) {
  httplib::Headers header;
  std::string body;
  GetSpecificPortMappingEntry(header, body, _upnpInfo->serviceType, ip, internal_port, external_port);
  auto res = _cli->Post(_upnpInfo->controlURL.c_str(), header, body, "text/xml");

  rapidxml::xml_document<> doc;
  doc.parse<0>((char*)res->body.c_str());
  return hasTag(doc.first_node(), "u:GetSpecificPortMappingEntryResponse") ? res->body : "";
}

void UpnpNatTraversal::GetSpecificPortMappingEntry(httplib::Headers& header, std::string& body, const std::string& serviceType, const std::string& ip, const std::string& internal_port, const std::string& external_port) {
  const std::string action = "GetSpecificPortMappingEntry";

  header.emplace("SoapAction", serviceType + "#" + action);

  setActionHeader(body);
  body.append("<u:" + action + " xmlns:u=\"" + serviceType + "\">");
  body.append("<NewRemoteHost></NewRemoteHost>");
  body.append("<NewExternalPort>" + external_port + "</NewExternalPort>");
  body.append("<NewProtocol>TCP</NewProtocol>");
  body.append("<NewInternalPort>" + internal_port + "</NewInternalPort>");
  body.append("<NewInternalClient>" + ip + "</NewInternalClient>");
  body.append("<NewEnabled>1</NewEnabled>");
  body.append("<NewPortMappingDescription>UPnP " + internal_port + " port Mapping</NewPortMappingDescription>");
  body.append("<NewLeaseDuration>0</NewLeaseDuration>");
  body.append("</u:" + action + ">");
  setActionTrailer(body);
}

UpnpNatTraversal::UPnPService UpnpNatTraversal::searchWANIPConnection() {
  std::string domain;
  std::string descriptionPath;
  std::string port;
  getGwUpnpInfo(domain, descriptionPath, port);

  _cli = new httplib::Client(domain, ::atoi(port.c_str()));

  auto res = _cli->Get(descriptionPath.c_str());

  rapidxml::xml_document<> doc;
  doc.parse<0>((char*)res->body.c_str());

  UPnPService service = findServiceType(doc.first_node("root")->first_node("device"), "urn:schemas-upnp-org:service:WANIPConnection:1");
  _upnpInfo = new UPnPService(service);

  return service;
}

std::string UpnpNatTraversal::getGwUpnpInfo(std::string& domain, std::string& path, std::string& port) {
#ifdef _MSC_VER
  WSAData wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
  auto upnp = getGwUpnpInfo_();
  if (upnp == "") return "";

#ifdef _MSC_VER
  WSACleanup();
#endif

  int index = upnp.find(":");
  if (index == std::string::basic_string::npos) {
    return 0;
  }
  index++;
  std::string uri = split(upnp.substr(index, upnp.length() - index), ' ')[0];
  std::cout << uri << std::endl;
  int start = uri.find("://");
  int end = uri.find(":", start + 3);
  domain = uri.substr(start + 3, end - (start + 3));
  auto port_path = uri.substr(end + 1, uri.length() - index);
  index = port_path.find("/");

  port = port_path.substr(0, index);
  path = port_path.substr(index, port_path.length() - index);

  return upnp;
}

std::string UpnpNatTraversal::getGwUpnpInfo_() {
  std::string gw = NetworkInfomation::getDefautlGW();
  std::string localIp = NetworkInfomation::getIP(gw);

  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(1900);

#ifdef _MSC_VER
  InetPton(AF_INET, L"239.255.255.250", &addr.sin_addr.S_un.S_addr);

  DWORD ipaddr;
  InetPton(AF_INET, StringToWString(localIp).c_str(), &ipaddr);
#else
  addr.sin_addr.s_addr = inet_addr("239.255.255.250");
  std::uint32_t ipaddr = inet_addr(localIp.c_str());
#endif
  
  if (int r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ipaddr, sizeof(ipaddr)) != 0) {
#ifdef _MSC_VER
    printf("setsockopt : %d\n", WSAGetLastError());
#else
    printf("setsockopt : %d\n", r);
#endif
    return "";
  }

  char CRLF[2] = { 0x0d, 0x0A };
  std::string mSearch("M-SEARCH * HTTP/1.1");
  mSearch.append(CRLF, 2);
  mSearch.append("HOST: 239.255.255.250 : 1900");
  mSearch.append(CRLF, 2);
  mSearch.append("MAN: \"ssdp:discover\"");
  mSearch.append(CRLF, 2);
  mSearch.append("MX: 3");
  mSearch.append(CRLF, 2);
  mSearch.append("ST: urn:schemas-upnp-org:service:WANIPConnection:1");
  mSearch.append(CRLF, 2);
  mSearch.append(CRLF, 2);

  while (1) {
    auto ret = sendto(sock, mSearch.c_str(), mSearch.length(), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
      printf("error sendto");
#ifdef _MSC_VER
      closesocket(sock);
#else
      close(sock);
#endif
      return "";
    }
    char buffRcv[2048];
    sockaddr_in their_addr;
#ifdef _MSC_VER
    int len = sizeof(struct sockaddr_in);
#else
    unsigned int len = sizeof(struct sockaddr_in);
#endif
    ret = recvfrom(sock, buffRcv, sizeof(buffRcv), 0, (struct sockaddr *)&their_addr, &len);
    if (ret < 0)
    {
      printf("Error in Receiving");
#ifdef _MSC_VER
      closesocket(sock);
#else
      close(sock);
#endif
      return "";
    }
    else {
      std::string upnp(buffRcv, ret);
      auto header = split(upnp, '\n');

      for (auto& line : header) {
        if ((line.find("LOCATION:") != std::string::basic_string::npos ||
          line.find("location:") != std::string::basic_string::npos ||
          line.find("Location:") != std::string::basic_string::npos) &&
          line.find(gw + ':') != std::string::basic_string::npos) {
#ifdef _MSC_VER
          closesocket(sock);
#else
          close(sock);
#endif

          if (line.back() == 0x0d) {
            line.erase(line.length() - 1);
          }
          return line;
        }
      }
    }
  }
#ifdef _MSC_VER
  closesocket(sock);
#else
  close(sock);
#endif
  return "";
}

std::string UpnpNatTraversal::getLocalIP() {
  if (_localIP == "") {
    _gwIP = NetworkInfomation::getDefautlGW();
    _localIP = NetworkInfomation::getIP(_gwIP);
  }
  return _localIP;
}

#ifdef _MSC_VER
std::wstring StringToWString(std::string oString) {
  // SJIS -> wstring
  int iBufferSize = MultiByteToWideChar(CP_ACP, 0, oString.c_str(), -1, (wchar_t*)NULL, 0);

  wchar_t* cpUCS2 = new wchar_t[iBufferSize];

  // SJIS -> wstring
  MultiByteToWideChar(CP_ACP, 0, oString.c_str(), -1, cpUCS2, iBufferSize);

  std::wstring oRet(cpUCS2, cpUCS2 + iBufferSize - 1);

  delete[] cpUCS2;

  return(oRet);
}
#endif

std::string NetworkInfomation::getDefautlGW() {
#ifdef _MSC_VER
  unsigned int index = 2;
  FILE* route = _popen("route PRINT -4 | findstr /R /C:\"^ *0\\.0\\.0\\.0  *0\\.0\\.0\\.0\"", "r");
#else
  unsigned int index = 1;
  FILE* route = popen("route -4 | grep ^0.0.0.0", "r");
  if (route == NULL) {
    route = popen("ip route | grep default", "r");
    index = 3;
  }
#endif
  assert(route);

  std::string gw("");
  char buff[1024];
  while (fgets(buff, 1024, route) != NULL) {
    auto strings = split(buff, ' ');
    if (strings.size() > index) {
      gw = strings[index];
      break;
    }
  }

#ifdef _MSC_VER
  _pclose(route);
#else
  pclose(route);
#endif

  return gw;
}

void NetworkInfomation::getNetworkAddr(const std::string& ip, unsigned char addr[4], const std::string& mask) {
  auto ip4 = split(ip, '.');
  assert(ip4.size() == 4);

  auto m = split(mask, '.');
  assert(m.size() == 4);

  for (int i = 0; i < 4; i++) {
    addr[i] = ::atoi(ip4[i].c_str()) & ::atoi(m[i].c_str());
  }
}

void NetworkInfomation::getNetworkAddr(const std::string& ip, unsigned char addr[4], const unsigned char mask[4]) {
  auto ip4 = split(ip, '.');
  assert(ip4.size() == 4);

  for (int i = 0; i < 4; i++) {
    addr[i] = ::atoi(ip4[i].c_str()) & mask[i];
  }
}

#ifdef _MSC_VER
std::string NetworkInfomation::getIP(const std::string& gw) {
  PMIB_IPADDRTABLE pIpAddrTable = 0;
  DWORD dwSize = 0;
  DWORD dwRetVal = 0;

  if (GetIpAddrTable(NULL, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
    pIpAddrTable = (MIB_IPADDRTABLE *)malloc(dwSize);
  }

  if ((dwRetVal = GetIpAddrTable(pIpAddrTable, &dwSize, 0)) == NO_ERROR) {
    if (pIpAddrTable->dwNumEntries > 0) {
      for (DWORD i = 0; i < pIpAddrTable->dwNumEntries; i++) {
        WCHAR buff[256];
        InetNtop(AF_INET, (struct in_addr *)&pIpAddrTable->table[i].dwAddr, buff, 1024);
        auto ipAddr = (struct in_addr *)&pIpAddrTable->table[i].dwAddr;
        auto netMask = (struct in_addr *)&pIpAddrTable->table[i].dwMask;
        unsigned char mask[4];
        mask[0] = netMask->S_un.S_un_b.s_b1;
        mask[1] = netMask->S_un.S_un_b.s_b2;
        mask[2] = netMask->S_un.S_un_b.s_b3;
        mask[3] = netMask->S_un.S_un_b.s_b4;

        unsigned char netAddr[4];
        netAddr[0] = ipAddr->S_un.S_un_b.s_b1 & mask[0];
        netAddr[1] = ipAddr->S_un.S_un_b.s_b2 & mask[1];
        netAddr[2] = ipAddr->S_un.S_un_b.s_b3 & mask[2];
        netAddr[3] = ipAddr->S_un.S_un_b.s_b4 & mask[3];

        unsigned char gwNetAddr[4];
        getNetworkAddr(gw, gwNetAddr, mask);
        if (memcmp(netAddr, gwNetAddr, 4) == 0) {
          std::stringstream ss;
          ss << (int)ipAddr->S_un.S_un_b.s_b1 << "." << (int)ipAddr->S_un.S_un_b.s_b2 << "." << (int)ipAddr->S_un.S_un_b.s_b3 << "." << (int)ipAddr->S_un.S_un_b.s_b4;
          return ss.str();
        }
      }
    }
  }
  return "";

}
#else
std::vector<std::string> getIfs() {
  const int MAX_IFR = 10;
  ifreq ifr[MAX_IFR];

  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifconf ifc;
  ifc.ifc_len = sizeof(ifr);

  ifc.ifc_ifcu.ifcu_buf = (char*)ifr;

  ioctl(fd, SIOCGIFCONF, &ifc);

  int nifs = ifc.ifc_len / sizeof(struct ifreq);

  std::vector<std::string> ifs;
  for (int i = 0; i < nifs; i++) {
    ifs.push_back(ifr[i].ifr_name);
  }

  close(fd);

  return ifs;
}

std::string NetworkInfomation::getIP(const std::string& gw) {
  auto interfaces = getIfs();
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifreq ifr;
  ifr.ifr_addr.sa_family = AF_INET;

  for (auto ifs : interfaces) {
    strncpy(ifr.ifr_name, ifs.c_str(), IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    std::string ip = inet_ntoa(((sockaddr_in*)&ifr.ifr_addr)->sin_addr);

    ioctl(fd, SIOCGIFNETMASK, &ifr);
    std::string mask = inet_ntoa(((sockaddr_in*)&ifr.ifr_addr)->sin_addr);

    unsigned char netAddr[4];
    getNetworkAddr(ip, netAddr, mask);

    unsigned char gwAddr[4];
    getNetworkAddr(gw, gwAddr, mask);

    if (memcmp(netAddr, gwAddr, 4) == 0) {
      return ip;
    }
  }
  close(fd);

  return "";
}
#endif