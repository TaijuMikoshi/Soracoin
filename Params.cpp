#include "Params.h"
#include <sstream>

const uint Parameters::MAX_UNPN_COUNT = 30;

ResultStatus Parameters::LoadConfig(std::string filePath) {
  std::ifstream ifs(filePath);
  if (!ifs) {
    filePath.append(" is not found.");
    logging(filePath);
    return ResultStatus(ResultStatus::FILE_NOT_FOUND);
  }

  std::string buff;
  while (std::getline(ifs, buff)) {
    auto index = buff.find("port=");
    if (index != std::string::npos) {
      auto data = split(buff, '=');
      if (data.size() >= 2) {
        int port = std::atoi(data[1].c_str());
        if (port > 0 && port < (2 << 16)) {
          _listenPort = port;
        }
        else {
          std::stringstream ss;
          ss << "port number in " << filePath << " is invalid.";
          logging(ss.str());
        }
      }
    }
    index = buff.find("user=");
    if (index != std::string::npos) {
      auto data = split(buff, '=');
      if (data.size() >= 2) {
        _userName = data[1];
      }
    }
    index = buff.find("password=");
    if (index != std::string::npos) {
      auto data = split(buff, '=');
      if (data.size() >= 2) {
        _rpcPassword = data[1];
      }
    }
  }

  return ResultStatus();
}