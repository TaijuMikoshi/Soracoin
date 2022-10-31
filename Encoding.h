#pragma once

#include <string>

namespace Encoding {
  void base58enc(unsigned char* data, int dataSize, std::string& b58);
  void base58dec(const std::string& b58, std::string& hex);
}