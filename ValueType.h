#pragma once

#include <vector>
#include <string>
#include <mutex>
#include <atomic>

using ulong = std::uint64_t;
using uint = std::uint32_t;// unsigned int;
using ushort = std::uint16_t; //  unsigned short;
using byte = std::uint8_t;// unsigned char;

inline ushort hexToUshort(const unsigned char* p) { return *(ushort*)p; }

inline bool is_pow2(unsigned int x) {
  if (x == 0) { return false; }
  return (x & (x - 1)) == 0;
}

inline unsigned int getLowestGreaterExp2(unsigned int x) {
  if (x == 0) return 0;
  if (x > 0x80000000) return 0;

  for (int i = 1; i <= sizeof(x) * 8; i++) {
    if (x > (0x80000000 >> i)) return (0x80000000 >> (i - 1));
  }
  return 0;
};

inline std::vector<std::string> split(std::string str, char del) {
  int first = 0;
  int last = str.find_first_of(del);

  std::vector<std::string> result;

  while (first < str.size()) {
    std::string subStr(str, first, last - first);

    result.push_back(subStr);

    first = last + 1;
    last = str.find_first_of(del, first);

    if (last == std::string::npos) {
      last = str.size();
    }
  }

  return result;
}

class ThreadStopFlag {
private:
  std::atomic<bool> _signale{ false };
public:
  void signal() { _signale = true; }
  bool operator!() { return !_signale; }
};