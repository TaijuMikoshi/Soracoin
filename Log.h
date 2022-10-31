#pragma once

#include <string>
#include <fstream>
#include <time.h>
#include <iostream>

#ifdef _WIN32
inline std::string currentTime() {
  time_t t = time(NULL);
  struct tm local;
  localtime_s(&local, &t);
  char buf[128];
  strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &local);
  return std::string(buf);
}
#else
inline std::string currentTime() {
  time_t t = time(NULL);
  struct tm local;
  localtime_r(&t, &local);
  char buf[128];
  strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &local);
  return std::string(buf);
}
#endif

class Logging {
private:
  std::string fileName;
  std::ofstream ofs;

public:
  Logging() {}

  Logging(const std::string& n) {
    ofs = std::ofstream(n, std::ios::app);
  }

  bool operator!() { return !ofs; }

  void log(const std::string& msg, const std::string& func, int line) {
    ofs << msg << " @ " << func << " : " << line << std::endl;
  }

};

extern Logging mylog;

#ifdef _DEBUG
#define logging(msg) {\
  mylog.log(msg, __func__, __LINE__);\
  std::cerr << msg << " @ " << __func__ << " : " << __LINE__ << std::endl;}
#else
#define logging(msg) \
  mylog.log(msg, __func__, __LINE__);
#endif
