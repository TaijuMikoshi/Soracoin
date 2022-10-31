#include <string>
#include <cstring>
#include <assert.h>
namespace Encoding {
  static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  static const int b58digitsMap[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
  };

  void base58enc(unsigned char* data, int dataSize, std::string& b58) {
    assert(data != NULL);
    assert(dataSize > 0);

    const int bufSize = (int)((double)dataSize / 0.732247624390946) + 1;  //log58(256^dataSize) + 1

    unsigned char* buf = (unsigned char*)malloc(bufSize);
    memset(buf, 0, bufSize);

    int high = 0;
    int j = 0;
    for (int i = 0, high = bufSize - 1; i < dataSize; i++, high = j) {
      int carry = data[i];
      for (j = bufSize - 1; (j > high) || carry != 0; --j) {
        carry += buf[j] * 256;
        buf[j] = carry % 58;
        carry /= 58;
        if (j == 0) break;
      }
    }

    for (int i = 0; i < bufSize; ++i) {
      b58.push_back(b58digits[buf[i]]);
    }
    free(buf);
  }

  void base58dec(const std::string& b58, std::string& hex) {
    assert(b58.length() > 0);

    const int bufSize = (int)((double)b58.length() / 1.365658237) + 1;  //log256(58^length) + 1
    unsigned char* buf = (unsigned char*)malloc(bufSize);
    memset(buf, 0, bufSize);
    int high = 0;
    int j = 0;
    for (int i = 0, high = bufSize - 1; i < b58.length(); i++, high = j) {
      int carry = b58digitsMap[b58[i]];
      for (j = bufSize - 1; (j > high) || carry != 0; --j) {
        carry += buf[j] * 58;
        buf[j] = carry % 256;
        carry /= 256;
      }
    }

    for (int i = 0; i < bufSize; ++i) {
      hex.push_back(buf[i]);
    }
    free(buf);
  }
}