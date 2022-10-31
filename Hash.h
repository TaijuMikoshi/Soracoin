#pragma once
#ifdef _WIN63
#define _WINHASH__
#include <windows.h>
#else
#include <openssl/sha.h>
#endif

class Hash {
private:
#ifdef _WINHASH__
  static const DWORD sha256HashLSize = 32; // SHA-256 256bit=32byte;
#else
  static const unsigned short sha256HashLSize = SHA256_DIGEST_LENGTH;
#endif
  static void sha256(const unsigned char* msg, int len, unsigned char* hash);
public:
  static const unsigned short HASH_LENGTH = sha256HashLSize;
  void hash(const unsigned char* msg, int len, unsigned char* hash) {
    Hash::sha256(msg, len, hash);
  }
};

extern Hash hashfunc;