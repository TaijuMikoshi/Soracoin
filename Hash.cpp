#include "Hash.h"
#include <mutex>
#ifdef _WINHASH__
HCRYPTPROV  hProv = NULL;
HCRYPTHASH  hHash = NULL;
PBYTE       pbHash = NULL;
std::mutex sha256Mutex;
using LockGuard = std::lock_guard<std::mutex>;

void freeResources() {
  if (hHash) {
    CryptDestroyHash(hHash);
  }

  if (hProv) {
    CryptReleaseContext(hProv, 0);
  }

  if (pbHash) {
    free(pbHash);
  }

  return;
}

//const DWORD sha256HashLSize = 32; // SHA-256 256bit=32byte
void Hash::sha256(const unsigned char* msg, int len, unsigned char* hash) {
  LockGuard lg(sha256Mutex);
  if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    // printf(" Error in AcquireContext 0x%08x \n", GetLastError());
    freeResources();
    return;
  }

  if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    //printf("Error in CryptCreateHash 0x%08x \n", GetLastError());
    freeResources();
    return;
  }

  if (!CryptHashData(hHash, msg, len, 0)) {
    //printf("Error in CryptHashData 0x%08x \n", GetLastError());
    freeResources();
    return;
  }

  DWORD hashlen = sha256HashLSize;
  pbHash = (unsigned char*)malloc(hashlen);
  if (NULL == pbHash) {
    //printf("unable to allocate memory\n");
    freeResources();
    return;
  }

  if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &hashlen, 0)) {
    //printf("Error in CryptGetHashParam 0x%08x \n", GetLastError());
    freeResources();
    return;
  }

  memcpy(hash, pbHash, hashlen);
  freeResources();
}
#else
void Hash::sha256(const unsigned char* msg, int len, unsigned char* hash) {
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, msg, len);
  SHA256_Final(hash, &sha_ctx);
}
#endif

Hash hashfunc = Hash();