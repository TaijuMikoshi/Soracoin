#pragma once

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

#include <string>
#include <vector>
#include <set>

namespace ECDSA {
  enum Status {
    PRIVATE_KEY_ERROR = -1, PUBLIC_KEY_ERROR = -2, EVP_MD_ERRO = -3,
    MALLOC_ERROR = -4, SIGN_ERROR = -6, KEY_GEN_ERROR = -7, KEY_COV_ERROR = -8,
    SUCCESS = 0
  };
}

class Wallet {
private:
  static const char AddressVersion = 0x01;
  static const int CURV_ID = NID_secp256k1;
  //int CURV_ID = NID_secp112r1;

public:
  struct PubPriAddr {
    std::string publicKey;
    std::string privateKey;
    std::string address;
  };

protected:
  std::set<PubPriAddr> addresses;

  std::string walletFile;

public:
  using Status = ECDSA::Status;

  static void getPublicKeyFromPrivateKey(const std::string& priKey, std::string& pubKey);
  static bool exportPrivateKey(const std::string& fname, const std::string& key);
  static bool exportPublicKey(const std::string& fname, const std::string& key);
  static bool check(std::string& pub, std::string& priv);

  static bool makeAddrFromPublicKey(std::string& pub, std::string& addr);
  static Status signature(const std::string& privateKey, const std::string& msg, std::string& sig);
  Wallet::Status signature(const std::string& msg, const std::string& fromAddr, std::string& sign, std::string& pubkey);

  static bool verify(const std::string& publicKey, const std::string& sig, const std::string& msg);

  bool loadWallet(std::string filepath);
  Status createAddress(std::string& pub, std::string& priv, std::string& addr);
  const std::set<PubPriAddr>& getAddress() { return addresses;}
  void getAddress(std::string& addr);

  bool getPublicPrivateKey(const std::string& addr, std::string& pubkey, std::string& privkey);

  bool hasAddr(const std::string& addr);

  bool makeUnLockingScript(const std::string& lockingScript, const std::string& fromAddr, std::string& unlockingScript);




};

inline bool operator<(const Wallet::PubPriAddr& lhs, const Wallet::PubPriAddr& rhs) {
  if (lhs.address < rhs.address) return true;
  else if (lhs.address > rhs.address) return false;

  if (lhs.privateKey < rhs.privateKey) return true;
  else if (lhs.privateKey > rhs.privateKey) return false;

  if (lhs.publicKey < rhs.publicKey) return true;
  else if (lhs.publicKey > rhs.publicKey) return false;

  return false;
}