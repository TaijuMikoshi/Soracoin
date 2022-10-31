#include "Wallet.h"

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#include <cassert>

#include <iostream>
#include <string>
#include <sstream>

#include "Log.h"
#include "Hash.h"
#include "Encoding.h"
#include "ValueType.h"
#include "Block.h"

namespace ECDSA {

  bool verify(EC_KEY *eckey, const unsigned char* msg, int msgLen, const std::string& sig) {
    assert(eckey != NULL);
    assert(msg != NULL);
    assert(msgLen > 0);

    // setup key
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if ((evp_key) == NULL) {
      logging("EVP_PKEY_new error");
      return false;
    }
    if (!EVP_PKEY_set1_EC_KEY(evp_key, eckey)) {
      logging("EVP_PKEY_set1_EC_KEY error");
      EVP_PKEY_free(evp_key);
      return false;
    }

    // setup EVP_MD context
    EVP_MD_CTX *evpx = EVP_MD_CTX_create();
    if (evpx == NULL) {
      logging("EVP_MD_CTX_create error");
      EVP_PKEY_free(evp_key);
      return false;
    }

    //Verify signature
    if (!EVP_VerifyInit_ex(evpx, EVP_sha256(), NULL)) {
      logging("EVP_VerifyInit error");
      return false;
    }

    /* Update */
    if (!EVP_VerifyUpdate(evpx, msg, msgLen)) {
      logging("EVP_VerifyUpdate error");
      return false;
    }

    /* Final */
    if (EVP_VerifyFinal(evpx, (unsigned char*)sig.c_str(), sig.length(), evp_key) != 1) {
      logging("EVP_VerifyFinal error");
      return  false;
    }
    return true;
  }

  Status sign(EC_KEY *eckey, const unsigned char* msg, int msgLen, std::string& sig) {
    assert(eckey != NULL);
    assert(msg != NULL);
    assert(msgLen > 0);

    // setup private key
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if ((evp_key) == NULL) {
      logging("EVP_PKEY_new error");
      return PRIVATE_KEY_ERROR;
    }
    if (!EVP_PKEY_set1_EC_KEY(evp_key, eckey)) {
      logging("EVP_PKEY_set1_EC_KEY error");
      EVP_PKEY_free(evp_key);
      return PRIVATE_KEY_ERROR;
    }

    // setup EVP_MD context
    EVP_MD_CTX *evpx = EVP_MD_CTX_create();
    if (evpx == NULL) {
      logging("EVP_MD_CTX_create error");
      EVP_PKEY_free(evp_key);
      return EVP_MD_ERRO;
    }

    // Signature generation
    unsigned int sigLen = EVP_PKEY_size(evp_key);
    unsigned char * signature = (unsigned char *)OPENSSL_malloc(sigLen);
    if (signature == NULL) {
      logging("OPENSSL_malloc error");
      EVP_PKEY_free(evp_key);
      return MALLOC_ERROR;
    }
    if (!EVP_SignInit_ex(evpx, EVP_sha256(), NULL)) {
      logging("EVP_SignInit_ex error");
      OPENSSL_free(signature);
      EVP_PKEY_free(evp_key);
      return SIGN_ERROR;
    }
    if (!EVP_SignUpdate(evpx, msg, msgLen)) {
      logging("EVP_SignUpdate error");
      OPENSSL_free(signature);
      EVP_PKEY_free(evp_key);
      return SIGN_ERROR;
    }
    if (!EVP_SignFinal(evpx, signature, &sigLen, evp_key)) {
      logging("EVP_SignFinal error");
      OPENSSL_free(signature);
      EVP_PKEY_free(evp_key);
      return SIGN_ERROR;
    }

    // copy signature to argment parameter
    for (int i = 0; i < sigLen; i++) {
      sig.push_back(signature[i]);
    }

    OPENSSL_free(signature);
    EVP_PKEY_free(evp_key);

    return SUCCESS;
  }

  Status generateKeyPair(std::string& pub_key, std::string& priv_key, int nid) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    if (EC_KEY_generate_key(ec_key) != 1) {
      logging("EC_KEY_generate_key error");
      EC_KEY_free(ec_key);
      return KEY_GEN_ERROR;
    }
    if (EC_KEY_check_key(ec_key) != 1) {
      logging("EC_KEY_check_key error");
      EC_KEY_free(ec_key);
      return KEY_GEN_ERROR;
    }

    try {
      BN_CTX* ctx = BN_CTX_new();
      const EC_POINT* ecp = EC_KEY_get0_public_key(ec_key);
      const EC_GROUP* group = EC_KEY_get0_group(ec_key);
      point_conversion_form_t from = EC_GROUP_get_point_conversion_form(group);
      char* pubHex = EC_POINT_point2hex(group, ecp, from, ctx);
      pub_key.assign(pubHex);
      BN_CTX_free(ctx);

      const BIGNUM* bn = EC_KEY_get0_private_key(ec_key);
      char* priHex = BN_bn2hex(bn);
      priv_key.assign(priHex);
    }
    catch (std::exception& e) {
      logging(e.what());
      EC_KEY_free(ec_key);
      return KEY_COV_ERROR;
    }
    EC_KEY_free(ec_key);

    return SUCCESS;
  }

  int stringToPublicKey(const std::string& pubKey, EC_KEY *eckey) {
    assert(eckey != NULL);

    EC_POINT *pub = NULL;
    pub = EC_POINT_hex2point(EC_KEY_get0_group(eckey), pubKey.c_str(), pub, NULL);
    EC_KEY_set_public_key(eckey, pub);

    return 0;
  }

  int stringToPrivateKey(const std::string& privKey, EC_KEY *eckey) {
    assert(eckey != NULL);
    assert(privKey.length() > 0);

    BIGNUM *priv = NULL;
    BN_hex2bn(&priv, privKey.c_str());
    EC_KEY_set_private_key(eckey, priv);
    BN_free(priv);
    return 0;
  }

  void privateToPublicKey(const std::string& priKey, std::string& pubKey, int nid) {
    BIGNUM *priv = NULL;
    BN_hex2bn(&priv, priKey.c_str());

    EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    EC_POINT* pub_key = EC_POINT_new(group);
    EC_KEY_set_private_key(eckey, priv);

    BN_CTX* ctx = BN_CTX_new();
    if (!EC_POINT_mul(group, pub_key, priv, NULL, NULL, ctx))
      logging("Error at EC_POINT_mul");

    point_conversion_form_t from = EC_GROUP_get_point_conversion_form(group);
    char* pubHex = EC_POINT_point2hex(group, pub_key, from, ctx);

    pubKey.assign(pubHex);

    BN_CTX_free(ctx);
    BN_free(priv);
  }
}

bool Wallet::makeAddrFromPublicKey(std::string& pub, std::string& addr) {
  try {
    unsigned char hash[32];
    hashfunc.hash((unsigned char*)pub.c_str(), pub.length(), hash);
    std::string addrSeed(hash, hash + 32);

    addrSeed.insert(addrSeed.begin(), AddressVersion);
    int checkSum = 0;
    for (int i = 0; i < addrSeed.length(); i++) {
      checkSum += addrSeed[i];
    }
    addrSeed.push_back(checkSum % 256);

    Encoding::base58enc((unsigned char*)addrSeed.c_str(), addrSeed.length(), addr);

    std::string AddrSuffix("netw");
    addr.insert(addr.begin(), AddrSuffix[3]);
    addr.insert(addr.begin(), AddrSuffix[2]);
    addr.insert(addr.begin(), AddrSuffix[1]);
    addr.insert(addr.begin(), AddrSuffix[0]);
  }
  catch (std::exception& e){
    logging(e.what());
    return false;
  }

  return true;
}

Wallet::Status Wallet::createAddress(std::string& pub, std::string& priv, std::string& addr) {
  auto r = ECDSA::generateKeyPair(pub, priv, CURV_ID);
  if (r != Status::SUCCESS) return r;

  makeAddrFromPublicKey(pub, addr);
  addresses.insert(PubPriAddr{ pub, priv, addr });


  std::ofstream ofs(walletFile, std::ios_base::app);
  ofs << priv << std::endl;

  return Status::SUCCESS;
}

bool Wallet::check(std::string& pub, std::string& priv) {
  EC_KEY *eckey = EC_KEY_new_by_curve_name(CURV_ID);
  ECDSA::stringToPrivateKey(priv, eckey);
  ECDSA::stringToPublicKey(pub, eckey);
  auto r = EC_KEY_check_key(eckey);
  EC_KEY_free(eckey);
  return (r == 1 ? true : false);
}

void Wallet::getPublicKeyFromPrivateKey(const std::string& priKey, std::string& pubKey) {
  ECDSA::privateToPublicKey(priKey, pubKey, CURV_ID);
}

bool Wallet::getPublicPrivateKey(const std::string& addr, std::string& pubkey, std::string& privkey) {
  for (auto& ppa : addresses) {
    if (ppa.address == addr) {
      pubkey = ppa.publicKey;
      privkey = ppa.privateKey;
      return true;
    }
   }
  return false;
}

bool Wallet::exportPrivateKey(const std::string& fname, const std::string& privKey) {
  assert(fname.length() > 0);
  assert(privKey.length() > 0);

  EC_KEY *eckey = EC_KEY_new_by_curve_name(CURV_ID);
  ECDSA::stringToPrivateKey(privKey, eckey);
  std::string pubKey;
  getPublicKeyFromPrivateKey(privKey, pubKey);
  ECDSA::stringToPublicKey(pubKey, eckey);

  FILE* f = fopen(fname.c_str(), "w");
  if (f != NULL) {
    PEM_write_ECPrivateKey(f, eckey, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    EC_KEY_free(eckey);
    return true;
  }
  else {
    std::stringstream ss;
    ss << "Can't create file : " << fname.c_str();
    logging(ss.str());
    EC_KEY_free(eckey);
    return false;
  }
}

bool Wallet::exportPublicKey(const std::string& fname, const std::string& key) {
  assert(fname.length() > 0);
  assert(key.length() > 0);

  EC_KEY *eckey = EC_KEY_new_by_curve_name(CURV_ID);
  ECDSA::stringToPublicKey(key, eckey);

  FILE* f = fopen(fname.c_str(), "w");
  if (f != NULL) {
    PEM_write_EC_PUBKEY(f, eckey);
    fclose(f);
    EC_KEY_free(eckey);
    return true;
  }
  else {
    std::stringstream ss;
    ss << "Can't create file : " << fname.c_str();
    logging(ss.str());
    EC_KEY_free(eckey);
    return false;
  }
}

Wallet::Status Wallet::signature(const std::string& privateKey, const std::string& msg, std::string& sig) {
  EC_KEY *eckey = EC_KEY_new_by_curve_name(CURV_ID);
  ECDSA::stringToPrivateKey(privateKey, eckey);
  auto r = ECDSA::sign(eckey, (unsigned char*)msg.c_str(), msg.length(), sig);
  EC_KEY_free(eckey);

  return r;
}

Wallet::Status Wallet::signature(const std::string& msg, const std::string& fromAddr, std::string& sign, std::string& pubkey){
  for (auto& ppa : addresses) {
    if (ppa.address == fromAddr) {
      auto r = signature(ppa.privateKey, msg, sign);
      pubkey = ppa.publicKey;
    }
  }
  return Status::SIGN_ERROR;
}

bool Wallet::verify(const std::string& publicKey, const std::string& sig, const std::string& msg) {
  EC_KEY *eckey = EC_KEY_new_by_curve_name(CURV_ID);
  ECDSA::stringToPublicKey(publicKey, eckey);
  auto r = ECDSA::verify(eckey, (unsigned char*)msg.c_str(), msg.length(), sig);
  EC_KEY_free(eckey);

  return r;
}


bool Wallet::loadWallet(std::string filepath) {
  walletFile = filepath;
  std::ifstream ifs(filepath);
  
  if (!ifs.is_open()) {
    std::stringstream ss;
    ss << filepath << " is not found\n";
    logging(ss.str());
    return false;
  }

  std::string privKey;
  while (getline(ifs, privKey)) {
    std::string pubKey;
    ECDSA::privateToPublicKey(privKey, pubKey, CURV_ID);
    if (!check(pubKey, privKey)) {
      std::stringstream ss;
      ss << "private key : " << privKey << " is error. It may be broken.\n";
      logging(ss.str());
    }
    else {
      std::string addr;
      if (!makeAddrFromPublicKey(pubKey, addr)) {
        std::stringstream ss;
        ss << "private key : " << privKey << " is error. It may be broken.\n";
        logging(ss.str());
      }
      else {
        addresses.insert(PubPriAddr{ pubKey, privKey, addr });
      }
    }
  }
  return true;
}

bool Wallet::hasAddr(const std::string& addr) {
  for (auto& ppa : addresses) {
    if (ppa.address == addr) {
      return true;
    }
  }
  return false;
}

bool Wallet::makeUnLockingScript(const std::string& lockingScript, const std::string& fromAddr, std::string& unlockingScript) {
  for (auto& ppa : addresses) {
    if (ppa.address == fromAddr) {
      unlockingScript.clear();
      std::string sig;
      signature(ppa.privateKey, lockingScript, sig);
      unlockingScript.append((char*)&Block::OP_CODE::OP_PUSH, sizeof(Block::OP_CODE::OP_PUSH));
      Block::OP_CODE::DATA_LEN_TYPE len = sig.length();
      unlockingScript.append((char*)&len, (char*)&len + sizeof(len));
      unlockingScript.append(sig);
      unlockingScript.append((char*)&Block::OP_CODE::OP_PUSH, sizeof(Block::OP_CODE::OP_PUSH));
      Block::OP_CODE::DATA_LEN_TYPE keyLen = ppa.publicKey.length();
      unlockingScript.append((char*)&keyLen, (char*)&keyLen + sizeof(keyLen));
      unlockingScript.append(ppa.publicKey);
      return true;
    }
  }
  return false;
}



void Wallet::getAddress(std::string& addr) {
  if (addresses.size() <= 0) {
    addr.clear();
    return;
  }

  addr = addresses.begin()->address;
}