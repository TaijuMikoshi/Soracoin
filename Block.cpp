#include "Block.h"

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

#include <cassert>

#include <iostream>
#include <stack>
#include <map>
#include <functional>
#include <iomanip>

#include "Log.h"
#include "Encoding.h"
#include "Hash.h"

namespace Block {
  const int Block::MinBlockSize = sizeof(BlockHeader) + sizeof(Block::_txCount);

  namespace OP_CODE {
    extern const OP_CODE_TYPE OP_PUSH = 0xFF01;
    extern const OP_CODE_TYPE OP_DUP = 0xFF02;
    extern const OP_CODE_TYPE OP_PUBKEY_TO_ADDR = 0xFF03;
    extern const OP_CODE_TYPE OP_EQVERIFY = 0xFF10;
    extern const OP_CODE_TYPE OP_CHECKSIG = 0xFF20;
  }

  const uint MAX_BLOCK_SIZE = 1000000;

  Input::Input(std::string& buff) {
    //sizeOfBinary = 0;
    total = 0;

    unsigned int copiedSize = 0;
    memcpy(&outputTxId, buff.c_str(), sizeof(outputTxId));
    copiedSize += sizeof(outputTxId);

    memcpy(&outputTxNumber, buff.c_str() + copiedSize, sizeof(outputTxNumber));
    copiedSize += sizeof(outputTxNumber);

    ushort len;
    memcpy(&len, buff.c_str() + copiedSize, sizeof(len));
    copiedSize += sizeof(len);
    script.append(buff.c_str() + copiedSize, len);
    assert(buff.length() > len);


    OP_CODE::DATA_LEN_TYPE siglen = *(ushort*)(script.c_str() + sizeof(OP_CODE::OP_CODE_TYPE));
    assert(buff.length() > siglen);

    OP_CODE::DATA_LEN_TYPE pubLen = *(ushort*)(script.c_str() + sizeof(OP_CODE::OP_CODE_TYPE) * 2 + sizeof(OP_CODE::DATA_LEN_TYPE) + siglen);
    assert(buff.length() > pubLen);

    std::string pubkey(script.c_str() + sizeof(OP_CODE::OP_CODE_TYPE) * 2 + sizeof(OP_CODE::DATA_LEN_TYPE) * 2 + siglen, pubLen);

    std::string from;
    Wallet::makeAddrFromPublicKey(pubkey, from);
    memcpy(&fromAddr, from.c_str(), (std::min)(sizeof(fromAddr), from.length()));
  }

  Input::Input(UTXO* utxo) {
    //sizeOfBinary = 0;
    total = 0;

    outputTxId = utxo->id;
    outputTxNumber = utxo->number;
    script = utxo->unLockingScript;
  }

  std::string Input::getBinary() {
    std::string buff;
    //buff.append((char*)&sizeOfBinary, sizeof(sizeOfBinary));
    buff.append((char*)&outputTxId, sizeof(outputTxId));
    buff.append((char*)&outputTxNumber, sizeof(outputTxNumber));

    ushort len = script.length();
    buff.append((char*)&len, sizeof(len));
    buff.append(script);
    return buff;
  }

  Output::Output(std::string& buff) {
    unsigned int copiedSize = 0;
    memcpy(&money, buff.c_str(), sizeof(money));
    copiedSize += sizeof(money);

    ushort sLen;
    memcpy(&sLen, buff.c_str() + copiedSize, sizeof(sLen));
    copiedSize += sizeof(sLen);
    script = std::string(buff.c_str() + copiedSize, sLen);
    copiedSize += sLen;

    ushort mLen;
    memcpy(&mLen, buff.c_str() + copiedSize, sizeof(mLen));
    copiedSize += sizeof(mLen);
    msg = std::string(buff.c_str() + copiedSize, mLen);
    copiedSize += mLen;

    ushort pubLen;
    memcpy(&pubLen, buff.c_str() + copiedSize, sizeof(pubLen));
    copiedSize += sizeof(pubLen);
    _pubkey = std::string(buff.c_str() + copiedSize, pubLen);
    copiedSize += pubLen;

    ushort sigLen;
    memcpy(&sigLen, buff.c_str() + copiedSize, sizeof(sigLen));
    copiedSize += sizeof(sigLen);
    _signature = std::string(buff.c_str() + copiedSize, sigLen);
    copiedSize += sigLen;


    for (int i = 0; i < script.length(); i += sizeof(OP_CODE::OP_CODE_TYPE)) {
      OP_CODE::OP_CODE_TYPE type = *(OP_CODE::OP_CODE_TYPE*)(script.c_str() + i);
      if (type == OP_CODE::OP_PUBKEY_TO_ADDR) {
        ushort size = *(OP_CODE::OP_CODE_TYPE*)(script.c_str() + i + sizeof(OP_CODE::OP_PUBKEY_TO_ADDR) + sizeof(OP_CODE::OP_PUSH));
        memcpy(&toAddr, script.c_str() + i + sizeof(OP_CODE::OP_PUBKEY_TO_ADDR) + sizeof(OP_CODE::OP_PUSH) + sizeof(size), size);
        break;
      }
    }


  }

  void Output::setOutput(const std::string& to, const uint m, const std::string message) {
    memcpy(&toAddr, to.c_str(), (std::min)(sizeof(toAddr), to.length()));
    money = m;

    script.append((char*)&OP_CODE::OP_DUP, sizeof(OP_CODE::OP_DUP));
    script.append((char*)&OP_CODE::OP_PUBKEY_TO_ADDR, sizeof(OP_CODE::OP_PUBKEY_TO_ADDR));
    script.append((char*)&OP_CODE::OP_PUSH, sizeof(OP_CODE::OP_PUSH));
    OP_CODE::DATA_LEN_TYPE AddrSize = sizeof(toAddr);
    script.append((char*)&AddrSize, sizeof(AddrSize));
    script.append((char*)&toAddr, sizeof(toAddr));
    script.append((char*)&OP_CODE::OP_EQVERIFY, sizeof(OP_CODE::OP_EQVERIFY));
    script.append((char*)&OP_CODE::OP_CHECKSIG, sizeof(OP_CODE::OP_CHECKSIG));

    msg = message;
  }

  std::string Output::getBinary() {
    std::string buff;
    buff.append((char*)&money, sizeof(money));

    ushort len = script.length();
    buff.append((char*)&len, sizeof(len));
    buff.append(script);

    ushort msgLen = msg.length();
    buff.append((char*)&msgLen, sizeof(msgLen));
    buff.append(msg);

    ushort pubLen = _pubkey.length();
    buff.append((char*)&pubLen, sizeof(pubLen));
    buff.append(_pubkey);

    ushort sigLen = _signature.length();
    buff.append((char*)&sigLen, sizeof(sigLen));
    buff.append(_signature);

    return buff;
  }

  bool Output::chceckLockingScript(const std::string& script) {
    int i = 0;
    for (i = 0; i < script.length(); ) {
      if (script.length() - i < sizeof(OP_CODE::OP_CODE_TYPE)) return false;
      OP_CODE::OP_CODE_TYPE op = *(OP_CODE::OP_CODE_TYPE*)(script.c_str() + i);
      i += sizeof(OP_CODE::OP_CODE_TYPE);

      auto f = scriptExecFunctions.find(op);
      if (f == scriptExecFunctions.end()) return false;
      auto o = dataFollowOperations.find(op);
      if (o == dataFollowOperations.end()) continue;

      if (script.length() - i < sizeof(OP_CODE::DATA_LEN_TYPE)) return false;
      OP_CODE::DATA_LEN_TYPE len = *(OP_CODE::DATA_LEN_TYPE*)(script.c_str() + i);
      i += sizeof(OP_CODE::DATA_LEN_TYPE);

      if (script.length() - i < len) return false;
      i += len;
    }

    if (i == script.length()) return true;

    return false;
  }

  bool Output::chceck() const {
    if (!Output::chceckLockingScript(this->script)) return false;
    auto msg = forSignatureMsg();
    return Wallet::verify(_pubkey, _signature, msg);
  }

  Tx::Tx(const std::string& tx) {
    unsigned int copySize = 0;
    memcpy(_hash.value, tx.c_str(), sizeof(_hash.value));
    copySize += sizeof(_hash.value);
    assert(copySize > 0);

    ushort numIn;
    memcpy(&numIn, tx.c_str() + copySize, sizeof(numIn));
    copySize += sizeof(numIn);
    assert(numIn > 0);

    for (int i = 0; i < numIn; i++) {
      std::string s(tx.c_str() + copySize, sizeof(TxId));
      copySize += sizeof(TxId);

      s.append(tx.c_str() + copySize, sizeof(ushort));
      copySize += sizeof(ushort);

      ushort len = *(ushort*)(tx.c_str() + copySize);
      s.append((char*)&len, sizeof(ushort));
      copySize += sizeof(ushort);

      s.append(tx.c_str() + copySize, len);
      copySize += len;

      if(CoinbaseInput::isCoinBase(s)){
        in.push_back(std::shared_ptr<Input>(new CoinbaseInput(s)));
      }
      else {
        in.push_back(std::shared_ptr<Input>(new Input(s)));
      }
    }

    ushort numOut;
    memcpy(&numOut, tx.c_str() + copySize, sizeof(numOut));
    copySize += sizeof(numOut);
    assert(numOut > 0);

    for (int i = 0; i < numOut; i++) {
      assert(tx.length() - copySize > 0);
      std::string s(tx.c_str() + copySize, tx.length() - copySize);
      out.push_back(std::shared_ptr<Output>(new Output(s)));
      copySize += out.back()->binarySize();
    }

    assert(tx.length() >= (copySize + sizeof(lockTime)));
    memcpy(&lockTime, tx.c_str() + copySize, sizeof(lockTime));
  }

  std::string Tx::getBinary() {
    std::string buff;

    buff.append(_hash.value, _hash.value + sizeof(_hash.value));

    ushort numIn = in.size();
    buff.append((char*)&numIn, (char*)&numIn + sizeof(numIn));

    for (auto i : in) {
      buff.append(i->getBinary());
    }

    ushort numOut = out.size();
    buff.append((char*)&numOut, sizeof(numOut));
    for (auto o : out) {
      buff.append(o->getBinary());
    }

    buff.append((char*)&lockTime, sizeof(lockTime));
    return buff;
  }

  std::string Tx::getInfo() {
    std::stringstream ss;

    ss << "Tx Hash : ";
    for(int i = 0; i < TxHashSize; i++){
      ss << std::hex << std::setw(2) << std::setfill('0') << (_hash.value[i] & 0xFF);
    }
    ss << std::endl;

    ss << "Input :\n";
    for (const auto& input : in) {
      ss << "\tOutput Tx Hash : ";
      for (int i = 0; i < TxIdSize; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (input->outputTxId.value[i] & 0xFF);
      }
      ss << std::endl;

      ss << "\tOutput Tx index : " << input->outputTxNumber << std::endl;
      ss << "\tUnlocking script : ";
      for (int i = 0; i < input->script.length(); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (input->script[i] & 0xFF);
      }
      ss << std::endl;
      ss << "------" << std::endl;
    }

    ss << "Output :\n";
    for (const auto& output : out) {
      ss << "\tAddress : " << AddressToString(output->toAddr) << std::endl;

      ss << "\tLocking script : ";
      for (int i = 0; i < output->script.length(); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (output->script[i] & 0xFF);
      }
      ss << std::endl;

      ss << "\tMessage : " << output->msg << std::endl;
      ss << "\tMoney : " << output->money << std::endl;
      ss << "------" << std::endl;
    }

    return ss.str();
  }
  
  Block::Block(const std::string& bin) {
    _isChecked = false;

    int offset = 0;

    memcpy(&_header, bin.c_str() + offset, sizeof(_header));
    offset += sizeof(_header);

    memcpy(&_txCount, bin.c_str() + offset, sizeof(_txCount));
    offset += sizeof(_txCount);

    for (int i = 0; i < _txCount; i++) {
      _txs.push_back(std::shared_ptr<Tx>(new Tx(std::string(bin.c_str() + offset, bin.length() - offset))));
      offset += _txs.back()->binarySize();
    }
  }

  std::string Block::getBinary() {
    std::string s;

    s.append((char*)&_header, sizeof(_header));
    _txCount = _txs.size();
    s.append((char*)&_txCount, sizeof(_txCount));
    for (auto tx : _txs) {
      s.append(tx->getBinary());
    }
    return s;
  }

  void Block::setMiningReward(const std::string& addr, const std::string& pubkey, const std::string& privkey) {
    _txs.insert(_txs.begin(), std::shared_ptr<Tx>(new Tx()));
    
    auto out = std::shared_ptr<Output>(new Output(addr, MiningReward));
    auto msg = out->forSignatureMsg();
    std::string sig;
    Wallet::signature(privkey, msg, sig);
    out->setSignature(pubkey, sig);
    _txs.front()->out.push_back(out);

    _txs.front()->in.push_back(std::shared_ptr<Input>(new CoinbaseInput(_header.previousBlockHash)));
    _txs.front()->lockTime = 0;
    _txCount = _txs.size();
  }

  void Block::calcMarklRoot() {
    std::vector<TxHash> hashs;
    for (uint i = 0; i < _txCount; i++) {
      hashs.push_back(_txs[i]->hash());
    }

    if (!is_pow2(_txCount)) {
      uint n = getLowestGreaterExp2(_txCount);
      n -= _txCount;

      for (uint i = 0; i < n; i++) {
        hashs.push_back(hashs.back());
      }
    }

    auto txhash = marklRoot(hashs);
    memcpy(&_header.marklRoot, &txhash, sizeof(_header.marklRoot));
  }

  TxHash Block::marklRoot(std::vector<TxHash>& v) {
    assert(v.size() > 0);
    uint size = v.size();
    if (size == 1) {
      return v.front();
    }

    char tmp[sizeof(TxId) * 2];
    std::vector<TxHash> h;
    for (uint i = 0; i < size; i += 2) {
      memcpy(tmp, v[i].value, sizeof(v[i]));
      memcpy(tmp + sizeof(v[i]), v[i + 1].value, sizeof(v[i + 1]));
      TxHash hash;
      hashfunc.hash((unsigned char*)tmp, sizeof(TxId) * 2, hash.value);
      h.push_back(hash);
    }
    return marklRoot(h);
  }

  void Block::setCurrentTime() {
    time_t t = time(NULL);
    struct tm local;
#ifdef _WIN64
    localtime_s(&local, &t);
#else
    localtime_r(&t, &local);
#endif
    _header.time.year = local.tm_year;
    _header.time.month = local.tm_mon;
    _header.time.day = local.tm_mday;
    _header.time.hour = local.tm_hour;
    _header.time.minute = local.tm_min;
    _header.time.second = local.tm_sec;
  }


  bool execScript(const std::string& unlockingscript, const std::string& lockingScript) {
    std::stack<std::string> stack;
    try {
      std::string script = unlockingscript + lockingScript;
      while (script.length() >= 2) {
        OP_CODE::OP_CODE_TYPE op = *(OP_CODE::OP_CODE_TYPE*)script.c_str();
        script.erase(0, sizeof(op));
        auto f = scriptExecFunctions.find(op);
        if (f == scriptExecFunctions.end()) return false;
        if (!f->second(stack, script, lockingScript)) return false;
      }

      if (script.length() != 0 || stack.size() > 0) return false;
    }
    catch (std::exception& e) {
      logging(e.what());
      return false;
    }

    return true;
  }
/*
  bool execScript(const std::string& unlockingscript, const std::string& lockingScript) {
    std::stack<std::string> stack;
    try {
      const unsigned char* script = (unsigned char*)unlockingscript.c_str();
      ushort num = hexToUshort(script);
      int readSize = sizeof(num);
      for (int i = 0; i < num; i++) {
        ushort len = hexToUshort(script + readSize);
        readSize += sizeof(len);

        stack.push(std::string((char*)(script + readSize), len));
        readSize += len;

        ushort keyLen = hexToUshort(script + readSize);
        readSize += sizeof(keyLen);

        stack.push(std::string((char*)(script + readSize), keyLen));
        readSize += keyLen;
      }
    }
    catch (std::exception& e) {
      logging(e.what());
      return false;
    }

    try {
      std::string script = lockingScript;
      while (script.length() >= 2) {
        OP_CODE::OP_CODE_TYPE op = *(OP_CODE::OP_CODE_TYPE*)script.c_str();
        script.erase(0, sizeof(op));
        auto f = scriptExecFunctions.find(op);
        if (f == scriptExecFunctions.end()) return false;
        if (!f->second(stack, script, lockingScript)) return false;
      }

      if (script.length() != 0 || stack.size() > 0) return false;
    }
    catch (std::exception& e) {
      logging(e.what());
      return false;
    }

    return true;
  }*/

  std::map<OP_CODE::OP_CODE_TYPE, std::function<bool(std::stack<std::string>&, std::string&, const std::string&)>> scriptExecFunctions;
  std::set<OP_CODE::OP_CODE_TYPE> dataFollowOperations;
  void initScriptExcec() {
    using namespace OP_CODE;
    scriptExecFunctions.insert(std::make_pair(OP_PUSH, op_push));
    scriptExecFunctions.insert(std::make_pair(OP_DUP, op_dup));
    scriptExecFunctions.insert(std::make_pair(OP_PUBKEY_TO_ADDR, op_pubkey_to_addr));
    scriptExecFunctions.insert(std::make_pair(OP_EQVERIFY, op_eqverify));
    scriptExecFunctions.insert(std::make_pair(OP_CHECKSIG, op_checksig));

    dataFollowOperations.insert(OP_PUSH);

  }

  bool op_push(std::stack<std::string>& stack, std::string& script, const std::string&) {
    OP_CODE::DATA_LEN_TYPE len = *(OP_CODE::DATA_LEN_TYPE*)script.c_str();
    script.erase(0, sizeof(len));

    if (script.length() < len) return false;

    stack.push(std::string(script.c_str(), len));
    script.erase(0, len);

    return true;
  }

  bool op_dup(std::stack<std::string>& stack, std::string&, const std::string&) {
    if (stack.size() <= 0) return false;

    auto t = stack.top();
    stack.push(t);

    return true;
  }

  bool op_pubkey_to_addr(std::stack<std::string>& stack, std::string& script, const std::string&) {
    if (stack.size() <= 0) return false;
    if (script.length() < 2) return false;

    auto pub = stack.top();
    stack.pop();
    std::string addr;
    if (!Wallet::makeAddrFromPublicKey(pub, addr)) return false;
    stack.push(addr);

    //OP_CODE::DATA_LEN_TYPE len = *(OP_CODE::DATA_LEN_TYPE*)script.c_str();
    //script.erase(0, sizeof(len));

    //if (script.length() < len) return false;

    //stack.push(std::string(script.c_str(), len));
    //script.erase(0, len);

    return true;
  }

  bool op_eqverify(std::stack<std::string>& stack, std::string&, const std::string&) {
    if (stack.size() < 2) return false;

    auto addr1 = stack.top();
    stack.pop();
    auto addr2 = stack.top();
    stack.pop();
    
    if (addr1 == addr2) return true;
    return false;
  }

  bool op_checksig(std::stack<std::string>& stack, std::string&, const std::string& lockingscript) {
    if (stack.size() < 2) return false;

    auto pub = stack.top();
    stack.pop();

    auto sig = stack.top();
    stack.pop();

    if (Wallet::verify(pub, sig, lockingscript)) return true;
    
    return false;
  }

  
};