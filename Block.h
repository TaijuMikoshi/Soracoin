#pragma once
#include <vector>
#include <algorithm>
#include <sstream>
#include <string>
#include <time.h>
#include <openssl/ec.h>
#include <iostream>
#include <map>
#include <stack>
#include <functional>
#include <string.h>
#include <memory>
#include <assert.h>

#include "ValueType.h"
#include "Wallet.h"
#include "Hash.h"

namespace Block{
  namespace OP_CODE{
    using OP_CODE_TYPE = unsigned short;
    using DATA_LEN_TYPE = unsigned short;
    extern const OP_CODE_TYPE OP_PUSH;
    extern const OP_CODE_TYPE OP_DUP;
    extern const OP_CODE_TYPE OP_PUBKEY_TO_ADDR;
    extern const OP_CODE_TYPE OP_EQVERIFY;
    extern const OP_CODE_TYPE OP_CHECKSIG;
  };

  extern std::map<OP_CODE::OP_CODE_TYPE, std::function<bool(std::stack<std::string>&, std::string&, const std::string&)>> scriptExecFunctions;
  extern std::set<OP_CODE::OP_CODE_TYPE> dataFollowOperations;

  bool op_push(std::stack<std::string>& stack, std::string& script, const std::string&);
  bool op_dup(std::stack<std::string>& stack, std::string&, const std::string&);
  bool op_pubkey_to_addr(std::stack<std::string>& stack, std::string& script, const std::string&);
  bool op_eqverify(std::stack<std::string>& stack, std::string&, const std::string&);
  bool op_checksig(std::stack<std::string>& stack, std::string&, const std::string& lockingscript);
  void initScriptExcec();

  //bool chceckLockingScript(std::string& script) const ;

  static const int TxIdSize = 32;
  struct TxId {
    unsigned char value[TxIdSize];
  };
  using TxHash = TxId;
  static const int TxHashSize = TxIdSize;

  inline std::string ToString(TxId& id) {
    return std::string((char*)id.value, TxHashSize);
  }

  inline TxHash StringToTxHash(std::string hash) {
    TxHash t;
    if (hash.length() != TxHashSize) {
      memset(t.value, 0, TxHashSize);
    }
    else {
      memcpy(t.value, hash.c_str(), TxHashSize);
    }

    return t;
  }

  inline bool isAll(TxId& hash, const unsigned char n) {
    for (int i = 0; i < TxIdSize; i++) {
      if (hash.value[i] != n) {
        return false;
      }
    }
    return true;
  }

  inline bool operator==(const TxHash& lhs, const std::string& rhs) {
    if (rhs.length() != TxHashSize) return false;
    for (int i = 0; i < TxHashSize; i++) {
      if (lhs.value[i] != (unsigned char)rhs[i]) return false;
    }
    return true;
  }

  inline void printTxHash(const TxHash& hash) {
    for (int i = 0; i < sizeof(TxHash); i++) {
      printf("%02x", hash.value[i]);
    }
  }

  inline void printCharStyleHash(const unsigned char hash[TxHashSize]) {
    for (int i = 0; i < TxHashSize; i++) {
      printf("%02x", hash[i]);
    }
  }

  inline bool operator<(const TxId& lhs, const TxId& rhs) {
    for (int i = 0; i < sizeof(TxId); i++) {
      if (lhs.value[i] > rhs.value[i]) return false;
      if (lhs.value[i] < rhs.value[i]) return true;
    }
    return false;
  }

  struct Address {
    unsigned char addr[51];
  };

  inline std::string AddressToString(const Address& addr) {
    std::string s;
    for (int i = 0; i < sizeof(addr.addr); i++) {
      s.push_back(addr.addr[i]);
    }
    return s;
  }

  extern const uint MAX_BLOCK_SIZE;

  const uint BlockHeaderHashLength = 32;
  struct BlockHeaderHash{
    unsigned char hash[BlockHeaderHashLength];
  };
  inline void printBlockHeaderHash(const BlockHeaderHash& hash){
    for (int i = 0; i < BlockHeaderHashLength; i++) {
      printf("%02x", hash.hash[i]);
    }
    printf("\n");
  }


  inline bool operator<(const BlockHeaderHash& bhh, const byte hash[BlockHeaderHashLength]) {
    for (int i = 0; i < BlockHeaderHashLength; i++) {
      if (bhh.hash[i] < hash[i]) return true;
      if (bhh.hash[i] > hash[i]) return false;
    }
    return false;
  }

  inline bool operator<(const byte hash[BlockHeaderHashLength], const BlockHeaderHash& bhh) {
    for (int i = 0; i < BlockHeaderHashLength; i++) {
      if (hash[i] < bhh.hash[i]) return true;
      if (hash[i] > bhh.hash[i]) return false;
    }
    return false;
  }

  inline bool operator<(const BlockHeaderHash& bhh, const BlockHeaderHash& bhh2) {
    if (memcmp(bhh.hash, bhh2.hash, BlockHeaderHashLength) < 0) { return true; }
    else { return false; }
  }

  inline bool operator==(const BlockHeaderHash& bhh, const BlockHeaderHash& bhh2) {
    if (memcmp(bhh.hash, bhh2.hash, BlockHeaderHashLength) == 0) { return true; }
    else {return false;}
  }

  inline bool operator==(const BlockHeaderHash& bhh, byte hash[BlockHeaderHashLength]) {
    if (memcmp(bhh.hash, hash, BlockHeaderHashLength) == 0) { return true; }
    else { return false; }
  }

  inline bool operator!(const BlockHeaderHash& bhh) {
    for (int i = 0; i < BlockHeaderHashLength; i++) {
      if (bhh.hash[i] != 0) return false;
    }
    return true;
  }

  const uint BitLengthOfMarklRoot = 32;
  struct MarklRoot {
    unsigned char hash[BitLengthOfMarklRoot];
  };
  
  class CompareableMarklRoot : public MarklRoot {
  public:
    CompareableMarklRoot() {}
    CompareableMarklRoot(MarklRoot& r) {
      memcpy(this->hash, r.hash, sizeof(MarklRoot));
    }

    bool operator <(const CompareableMarklRoot& rhs) const {
      for (int i = BitLengthOfMarklRoot - 1; i >= 0; i--) {
        if (this->hash[i] < rhs.hash[i]) {
          return true;
        }
        else if (this->hash[i] > rhs.hash[i]){
          return false;
        }
      }
      return false;
    }

    bool operator ==(const CompareableMarklRoot& rhs) const {
      for (int i = BitLengthOfMarklRoot - 1; i >= 0; i--) {
        if (this->hash[i] != rhs.hash[i]) {
          return false;
        }
      }
      return true;
    }
  };

  class Output {
  private:
    std::string _pubkey;
    std::string _signature;

  public:
    uint money;
    std::string msg;
    std::string script;

    Address toAddr;

  public:
    Output() { }
    Output(const std::string& to, const uint m, const std::string message="") {
      setOutput(to, m, message);
    }

    Output(std::string& buff);

    Output(Output* out) {
      money = out->money;
      msg = out->msg;
      script = out->script;
      memcpy(toAddr.addr, out->toAddr.addr, sizeof(toAddr.addr));
      _pubkey = out->_pubkey;
      _signature = out->_signature;
    }

    void setOutput(const std::string& to, const uint m, const std::string message="");

    void setSignature(const std::string& pubkey, const std::string& sig) {
      this->_pubkey = pubkey;
      this->_signature = sig;
    }

    std::string signature() { return _signature; }
    std::string pubkey() { return _pubkey; }

    std::string forSignatureMsg() const {
      std::string msg((char*)&money, sizeof(money));
      msg.append(msg);
      msg.append(script);
      return msg;
    }

    uint binarySize() {
      uint size = 0;
      size += sizeof(money);
      size += sizeof(ushort); // length of msg;
      size += msg.length();
      size += sizeof(ushort); // length of script;
      size += script.length();
      size += sizeof(ushort); // length of pubkey;
      size += _pubkey.length();
      size += sizeof(ushort); // lenhth of sigunature;
      size += _signature.length();

      return size;
    }

    //uint binary(unsigned char* buff, uint n);
    std::string getBinary();

    static bool chceckLockingScript(const std::string& script);
    bool chceck() const;
  };

  class UTXO : public Output {
  public:
    TxId id;
    uint number;
    std::string unLockingScript;

    UTXO() {}
    UTXO(std::shared_ptr<Output> out, const TxId& hash, uint n) : Output(out.get()) {
      memcpy(&id.value, hash.value, TxHashSize);
      number = n;
    }
    UTXO(Output* out, const TxId& hash, uint n) : Output(out) {
      memcpy(&id.value, hash.value, TxHashSize);
      number = n;
    }
  };

  class Input{
  public:
    TxId outputTxId;
    ushort outputTxNumber;
    std::string script;

    uint total;

    Address fromAddr;

  public:
    Input() {
      total = 0;
    }

    virtual ~Input(){}

    Input(std::string& buff);

    Input(UTXO* utox);

    uint binarySize() {
      uint size = 0;
      size += sizeof(outputTxId);
      size += sizeof(outputTxNumber);
      size += sizeof(ushort);
      size += script.length();
      return size;
    }

    std::string getBinary();

    virtual void print() {
      std::cout << "ref TxHash : ";
      printTxHash(outputTxId);
      std::cout << " , #" << outputTxNumber << std::endl;
    }
    virtual void updateNonce(const int n) {}

    virtual bool check(const unsigned char h, const uint n) {
      if (!isAll(outputTxId, h)) {
        return false;
      }
      if (Input::outputTxNumber != n) {
        return false;
      }
      return true;
    }
  };

  class Nonce {
  public:
    static const int NonceSize = 8;
    unsigned char value[NonceSize];

    Nonce() {
      memset(value, 0, NonceSize);
    }

    Nonce(const Nonce& n) {
      memcpy(value, n.value, NonceSize);
    }

    void print() {
      for (int i = 0; i < NonceSize; i++) {
        printf("%02X", value[i]);
      }
    }

    const Nonce& operator+=(const int rhs) {
      int carry = rhs;
      for (int i = NonceSize - 1; i >= 0; --i) {
        carry = (int)value[i] + carry;
        if (carry <= 255) {
          value[i] = carry;
          break;
        }
        else {
          value[i] = carry - 256;
          carry /= 256;
        }
      }
      return *this;
    }

    const Nonce operator+(const int rhs) const {
      Nonce t(*this);
      return t += rhs;
    }

    const Nonce operator++() {
      Nonce t(*this);
      *this += 1;
      return t;
    }
  };

  class CoinbaseInput : public Input {
  public:
   // static const std::string scriptHeader;
    static const uint CoinbaseOuputTxId = 0;
    static const ushort CoinbaseOutputTxNumber = 0xFFFF;
    Nonce nonce;
    unsigned int nonceIndex;
    CoinbaseInput(BlockHeaderHash& prvHash) {
      memset(Input::outputTxId.value, CoinbaseOuputTxId, sizeof(Input::outputTxId.value));
      Input::outputTxNumber = CoinbaseOutputTxNumber;

      Input::script.assign((char*)prvHash.hash, sizeof(BlockHeaderHash));
      nonceIndex = Input::script.length();
      Input::script.append((char*)nonce.value, Nonce::NonceSize);
    }
    
    CoinbaseInput(std::string& bin) {
      uint copySize = 0;
      memcpy(Input::outputTxId.value, bin.c_str(), sizeof(Input::outputTxId.value));
      copySize += sizeof(Input::outputTxId.value);

      memcpy(&(Input::outputTxNumber), bin.c_str() + copySize, sizeof(Input::outputTxNumber));
      copySize += sizeof(Input::outputTxNumber);

      Input::script.assign(bin.c_str() + copySize, sizeof(BlockHeaderHash));
      copySize += sizeof(BlockHeaderHash);

      nonceIndex = Input::script.length();;
      Input::script.append(bin.c_str() + copySize, Nonce::NonceSize);

      std::string from = "coinbase";
      memcpy(&fromAddr, from.c_str(), (std::min)(sizeof(fromAddr), from.length()));
    }

    ~CoinbaseInput() {}

    static bool isCoinBase(std::string& bin) {
      assert(bin.length() >= sizeof(Input::outputTxId.value) + sizeof(CoinbaseOutputTxNumber));

      for (int i = 0; i < sizeof(Input::outputTxId.value); i++) {
        if (bin[i] != CoinbaseOuputTxId) return false;
      }

      ushort index = *(ushort*)(bin.c_str() + sizeof(Input::outputTxId.value));
      if (index != CoinbaseOutputTxNumber) return false;

      return true;
    }

    virtual void print() {
      Input::print();
      std::cout << "nonce : ";
      nonce.print();
      std::cout << std::endl;
    }

    virtual void updateNonce(const int n) {
      nonce += n;
      for (int i = 0; i < Nonce::NonceSize; i++){
        Input::script[nonceIndex + i] = nonce.value[0 + i];
      }
    }
  };

  class Tx {
  private:
    TxHash _hash;

  public:
    
    std::vector<std::shared_ptr<Input>> in;
    std::vector<std::shared_ptr<Output>> out;

    uint lockTime;



    Tx() {}
    Tx(const std::string& tx);

    uint binarySize() {
      uint s = 0;
      s += sizeof(_hash);
      s += sizeof(ushort); // number of input;
      for (auto it : in) {
        s += it->binarySize();
      }

      s += sizeof(ushort); // number of output;
      for (auto it : out) {
        s += it->binarySize();
      }

      s += sizeof(lockTime);
      return s;
    }

    std::string getBinary();

    const TxId& hash() { return _hash; }

    void calcHash() {
      std::string bin = getBinary();
      hashfunc.hash((unsigned char*)bin.c_str() + TxHashSize, bin.length() - TxHashSize, _hash.value);
    }

    std::string getInfo();
  };

#pragma pack(1)
  struct Timestamp {
    uint year;
    uint month;
    uint day;
    uint hour;
    uint minute;
    uint second;
  };

  struct BlockHeader {
    ushort version;
    BlockHeaderHash previousBlockHash;
    MarklRoot marklRoot;
    Timestamp time;
    BlockHeaderHash difficulty;
    //uint nonce;
  };
#pragma pack()

  static const unsigned int MiningReward = 100;

  class Block {
  public:
    static const int MinBlockSize;

  private:
    BlockHeader _header;
    ushort _txCount;
    std::vector<std::shared_ptr<Tx>> _txs;
    bool _isChecked;

  public:
    const BlockHeader& header() const { return _header; }
    const ushort& txCount() const { return _txCount; }
    const std::vector<std::shared_ptr<Tx>>& txs() const { return _txs; }
    const bool& isChecked() const { return _isChecked; }

  public:
    Block() {
      _isChecked = false;

      memset(&(_header), 0, sizeof(_header));
      //_header.previousBlockHash = { 0 };
      //memset(&(_header.time), 0, sizeof(Timestamp));
      //_header.difficulty;
      //_header.marklRoot = { 0 };

      _txs.clear();

    }
    Block(const std::string& bin);

    Block(const Block& b) {
      memcpy((char*)&_header, (char*)&b._header, sizeof(BlockHeader));
      _txCount = b.txCount();
      std::copy(b.txs().begin(), b.txs().end(), std::back_inserter(_txs));
      _isChecked = false;
    }

    std::string getBinary();

    void add(std::shared_ptr<Tx> d) { _txs.push_back(d);}

    void setChecked(bool b) { _isChecked = b; }

    void setMiningReward(const std::string& addr, const std::string& pubkey, const std::string& privkey);

    void calcMarklRoot();

    void setBlockVersion(ushort v) { _header.version = v; }

    void setCurrentTime();

    void setPreviousBlockHeaderHash(const BlockHeaderHash& h) {
      memcpy(&_header.previousBlockHash, &h, sizeof(BlockHeaderHash));
    }

    void setDiffculty(char diff[hashfunc.HASH_LENGTH]) {
      memcpy(_header.difficulty.hash, diff, hashfunc.HASH_LENGTH);
    }

  private:
    TxHash marklRoot(std::vector<TxHash>& v);
  };

  bool execScript(const std::string& unlockingScript, const std::string& lockingScript);
};