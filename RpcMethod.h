#pragma once
#include <string>
#include <vector>

#include "ValueType.h"
#include "Block.h"

namespace RpcMethod{
  enum status {
    NO_ERROR_METHOD = 0, PARAM_FORMAT_ERROR
  };

  static std::string sendmoney = "sendmoney";
  static std::string getbalance = "getbalance";
  static std::string getbalancedetail = "getbalancedetail";
  static std::string generateaddress = "generateaddress";
  static std::string showtransaction = "showtransaction";

  class JsonParseResult {
  protected:
    const std::string method;
  public:
    JsonParseResult(std::string m) : method(m) {}
    virtual ~JsonParseResult() {}
    std::string getMethod() { return method;}
  };

  class SendMoney : public JsonParseResult {
  public:
    std::string fromAddr;
    
    std::vector<std::string> message;

    std::vector<std::string> toAddrs;
    std::vector<uint> money;

    unsigned int fee;

  public:
    SendMoney(): JsonParseResult(sendmoney){}
    ~SendMoney() {}
  };

  class GenerateAddress : public JsonParseResult {
  public:
  public:
    GenerateAddress() : JsonParseResult(generateaddress) {}
    ~GenerateAddress() {}
  };

  class GetBalance : public JsonParseResult {
  public:
  public:
    GetBalance() : JsonParseResult(getbalance) {}
    ~GetBalance() {}
  };

  class GetBalanceDetail : public JsonParseResult {
  public:
  public:
    GetBalanceDetail() : JsonParseResult(getbalancedetail) {}
    ~GetBalanceDetail() {}
  };

  class ShowTransaction : public JsonParseResult {
  private:
    Block::TxId txid;

  public:
    ShowTransaction() : JsonParseResult(showtransaction) {}
    ~ShowTransaction() {}

    status setTxId(const std::string& id);

    const Block::TxId& getTxId() { return txid; }
  };
}

