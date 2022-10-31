#include <sstream>
#include <iostream>

#include "JsonHandler.h"
#include "RpcMethod.h"
#include "Log.h"

JsonHandler::JsonHandler() {
  methods.insert(std::make_pair(RpcMethod::sendmoney, std::bind(&JsonHandler::sendMoney, std::ref(*this))));
  methods.insert(std::make_pair(RpcMethod::generateaddress, std::bind(&JsonHandler::generateAddress, std::ref(*this))));
  methods.insert(std::make_pair(RpcMethod::getbalance, std::bind(&JsonHandler::getBalance, std::ref(*this))));
  methods.insert(std::make_pair(RpcMethod::getbalancedetail, std::bind(&JsonHandler::getBalanceDetail, std::ref(*this))));
  methods.insert(std::make_pair(RpcMethod::showtransaction, std::bind(&JsonHandler::showTransaction, std::ref(*this))));
}

json& JsonHandler::setJsonByString(std::string str) {
  std::stringstream sstr;
  sstr << str;
  sstr >> this->j;

  return j;
}

JsonHandler::status JsonHandler::parse() {
  if (j["jsonrpc"] != "1.0") {
    return NO_MATCH_RPC_VERSION;
  }

  auto it = methods.find(j["method"]);
  if(it != methods.end()) return it->second();

  return NO_MATCH_RPC_METHOD;

}

JsonHandler::status JsonHandler::sendMoney() {
  RpcMethod::SendMoney* ret = new RpcMethod::SendMoney();
  
  if (j["params"].empty()) return NO_PARAMS;
  if (j["params"][0].empty()) return TOO_FEW_PARAMS;
  if (j["params"][1].empty()) return TOO_FEW_PARAMS;
  
  ret->fromAddr = j["params"][0];

  ret->fee = 0.0;
  if (!j["params"][2].empty()) {
    ret->fee = j["params"][2];
  }

  for (unsigned int i = 0; i < j["params"][1].size(); i++) {
    if (!j["params"][1][i].contains("address")) return TOO_FEW_PARAMS;
    if (!j["params"][1][i].contains("amount")) return TOO_FEW_PARAMS;
    
    ret->toAddrs.push_back(j["params"][1][i]["address"]);
    ret->money.push_back(j["params"][1][i]["amount"]);

    if (j["params"][1][i].contains("message")) {
      ret->message.push_back(j["params"][1][i]["message"]);
    }
    else {
      ret->message.push_back("");
    }
  }
  

  parseResult.reset(ret);

  return NO_ERROR_JSON;
}

JsonHandler::status JsonHandler::generateAddress() {
  RpcMethod::GenerateAddress* ret = new RpcMethod::GenerateAddress();
  parseResult.reset(ret);

  return NO_ERROR_JSON;
}

JsonHandler::status JsonHandler::getBalance() {
  RpcMethod::GetBalance* ret = new RpcMethod::GetBalance();
  parseResult.reset(ret);

  return NO_ERROR_JSON;
}

JsonHandler::status JsonHandler::getBalanceDetail() {
  RpcMethod::GetBalanceDetail* ret = new RpcMethod::GetBalanceDetail();
  parseResult.reset(ret);

  return NO_ERROR_JSON;
}

JsonHandler::status JsonHandler::showTransaction() {
  RpcMethod::ShowTransaction* ret = new RpcMethod::ShowTransaction();

  if (j["params"].empty()) return NO_PARAMS;

  if (ret->setTxId(j["params"]) == RpcMethod::NO_ERROR_METHOD) {
    parseResult.reset(ret);
    return NO_ERROR_JSON;
  }
  else {
    return PARAM_FORMAT_ERROR;
  }
}