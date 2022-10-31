#pragma once
#include <memory>

#include "lib/nlohmann-json.h"
#include "RpcMethod.h"

using json = nlohmann::json;

class JsonHandler {
public:

  enum status {
    NO_ERROR_JSON = 0, NO_MATCH_RPC_VERSION, NO_MATCH_RPC_METHOD, NO_PARAMS, TOO_FEW_PARAMS, PARAM_FORMAT_ERROR
  };

protected:
  json j;

  std::map<std::string, std::function<JsonHandler::status()> > methods;

  std::shared_ptr<RpcMethod::JsonParseResult> parseResult;

public:

  JsonHandler();

  json& setJsonByString(std::string str);

  status parse();

  std::shared_ptr<RpcMethod::JsonParseResult>& getParseResult() { return parseResult; }

  status sendMoney();

  status generateAddress();

  status getBalance();

  status getBalanceDetail();

  status showTransaction();
};