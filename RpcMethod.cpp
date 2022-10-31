#include "RpcMethod.h"

namespace RpcMethod {
  status ShowTransaction::setTxId(const std::string& id) {
    if (id.length() != Block::TxIdSize*2) return PARAM_FORMAT_ERROR;

    for (int i = 0; i < Block::TxIdSize; i++) {
      char h[3];
      h[0] = id[i * 2 + 0];
      h[1] = id[i * 2 + 1];
      h[2] = '\0';
      unsigned char hex = std::stoi(h, nullptr, 16);
      txid.value[i] = hex;
    }

    return NO_ERROR_METHOD;
  }
}