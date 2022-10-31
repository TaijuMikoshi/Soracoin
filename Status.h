#pragma once

#include "ValueType.h"

class ResultStatus {
public:
  enum STATUS
  {
    ALL_CORRECT, FAILED, FILE_NOT_FOUND, INIT_ERROR
  };

protected:
  STATUS status;

public:
  ResultStatus(STATUS st = ALL_CORRECT) { status = ALL_CORRECT; }

  STATUS getStatus() { return status; }

  bool operator==(const ResultStatus& rhs) { return status == rhs.status;}
  bool operator!=(const ResultStatus& rhs) { return status != rhs.status;}
  bool operator==(const STATUS& st) { return status == st;}
  bool operator!=(const STATUS& st) { return status != st;}
};

class NetworkStatus : ResultStatus {

};