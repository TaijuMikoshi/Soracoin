/*!
@file    
@brief   Definition of Node class
*/

#pragma once

#include <memory>
#include <vector>
#include "Status.h"
#include "lib/httplib.h"
#include "BlockChain.h"
#include "FileHandler.h"
#include "JsonHandler.h"
#include "Log.h"
#include "Peer.h"

namespace QueryType {
  extern std::string transaction;
  extern std::string miningedblock;
  extern std::string getpeers;
  extern std::string introducepeers;
};

//using TxId = unsigned long long;
void binaryToTxId(unsigned char* data, int size, Block::TxId& id);

class ConfirmedTransaction {
public:
  std::string hash;
  int counter;

  ConfirmedTransaction() {
    counter = 0;
  }

  ConfirmedTransaction(std::string& hash) {
    counter = 0;
    this->hash = hash;
  }

  bool operator<(const ConfirmedTransaction& rhs) const {
    if (hash < rhs.hash) return true;
    if (hash > rhs.hash) return false;
    if (counter < rhs.counter) return true;
    
    return false;
  }
};

class Pool{
private:
  using LockGuard = std::lock_guard<std::mutex>;

  std::mutex txPoolMutex;
  std::map<std::string, std::string> _transactionPool;

  std::mutex confTxPoolMutex;
  std::set<ConfirmedTransaction> _confirmedTransactionHashPools;

  std::mutex conectedPeersMutex;
  std::map<Peer, std::shared_ptr<httplib::Client> > _conectedPeers;

  std::mutex blockRequestPeersMutex;
  std::map<Peer, int> _blockRequestPeers;

  std::mutex postDataMutex;
  httplib::MultipartFormDataItems _postDataPool;

public:
  Pool() {}
  ~Pool() {}

  size_t transactionPoolSize() { return _transactionPool.size(); }

  void addTransaction(const std::string& key, const std::string& data) {
    LockGuard lg(txPoolMutex);
    _transactionPool.insert(std::make_pair(key, data));
  }

  std::string getTransaction(const std::string& key) {
    LockGuard lg(txPoolMutex);
    const auto& it = _transactionPool.find(key);
    if (it == _transactionPool.end()) return "";
    
    return it->second;
  }

  bool hasTransaction(const std::string& key) {
    LockGuard lg(txPoolMutex);
    const auto& it = _transactionPool.find(key);
    return it != _transactionPool.end();
  }

  std::map<std::string, std::string> getTransaction() {
    LockGuard lg(txPoolMutex);
    return std::map<std::string, std::string>(_transactionPool);
  }

  size_t eraseTransaction(std::string& key) {
    LockGuard lg(txPoolMutex);
    return _transactionPool.erase(key);
  }

  size_t eraseTransaction(const std::shared_ptr<Block::Block>& block) {
    LockGuard lg(txPoolMutex);
    for (const auto& tx : block->txs()) {
      tx->calcHash();
      auto h = tx->hash();
      _transactionPool.erase(ToString(h));
    }
    return _transactionPool.size();
  }

  size_t eraseTransaction(const std::shared_ptr<Block::Tx>& tx) {
    LockGuard lg(txPoolMutex);
    tx->calcHash();
    auto h = tx->hash();
    _transactionPool.erase(ToString(h));
    return _transactionPool.size();
  }

  bool hasConfirmedTransaction(ConfirmedTransaction& c) {
    LockGuard lg(confTxPoolMutex);
    const auto& it = _confirmedTransactionHashPools.find(c);
    return it != _confirmedTransactionHashPools.end();
  }


  size_t conectedPeerPoolSize() { return _conectedPeers.size(); }

  void addConectedPeer(const Peer& p,std::shared_ptr<httplib::Client> c) {
    LockGuard lg(conectedPeersMutex);
    _conectedPeers.insert(std::make_pair(p,c));
  }

  std::map<Peer, std::shared_ptr<httplib::Client>> getConectedPeer() {
    LockGuard lg(conectedPeersMutex);
    return  std::map<Peer, std::shared_ptr<httplib::Client>>(_conectedPeers);
  }

  bool conected(const Peer& p) {
    return _conectedPeers.find(p) != _conectedPeers.end();
  }

  size_t eraseConectedPeer(const Peer& p) {
    LockGuard lg(conectedPeersMutex);
    return _conectedPeers.erase(p);
  }

  void addPostData(httplib::MultipartFormData data) {
    LockGuard lg(postDataMutex);
    _postDataPool.push_back(data);
  }

  void addPostData(std::string bin, std::string queryType) {
    httplib::MultipartFormData item{
      queryType, bin ,queryType, "application/octet-stream"
    };

    LockGuard lg(postDataMutex);
    _postDataPool.push_back(item);
  }

  httplib::MultipartFormDataItems getPostData() {
    LockGuard lg(postDataMutex);
    return httplib::MultipartFormDataItems(_postDataPool);
  }

  std::map<Peer, int> getBlockReqestPeers() {
    LockGuard lg(blockRequestPeersMutex);
    return std::map<Peer, int>(_blockRequestPeers);
  }

  int getBlockReqestPeers(Peer& p) {
    LockGuard lg(blockRequestPeersMutex);
    auto it = _blockRequestPeers.find(p);
    if (it != _blockRequestPeers.end()) return it->second;
    else return -1;
  }

  void setBlockIndexForBlockReqestPeers(const Peer& p, int n) {
    LockGuard lg(blockRequestPeersMutex);
    auto it = _blockRequestPeers.find(p);
    if (it != _blockRequestPeers.end()) {
      if (it->second < n) {
        _blockRequestPeers[p] = n;
      }
    }
    else {
      _blockRequestPeers.insert(std::make_pair(p, n));
    }
  }

  void eraseBlockReqestPeers(const Peer& p) {
    _blockRequestPeers.erase(p);
  }

  void clearPostData() { return _postDataPool.clear(); }

};

class Node {
private:
  ushort listenPort;
  std::string localIpAddr;

  ushort externalListenPort;
  std::string globalIpAddr;

  std::string rpcPassword;
  std::string rpcUser;

  ThreadStopFlag threadStop;

protected:

  httplib::Server svr;

  std::set<std::shared_ptr<Peer>> knownPeers;

  std::unique_ptr<std::thread> serverThread;
  std::unique_ptr<std::thread> clientThread;
  std::unique_ptr<std::thread> miningThread;

  BlockChainHandler bcHandler;
  JsonHandler jsonHandler;

  Pool pool;

  std::map<std::string, std::function<std::string(const httplib::MultipartFormData&)> > queryHandler;
  std::map<std::string, std::function<std::string(std::shared_ptr<RpcMethod::JsonParseResult>&)>> jsonQueryHandler;

  std::map<std::string, std::function<void(const httplib::Result&)> > responseHandler;

  Wallet wallet;

  std::vector<std::shared_ptr<Block::UTXO>> myUTXOs;

  void postBinayData();

  void broadCastPeerInfo();

  static void sleep(const int time) {
#ifdef _WIN32
    Sleep(time);
#else
    usleep((unsigned long)time * 1000);
#endif
  }

public:
  Node();
  ~Node();

  ResultStatus init(const std::string& walleFile, const std::string& peerInfoFile, const Parameters& param, const std::string& blockFileDirPath);

  ResultStatus serverStart();
  ResultStatus clientStart();
  ResultStatus minigStart();

  void clientProc();

  void listen();
  void waitToStopServer();
  void waitToStopClient();
  void waitToStopMinig();

  void HttpGetRequestHandler(const httplib::Request &, httplib::Response &res);
  void HttpPostRequestHandler(const httplib::Request &req, httplib::Response &res, const httplib::ContentReader &content_reader);
  
  std::string transactionQueryHandler(const httplib::MultipartFormData &file);
  std::string miningedBlockQueryHandler(const httplib::MultipartFormData &file);
  std::string getPeersQueryHandler(const httplib::MultipartFormData &file);
  void getPeersResponseHandler(const httplib::Result &res);
  std::string introducePeersQueryHandler(const httplib::MultipartFormData &file);
  std::string getBlockQueryHandler(const httplib::MultipartFormData &file);
  std::string sendBlockQueryHandler(const httplib::MultipartFormData &file);

  void sendStopReq();

  //void postBinayData(unsigned char* buff, int size, std::string& querayType);
  //void postBinayData(const std::string& msg, std::string& querayType);
  std::string sendMoney(std::shared_ptr<RpcMethod::JsonParseResult>& result);
  std::string generateAddress(std::shared_ptr<RpcMethod::JsonParseResult>& result);
  std::string getBlance(std::shared_ptr<RpcMethod::JsonParseResult>& result);
  std::string getBlanceDetail(std::shared_ptr<RpcMethod::JsonParseResult>& result);
  std::string showTransaction(std::shared_ptr<RpcMethod::JsonParseResult>& result);

  //void searchUTXO(std::string fromAddr, double moeny, std::vector<Block::UTXO>& utxos);

  //void calcMarklRoot(Block::Block& b);
  //void calcMarklRootWithoutMiningAward(Block::Block& b, Block::MarklRoot& root);

  void miningProc();
  void mining(int sleep);

  void getPeers();

  void sendBlock();

  void postBlockGetRequest();

  int getBlockHeight(){ return bcHandler.getBlockHeight(); }

  void stopSignal() {
    svr.stop();
    threadStop.signal(); 


  }

protected:
  ResultStatus initNetwork();
  ResultStatus initPeers(const std::string& filename);

  void searchMyUtxos();

};