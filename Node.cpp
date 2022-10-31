#include <thread>
#include <assert.h>
#include <typeinfo> 
#include <iomanip>

#include "Node.h"
#include "Params.h"
#include "Block.h"
#include "Hash.h"
#include "Log.h"

namespace QueryType {
  std::string transaction = "transaction";
  std::string miningedblock = "miningedblock";
  std::string getpeers = "getpeers";
  std::string introducepeers = "introducepeers";
  std::string getblock = "getblock";
  std::string sendblock = "sendblock";
};

void binaryToTxId(unsigned char* data, int size, Block::TxId& id) {
  hashfunc.hash(data, size, id.value);
  return ;
}

Node::Node() {
  queryHandler.insert(std::make_pair(QueryType::transaction, std::bind(&Node::transactionQueryHandler, std::ref(*this), std::placeholders::_1)));
  queryHandler.insert(std::make_pair(QueryType::miningedblock, std::bind(&Node::miningedBlockQueryHandler, std::ref(*this), std::placeholders::_1)));
  queryHandler.insert(std::make_pair(QueryType::getpeers, std::bind(&Node::getPeersQueryHandler, std::ref(*this), std::placeholders::_1)));
  queryHandler.insert(std::make_pair(QueryType::introducepeers, std::bind(&Node::introducePeersQueryHandler, std::ref(*this), std::placeholders::_1)));
  queryHandler.insert(std::make_pair(QueryType::getblock, std::bind(&Node::getBlockQueryHandler, std::ref(*this), std::placeholders::_1)));
  queryHandler.insert(std::make_pair(QueryType::sendblock, std::bind(&Node::sendBlockQueryHandler, std::ref(*this), std::placeholders::_1)));

  responseHandler.insert(std::make_pair(QueryType::getpeers, std::bind(&Node::getPeersResponseHandler, std::ref(*this), std::placeholders::_1)));

  jsonQueryHandler.insert(std::make_pair(RpcMethod::sendmoney, std::bind(&Node::sendMoney, std::ref(*this), std::placeholders::_1)));
  jsonQueryHandler.insert(std::make_pair(RpcMethod::generateaddress, std::bind(&Node::generateAddress, std::ref(*this), std::placeholders::_1)));
  jsonQueryHandler.insert(std::make_pair(RpcMethod::getbalance, std::bind(&Node::getBlance, std::ref(*this), std::placeholders::_1)));
  jsonQueryHandler.insert(std::make_pair(RpcMethod::getbalancedetail, std::bind(&Node::getBlanceDetail, std::ref(*this), std::placeholders::_1)));
  jsonQueryHandler.insert(std::make_pair(RpcMethod::showtransaction, std::bind(&Node::showTransaction, std::ref(*this), std::placeholders::_1)));
}

Node::~Node() {

}

ResultStatus Node::init(const std::string& walleFile, const std::string& peerInfoFile, const Parameters& param, const std::string& blockFileDirPath) {
  wallet.loadWallet(walleFile);

  bcHandler.init(blockFileDirPath);

  searchMyUtxos();

  initNetwork();

  localIpAddr = param.localIpAddress();
  listenPort = param.listenPort();

  globalIpAddr = param.globalIpAddress();
  externalListenPort = param.externalPort();

  rpcPassword = param.rpcPassword();
  rpcUser = param.userName();

  initPeers(peerInfoFile);

  return ResultStatus();
}

void Node::HttpGetRequestHandler(const httplib::Request &req, httplib::Response &res) {
  if (req.has_param("stop")) {
    res.set_content("stopping server", "text/plain");
    this->svr.stop();
  }
  else if (req.has_param("nodesInfo")) {
    auto info = new std::string("172.16.1.3:8080");

    res.set_content_provider(
      info->size(), "application/octet-stream",
      [info](size_t offset, size_t length, httplib::DataSink &sink) {
        const auto &d = *info;
        sink.write(&d[offset], std::min(length, (size_t)4));
        return true;
      },
      [info](bool success) {delete info; }
    );
      
  }
  else {
    res.set_content("Hello World", "text/plain");
  }
}

void Node::HttpPostRequestHandler(const httplib::Request &req, httplib::Response &res, const httplib::ContentReader &content_reader) {
  if (req.is_multipart_form_data()) {
    httplib::MultipartFormDataItems files;
    content_reader(
      [&](const httplib::MultipartFormData &file) {
        files.push_back(file);
        return true;
    },
      [&](const char *data, size_t data_length) {
        files.back().content.append(data, data_length);
        return true;
    });
    
    for (auto it = files.begin(); it != files.end(); ++it) {
#ifdef _DEBUG
      std::cout << it->filename << std::endl;
      std::cout << it->content_type << std::endl;
      std::cout << it->name << std::endl;
#endif
      auto handler = queryHandler.find(it->name);
      if (handler != queryHandler.end()) {
        auto ret = handler->second(*it);
        res.body.append(ret);
      }
    }

  }else{ // RPC method
    std::string body;
    content_reader([&](const char *data, size_t data_length) {
      body.append(data, data_length);
      return true;
    });
    json j = jsonHandler.setJsonByString(body);
#ifdef _DEBUG
    std::cout << j["jsonrpc"] << std::endl;
    std::cout << j["method"] << std::endl;
#endif
    auto parseState = jsonHandler.parse();
    if (parseState == JsonHandler::NO_ERROR_JSON) {
      auto result = jsonHandler.getParseResult();
      try {
        std::string ret = jsonQueryHandler[result->getMethod()](result);
        res.body.append(ret);
        if (res.body.back() != '\n') res.body.push_back('\n');
      }catch(std::exception& e) {
        logging(e.what());
        std::stringstream ss;
        ss << "method : "<< j["method"];
        res.body.append(" is not support\n");
      }
    }
    else {
      std::stringstream ss;
      ss << "json parse error : " << parseState << std::endl;
      res.body.append(ss.str());
    }
  }
  auto size = req.files.size();
}

std::string Node::transactionQueryHandler(const httplib::MultipartFormData &file) {
  std::cout << file.name << std::endl;  
  std::cout << file.content.length() << std::endl;
  Block::Tx tx(file.content);
  tx.calcHash();
  std::string hash((char*)tx.hash().value, Block::TxHashSize);

  if (!pool.hasTransaction(hash)) {
    pool.addTransaction(hash, file.content);
    pool.addPostData(file);
    //this->postBinayData(file.content, QueryType::transaction);
  }

  return "success";
}

ResultStatus Node::initNetwork() {
  svr.Get("/", [&](const httplib::Request &req, httplib::Response &res) {
    this->HttpGetRequestHandler(req, res);
  });

  svr.Post("/", [&](const httplib::Request& req, httplib::Response &res, const httplib::ContentReader &content_reader) {
    this->HttpPostRequestHandler(req, res, content_reader);
  });

  return ResultStatus();
}

ResultStatus Node::initPeers(const std::string& filename) {
  std::ifstream ifs(filename);
  if (!ifs) return ResultStatus(ResultStatus::FILE_NOT_FOUND);

  while (!ifs.eof()) {
    std::string buff;
    std::getline(ifs, buff);
    auto pos = buff.find(":");
    if (pos == std::string::basic_string::npos) continue;

    std::string ipaddress(buff.data(), pos);
    std::string portStr(&buff.c_str()[pos+1], buff.length() - pos - 1);
    uint port = std::atoi(portStr.c_str());

    std::shared_ptr<Peer> p = std::shared_ptr<Peer>(new Peer(ipaddress, port));
    if(p->isInit()) knownPeers.insert(p);
  }

  int n = knownPeers.size();
  n = n > 10 ? 10 : n;
  for(const auto& p : knownPeers){
    if (--n < 0) break;
    std::string uri("http://");
    uri.append(p->ipaddress());
    uri.append(":");
    uri.append(std::to_string(p->port()));
   // conectedPeers.push_back(std::shared_ptr<httplib::Client>(new httplib::Client(uri)));
    pool.addConectedPeer(Peer(p->ipaddress(), p->port()), std::shared_ptr<httplib::Client>(new httplib::Client(uri)));
  }
  return ResultStatus(ResultStatus::ALL_CORRECT);
}

void Node::listen() {
  svr.listen("0.0.0.0", listenPort);
}

ResultStatus Node::serverStart() {
  serverThread.reset(new std::thread(&Node::listen, this));
  return ResultStatus();
}

ResultStatus Node::clientStart() {
  clientThread.reset(new std::thread(&Node::clientProc, this));
  return ResultStatus();
}

ResultStatus Node::minigStart() {
  miningThread.reset(new std::thread(&Node::miningProc, this));
  return ResultStatus();
}

void Node::clientProc() {
  while (!threadStop) {
    int time = 1000; // msec
    Node::sleep(time);

    postBinayData();
    postBlockGetRequest();
    sendBlock();

    broadCastPeerInfo();
  }
}

void Node::waitToStopServer() {
  serverThread->join();
}

void Node::waitToStopClient() {
  clientThread->join();
}

void Node::waitToStopMinig() {
  miningThread->join();
}


void Node::sendStopReq() {
//  cli->Post("/", "{\"UserName\":\"abcererJson\"}", "text/plane");
}

void Node::postBinayData() {
  const auto& conectedPeers = pool.getConectedPeer();
  httplib::MultipartFormDataItems items = pool.getPostData();
  if (items.size() <= 0) return;

  for (auto &item : items) {
    for (auto it = conectedPeers.begin(); it != conectedPeers.end(); ++it) {
      httplib::MultipartFormDataItems data = { item };
      auto response = it->second->Post("/", data);
      if (response.error() == httplib::Error::Connection) {
        auto t = *it;
        pool.eraseConectedPeer(it->first);
      }
      
      auto handler = responseHandler.find(item.name);
      if (handler != responseHandler.end()) {
        handler->second(response);
      }
    }
  }
  pool.clearPostData();
}

//void Node::postBinayData(const std::string& msg, std::string& querayType) {
//  httplib::MultipartFormData item = { querayType, msg, querayType, "application/octet-stream" };
//  pool.addPostData(item);
//}
//
//void Node::postBinayData(unsigned char* buff, int size, std::string& querayType) {
//  std::string s(buff, buff+size);
//  postBinayData(s, querayType);
//}


std::string Node::sendMoney(std::shared_ptr<RpcMethod::JsonParseResult>& result) {
  auto sendmoney = std::dynamic_pointer_cast<RpcMethod::SendMoney>(result);
  if (sendmoney == NULL) {
    return "json format error";
  }

  std::cout << "sendmoney" << std::endl;
  std::cout << sendmoney->fromAddr << std::endl;

  unsigned int totalMoeny = sendmoney->fee;
  for (auto m : sendmoney->money) { totalMoeny += m; }
  
  searchMyUtxos();
  std::vector<std::shared_ptr<Block::UTXO>> utxos;
  unsigned int sum = 0;
  for (auto it = myUTXOs.begin(); it != myUTXOs.end(); ) {
    if (AddressToString((*it)->toAddr) == sendmoney->fromAddr) {
      sum += (*it)->money;

      wallet.makeUnLockingScript((*it)->script, sendmoney->fromAddr, (*it)->unLockingScript);

      utxos.push_back(*it);

      it = myUTXOs.erase(it);
      if (sum >= totalMoeny) {
        break;
      }
    }
    if (sum >= totalMoeny) { break;}
    ++it;
  }

  Block::Tx tx;
  for(auto utxo : utxos){
    tx.in.push_back(std::shared_ptr<Block::Input>(new Block::Input(utxo.get())));
  }
  
  for (uint i = 0; i < sendmoney->toAddrs.size(); i++) {
    auto o = std::shared_ptr<Block::Output>(new Block::Output(sendmoney->toAddrs[i], sendmoney->money[i], sendmoney->message[i]));

    std::string sigMsg = o->forSignatureMsg();
    std::string sig;
    std::string pubkey;
    auto result = wallet.signature(sigMsg, sendmoney->fromAddr, sig, pubkey);
    if (result != Wallet::Status::SUCCESS) { return ""; }
    o->setSignature(pubkey, sig);

    tx.out.push_back(o);
  }

  if (sum > totalMoeny) {
    tx.out.push_back(std::shared_ptr<Block::Output>(new Block::Output(sendmoney->fromAddr, sum - totalMoeny)));
  }

  tx.lockTime = 0;
  tx.calcHash();
  
  std::string bin = tx.getBinary();

  std::string hash = std::string((char*)tx.hash().value, Block::TxHashSize);
  //transactionPool.insert(std::make_pair(hash, bin));
  httplib::MultipartFormData item{
    QueryType::transaction, bin ,QueryType::transaction, "application/octet-stream"
  };
  transactionQueryHandler(item);

  //this->postBinayData(bin, QueryType::transaction);

  std::stringstream ss;
  for (auto& s : hash) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (s & 0xFF);
  }
  return ss.str();
}

std::string Node::generateAddress(std::shared_ptr<RpcMethod::JsonParseResult>& result) {
  auto gen = std::dynamic_pointer_cast<RpcMethod::GenerateAddress>(result);
  if (gen == NULL) return "json format error";

  std::string pub;
  std::string priv;
  std::string addr;
  wallet.createAddress(pub, priv, addr);

  return addr;
}

std::string Node::getBlance(std::shared_ptr<RpcMethod::JsonParseResult>& result) {
  auto get = std::dynamic_pointer_cast<RpcMethod::GetBalance>(result);
  if (get == NULL) return "json format error";

  searchMyUtxos();

  int balance = 0;
  for (auto out : myUTXOs) {
    if (wallet.hasAddr(AddressToString(out->toAddr))) {
      balance += out->money;
    }
  }

  std::stringstream ss;
  ss << "balace : " << balance;

  return ss.str();
}

std::string Node::getBlanceDetail(std::shared_ptr<RpcMethod::JsonParseResult>& result) {
  auto get = std::dynamic_pointer_cast<RpcMethod::GetBalanceDetail>(result);
  if (get == NULL) return "json format error";

  searchMyUtxos();

  std::map<std::string, int> balance;
  for (auto out : myUTXOs) {
    std::string addr = AddressToString(out->toAddr);
    if (wallet.hasAddr(addr)) {
      int m = out->money;
      auto it = balance.find(addr);
      if (it != balance.end()) {
        it->second += m;
      }
      else {
        balance.insert(std::make_pair(addr, m));
      }
    }
  }

  std::stringstream msg;
  int total = 0;
  auto addrs = wallet.getAddress();
  for (auto addr : addrs) {
    auto it = balance.find(addr.address);
    if (it != balance.end()) {
      msg << it->first << " : " << it->second << std::endl;
      total += it->second;
    }
    else {
      msg << addr.address << " : " << 0 << std::endl;
    }
  }
  msg << "---" << std::endl;
  msg << "total : " << total << std::endl;

  return msg.str();
}

std::string Node::showTransaction(std::shared_ptr<RpcMethod::JsonParseResult>& result) {
  auto show = std::dynamic_pointer_cast<RpcMethod::ShowTransaction>(result);
  if (show == NULL) return "json format error";

  std::string hash = std::string((char*)show->getTxId().value, Block::TxHashSize);
  
  ConfirmedTransaction h(hash);
  //auto it = confirmedTransactionHashPools.find(h);
  //if (it != confirmedTransactionHashPools.end()) {
  //  std::stringstream ss;
  //  ss << it->counter << std::endl;
  //  return ss.str();
  //}
  if (pool.hasConfirmedTransaction(h)) {
    std::stringstream ss;
    ss << h.counter << std::endl;
    return ss.str();
  }

  //auto um = pool.getTransaction(hash);//transactionPool.find(hash);
  //if (um != "") {
  //  std::cout << "unmining" << std::endl;
  //}

  const std::shared_ptr<Block::Tx> tx = bcHandler.getTransaction(hash);
  if(tx == nullptr) return "not found";

  std::string info = tx->getInfo();
  return info;
}

void Node::miningProc() {
  while (!threadStop) {
    Node::sleep(1); // msec
    mining(1);
  }
}

void Node::mining(int sleep) {
  if (pool.transactionPoolSize() <= 0) {
    return;
  }

  Block::Block block;
  uint totalSize = 0;
  const auto& transactionPool = pool.getTransaction();
  for (auto it = transactionPool.begin(); it != transactionPool.end(); ++it) {
    if (totalSize + it->second.length() > Block::MAX_BLOCK_SIZE) {
      break;
    }

    std::shared_ptr<Block::Tx> tx = std::shared_ptr<Block::Tx>(new Block::Tx(it->second));

    totalSize += tx->binarySize();
    block.add(tx);
  }

  block.setBlockVersion(0x0001);
  block.setCurrentTime();

  std::string pub;
  std::string priv;
  std::string miningAddr;
  wallet.getAddress(miningAddr);
  if (miningAddr.length() == 0) {
    wallet.createAddress(pub, priv, miningAddr);
  }
  else {
    wallet.getPublicPrivateKey(miningAddr, pub, priv);
  }

  Block::BlockHeaderHash privHash;
  bcHandler.getLastBlockHeaderHash(privHash);
  block.setPreviousBlockHeaderHash(privHash);
  block.setMiningReward(miningAddr, pub, priv);

  char diff[hashfunc.HASH_LENGTH];
  memset(diff, 0, sizeof(diff));
  diff[0] = 0x01;
  block.setDiffculty(diff);

  std::shared_ptr<Block::Input> coinbase = block.txs()[0]->in[0];

  byte hash[hashfunc.HASH_LENGTH];
  while (1) {
    block.txs()[0]->calcHash();
    block.calcMarklRoot();
    hashfunc.hash((byte*)&(block.header()), sizeof(Block::BlockHeader), hash);

#ifdef _DEBUG__
    Block::printCharStyleHash(hash);
    printf("\n");
    Block::printCharStyleHash(block.header().marklRoot.hash);
    printf("\n");
    printTxHash(block.txs[0]->hash());
    printf("\n");
#endif
    if (hash < block.header().difficulty) {
      auto bin = block.getBinary();
      //bcHandler.addBlock(std::unique_ptr<Block::Block>(new Block::Block(block)));
      httplib::MultipartFormData items = {
        QueryType::miningedblock, bin, QueryType::miningedblock, "application/octet-stream",
      };
      miningedBlockQueryHandler(items);

      //postBinayData(bin, QueryType::miningedblock);

#ifdef _DEBUG
      Block::printCharStyleHash(hash);
      printf("\n");
#endif
      break;
    }

    // update nonce in a coinbase transaction
    coinbase->updateNonce(1);

    //Node::sleep(sleep); // msec
  }
}

void Node::getPeers() {
  std::string peers;

  const ushort num = knownPeers.size();
  peers.assign((char*)&num, sizeof(num));
  for (const auto& p : knownPeers) {
    std::string bin = p->getBinary();
    const ushort size = bin.length();
    peers.append((char*)&size, sizeof(size));
    peers.append(bin.begin(), bin.end());
  }

  httplib::MultipartFormData item{
    QueryType::getpeers, peers ,QueryType::getpeers, "application/octet-stream"
  };
  pool.addPostData(item);
  //postBinayData(peers, QueryType::getpeers);
}

std::string Node::miningedBlockQueryHandler(const httplib::MultipartFormData &file) {
  std::shared_ptr<Block::Block> block = std::shared_ptr<Block::Block>(new Block::Block(file.content));

#ifdef _DEBUG
  std::cout << Block::AddressToString(block->txs().back()->out[0]->toAddr) << std::endl;
#endif
  
  if (bcHandler.addBlock(block)) {
    pool.eraseTransaction(block);
    pool.addPostData(file);
    return "confirming";
  }
  else {
    auto txs = bcHandler.getInvalidTransaction(block);
    for (auto& tx : txs) {
      pool.eraseTransaction(tx);
    }
  }

  return "invalid block";
}

void Node::getPeersResponseHandler(const httplib::Result &res) {
  std::cout << res->body << std::endl;

}

std::string Node::getPeersQueryHandler(const httplib::MultipartFormData &file) {
#ifdef _DEBG
  std::cout << "getPeers" << std::endl;
#endif

  std::set<std::shared_ptr<Peer>> introducedPeers;

  const std::string& bin = file.content;
  if (bin.length() >= sizeof(ushort)) {
    const ushort num = *(ushort*)&(bin.c_str()[0]);
    uint readSize = sizeof(num);
    for (uint i = 0; i < num; i++) {
      if (bin.length() <= readSize + sizeof(ushort)) break;

      const ushort size = *(ushort*)&(bin.c_str()[readSize]);
      readSize += sizeof(size);

      if (bin.length() < readSize + size) break;

      std::string peer(&bin.c_str()[readSize], size);
      introducedPeers.insert(std::shared_ptr<Peer>(new Peer(peer)));
    }
  }

  std::vector<std::shared_ptr<Peer>> itroducingPeers;
  for (const auto& p : knownPeers) {
    if (introducedPeers.find(p) == introducedPeers.end()) {
      itroducingPeers.push_back(p);
    }
  }

  for (const auto& p : introducedPeers) {
    if (knownPeers.find(p) == knownPeers.end()) {
      knownPeers.insert(p);
    }
  }

  std::string response;
  
  const ushort num = itroducingPeers.size();
  response.assign((char*)&num, sizeof(num));

  for (const auto& p : introducedPeers) {
    std::string data = p->getBinary();
    const ushort s = data.length();
    response.append((char*)&s, sizeof(s));
    response.append(data.begin(), data.end());
  }

  return response;
}

std::string Node::introducePeersQueryHandler(const httplib::MultipartFormData &file) {
  Peer p(file.content);
  if (!pool.conected(p)) {
    std::string uri("http://");
    uri.append(p.ipaddress());
    uri.append(":");
    uri.append(std::to_string(p.port()));
    pool.addConectedPeer(p, std::shared_ptr<httplib::Client>(new httplib::Client(uri)));
#ifdef _DEBUG
    std::cout << "newly connected";
#endif
    return "addToConnectedPeer";
  }

  return "already known";
}

void Node::postBlockGetRequest() {
  auto h = getBlockHeight() + 1;
  Peer p(localIpAddr, listenPort);

  std::string bin = p.getBinary();
  bin.append(":");
  bin.append((char*)&h, sizeof(h));

  httplib::MultipartFormData item{
    QueryType::getblock, bin ,QueryType::getblock, "application/octet-stream"
  };
  pool.addPostData(item);
}

std::string Node::getBlockQueryHandler(const httplib::MultipartFormData &file) {
  std::string bin = file.content;

  Peer p(bin);

  if (bin.length() != 1 + p.ipaddress().length() + sizeof(p.port()) + 1 + sizeof(getBlockHeight())) return "";

  int height = *(int*)(bin.c_str() + 1 + p.ipaddress().length() + sizeof(p.port()) + 1);
  int myBlockHeight = getBlockHeight();

  if (height > myBlockHeight) { return "up to date." ; }

  pool.setBlockIndexForBlockReqestPeers(p, height);

  return "Please wait to recive blocks.";
}

std::string Node::sendBlockQueryHandler(const httplib::MultipartFormData &file) {
  miningedBlockQueryHandler(file);
  return "";
}

void Node::broadCastPeerInfo() {
  Peer p(localIpAddr, listenPort);
  httplib::MultipartFormData item{
    QueryType::introducepeers, p.getBinary() ,QueryType::introducepeers, "application/octet-stream"
  };
  pool.addPostData(item);

  //postBinayData(p.getBinary(), QueryType::introducepeers);
}

void Node::sendBlock() {
  auto peers = pool.getBlockReqestPeers();

  for (auto p : peers) {
    auto b = bcHandler.getBlock(p.second);

    httplib::MultipartFormDataItems items;
    for (auto block : b) {
      httplib::MultipartFormData item{
        QueryType::sendblock, block->block->getBinary() ,QueryType::sendblock, "application/octet-stream"
      };
      items.push_back(item);
    }
    httplib::Client cli(p.first.getUri());
    cli.Post("/", items);


    pool.eraseBlockReqestPeers(p.first);
    //pool.setBlockIndexForBlockReqestPeers(p.first, p.second + 1);
  }
}

void Node::searchMyUtxos() {
  myUTXOs.clear();
  bcHandler.findUTXO(wallet.getAddress(), myUTXOs);
}



