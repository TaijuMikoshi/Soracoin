#include "BlockChain.h"

#include <iostream>
#include <stack>
#include "Log.h"
#include "FileHandler.h"

std::string BlockChainHandler::directory = "./";
std::string BlockChainHandler::blocksFile = "block";

ResultStatus BlockChainHandler::setDirectory(std::string dir) {
  directory = dir;
  return ResultStatus();
}

ResultStatus BlockChainHandler::init(const std::string& blockFileDirPath) {
  //mainChain.reset(new FullBlockChain());
  genesisBlock.reset(new BlockData());
  std::shared_ptr<Block::Block> b(new Block::Block());
  //mainChain->setBlock(b);
  genesisBlock->block = b;

  Block::Output* out = new Block::Output();
  std::string genAddr("netw13QfeuzDutNAXA9ca4nodNBg6kEqAMCYe14tUHoQMMUN6NV");
  out->setOutput(genAddr, 1000000);
  Block::Tx* t = new Block::Tx();
  t->out.push_back(std::shared_ptr<Block::Output>(out));
  t->out.back()->msg.append("I thought what I'd do was, I'd pretend I was one of those deaf-mutes.");
  t->calcHash();
  genesisBlock->block->add(std::shared_ptr<Block::Tx>(t));


  Block::BlockHeaderHash hash;
  hashfunc.hash((unsigned char*)&genesisBlock->block->header(), sizeof(genesisBlock->block->header()), hash.hash);
  genesisBlock->hash = hash;
  genesisBlock->confirmedCount = 0xFFFFFFFF;

  //lastBlockOfMainChain = mainChain;
  allUtxo.insert(std::make_pair(InputIndex(t->hash(), 0), t->out[0]));
  //lastBlocks.insert(std::make_pair(mainChain->hash(), mainChain));

  lastBlockData.insert(std::make_pair(hash, genesisBlock));

  loadBlockFile(blockFileDirPath);

  return ResultStatus();
}

ulong BlockChainHandler::getBlockHeight() {
  ulong index = genesisBlock->index;
  for (auto block : lastBlockData) {
    if (index < block.second->index) {
      index = block.second->index;
    }
  }
  return index;
}

std::shared_ptr<BlockData> BlockChainHandler::updateOrphanBlocks(std::shared_ptr <BlockData>& bd) {
  LockGuard lg(mutex);
  auto it = orphan.find(bd->hash);
  if (it != orphan.end()) {
    std::shared_ptr<BlockData> p = it->second;
    orphan.erase(it);
    return p;
  }
  else {
    return nullptr;
  }
}

bool BlockChainHandler::addBlock(std::shared_ptr <Block::Block> b, BlockDataIndex index, uint confirmedCound) {
  std::shared_ptr <BlockData> bd(new BlockData());
  bd->block = b;
  bd->confirmedCount = confirmedCound;
  bd->index = 0;
  hashfunc.hash((unsigned char*)&b->header(), sizeof(b->header()), bd->hash.hash);

  if (!checkBlock(b, bd->hash)) return false;

  if (addBlock(bd)) {
    if (index.fname == "") {
      index = bf->writeBlock(bd);
    }
    addBlockFileIndex(bd->hash, index);
    addBlockHeight(bd->index, bd->hash);
    updateTransaction(bd, index);
    auto p = updateOrphanBlocks(bd);
    if (p != nullptr) {
      addBlock(p->block);
    }
  }

  updateUTXO(bd->block);
  return true;
}



bool BlockChainHandler::addBlock(std::shared_ptr<BlockData>& bd) {
  LockGuard lg(mutex);
  auto it = lastBlockData.find(bd->block->header().previousBlockHash);
  if (it == lastBlockData.end()) {
    orphan.insert(std::make_pair(bd->block->header().previousBlockHash, bd));
    return false;
  }

  std::shared_ptr<BlockData> prevBlock = it->second;
  lastBlockData.erase(it);

  bd->index = prevBlock->index + 1;
  lastBlockData.insert(std::make_pair(bd->hash, bd));

  return true;
}

void BlockChainHandler::findUTXO(const std::set<Wallet::PubPriAddr>& addrs, std::vector<std::shared_ptr<Block::UTXO>>& utxos) {
  for (auto utxo : allUtxo) {
    int i = utxo.first.index;
    for (auto addr : addrs) {
      if (std::string((char*)utxo.second->toAddr.addr, sizeof(utxo.second->toAddr.addr)) == addr.address) {
        utxos.push_back(std::shared_ptr<Block::UTXO>(new Block::UTXO(utxo.second, utxo.first.tx, utxo.first.index)));
        break;
      }
    }
  }
}

void BlockChainHandler::getLastBlockHeaderHash(Block::BlockHeaderHash& hash) {
  std::shared_ptr<BlockData> bd = genesisBlock;;
  for (auto it = lastBlockData.begin(); it != lastBlockData.end(); ++it) {
    if (bd->index < it->second->index) {
      bd = it->second;
    }
  }
  memcpy(hash.hash, bd->hash.hash, sizeof(Block::BlockHeaderHash));
}

bool BlockChainHandler::checkBlock(std::shared_ptr<Block::Block> b) {
  Block::BlockHeaderHash hash;
  hashfunc.hash((unsigned char*)&b->header(), sizeof(b->header()), hash.hash);
  return checkBlock(b, hash);
}

bool BlockChainHandler::checkBlock(std::shared_ptr<Block::Block> b, const Block::BlockHeaderHash& headerHash) {
  int numOfCoinbase = 0;
  int coinbasePos = -1;
  int totalInputMoney = 0;
  int totalOutputMoney = 0;
  std::set<InputIndex> inputIndexies;

  if (b->header().difficulty < headerHash) return false;

  for (int i = 0; i < b->txs().size(); i++) {
    for (auto in : b->txs()[i]->in) {
      if (in->check(Block::CoinbaseInput::CoinbaseOuputTxId, Block::CoinbaseInput::CoinbaseOutputTxNumber)) {
        numOfCoinbase++;
        if (numOfCoinbase > 1) return false;
        coinbasePos = i;
      }
      else {
        InputIndex iIndex(in->outputTxId, in->outputTxNumber);
        int money;
        if (!isValidInput(iIndex, in->script, money)) return false;

        size_t size = inputIndexies.size();
        inputIndexies.insert(iIndex);
        if (size == inputIndexies.size()) return false;

        totalInputMoney += money;
      }
    }
    for (const auto& out : b->txs()[i]->out) {
      if (!out->chceck()) return false;
      totalOutputMoney += out->money;
    }
  }

  int sub = totalOutputMoney - (totalInputMoney + Block::MiningReward);
  if (sub != 0) return false;
  b->setChecked(true);

  return true;
}

std::vector<std::shared_ptr<Block::Tx>> BlockChainHandler::getInvalidTransaction(std::shared_ptr<Block::Block> b) {
  std::set<int> invalidTxIndex;
  for (int i = 0; i < b->txs().size(); i++) {
    for (auto in : b->txs()[i]->in) {
      if (in->check(Block::CoinbaseInput::CoinbaseOuputTxId, Block::CoinbaseInput::CoinbaseOutputTxNumber)) {
        continue;
      }
      else {
        InputIndex iIndex(in->outputTxId, in->outputTxNumber);
        int money;
        if (!isValidInput(iIndex, in->script, money)) {
          invalidTxIndex.insert(i);
          break;;
        }
      }
    }
    for (const auto& out : b->txs()[i]->out) {
      if (!out->chceck()) {
        invalidTxIndex.insert(i);
        break;
      }
    }
  }

  std::vector<std::shared_ptr<Block::Tx>> invalidTxs;
  for (int i = 0; i < b->txs().size(); i++) {
    invalidTxs.push_back(b->txs()[i]);
  }

  return invalidTxs;
}

bool BlockChainHandler::isValidInput(InputIndex& input, std::string& unlockingscript, int& money) {
  auto output = allUtxo.find(input);
  if (output == allUtxo.end()) return false;

  money = output->second->money;

  return Block::execScript(unlockingscript, output->second->script);
}

void BlockChainHandler::updateUTXO(std::shared_ptr<Block::Block> b) {
  LockGuard lg(mutex);

  if (!b->isChecked()) {
    Block::BlockHeaderHash hash;
    hashfunc.hash((unsigned char*)&b->header(), sizeof(b->header()), hash.hash);
    if (!checkBlock(b, hash)) return;
  }

  for (int i = 0; i < b->txs().size(); i++) {
    for (const auto& in : b->txs()[i]->in) {
      if (in->check(Block::CoinbaseInput::CoinbaseOuputTxId, Block::CoinbaseInput::CoinbaseOutputTxNumber)) {
        continue;
      }
      else {
        InputIndex iIndex(in->outputTxId, in->outputTxNumber);
        auto it = allUtxo.find(iIndex);
        if (it == allUtxo.end()) {
          logging("UTXO error!");
        }
        allUtxo.erase(it);
      }
    }
    for (int n = 0; n < b->txs()[i]->out.size(); n++) {
      b->txs()[i]->out[n]->getBinary();
      b->txs()[i]->calcHash();
      allUtxo.insert(std::make_pair(InputIndex(b->txs()[i]->hash(), n), b->txs()[i]->out[n]));
    }
  }
}

void BlockChainHandler::updateTransaction(std::shared_ptr<BlockData> b, BlockDataIndex index) {
  LockGuard lg(mutex);
  for (auto tx : b->block->txs()) {
    transactionHash.insert(std::make_pair(tx->hash(), index));
  }
}

const std::shared_ptr<Block::Tx> BlockChainHandler::getTransaction(const std::string& hash) {
  auto it = transactionHash.find(Block::StringToTxHash(hash));
  if (it == transactionHash.end()) return nullptr;

  auto block = bf->getBlock(it->second);
  for (auto& tx : block->block->txs()) {
    if (tx->hash() == hash) {
      return tx;
    }
  }
  return nullptr;
}


std::shared_ptr<BlockData> BlockChainHandler::getBlock(Block::BlockHeaderHash& hash) {
  auto it = blockDataFileIndex.find(hash);
  if (it == blockDataFileIndex.end()) {
    return nullptr;
  }
  return bf->getBlock(it->second);
}

std::vector< std::shared_ptr<BlockData> > BlockChainHandler::getBlock(ulong height) {
  std::vector< std::shared_ptr<BlockData> > blocks;
  auto r = blockDataHeightList.equal_range(height);
  for (auto it = r.first; it != r.second; ++it) {
    auto b = getBlock(it->second);
    if(b != nullptr) blocks.push_back(b);
  }
  
  return blocks;
}

void BlockChainHandler::addBlockFileIndex(const Block::BlockHeaderHash& hash, const BlockDataIndex& index) {
  LockGuard lg(mutex);
  blockDataFileIndex.insert(std::make_pair(hash, index));
}

void BlockChainHandler::addBlockHeight(const ulong Height, const Block::BlockHeaderHash& hash) {
  LockGuard lg(mutex);
  blockDataHeightList.insert(std::make_pair(Height, hash));
}

void BlockChainHandler::loadBlockFile(const std::string& blockFileDirPath) {
  bf.reset(new File::BlockFile(blockFileDirPath));
  bf->loadBlock(*this);
}