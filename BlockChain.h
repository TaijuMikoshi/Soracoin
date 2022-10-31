#pragma once

#include <fstream>
#include <iostream>
#include <map>
#include <set>

#include "Block.h"
#include "Params.h"
#include "Block.h"

namespace File {
  class BlockFile;
}

class InputIndex {
public:
  const Block::TxId tx;
  const unsigned int index;

  InputIndex(Block::TxId t, unsigned int i) : tx(t), index(i) {
  }

  bool operator<(const InputIndex& rhs) const {
    if (tx < rhs.tx) return true;
    if (rhs.tx < tx) return false;
    if (index < rhs.index) return true;
    return false;
  }
};

struct BlockData {
  ulong index;
  uint confirmedCount;
  Block::BlockHeaderHash hash;
  std::shared_ptr <Block::Block> block;
};

class FullBlockChain {
public:
  using FlagType = byte;
private:
  int _index;
  int _confirmedCount;
  Block::BlockHeaderHash _hash;
  std::shared_ptr <Block::Block> _block;
  std::shared_ptr<FullBlockChain> _parent;
  std::shared_ptr<FullBlockChain> _child;
  std::set< std::shared_ptr<FullBlockChain> > _sibling;
  enum BlockSate {
    NORMAL = 0b00000000, INVALID = 0b10000000,
  };
  FlagType _flags;

public:
  const int& index() const { return _index; }
  void setIndex(int i) { _index = i; }

  const int& confirmedCount() const { return _confirmedCount; }
  void setConfirmedCount(int c) { _confirmedCount = c; }

  const Block::BlockHeaderHash& hash() const { return _hash; }
  void setHash(Block::BlockHeaderHash& h) { memcpy(_hash.hash, h.hash, sizeof(Block::BlockHeaderHash)); };

  const std::shared_ptr<Block::Block>& block() { return _block; }
  void setBlock(std::shared_ptr<Block::Block> b) { _block = b; }

  const std::shared_ptr<FullBlockChain>& parent() { return _parent; }
  void setParent(std::shared_ptr<FullBlockChain> bc) { _parent = bc; }

  const std::shared_ptr<FullBlockChain>& child() { return _child; }
  void setChild(std::shared_ptr<FullBlockChain> bc) { _child = bc; }

  const std::set< std::shared_ptr<FullBlockChain> >& sibling() { return _sibling; }
  void addSibling(std::shared_ptr<FullBlockChain> s) { _sibling.insert(s); }
  void eraseSibling(std::shared_ptr<FullBlockChain> s) { _sibling.erase(s); };

  const FlagType& flags() const { return _flags; }
  void setFlags(FlagType s) { _flags |= s; }

  FullBlockChain() {
    _index = 0;
    _confirmedCount = 0;
    memset(_hash.hash, 0, sizeof(Block::BlockHeaderHash));
    _block.reset();
    _parent.reset();
    _child.reset();
    _sibling.clear();
    _flags = NORMAL;
  }

};


struct BlockDataIndex {
  std::string fname;
  std::ios::pos_type offset;
};

class BlockChainHandler {
protected:
  static std::string directory;
  static std::string blocksFile;

  using LockGuard = std::lock_guard<std::mutex>;

  std::mutex mutex;

  std::shared_ptr<BlockData> genesisBlock;

  std::map<Block::BlockHeaderHash, std::shared_ptr<BlockData>> lastBlockData;
  std::map<Block::BlockHeaderHash, std::shared_ptr<BlockData>> orphan;

  std::map<InputIndex, std::shared_ptr<Block::Output>> allUtxo;

  std::map<Block::TxHash, BlockDataIndex> transactionHash;

  std::map<Block::BlockHeaderHash, BlockDataIndex> blockDataFileIndex;

  std::multimap<ulong, Block::BlockHeaderHash> blockDataHeightList;


  std::unique_ptr<File::BlockFile> bf;

private:
  bool isValidInput(InputIndex& input, std::string& unlockingscript, int& money);

  bool checkBlock(std::shared_ptr<Block::Block> b, const Block::BlockHeaderHash& headerHash);

  bool addBlock(std::shared_ptr<BlockData>& bd);
  
  std::shared_ptr<Block::Block> updateOrphanBlocks(std::shared_ptr<FullBlockChain>& bc);
  std::shared_ptr<BlockData> updateOrphanBlocks(std::shared_ptr <BlockData>& bd);

  void loadBlockFile(const std::string& blockFileDirPath);

public:
  static ResultStatus setDirectory(std::string dir);

public:

  BlockChainHandler() {}
  ~BlockChainHandler() {}

  ResultStatus init(const std::string& blockFileDirPath);

  bool addBlock(std::shared_ptr<Block::Block> b, BlockDataIndex index = {"", 0}, uint cinfirmedCound = 0);
  
  void findUTXO(const std::set<Wallet::PubPriAddr>& addrs, std::vector<std::shared_ptr<Block::UTXO>>& utxos);

  void getLastBlockHeaderHash(Block::BlockHeaderHash& hash);

  void updateUTXO(std::shared_ptr<Block::Block> b);

  void updateTransaction(std::shared_ptr<BlockData> b, BlockDataIndex index);

  const std::shared_ptr<Block::Tx> getTransaction(const std::string& hash);

  ulong getBlockHeight();

  std::shared_ptr<BlockData> getBlock(Block::BlockHeaderHash& hash);
  std::vector< std::shared_ptr<BlockData> > getBlock(ulong height);

  bool checkBlock(std::shared_ptr<Block::Block> b);

  std::vector<std::shared_ptr<Block::Tx>> getInvalidTransaction(std::shared_ptr<Block::Block> block);

  const Block::BlockHeaderHash getGenesisBlockHeaderHash() { return genesisBlock->hash; }

  void addBlockFileIndex(const Block::BlockHeaderHash&, const BlockDataIndex&);
  void addBlockHeight(const ulong Height, const Block::BlockHeaderHash& hash);
};