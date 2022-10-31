#pragma once
#include <string>
#include <sstream>
#include <ios>  
#include <iomanip>
#include <fstream>
#include <assert.h>

#include "Block.h"
#include "BlockChain.h"

// maximum 10,000 blocks in a blockXXXXXXXX.dat
// For exsample;
// block00000000.dat has block#0 to block#9,999 , 
// block00000001.dat has block#10,000 to block#19,999

namespace File {
  //struct BlockData {
  //  std::string block;
  //  FullBlockChain::FlagType flags;
  //  Block::BlockHeaderHash childHash;
  //};

  class BlockFile {
  private:
    static const std::string prefix;
    static const std::string suffix;
    static const unsigned char digits = 8;
    static const unsigned int MaxBlock = 10000;
    using Version = byte;
    using BlockCount = ushort;

    std::string dir;

    unsigned long lastWriteBlock;

  public:
    BlockFile(const std::string& path) {
      dir = path;
      if (dir.back() != '/') dir.append("/");
      lastWriteBlock = 0;
    }


    void loadBlock(BlockChainHandler& bch);

    std::shared_ptr<BlockData> getBlock(BlockDataIndex& index);

    BlockDataIndex writeBlock(const std::shared_ptr<BlockData>& bd);

    void writeFileHeader(std::fstream& fs);

    void updateBlockNum(std::fstream& fs, BlockCount num);

    BlockCount readBlockNum(std::fstream& fs);


  };
}