#include <assert.h>

#include "FileHandler.h"

namespace File {

  const std::string BlockFile::prefix = "block";
  const std::string BlockFile::suffix = ".dat";

  void BlockFile::loadBlock(BlockChainHandler& bch) {
    char* buff = (char*)malloc(Block::MAX_BLOCK_SIZE);

    for (uint i = 0; i < 100000000; i++) {
      std::stringstream ss;
      ss << std::setfill('0') << std::right << std::setw(digits) << i;
      std::string fname = dir + prefix + ss.str() + suffix;

      std::ifstream ifs(fname, std::ios::binary);
      if (ifs.fail()) break;

      Version ver = 0;
      ifs.read((char*)&ver, sizeof(ver));
      assert(!ifs.fail());

      BlockCount num = 0;
      ifs.read((char*)&num, sizeof(num));
      assert(!ifs.fail());

      while (num--) {
        BlockDataIndex index;
        index.fname = fname;
        index.offset = ifs.tellg();

        uint cf = 0;
        ifs.read((char*)&cf, sizeof(cf));
        assert(!ifs.fail());

        uint size;
        ifs.read((char*)&size, sizeof(size));
        assert(!ifs.fail());
        assert(size > 0);

        ifs.read(buff, size);
        assert(!ifs.fail());
        std::string block(buff, size);
        assert(block.length() == size);

        std::shared_ptr<Block::Block> b(new Block::Block(block));
        assert(bch.checkBlock(b) == true);

        bch.addBlock(b, index, cf);
      }
      ifs.close();
    }
    free(buff);
  }

  std::shared_ptr<BlockData> BlockFile::getBlock(BlockDataIndex& index) {
    std::ifstream ifs(index.fname, std::ios::binary);
    ifs.seekg(index.offset);
    assert(!ifs.fail());

    std::shared_ptr<BlockData> b(new BlockData());

    uint cf = 0;
    ifs.read((char*)&cf, sizeof(cf));
    assert(!ifs.fail());
    b->confirmedCount = cf;

    uint size;
    ifs.read((char*)&size, sizeof(size));
    assert(!ifs.fail());
    assert(size > 0);

    char* buff = (char*)malloc(size);
    ifs.read(buff, size);
    assert(!ifs.fail());

    std::string bin(buff, size);
    assert(bin.length() == size);
    free(buff);
    b->block.reset(new Block::Block(bin));
    hashfunc.hash((unsigned char*)&b->block->header(), sizeof(b->block->header()), b->hash.hash);

    return b;
  }

  void BlockFile::writeFileHeader(std::fstream& fs) {
    fs.seekp(0, std::ios_base::beg);
    Version ver = 0x01;
    fs.write((char*)&ver, sizeof(ver));
    assert(!fs.fail());

    BlockCount n = 0x0000;
    fs.write((char*)&n, sizeof(n));
    assert(!fs.fail());
  }

  void BlockFile::updateBlockNum(std::fstream& fs, BlockCount num) {
    fs.seekp(sizeof(Version), std::ios_base::beg);
    fs.write((char*)&num, sizeof(num));
    assert(!fs.fail());
  }

  BlockFile::BlockCount BlockFile::readBlockNum(std::fstream& fs) {
    fs.seekg(sizeof(Version), std::ios_base::beg);
    if (fs.fail()) return 0;

    BlockCount count = 0;
    fs.read((char*)&count, sizeof(count));
    if (fs.fail()) return 0;

    return count;
  }

  BlockDataIndex BlockFile::writeBlock(const std::shared_ptr<BlockData>& bd) {
    std::stringstream ss;
    ss << std::setfill('0') << std::right << std::setw(digits) << bd->index / MaxBlock;
    std::string fname = dir + prefix + ss.str() + suffix;

    BlockCount count = 0;
    std::fstream fs(fname, std::ios::binary | std::ios::in | std::ios::out);
    if (fs.fail()) {
      fs.open(fname, std::ios::binary | std::ios::out);
      assert(!fs.fail());
      writeFileHeader(fs);
    }
    else {
      count = readBlockNum(fs);
    }

    count++;
    updateBlockNum(fs, count);

    fs.seekp(0, std::ios::end);

    BlockDataIndex index;
    index.fname = fname;
    index.offset = fs.tellp();

    fs.write((char*)&bd->confirmedCount, sizeof(bd->confirmedCount));
    assert(!fs.fail());

    std::string bin = bd->block->getBinary();
    uint size = bin.length();

    fs.write((char*)&size, sizeof(size));
    assert(!fs.fail());

    fs.write(bin.c_str(), bin.length());
    assert(!fs.fail());

    return index;
  }

}