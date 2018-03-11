#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <vector>

namespace cry {

class crc64 {
private:
  std::uint64_t value;

public:
  crc64();
  crc64(std::vector<std::uint8_t> &data);
  ~crc64();
  void set(std::vector<std::uint8_t> &data);
  std::uint64_t get();
};

class crc32 {
private:
  std::uint32_t value;

public:
  crc32();
  crc32(std::vector<std::uint8_t> &data);
  ~crc32();
  void set(std::vector<std::uint8_t> &data);
  std::uint32_t get();
};

class ecb {
private:
  std::uint32_t block_size;
public:
  ecb();
  ecb(std::uint32_t current_block_size);
  ~ecb();
  void set_block_size(std::uint32_t current_block_size);
  void generate_key(std::vector<uint8_t> *key);
  void encrypt(std::vector<uint8_t> *data, std::vector<uint8_t> *key);
};

class gambling {
public:
  gambling();
  ~gambling();
  void generate_key(std::vector<uint8_t> *key, std::uint64_t data_size);
  void encrypt(std::vector<uint8_t> *data, std::vector<uint8_t> *key);
};

}; // namespace cry

#endif