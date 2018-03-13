#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <vector>

const std::uint32_t const_s_box[] = { 0x637c777b,0xf26b6fc5,0x3001672b,0xfed7ab76,\
      0xca82c97d,0xfa5947f0,0xadd4a2af,0x9ca472c0,\
      0xb7fd9326,0x363ff7cc,0x34a5e5f1,0x71d83115,\
      0x04c723c3,0x1896059a,0x071280e2,0xeb27b275,\
      0x09832c1a,0x1b6e5aa0,0x523bd6b3,0x29e32f84,\
      0x53d100ed,0x20fcb15b,0x6acbbe39,0x4a4c58cf,\
      0xd0efaafb,0x434d3385,0x45f9027f,0x503c9fa8,\
      0x51a3408f,0x929d38f5,0xbcb6da21,0x10fff3d2,\
      0xcd0c13ec,0x5f974417,0xc4a77e3d,0x645d1973,\
      0x60814fdc,0x222a9088,0x46eeb814,0xde5e0bdb,\
      0xe0323a0a,0x4906245c,0xc2d3ac62,0x9195e479,\
      0xe7c8376d,0x8dd54ea9,0x6c56f4ea,0x657aae08,\
      0xba78252e,0x1ca6b4c6,0xe8dd741f,0x4bbd8b8a,\
      0x703eb566,0x4803f60e,0x613557b9,0x86c11d9e,\
      0xe1f89811,0x69d98e94,0x9b1e87e9,0xce5528df,\
      0x8ca1890d,0xbfe64268,0x41992d0f,0xb054bb16 };

const std::uint32_t const_inv_s_box[] = { 0x52096ad5,0x3036a538,0xbf40a39e,0x81f3d7fb,\
      0x7ce33982,0x9b2fff87,0x348e4344,0xc4dee9cb,\
      0x547b9432,0xa6c2233d,0xee4c950b,0x42fac34e,\
      0x082ea166,0x28d924b2,0x765ba249,0x6d8bd125,\
      0x72f8f664,0x86689816,0xd4a45ccc,0x5d65b692,\
      0x6c704850,0xfdedb9da,0x5e154657,0xa78d9d84,\
      0x90d8ab00,0x8cbcd30a,0xf7e45805,0xb8b34506,\
      0xd02c1e8f,0xca3f0f02,0xc1afbd03,0x01138a6b,\
      0x3a911141,0x4f67dcea,0x97f2cfce,0xf0b4e673,\
      0x96ac7422,0xe7ad3585,0xe2f937e8,0x1c75df6e,\
      0x47f11a71,0x1d29c589,0x6fb7620e,0xaa18be1b,\
      0xfc563e4b,0xc6d27920,0x9adbc0fe,0x78cd5af4,\
      0x1fdda833,0x8807c731,0xb1121059,0x2780ec5f,\
      0x60517fa9,0x19b54a0d,0x2de57a9f,0x93c99cef,\
      0xa0e03b4d,0xae2af5b0,0xc8ebbb3c,0x83539961,\
      0x172b047e,0xba77d626,0xe1691463,0x55210c7d };


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