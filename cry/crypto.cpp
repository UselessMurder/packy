#include <cry/crypto.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <global/global_entities.h>

namespace cry {

crc64::crc64() {}
crc64::crc64(std::vector<std::uint8_t> &data) { set(data); }
crc64::~crc64() {}
void crc64::set(std::vector<std::uint8_t> &data) {
  value = 0;
  bool bit = false;
  for (std::uint32_t i = 0; i < data.size(); i++) {
    std::uint8_t c = (std::uint8_t)(data[i] | 0x20);
    for (uint_fast8_t i = 0x01; i & 0xff; i <<= 1) {
      bit = value & 0x8000000000000000;
      if (c & i) {
        bit = !bit;
      }
      value <<= 1;
      if (bit) {
        value ^= 0xad93d23594c935a9;
      }
    }
    value &= 0xffffffffffffffff;
  }
  value = value & 0xffffffffffffffff;
  uint_fast64_t ret = value & 0x01;
  for (size_t i = 1; i < 64; i++) {
    value >>= 1;
    ret = (ret << 1) | (value & 0x01);
  }
  value = ret ^ 0x0000000000000000;
}
std::uint64_t crc64::get() { return value; }

crc32::crc32() {}
crc32::crc32(std::vector<std::uint8_t> &data) { set(data); }
crc32::~crc32() {}
void crc32::set(std::vector<std::uint8_t> &data) {
  value = 0;
  for (std::uint32_t i = 0; i < data.size(); i++) {
    value ^= (std::uint8_t)(data[i] | 0x20);
    for (std::uint8_t j = 0; j < 8; j++) {
      value = (value >> 1) ^ (0x82F63B78 * (value & 1));
    }
  }
}
std::uint32_t crc32::get() { return value; }

ecb::ecb() { block_size = 1; }
ecb::ecb(std::uint32_t current_block_size) { block_size = current_block_size; }
ecb::~ecb() {}

void ecb::set_block_size(std::uint32_t current_block_size) {
  block_size = current_block_size;
}

void ecb::generate_key(std::vector<uint8_t> *key) {
  for (std::uint32_t i = 0; i < block_size; i++)
    key->push_back(
        static_cast<std::uint8_t>(global::rc.generate_random_number()));
}
void ecb::encrypt(std::vector<uint8_t> *data, std::vector<uint8_t> *key) {
  if (data->size() % key->size() != 0)
    throw std::domain_error("Invalid data align for ecb");

  for (std::uint64_t i = 0, j = 0; i < data->size(); i++, j++) {
    if (j >= key->size()) j = 0;
    (*data)[i] = (*data)[i] ^ (*key)[j];
  }
}

gambling::gambling() {}
gambling::~gambling() {}
void gambling::generate_key(std::vector<uint8_t> *key,
                            std::uint64_t data_size) {
  for (std::uint64_t i = 0; i < data_size; i++)
    key->push_back(
        static_cast<std::uint8_t>(global::rc.generate_random_number()));
}
void gambling::encrypt(std::vector<uint8_t> *data, std::vector<uint8_t> *key) {
  if (data->size() != key->size())
    throw std::domain_error("Invalid gambling key");

  for (std::uint64_t i = 0; i < data->size(); i++) {
    (*data)[i] = (*data)[i] ^ (*key)[i];
  }
}

aes::aes() {}
aes::~aes() {}
void aes::generate_key(std::vector<uint8_t> *key) {
  for (std::uint64_t i = 0; i < CryptoPP::AES::MAX_KEYLENGTH; i++)
    key->push_back(
        static_cast<std::uint8_t>(global::rc.generate_random_number()));
}
void aes::encrypt(std::vector<uint8_t> *data, std::vector<uint8_t> *key) {
  if (key->size() != 32) throw std::domain_error("Invalid aes key");

  if (data->size() % 16 != 0) throw std::domain_error("Invalid aes padding");

  CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e(&((*key)[0]), key->size());
  e.ProcessData(&((*data)[0]), &((*data)[0]), data->size());
}
}  // namespace cry