// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <global/global_entities.h>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace global {

named_defer::named_defer() {}
named_defer::~named_defer() {
  if (f) f();
}
void named_defer::set_defer(std::function<void()> current_f) { f = current_f; }

random_sequence::random_sequence() {
  alphanum =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "!@#$%^&*()_-~`№+\"\'<>||\\/.,?:;[]{}";
  alphanum_safe =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
}

random_sequence::~random_sequence() {}

std::uint64_t random_sequence::generate_random_number() {
  std::uint64_t value;
  rng.GenerateBlock((CryptoPP::byte *)&value, 8);
  return value;
}

bool random_sequence::may_be(uint64_t percent) {
  if(percent > 100)
    throw std::invalid_argument("Percent can`t be more than 100");
  if((generate_random_number() % 100) >= percent)
    return false;
  return true;
}

std::string random_sequence::generate_random_string(std::uint32_t length,
                                                    bool is_safe) {
  std::string result_string;

  const std::string *ptr = 0;

  if (is_safe)
    ptr = &alphanum_safe;
  else
    ptr = &alphanum;

  if (is_safe)
    for (std::uint32_t i = 0; i < length; i++)
      result_string += (*ptr)[generate_random_number() % (ptr->length() - 1)];

  return result_string;
}

consistent_sequence::consistent_sequence() {}
consistent_sequence::~consistent_sequence() {}

std::uint64_t consistent_sequence::generate_unique_number(
    std::string storage_name) {
  if (consistent_sequence_storage.count(storage_name) < 1)
    consistent_sequence_storage[storage_name] = 0;
  else
    consistent_sequence_storage[storage_name]++;
  return consistent_sequence_storage[storage_name];
}

std::string consistent_sequence::generate_unique_string(
    std::string storage_name) {
  if (consistent_sequence_storage.count(storage_name) < 1)
    consistent_sequence_storage[storage_name] = 0;
  else
    consistent_sequence_storage[storage_name]++;
  std::stringstream ss;
  ss << storage_name << consistent_sequence_storage[storage_name];
  return ss.str();
}

tag_container::tag_container() {}

tag_container::tag_container(std::initializer_list<std::string> current_tags) {
  for (auto t : current_tags) tags.insert(t);
};

tag_container::~tag_container() {}

bool tag_container::check_tag(std::string tag_name) {
  return (tags.find(tag_name) != tags.end());
}

void tag_container::add_tag(std::string tag_name) {
  if (check_tag(tag_name))
    throw std::invalid_argument("Flag with name: " + tag_name +
                                " already exist!");
  tags.insert(tag_name);
}

void tag_container::remove_tag(std::string tag_name) {
  if (!check_tag(tag_name))
    throw std::invalid_argument("Can`t remove flag with name: " + tag_name +
                                " no such flag!");
  tags.erase(tag_name);
}

void tag_container::switch_tag(std::string tag_name) {
  if (check_tag(tag_name))
    remove_tag(tag_name);
  else
    add_tag(tag_name);
}

bool tag_container::check_tags(
    std::initializer_list<std::string> current_tags) {
  for (auto t : current_tags) {
    if (!check_tag(t)) return false;
  }
  return true;
}

void tag_container::add_tags(std::initializer_list<std::string> current_tags) {
  for (auto t : current_tags) add_tag(t);
}
void tag_container::remove_tags(
    std::initializer_list<std::string> current_tags) {
  for (auto t : current_tags) remove_tag(t);
}

void tag_container::switch_tags(
    std::initializer_list<std::string> current_tags) {
  for (auto t : current_tags) switch_tag(t);
}

void tag_container::reset_tags(
    std::initializer_list<std::string> current_tags) {
  tags.clear();
  for (auto f : current_tags) tags.insert(f);
}

void tag_container::clear_tags() { tags.clear(); }

flag_container::flag_container() { flag_storage = 0; }
flag_container::flag_container(
    std::initializer_list<std::uint8_t> current_flags) {
  flag_storage = 0;
  for (auto f : current_flags) set_flag(f);
}
flag_container::flag_container(std::uint64_t current_flags) {
  flag_storage = current_flags;
}
flag_container::flag_container(const flag_container &fc) {
  flag_storage = fc.flag_storage;
}
flag_container::~flag_container() {}
bool flag_container::check_flag(std::uint8_t flag_index) {
  if (flag_index >= 64)
    throw std::out_of_range("Index: " + std::to_string(flag_index) +
                            " out of range, flag may be between only 0~63");
  if ((flag_storage >> static_cast<std::uint64_t>(flag_index)) & 1) return true;
  return false;
}

void flag_container::set_flag(std::uint8_t flag_index) {
  if (flag_index >= 64)
    throw std::out_of_range("Index: " + std::to_string(flag_index) +
                            " out of range, flag may be between only 0~63");
  flag_storage |= std::uint64_t(1) << static_cast<std::uint64_t>(flag_index);
}

void flag_container::unset_flag(std::uint8_t flag_index) {
  if (flag_index >= 64)
    throw std::out_of_range("Index: " + std::to_string(flag_index) +
                            " out of range, flag may be only between 0~63");
  flag_storage &= ~(std::uint64_t(1) << static_cast<std::uint64_t>(flag_index));
}

void flag_container::switch_flag(std::uint8_t flag_index) {
  if (flag_index >= 64)
    throw std::out_of_range("Index: " + std::to_string(flag_index) +
                            " out of range, flag may be only between 0~63");
  flag_storage ^= std::uint64_t(1) << static_cast<std::uint64_t>(flag_index);
}

bool flag_container::check_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  for (auto f : current_flags) {
    if (!check_flag(f)) return false;
  }
  return true;
}

void flag_container::set_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  for (auto f : current_flags) set_flag(f);
}
void flag_container::unset_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  for (auto f : current_flags) unset_flag(f);
}

void flag_container::switch_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  for (auto f : current_flags) switch_flag(f);
}

void flag_container::reset_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  clear_flags();
  for (auto f : current_flags) set_flag(f);
}
void flag_container::clear_flags() { flag_storage = 0; }

bool flag_container::is_same(flag_container &current_flag_container) {
  if (flag_storage == current_flag_container.flag_storage) return true;
  return false;
}

bool flag_container::is_match(flag_container &current_flag_container) {
  if ((flag_storage & current_flag_container.flag_storage) !=
      current_flag_container.flag_storage)
    return false;
  return true;
}

void flag_container::move_flags(flag_container &current_flag_container) {
  flag_storage = current_flag_container.flag_storage;
}

void flag_container::copy_flags(flag_container current_flag_container) {
  flag_storage = flag_storage | current_flag_container.flag_storage;
}

std::string flag_container::flags_to_string() {
  return std::bitset<64>(flag_storage).to_string();
}

random_sequence rc;
consistent_sequence cs;

void align(std::uint64_t &size, std::uint64_t &overhead,
           std::uint64_t align_value) {
  if (align_value <= 0) throw std::invalid_argument("Align can not be zero!");

  std::uint64_t count = (size + overhead) / align_value;

  if ((size + overhead) % align_value != 0) count++;

  overhead = (count * align_value) - size;
}

union uint32_uint8 {
  std::uint32_t value;
  std::uint8_t bytes[4];
};

void table_to_byte_array(std::vector<std::uint8_t> *byte_array,
                         std::vector<std::uint32_t> *table) {
  for (auto row : *table) {
    uint32_uint8 tmp;
    tmp.value = row;
    for (std::uint8_t i = 0; i < 4; i++) byte_array->push_back(tmp.bytes[i]);
  }
}

void wipe_memory(std::vector<std::uint8_t> *mem, std::uint32_t begin,
                 std::uint32_t size) {
  if (begin > begin + size || mem->size() < begin + size) {
    throw std::domain_error(
        "Can`t wipe memory with size: " + std::to_string(mem->size()) +
        "from: " + std::to_string(begin) + "to: " + std::to_string(begin + size));
  }

  for (std::uint32_t i = begin; i < begin + size; i++) (*mem)[i] = 0;
}

uint32_t rotl32 (uint32_t n, unsigned int c)
{
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);

  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}

uint32_t rotr32 (uint32_t n, unsigned int c)
{
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);

  c &= mask;
  return (n>>c) | (n<<( (-c)&mask ));
}

}  // namespace global