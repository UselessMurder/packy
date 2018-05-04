#ifndef GLOBAL_H
#define GLOBAL_H

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>
#include <set>
#include <string>
#include <vector>
#include <cryptopp/osrng.h>

#define DEFER_NAME_1(x, y) x##y
#define DEFER_NAME_2(x, y) DEFER_NAME_1(x, y)
#define DEFER_NAME_3(x) DEFER_NAME_2(x, __COUNTER__)
#define DEFER(code)                                                            \
  auto DEFER_NAME_3(_defer_) = global::make_defer([&]() { code })

namespace global {

template <typename F> struct unamed_defer {
  F f;
  unamed_defer(F f) : f(f) {}
  ~unamed_defer() { f(); }
};

template <typename F> unamed_defer<F> make_defer(F f) {
  return unamed_defer<F>(f);
}

class named_defer {
private:
  std::function<void()> f;

public:
  named_defer();
  ~named_defer();
  void set_defer(std::function<void()> current_f);
};

class tag_container {
private:
  std::set<std::string> tags;

public:
  tag_container();
  tag_container(std::initializer_list<std::string> current_tags);
  virtual ~tag_container();
  bool check_tag(std::string tag_name);
  void add_tag(std::string tag_name);
  void remove_tag(std::string tag_name);
  void switch_tag(std::string tag_name);
  bool check_tags(std::initializer_list<std::string> current_tags);
  void add_tags(std::initializer_list<std::string> current_tags);
  void remove_tags(std::initializer_list<std::string> current_tags);
  void switch_tags(std::initializer_list<std::string> current_tags);
  void reset_tags(std::initializer_list<std::string> current_tags);
  void clear_tags();
};

class flag_container {
private:
  std::uint64_t flag_storage;

public:
  flag_container();
  flag_container(const flag_container &fc);
  flag_container(std::initializer_list<std::uint8_t> current_flags);
  flag_container(std::uint64_t current_flags);
  virtual ~flag_container();
  virtual bool check_flag(std::uint8_t flag_index);
  virtual void set_flag(std::uint8_t flag_index);
  virtual void unset_flag(std::uint8_t flag_index);
  virtual void switch_flag(std::uint8_t flag_index);
  virtual bool check_flags(std::initializer_list<std::uint8_t> current_flags);
  virtual void set_flags(std::initializer_list<std::uint8_t> current_flags);
  virtual void unset_flags(std::initializer_list<std::uint8_t> current_flags);
  virtual void switch_flags(std::initializer_list<std::uint8_t> current_flags);
  virtual void reset_flags(std::initializer_list<std::uint8_t> current_flags);
  virtual void clear_flags();
  virtual bool is_same(flag_container &current_flag_container);
  virtual bool is_match(flag_container &current_flag_container);
  virtual void move_flags(flag_container &current_flag_container);
  virtual void copy_flags(flag_container current_flag_container);
  virtual std::string flags_to_string();
};

class random_sequence {
private:
  CryptoPP::AutoSeededRandomPool rng;
  std::string alphanum;
  std::string alphanum_safe;

public:
  random_sequence();
  virtual ~random_sequence();
  std::uint64_t generate_random_number();
  std::string generate_random_string(std::uint32_t length, bool is_safe);
  template <typename T> void random_shuffle_vector(std::vector<T> *v) {
    std::random_shuffle(v->begin(), v->end(), [this](int i) -> int {
      return static_cast<std::uint32_t>(this->generate_random_number()) % i;
    });
  }
};

class consistent_sequence {
private:
  std::unordered_map<std::string, std::uint64_t> consistent_sequence_storage;

public:
  consistent_sequence();
  virtual ~consistent_sequence();
  std::uint64_t generate_unique_number(std::string storage_name);
  std::string generate_unique_string(std::string storage_name);
};

extern random_sequence rc;
extern consistent_sequence cs;

void align(std::uint64_t &size, std::uint64_t &overhead,
           std::uint64_t align_value);

void table_to_byte_array(std::vector<std::uint8_t> *byte_array, std::vector<std::uint32_t> *table);

void wipe_memory(std::vector<std::uint8_t> &mem, std::uint32_t begin, std::uint32_t end);

template <typename T> void value_to_vector(std::vector<std::uint8_t> *bytes, T value, std::uint8_t count) {
  bytes->clear();
  std::uint8_t *begin = reinterpret_cast<std::uint8_t *>(&value);
  std::uint8_t *end = begin + count;
  bytes->insert(bytes->end(), begin, end);
}

} // namespace global

#endif