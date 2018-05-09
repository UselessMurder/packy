#ifndef BINDING_H
#define BINDING_H

#include <global/global_entities.h>

//#define NODE_DEBUG
#define USE_CACHE

#include <any>
#include <bitset>
#include <cstdint>
#include <functional>
#include <list>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace eg {

const std::uint64_t build_stub8 = 0x12;
const std::uint64_t build_stub16 = 0x1234;
const std::uint64_t build_stub32 = 0x12345678;
const std::uint64_t build_stub64 = 0x123456789ABCDEF0;

enum class build_states : std::uint8_t {
  programming = 0,
  aligning = 1,
  taging = 2,
  keyring = 3,
  locating = 4,
  translating = 5,
  done = 6
};

namespace dependence_flags {
enum df : std::uint8_t {
  content = 0,
  shift = 1,
  full_size = 2,
  payload_size = 3
};
}

namespace bypass_flags {
enum schf : std::uint8_t { self = 0, childs = 1, parents = 2, broadcast = 3 };
}

namespace properties_flags {
enum gdf : std::uint8_t { get_root = 0, alter_self = 1, alter_childs = 2 };
}

namespace type_flags {
enum nf : std::uint8_t {
  node_current = 0,
  build_root = 1,
  build_memory = 2,
  build_frame = 3,
  build_form = 4,
  build_part = 5,
  build_invariant = 6,
  part_simple = 7,
  dependence = 8,
  node_cached = 9,
  memory_group = 10,
  fixed = 11,
  memory_static = 12,
  group_taged = 13,
  group_random = 14,
  group_sequence_constructed = 15,
  align_code = 16,
  balanced = 17,
  memory_code = 18,
  memory_data = 19,
  memory_dependence = 20,
  build_branch = 21,
  morph_branch = 22,
  trash_branch = 23,
  memory_top = 24,
  invariant_recursive = 25,
  ignore = 26,
  stack_safe = 27,
  flag_safe = 28,
  fundomental_undepended = 29,
  debug_unprotected = 30,
  will_balanced = 31,
  do_not_use_shift = 32,
  shift_is_set = 33
};
}

namespace crypto_flags {
enum cf : std::uint8_t { variable_length_key = 0, block_chiper = 1 };
};

class global_object {
 private:
  std::uint64_t global_object_id;

 public:
  global_object();
  global_object(const global_object &obj);
  global_object &operator=(global_object &obj);
  virtual ~global_object();
  std::uint64_t get_object_id();
};

class node : public global_object, public global::flag_container {
 protected:
  node *parent_node;
  std::vector<node *> childs;
  
  node *last_current;

  std::unordered_set<std::uint64_t> contexts;
  std::unordered_set<std::uint64_t> recall;

  void join_context(std::uint64_t ctx);
  void leave_context(std::uint64_t ctx);

 public:
  std::string name;
  node(node *parent);
  node(const node &n);
  virtual ~node();

  node &operator=(node &n);

  std::vector<node *> *get_childs();

  virtual void set_name(std::string current_name);
  virtual std::string get_name();

  virtual void grab_node(node *child_node);
  virtual void free_node(node *child_node);
  virtual void set_parent(node *current_parent);

  bool run_functor(std::function<bool(node *, std::uint64_t)> functor,
                   global::flag_container flags, std::uint64_t ctx);

  void bind_recall(std::uint64_t ctx);
  void untie_recall(std::uint64_t ctx);
  bool is_recall(std::uint64_t ctx);

  void select_node();
  void unselect_node();
  node *get_current();
  bool in_context(std::uint64_t ctx);
};

template <typename T>
T *node_cast(node *n) {
  T *ptr = dynamic_cast<T *>(n);
  if (ptr == reinterpret_cast<T *>(0))
    throw std::domain_error("Wrong type cast for node with id: " +
                            std::to_string(n->get_object_id()));
  return ptr;
}

template <typename T>
T *get_current_node(node *n) {
  return node_cast<T>(n->get_current());
}

template <typename T>
T *find_node_by_name(node *current_node, std::string name,
                     global::flag_container search_flags) {
  node *n;
  bool ok = current_node->run_functor(
      [&n, &name](node *current_node, std::uint64_t ctx) -> bool {
        if (std::strcmp(name.data(), current_node->get_name().data()) == 0) {
          n = current_node;
          return true;
        }
        return false;
      },
      search_flags, global::cs.generate_unique_number("ctx"));
  if (!ok) throw std::domain_error("Cant`t find node by name: " + name);

  return node_cast<T>(n);
}

template <typename T>
T *find_node_by_flag(node *current_node, std::uint8_t node_flag,
                     global::flag_container search_flags) {
  node *n;
  bool ok = current_node->run_functor(
      [&n, &node_flag](node *current_node, std::uint64_t ctx) -> bool {
        if (current_node->check_flag(node_flag)) {
          n = current_node;
          return true;
        }
        return false;
      },
      search_flags, global::cs.generate_unique_number("ctx"));
  if (!ok)
    throw std::domain_error("Cant`t find node by flag: " +
                            std::to_string(node_flag));

  return node_cast<T>(n);
}

template <typename T>
T *find_node_by_flags(node *current_node, global::flag_container node_flags,
                      global::flag_container search_flags) {
  node *n;
  bool ok = current_node->run_functor(
      [&n, &node_flags](node *current_node, std::uint64_t ctx) -> bool {
        if (current_node->is_match(node_flags)) {
          n = current_node;
          return true;
        }
        return false;
      },
      search_flags, global::cs.generate_unique_number("ctx"));
  if (!ok)
    throw std::domain_error("Cant`t find node by flags: " +
                            node_flags.flags_to_string());

  return node_cast<T>(n);
}

class current_cache {
 private:
  std::uint64_t list_size;
  std::list<node *> currents;

 public:
  current_cache();
  ~current_cache();
  void append_current(node *new_current);
  void remove_current();
  node *get_current();
};

#ifdef USE_CACHE
extern current_cache global_cache;
#endif

class loop_guard {
 private:
  std::unordered_map<std::string, std::unordered_set<std::uint64_t>>
      loop_storages;

 public:
  loop_guard();
  virtual ~loop_guard();
  void join(std::string storage_name, std::uint64_t id);
  void leave(std::string storage_name, std::uint64_t id);
};

class key_value_storage {
 private:
  std::unordered_map<std::string, std::any> values_storage;

 public:
  key_value_storage() {}
  virtual ~key_value_storage() {}
  void set_value(std::string key, std::any value) {
    values_storage[key] = value;
  }
  template <typename T>
  T get_value(std::string key) {
    if (values_storage.count(key) < 1)
      throw std::out_of_range("Can`t find value with key: " + key);

    if (values_storage[key].type() != typeid(T))
      throw std::invalid_argument("Wrong value type with key: " + key);

    return std::any_cast<T>(values_storage[key]);
  }
  void remove_value(std::string key) {
    if (values_storage.count(key) < 1)
      throw std::out_of_range("Can`t find value with key: " + key);
    values_storage.erase(key);
  }
};

class crypto_alghorithm : public global::flag_container {
 private:
  std::function<void(std::vector<std::uint8_t> *, std::vector<std::uint8_t> *)>
      alg;
  std::function<void(std::vector<std::uint8_t> *,
                     std::map<std::string, std::uint64_t> *parameters)>
      key_generator;
  std::uint64_t align_value;

 public:
  crypto_alghorithm();
  ~crypto_alghorithm();
  std::uint64_t get_align();
  void set_alghorithm(std::function<void(std::vector<std::uint8_t> *,
                                         std::vector<std::uint8_t> *)>
                          current_alg);
  void set_generator(
      std::function<void(std::vector<std::uint8_t> *,
                         std::map<std::string, std::uint64_t> *parameters)>
          current_generator);
  void set_align(std::uint64_t current_align);
  void alter(std::vector<std::uint8_t> *data, std::vector<std::uint8_t> *key);
  void generate_key(std::vector<std::uint8_t> *key,
                    std::map<std::string, std::uint64_t> *parameters);
};

class string_container {
 protected:
  std::vector<std::string> names;

 public:
  string_container(std::vector<std::string> current_names);
  string_container(const string_container &obj);
  virtual ~string_container();
  std::string get_name_by_index(std::uint32_t index);
};

class recursion_counter {
 private:
  std::uint64_t r_counter;
  std::uint64_t r_stack_size;
  std::list<std::uint64_t> r_stack;

 public:
  recursion_counter();
  ~recursion_counter();
  void set_recursion_counter(std::uint64_t counter);
  std::uint64_t get_recursion_counter();
  bool is_recursion_counter();
  void up_recursion_counter();
  void down_recursion_counter();
  void store_recursion_counter();
  void load_recursion_counter();
};

class printable_object {
 public:
  printable_object();
  virtual ~printable_object();
  virtual std::string to_string() = 0;
};

}  // namespace eg

#endif