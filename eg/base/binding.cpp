// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <eg/base/base_eg.h>
#include <global/global_entities.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <stdexcept>

namespace eg {

current_cache global_cache;

global_object::global_object() {
  global_object_id = global::cs.generate_unique_number("gobj");
}

global_object::global_object(const global_object &obj) {
  global_object_id = global::cs.generate_unique_number("gobj");
}

global_object &global_object::operator=(global_object &obj) {
  this->global_object_id = global::cs.generate_unique_number("gobj");
  return *this;
}

global_object::~global_object() {}

std::uint64_t global_object::get_object_id() { return global_object_id; }

node::node(node *parent) : global_object(), global::flag_container() {
  parent_node = parent;
  if (parent != reinterpret_cast<node *>(0)) parent_node->grab_node(this);
  last_current = reinterpret_cast<node *>(0);
}

node::~node() {
  for (auto ch : childs) delete ch;
}

node::node(const node &n) : global_object(n), global::flag_container(n) {
  parent_node = reinterpret_cast<node *>(0);
  last_current = reinterpret_cast<node *>(0);
  name = n.name;
}

node &node::operator=(node &n) {
  global_object::operator=(n);
  this->parent_node = reinterpret_cast<node *>(0);
  this->last_current = reinterpret_cast<node *>(0);
  this->name = n.name;
  return *this;
}

void node::join_context(std::uint64_t ctx) { contexts.insert(ctx); }
void node::leave_context(std::uint64_t ctx) {
  if (contexts.find(ctx) == contexts.end())
    throw std::invalid_argument("Node can`t leave context: " +
                                std::to_string(ctx) + " because not joined it");
  contexts.erase(ctx);
}

bool node::in_context(std::uint64_t ctx) {
  if (contexts.find(ctx) != contexts.end()) return true;
  return false;
}

void node::bind_recall(std::uint64_t ctx) { recall.insert(ctx); }
void node::untie_recall(std::uint64_t ctx) {
  if (recall.find(ctx) == recall.end())
    throw std::invalid_argument("Node can`t leave context: " +
                                std::to_string(ctx) + " because not joined it");
  recall.erase(ctx);
}
bool node::is_recall(std::uint64_t ctx) {
  if (recall.find(ctx) != recall.end()) return true;
  return false;
}

void node::set_name(std::string current_name) { name = current_name; }

std::string node::get_name() { return name; }

void node::set_parent(node *current_parent) {
  if (parent_node != reinterpret_cast<node *>(0)) {
    parent_node->free_node(this);
  }
  parent_node = current_parent;
  current_parent->grab_node(this);
}

void node::grab_node(node *child_node) { childs.push_back(child_node); }

void node::free_node(node *child_node) {
  for (std::uint32_t i = 0; i < childs.size(); i++) {
    if (childs[i]->get_object_id() == child_node->get_object_id()) {
      childs.erase(childs.begin() + i);
      return;
    }
  }
  throw std::invalid_argument("Cant`t free node with id: " +
                              std::to_string(child_node->get_object_id()));
}

std::vector<node *> *node::get_childs() { return &childs; }

bool node::run_functor(std::function<bool(node *, std::uint64_t)> functor,
                       global::flag_container flags, std::uint64_t ctx) {
  
  if (flags.check_flag(bypass_flags::self)) {
    if (functor(this, ctx)) return true;
  }

  join_context(ctx);
  DEFER(this->leave_context(ctx););

  bool p = false;

  if (flags.check_flag(bypass_flags::childs)) {
    for (auto ch : childs) {
      if (!ch->in_context(ctx)) {
        p = ch->run_functor(functor, std::uint64_t(0x3), ctx);
        if (p) return p;
      }
    }
  }

  if (is_recall(ctx)) {
    DEFER(this->untie_recall(ctx););
    if (functor(this, ctx)) return true;
  }

  if (flags.check_flag(bypass_flags::parents)) {
    if (parent_node == reinterpret_cast<node *>(0) ||
        parent_node->in_context(ctx))
      return p;
    if (flags.check_flag(bypass_flags::broadcast)) {
      p = parent_node->run_functor(functor, std::uint64_t(0xF), ctx);
    } else
      p = parent_node->run_functor(functor, std::uint64_t(0x5), ctx);
  }
  return p;
}

void node::select_node() {
#ifdef USE_CACHE
  global_cache.append_current(this);
#else
  if (check_flag(type_flags::node_current))
    throw std::domain_error(
        "Cant`t select node, because node already selected");

  node *target = 0;

  bool p = run_functor(
      [&target](node *n, std::uint64_t ctx) mutable -> bool {
        if (n->check_flag(type_flags::node_current)) {
          target = n;
          return true;
        }
        return false;
      },
      std::uint64_t(0xF), global::cs.generate_unique_number("ctx"));

  if (p) {
    target->unset_flag(type_flags::node_current);
    last_current = target;
  }
  set_flag(type_flags::node_current);
#endif
}

void node::unselect_node() {
#ifdef USE_CACHE
  global_cache.remove_current();
#else
  node *target = 0;

  bool p = run_functor(
      [&target](node *n, std::uint64_t ctx) mutable -> bool {
        if (n->check_flag(type_flags::node_current)) {
          target = n;
          return true;
        }
        return false;
      },
      std::uint64_t(0xF), global::cs.generate_unique_number("ctx"));

  if (!p)
    throw std::domain_error(
        "Cant`t unselect node, because no one node selected");

  target->unset_flag(type_flags::node_current);
  if (target->last_current != reinterpret_cast<node *>(0))
    target->last_current->set_flag(type_flags::node_current);
#endif
}

node *node::get_current() {
#ifdef USE_CACHE
  return global_cache.get_current();
#else
  return find_node_by_flag<node>(this, type_flags::node_current,
                                 {bypass_flags::self, bypass_flags::childs});
#endif
}

loop_guard::loop_guard() {}

loop_guard::~loop_guard() {}

void loop_guard::join(std::string storage_name, std::uint64_t id) {
  if (loop_storages.count(storage_name) < 1)
    loop_storages[storage_name] = std::unordered_set<std::uint64_t>();

  auto &current_storage = loop_storages[storage_name];

  if (current_storage.find(id) != current_storage.end())
    throw std::invalid_argument("Loop detected with id: " + std::to_string(id));

  current_storage.insert(id);
}

void loop_guard::leave(std::string storage_name, std::uint64_t id) {
  if (loop_storages.count(storage_name) < 1)
    loop_storages[storage_name] = std::unordered_set<std::uint64_t>();

  auto &current_storage = loop_storages[storage_name];

  if (current_storage.size() < 1)
    throw std::out_of_range("Loop storage already empty, id: " +
                            std::to_string(id));

  current_storage.erase(id);
}

crypto_alghorithm::crypto_alghorithm() : global::flag_container() {
  align_value = 1;
}

crypto_alghorithm::~crypto_alghorithm() {}

std::uint64_t crypto_alghorithm::get_align() { return align_value; }

void crypto_alghorithm::set_align(std::uint64_t current_align) {
  align_value = current_align;
}

void crypto_alghorithm::set_alghorithm(
    std::function<void(std::vector<std::uint8_t> *,
                       std::vector<std::uint8_t> *)>
        current_alg) {
  alg = current_alg;
}
void crypto_alghorithm::set_generator(
    std::function<void(std::vector<std::uint8_t> *,
                       std::map<std::string, std::uint64_t> *parameters)>
        current_generator) {
  key_generator = current_generator;
}

void crypto_alghorithm::alter(std::vector<std::uint8_t> *data,
                              std::vector<std::uint8_t> *key) {
  if (!alg) throw std::domain_error("Currupted algorithm function!");
  alg(data, key);
}

void crypto_alghorithm::generate_key(
    std::vector<std::uint8_t> *key,
    std::map<std::string, std::uint64_t> *parameters) {
  if (!key_generator)
    throw std::domain_error("Currupted key generation function!");
  key_generator(key, parameters);
}

string_container::string_container(std::vector<std::string> current_names) {
  names = current_names;
}

string_container::string_container(const string_container &obj) {
  names = obj.names;
}

string_container::~string_container() {}

std::string string_container::get_name_by_index(std::uint32_t index) {
  if (index >= names.size())
    throw std::out_of_range("Can`t find name with index: " +
                            std::to_string(index));
  return names[index];
}

recursion_counter::recursion_counter() {
  r_counter = 0;
  r_stack_size = 0;
}
recursion_counter::~recursion_counter() {}
void recursion_counter::set_recursion_counter(std::uint64_t counter) {
  r_counter = counter;
}
std::uint64_t recursion_counter::get_recursion_counter() { return r_counter; }
bool recursion_counter::is_recursion_counter() {
  if (r_counter != 0) return true;
  return false;
}
void recursion_counter::up_recursion_counter() {
  if (r_counter <= 0)
    throw std::domain_error("Recursion counter is already zero");
  r_counter--;
}
void recursion_counter::down_recursion_counter() { r_counter++; }

void recursion_counter::store_recursion_counter() {
  r_stack.push_back(r_counter);
  r_stack_size++;
}
void recursion_counter::load_recursion_counter() {
  if (r_stack_size == 0) throw std::domain_error("Recursion stack is empty");
  r_stack_size--;
  r_counter = r_stack.back();
  r_stack.pop_back();
}

printable_object::printable_object() {}
printable_object::~printable_object() {}

current_cache::current_cache() { list_size = 0; }
current_cache::~current_cache() {}
void current_cache::append_current(node *new_current) {
  if (list_size != 0) currents.back()->unset_flag(type_flags::node_current);
  new_current->set_flag(type_flags::node_current);
  currents.push_back(new_current);
  list_size++;
}
void current_cache::remove_current() {
  if (list_size == 0) throw std::domain_error("Current cache is empty!");
  currents.back()->unset_flag(type_flags::node_current);
  currents.pop_back();
  list_size--;
  if (list_size != 0) currents.back()->set_flag(type_flags::node_current);
}

node *current_cache::get_current() {
  if (list_size == 0) throw std::domain_error("Current cache is empty!");
  return currents.back();
}

}  // namespace eg