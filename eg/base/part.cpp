#include <eg/base/base_eg.h>

#include <cstdint>
#include <global/global_entities.h>
#include <sstream>
#include <string>

namespace eg {
part::part(node *parent) : node(parent) { set_flag(type_flags::build_part); }

part::part(const part &obj) : node(obj) {}

part::~part() {}

bool part::in_trash() {
  if (parent_node == reinterpret_cast<node *>(0))
    return true;
  if (parent_node->check_flag(type_flags::trash_branch))
    return true;
  return false;
}

void part::set_parent(node *current_parent) {
  if (in_trash()) {
    if (parent_node != reinterpret_cast<node *>(0)) {
      parent_node->free_node(this);
    }
    parent_node = current_parent;
    current_parent->grab_node(this);
  } else
    clone()->set_parent(current_parent);
}

dependence_part::dependence_part(node *parent) : part(parent) {
  set_flag(type_flags::dependence);
}
dependence_part::~dependence_part() {}
void dependence_part::set_resolver(
    std::function<std::uint64_t(part *p)> current_resolver) {
  resolver = current_resolver;
}
std::uint64_t dependence_part::get_value() {
  if (!resolver)
    throw std::domain_error("Resolver for dependence part with id: " +
                            std::to_string(get_object_id()) + " is not set!");
  return resolver(this);
}
std::string dependence_part::to_string() { return std::to_string(get_value()); }

part *dependence_part::clone() { return new dependence_part(*this); }

part_wrapper::part_wrapper(node *parent, part *current_part,
                           std::vector<uint64_t> current_values)
    : part(parent) {
  current_part->set_parent(this);
  values = current_values;
}

part_wrapper::part_wrapper(const part_wrapper &obj) : part(obj) {
  values = obj.values;
  wrapper = obj.wrapper;
  if (childs.size() != 1)
    throw std::domain_error("Too many childs for wrapper with id: " +
                            std::to_string(get_object_id()));
  node_cast<part>(childs[0])->clone()->set_parent(this);
}

part_wrapper::~part_wrapper() {}

void part_wrapper::set_wrapper(
    std::function<std::uint64_t(part_wrapper *p)> current_wrapper) {
  wrapper = current_wrapper;
}

std::uint64_t part_wrapper::get_value() {
  if (!wrapper)
    throw std::domain_error("Wrapper for wrapper part with id: " +
                            std::to_string(get_object_id()) + " is not set!");
  return wrapper(this);
}

std::uint64_t part_wrapper::get_value_by_index(std::uint32_t index) {
  if (index >= values.size())
    throw std::out_of_range(
        "Can`t find value with index: " + std::to_string(index) +
        " in part wrapper with id: " + std::to_string(get_object_id()));
  return values[index];
}

part *part_wrapper::get_wrapped() {
  if (childs.size() != 1)
    throw std::domain_error("Too many childs for wrapper with id: " +
                            std::to_string(get_object_id()));
  return node_cast<part>(childs[0]);
}

std::string part_wrapper::to_string() { return get_wrapped()->to_string(); }

bool part_wrapper::check_flag(std::uint8_t flag_index) {
  return get_wrapped()->check_flag(flag_index);
}
void part_wrapper::set_flag(std::uint8_t flag_index) {
  get_wrapped()->set_flag(flag_index);
}
void part_wrapper::unset_flag(std::uint8_t flag_index) {
  get_wrapped()->unset_flag(flag_index);
}
void part_wrapper::switch_flag(std::uint8_t flag_index) {
  get_wrapped()->switch_flag(flag_index);
}
bool part_wrapper::check_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  return get_wrapped()->check_flags(current_flags);
}
void part_wrapper::set_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  get_wrapped()->set_flags(current_flags);
}
void part_wrapper::unset_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  get_wrapped()->unset_flags(current_flags);
}
void part_wrapper::switch_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  get_wrapped()->switch_flags(current_flags);
}
void part_wrapper::reset_flags(
    std::initializer_list<std::uint8_t> current_flags) {
  get_wrapped()->reset_flags(current_flags);
}
void part_wrapper::clear_flags() { get_wrapped()->clear_flags(); }
bool part_wrapper::is_same(flag_container &current_flag_container) {
  return get_wrapped()->is_same(current_flag_container);
}
bool part_wrapper::is_match(flag_container &current_flag_container) {
  return get_wrapped()->is_match(current_flag_container);
}
void part_wrapper::move_flags(flag_container &current_flag_container) {
  get_wrapped()->move_flags(current_flag_container);
}
void part_wrapper::copy_flags(flag_container current_flag_container) {
  get_wrapped()->copy_flags(current_flag_container);
}
std::string part_wrapper::flags_to_string() {
  return get_wrapped()->flags_to_string();
}

part *part_wrapper::clone() { return new part_wrapper(*this); }

cached_dependence::cached_dependence(node *parent,
                                     std::vector<std::string> names)
    : dependence_part(parent), string_container(names) {}

cached_dependence::cached_dependence(const cached_dependence &obj)
    : dependence_part(obj), string_container(obj) {
  cached_value = obj.cached_value;
}

cached_dependence::~cached_dependence() {}

std::uint64_t cached_dependence::get_cached_value() {
  if (!check_flag(type_flags::node_cached))
    throw std::domain_error("Cached value is not set for part with id: " +
                            std::to_string(get_object_id()));
  return cached_value;
}
void cached_dependence::set_cached_value(std::uint64_t value) {
  set_flag(type_flags::node_cached);
  cached_value = value;
}

part *cached_dependence::clone() { return new cached_dependence(*this); }

} // namespace eg