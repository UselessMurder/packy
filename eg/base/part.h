#ifndef PART_H
#define PART_H

#include <eg/base/binding.h>
#include <cstdint>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>

namespace eg {
class part : public node, public printable_object {
protected:
  bool in_trash();
public:
  part(node *parent);
  part(const part &obj);
  virtual ~part();
  virtual std::string to_string() = 0;
  virtual part *clone() = 0;
  virtual void set_parent(node *current_parent);
};

class dependence_part : public part {
protected:
  std::function<std::uint64_t(part *p)> resolver;

public:
  dependence_part(node *parent);
  dependence_part(const dependence_part &obj) : part(obj) {
    resolver = obj.resolver;
  }
  virtual ~dependence_part();
  void set_resolver(std::function<std::uint64_t(part *p)> current_resolver);
  std::uint64_t get_value();
  std::string to_string();
  virtual part *clone();
};

template <typename T> class simple_part : public part {
private:
  T value;

public:
  simple_part(node *parent, T current_value) : part(parent) {
    set_flag(type_flags::part_simple);
    value = current_value;
  }
  simple_part(const simple_part &obj) : part(obj) {
    value = obj.value;
  }
  ~simple_part() {}

  T get_value() { return value; }

  void set_value(T current_value) { value = current_value; }

  std::string to_string() {
    std::stringstream s;
    s << value;
    return s.str();
  }
  virtual part *clone() {
    return new simple_part<T>(*this);
  }
};

class part_wrapper : public part {
private:
  std::vector<std::uint64_t> values;
  std::function<std::uint64_t(part_wrapper *p)> wrapper;

public:
  part_wrapper(node *parent, part *current_part,
               std::vector<uint64_t> current_values);
  part_wrapper(const part_wrapper &obj);
  ~part_wrapper();
  void
  set_wrapper(std::function<std::uint64_t(part_wrapper *p)> current_wrapper);
  std::uint64_t get_value();
  std::uint64_t get_value_by_index(std::uint32_t index);
  std::string to_string();
  part *get_wrapped();
  bool check_flag(std::uint8_t flag_index);
  void set_flag(std::uint8_t flag_index);
  void unset_flag(std::uint8_t flag_index);
  void switch_flag(std::uint8_t flag_index);
  bool check_flags(std::initializer_list<std::uint8_t> current_flags);
  void set_flags(std::initializer_list<std::uint8_t> current_flags);
  void unset_flags(std::initializer_list<std::uint8_t> current_flags);
  void switch_flags(std::initializer_list<std::uint8_t> current_flags);
  void reset_flags(std::initializer_list<std::uint8_t> current_flags);
  void clear_flags();
  bool is_same(flag_container &current_flag_container);
  bool is_match(flag_container &current_flag_container);
  void move_flags(flag_container &current_flag_container);
  void copy_flags(flag_container current_flag_container);
  std::string flags_to_string();
  virtual part *clone();
};

class cached_dependence : public dependence_part, public string_container {
private:
  uint64_t cached_value;

public:
  cached_dependence(node *parent, std::vector<std::string> names);
  cached_dependence(const cached_dependence &obj);
  ~cached_dependence();
  std::uint64_t get_cached_value();
  void set_cached_value(std::uint64_t value);
  virtual part *clone();
};

template <typename T> T get_part_value(part *p) {
  auto sp = dynamic_cast<simple_part<T> *>(p);
  if (sp == reinterpret_cast<simple_part<T> *>(0))
    throw std::invalid_argument("Cant`t get value from part with id: " +
                                std::to_string(p->get_object_id()));
  return sp->get_value();
}

template <> std::uint64_t inline get_part_value<std::uint64_t>(part *p) {
  std::uint64_t val = 0;
  auto dp = dynamic_cast<dependence_part *>(p);
  if (dp != reinterpret_cast<dependence_part *>(0))
    return dp->get_value();
  auto wp = dynamic_cast<part_wrapper *>(p);
  if (wp != reinterpret_cast<part_wrapper *>(0))
    return wp->get_value();
  auto sp = dynamic_cast<simple_part<std::uint64_t> *>(p);
  if (sp != reinterpret_cast<simple_part<std::uint64_t> *>(0))
    return sp->get_value();
  throw std::invalid_argument("Cant`t get value from part with id: " +
                              std::to_string(p->get_object_id()));
  return val;
}

template <typename T> void set_part_value(part *p, T value) {
  auto sp = dynamic_cast<simple_part<T> *>(p);
  if (sp != reinterpret_cast<simple_part<T> *>(0)) {
    sp->set_value(value);
    return;
  }
  throw std::invalid_argument("Cant`t set value from part with id: " +
                              std::to_string(p->get_object_id()));
}

template <typename T>
simple_part<T> *create_simple_part(node *parent, T value) {
  return new simple_part<T>(parent, value);
}

} // namespace eg

#endif