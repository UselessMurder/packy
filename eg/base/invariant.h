#ifndef INVARIANT_H
#define INVARIANT_H

#include <eg/base/binding.h>
#include <functional>
#include <map>
#include <eg/base/part.h>
#include <string>
#include <vector>

namespace eg {

class invariant : public node {
private:
  std::map<std::string, std::string> registers;
  std::map<std::string, std::uint32_t> variables;
  std::function<void(global::flag_container, std::map<std::string, part *> *)> programmer;
  std::function<bool(std::vector<part *> *)> validator;
  std::function<void(std::map<std::string, part *> *)> balancer;

public:
  invariant(node *parent);
  ~invariant();
  bool try_execute(global::flag_container fl, std::vector<part *> *args);
  void add_register(std::string register_name, std::string group_name);
  void add_variable(std::string variable_name, std::uint32_t bitness);
  void register_programmer(
      std::function<void(global::flag_container, std::map<std::string, part *> *)> current_programmer);
  void register_validator(
      std::function<bool(std::vector<part *> *)> current_validator);
  void register_balancer(
      std::function<void(std::map<std::string, part *> *)> current_balancer);
  void validate_variables(std::map<std::string, part *> *vars);
};

} // namespace eg

#endif