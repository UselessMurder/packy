#include <eg/base/base_eg.h>

namespace eg {

form::form(node *parent) : node(parent) { set_flag(type_flags::build_form); }

form::~form() {}

void form::add_argument(std::string argument_name) {
  for (auto a : arguments)
    if (a.first == argument_name)
      throw std::invalid_argument(
          "Argument with same name: " + argument_name +
          " in form with id:" + std::to_string(get_object_id()));

  arguments.push_back(std::make_pair(argument_name, 0));
}

void form::add_argument(std::string argument_name, std::uint32_t bitness) {
  for (auto a : arguments)
    if (a.first == argument_name)
      throw std::invalid_argument(
          "Argument with same name: " + argument_name +
          " in form with id:" + std::to_string(get_object_id()));
  arguments.push_back(std::make_pair(argument_name, bitness));
}

std::vector<std::pair<std::string, std::uint32_t>> *form::get_arguments() {
  return &arguments;
}

void form::validate_arguments(std::map<std::string, part *> *args) {
  build_root *root =
      find_node_by_flag<build_root>(this, type_flags::build_root, {bypass_flags::parents});
  for (auto a : arguments) {
    if (a.second != 0  && !root->validate_bitness(get_part_value<std::uint64_t>((*args)[a.first]),
                                a.second))
      throw std::invalid_argument(
          "Invalid bytness of argument with name: " + a.first +
          " needed bitness: " + std::to_string(a.second));
  }
}

void form::get_invariants(std::vector<invariant *> *invariants) {
  for (auto ch : childs) {
    if (ch->check_flag(type_flags::build_invariant)) {
      invariants->push_back(node_cast<invariant>(ch));
    }
  }
}

} // namespace eg