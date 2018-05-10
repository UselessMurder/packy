// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <eg/base/base_eg.h>

namespace eg {

invariant::invariant(node *parent) : node(parent) {
  set_flag(type_flags::build_invariant);
}

invariant::~invariant() {}

void invariant::add_register(std::string register_name,
                             std::string group_name) {
  if (registers.count(register_name) > 0)
    throw std::invalid_argument("Register with same name: " + register_name +
                                " already exists in invariant with id: " +
                                std::to_string(get_object_id()));
  registers[register_name] = group_name;
}

void invariant::add_variable(std::string variable_name, std::uint32_t bitness) {
  if (variables.count(variable_name) > 0)
    throw std::invalid_argument("Variable with same name: " + variable_name +
                                " already exists in invariant with id: " +
                                std::to_string(get_object_id()));
  variables[variable_name] = bitness;
}

void invariant::register_programmer(
    std::function<void(global::flag_container, std::map<std::string, part *> *)>
        current_programmer) {
  programmer = current_programmer;
}

void invariant::register_validator(
    std::function<bool(std::vector<part *> *)> current_validator) {
  validator = current_validator;
}

void invariant::register_balancer(
    std::function<void(std::map<std::string, part *> *)> current_balancer) {
  balancer = current_balancer;
}

void invariant::validate_variables(std::map<std::string, part *> *vars) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  for (auto v : variables) {
    if (!root->validate_bitness(get_part_value<std::uint64_t>((*vars)[v.first]),
                                v.second))
      throw std::invalid_argument(
          "Invalid bytness of argument with name: " + v.first +
          " needed bitness: " + std::to_string(v.second));
  }
}

bool invariant::try_execute(global::flag_container fl,
                            std::vector<part *> *args) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  global::named_defer recursion_guard;

  auto args_template = find_node_by_flag<form>(this, type_flags::build_form,
                                               {bypass_flags::parents})
                           ->get_arguments();

  if (args->size() != args_template->size())
    throw std::invalid_argument(
        "Not enough arguments for execute invariant with id: " +
        std::to_string(get_object_id()));

  if (check_flag(type_flags::invariant_recursive)) {
    if (!root->is_recursion_counter()) return false;
    root->up_recursion_counter();
    recursion_guard.set_defer([root]() { root->down_recursion_counter(); });
  }

  if (validator)
    if (!validator(args)) return false;

  std::map<std::string, std::string> regs;
  if (!root->try_grab_registers(&registers, &regs)) return false;
  DEFER(root->free_registers(&regs););

  std::map<std::string, part *> vars;

  for (auto r : regs)
    vars[r.first] = create_simple_part(root->get_trash_node(), r.second);

  for (std::uint32_t i = 0; i < args->size(); i++)
    vars[(*args_template)[i].first] = (*args)[i];

  bool activated_branch = false;

  for (auto a : *args) {
    if (a->check_flag(type_flags::will_balanced)) {
      activated_branch = true;
      break;
    }
  }

  for (auto v : variables) {
    vars[v.first] = create_simple_part(root->get_trash_node(),
                                       root->get_stub_with_bitness(v.second));
    if (balancer || activated_branch)
      vars[v.first]->set_flag(type_flags::will_balanced);
  }

  node *current = get_current_node<node>(root->get_build_node());

  if (!current->check_flag(type_flags::memory_group))
    throw std::domain_error("Instruction can be located only in group");

  group *g = reinterpret_cast<group *>(0);

  if (balancer) {
    activation_group *ag = new activation_group(current, this);
    ag->set_balancer(balancer);
    ag->set_variables(&vars);
    for (auto a : *args_template) vars[a.first]->set_parent(ag);
    g = ag;
  } else {
    g = new group(current);
    find_node_by_flag<form>(this, type_flags::build_form,
                            {bypass_flags::parents})
        ->validate_arguments(&vars);
  }

  g->set_flag(type_flags::align_code);

  g->select_node();
  DEFER(g->unselect_node(););
  if (programmer) {
    programmer(fl, &vars);
  } else {
    throw std::domain_error(
        "Cant`t execute invariant with id: " + std::to_string(get_object_id()) +
        ", because programmer is not set");
  }

  return true;
}

};  // namespace eg