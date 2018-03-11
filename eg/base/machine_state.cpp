#include <algorithm>
#include <eg/base/machine_state.h>
#include <functional>
#include <global/global_entities.h>

namespace eg {

machine_state::machine_state() {}

machine_state::~machine_state() {}

void machine_state::set_registers(
    std::initializer_list<std::string> registers) {
  if (state.size() != 0)
    throw std::domain_error("Registers already set");
  for (auto register_name : registers) {
    state[register_name] = false;
    local_stack[register_name] = std::make_pair(0, std::list<bool>());
  }
}

void machine_state::add_group(std::string group_name,
                              std::vector<std::string> registers) {
  for (auto reg : registers) {
    if (state.count(reg) < 1)
      throw std::invalid_argument("Register with name: " + reg +
                                  " is not exists");
  }
  groups[group_name] = registers;
  group_stack[group_name] = std::make_pair(0, std::list<std::vector<bool>>());
}

void machine_state::local_save(std::string register_name) {
  if (state.count(register_name) < 1)
    throw std::invalid_argument("Register with name: " + register_name +
                                " is not exists");
  local_stack[register_name].first++;
  local_stack[register_name].second.push_back(state[register_name]);
}

void machine_state::local_load(std::string register_name) {
  if (state.count(register_name) < 1)
    throw std::invalid_argument("Register with name: " + register_name +
                                " is not exists");
  if (local_stack[register_name].first < 1)
    throw std::domain_error("Stack for register with name: " + register_name +
                            " is empty");
  local_stack[register_name].first--;
  state[register_name] = local_stack[register_name].second.back();
  local_stack[register_name].second.pop_back();
}

void machine_state::group_save(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  group_stack[group_name].first++;
  group_stack[group_name].second.push_back(std::vector<bool>());
  std::vector<bool> *current_state = &(group_stack[group_name].second.back());
  std::vector<std::string> *current_group = &(groups[group_name]);
  for (auto reg : *current_group)
    current_state->push_back(state[reg]);
}

void machine_state::group_load(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  if (group_stack[group_name].first < 1)
    throw std::domain_error(
        "Stack for registers group with name: " + group_name + " is empty");
  group_stack[group_name].first--;
  std::vector<bool> *current_state = &(group_stack[group_name].second.back());
  std::vector<std::string> *current_group = &(groups[group_name]);
  for (std::uint32_t i = 0; i < current_group->size(); i++)
    state[(*current_group)[i]] = (*current_state)[i];
  group_stack[group_name].second.pop_back();
}

std::uint32_t machine_state::get_free_count(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  std::uint32_t count = 0;
  std::vector<std::string> *current_group = &(groups[group_name]);
  for (auto reg : *current_group) {
    if (!state[reg])
      count++;
  }
  return count;
}

void machine_state::grab_register(std::string register_name) {
  if (state.count(register_name) < 1)
    throw std::invalid_argument("Register with name: " + register_name +
                                " is not exists");
  bool *rs = &(state[register_name]);
  if (*rs)
    throw std::invalid_argument("Register with name: " + register_name +
                                " is already grabed");
  *rs = true;
}

void machine_state::free_register(std::string register_name) {
  if (state.count(register_name) < 1)
    throw std::invalid_argument("Register with name: " + register_name +
                                " is not grabed");
  state[register_name] = false;
}

void machine_state::grab_group(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  std::vector<std::string> *current_group = &(groups[group_name]);
  for (auto reg : *current_group) {
    bool *rs = &(state[reg]);
    if (*rs)
      throw std::invalid_argument("Register with name: " + reg +
                                  " is already grabed");
    *rs = true;
  }
}

void machine_state::free_group(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  std::vector<std::string> *current_group = &(groups[group_name]);
  for (auto reg : *current_group)
    state[reg] = false;
}

std::string machine_state::get_free(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  std::vector<std::string> current_group = groups[group_name];
  global::rc.random_shuffle_vector(&current_group);
  std::string current_register = "";
  bool has = false;
  for (auto reg : current_group) {
    if (!state[reg]) {
      current_register = reg;
      has = true;
      break;
    }
  }
  if (!has)
    throw std::invalid_argument("All registers in group with name: " +
                                group_name + " is already grabed");
  return current_register;
}

std::string machine_state::get_rand(std::string group_name) {
  if (groups.count(group_name) < 1)
    throw std::invalid_argument("Registers group with name: " + group_name +
                                " is not exists");
  std::vector<std::string> current_group = groups[group_name];
  global::rc.random_shuffle_vector(&current_group);
  return current_group[global::rc.generate_random_number() %
                       current_group.size()];
}

std::string machine_state::get_sub_register(std::string register_name,
                                            std::string half_name) {
  if (sub_registers.count(register_name) < 1)
    throw std::invalid_argument("Register with name: " + register_name +
                                " doesn`t have sub registers");

  if (sub_registers[register_name].count(half_name) < 1)
    throw std::invalid_argument(
        "Register with name: " + register_name +
        " doesn`t have sub register with name: " + half_name);

  return sub_registers[register_name][half_name]; 
}

bool machine_state::try_grab_registers(
    std::map<std::string, std::string> *in,
    std::map<std::string, std::string> *out) {

  std::vector<std::string> groups_sequence;
  std::set<std::string> used_groups;
  std::multimap<std::string, std::string> group_members;

  for (auto r : *in) {
    used_groups.insert(r.second);
    group_members.insert(std::make_pair(r.second, r.first));
  }

  for (auto g : used_groups)
    groups_sequence.push_back(g);

  for (auto g : used_groups) {
    if (groups.count(g) == 0)
      throw std::invalid_argument("Registers group with name: " + g +
                                  " is not exists");
  }

  std::sort(groups_sequence.begin(), groups_sequence.end(),
            [this](const std::string &s1, const std::string &s2) -> bool {
              return this->groups[s1].size() < this->groups[s2].size();
            });

  for (auto g : groups_sequence) {
    auto range = group_members.equal_range(g);
    for (auto i = range.first; i != range.second; ++i) {
      if (get_free_count(g) < 1) {
        free(out);
        return false;
      }
      auto r = get_free(g);
      state[r] = true;
      (*out)[i->second] = r;
    }
  }
  return true;
}

void machine_state::free_registers(
    std::map<std::string, std::string> *registers) {
  for (auto r : *registers)
    state[r.second] = false;
}

 void machine_state::add_sub_registers(
      std::string register_name,
      std::initializer_list<std::pair<std::string, std::string>> half_register) {

  if (state.count(register_name) < 1)
    throw std::invalid_argument("Register with name: " + register_name +
                                " is not exists");

  if(sub_registers.count(register_name) < 1)
    sub_registers[register_name] = std::map<std::string,std::string>();

  for(auto hr : half_register)
    sub_registers[register_name][hr.first] = hr.second;
 }

} // namespace eg