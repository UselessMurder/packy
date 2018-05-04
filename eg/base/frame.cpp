// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <algorithm>
#include <eg/base/base_eg.h>
#include <chrono>
#include <cstdlib>
#include <limits>

namespace eg {

frame::frame(node *parent) : node(parent) {
  set_flag(type_flags::build_frame);
  size = 0;
}

frame::~frame() {}

void frame::get_voids(std::vector<var> *voids) {
  std::vector<var *> exists;
  for (auto v : fixed)
    exists.push_back(
        find_node_by_name<frame>(
            this, v.second, {bypass_flags::parents, bypass_flags::broadcast})
            ->get_var(v.first));
  std::sort(
      exists.begin(), exists.end(),
      [](const var *a, const var *b) -> bool { return a->shift < b->shift; });
  std::uint64_t shift_pointer = 0;
  for (auto v : exists) {
    if (v->shift - shift_pointer > v->size)
      voids->push_back(var{.size = (v->shift - shift_pointer) - v->size,
                           .shift = shift_pointer});
    shift_pointer = v->shift;
  }
  voids->push_back(
      var{.size = std::numeric_limits<std::uint64_t>::max() - shift_pointer,
          .shift = shift_pointer});
}

void frame::fill(var space, std::vector<std::string> *values) {
  std::list<std::string> losers;
  for (auto name : *values) {
    if (vars[name].size <= space.size) {
      space.shift += vars[name].size;
      space.size -= vars[name].size;
      vars[name].shift = space.shift;
    } else {
      losers.push_back(name);
    }
  }
  values->clear();
  values->insert(values->end(), losers.begin(), losers.end());
}

void frame::add_var(std::string var_name, std::uint64_t size) {
  if (check_flag(type_flags::fixed))
    throw std::domain_error(
        "Cant`t add variable to fixed stack frame with id: " +
        std::to_string(get_object_id()));
  if (vars.count(var_name) > 0)
    throw std::invalid_argument(
        "Variable with same name: " + var_name +
        " already exists in frame with id: " + std::to_string(get_object_id()));
  vars[var_name] = var{.size = size, .shift = 0};
}

var *frame::get_var(std::string var_name) {
  if (!check_flag(type_flags::fixed))
    throw std::domain_error("Cant`t get var from non fixed frame with id: " +
                            std::to_string(get_object_id()));
  if (vars.count(var_name) < 1)
    throw std::invalid_argument(
        "Variable with name: " + var_name +
        " is not exists if frame with id: " + std::to_string(get_object_id()));
  return &vars[var_name];
}

std::uint64_t frame::get_frame_size() {
  if (!check_flag(type_flags::fixed))
    throw std::domain_error("Cant`t get size of frame with id: " +
                            std::to_string(get_object_id()));
  return size;
}

void frame::add_dependence(std::string var_name, std::string frame_name) {
  if (check_flag(type_flags::fixed))
    throw std::domain_error("Cant`t add dependence to fixed frame with id: " +
                            std::to_string(get_object_id()));
  if (fixed.count(var_name) > 0)
    throw std::invalid_argument(
        "Dependence with same name: " + var_name +
        " already exists in frame with id: " + std::to_string(get_object_id()));
  fixed[var_name] = frame_name;
}

void frame::fix_vars() {

  if (check_flag(type_flags::fixed))
    throw std::domain_error("Cant`t fix already fixed frame with id: " +
                            std::to_string(get_object_id()));

  std::vector<std::string> heap;
  for (auto v : vars)
    heap.push_back(v.first);
  global::rc.random_shuffle_vector(&heap);
  std::vector<var> voids;
  get_voids(&voids);
  for (std::uint32_t i = 0; i < voids.size() && !heap.empty(); i++)
    fill(voids[i], &heap);
  if (!heap.empty())
    throw std::domain_error("Not all variables was fixed in frame with id: " +
                            std::to_string(get_object_id()));
  for (auto v : fixed) {
    if (vars.count(v.first) > 0)
      throw std::invalid_argument("Variable with same name: " + v.first +
                                  " already exists in frame with id: " +
                                  std::to_string(get_object_id()));
    vars[v.first] =
        *(find_node_by_name<frame>(
              this, v.second, {bypass_flags::parents, bypass_flags::broadcast})
              ->get_var(v.first));
  }
  auto last =
      std::max_element(vars.begin(), vars.end(),
                       [](const std::pair<std::string, var> &p1,
                          const std::pair<std::string, var> &p2) -> bool {
                         return p1.second.shift < p2.second.shift;
                       });
  if (last != vars.end()) {
    size = last->second.shift;
  } else {
    size = 0;
  }
  set_flag(type_flags::fixed);
}

std::string frame::to_string() {
  std::stringstream ss;
  ss << "frame:" << name << "@" << size << ":(" << get_object_id() << "):\n";
  for(auto v : vars)
    ss << "var:" << v.first << ":(" << v.second.shift << "," << v.second.size << ")\n";
  for(auto ch : childs)
    if(ch->check_flag(type_flags::build_memory))
    ss << node_cast<memory_piece>(ch)->to_string(); 
  return ss.str();
}

} // namespace eg