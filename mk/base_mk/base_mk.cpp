// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <mk/base_mk/base_mk.h>

namespace mk {

trap::trap() : tag_container() {}
trap::trap(std::function<void(eg::key_value_storage &values, global::flag_container flags)> current_body)
    : tag_container() {
  body = current_body;
}

void trap::set_body(
    std::function<void(eg::key_value_storage &values, global::flag_container flags)> current_body) {
  body = current_body;
}

void trap::execute(eg::key_value_storage &values, global::flag_container flags) { body(values, flags); }

base_mk::base_mk() {
  file = reinterpret_cast<fs::out_file *>(0);
  loader = reinterpret_cast<ld::base_ld *>(0);
  zero_id = add_container();
}
base_mk::base_mk(fs::out_file *out_file) {
  file = out_file;
  loader = reinterpret_cast<ld::base_ld *>(0);
  zero_id = add_container();
}
base_mk::~base_mk() {}
void base_mk::set_file(fs::out_file *out_file) { file = out_file; }
fs::out_file *base_mk::get_file() { return file; }
void base_mk::set_loader(ld::base_ld *current_loader) {
  loader = current_loader;
}
ld::base_ld *base_mk::get_loader() { return loader; }

void base_mk::add_trap(
    std::string trap_name,
    std::function<void(eg::key_value_storage &values, global::flag_container flags)> trap_code) {
  traps[trap_name] = trap_code;
}

void base_mk::insert_trap(std::string trap_name, global::flag_container flags) {
  insert_trap(trap_name, zero_id, flags);
}

void base_mk::insert_trap(std::string name, uint64_t id, global::flag_container flags) {
  traps[name].execute(trap_containers[id], flags);
}

void base_mk::add_tags_to_trap(
    std::string trap_name, std::initializer_list<std::string> current_tags) {
  traps[trap_name].add_tags(current_tags);
}

std::uint64_t base_mk::add_container() {
  auto id = global::cs.generate_unique_number("traps");
  trap_containers[id];
  return id;
}

void base_mk::remove_container(std::uint64_t id) { trap_containers.erase(id); }

void base_mk::remove_from_container(uint64_t container_id, std::string name) {
  trap_containers[container_id].remove_value(name);
}

void base_mk::insert_random_trap(
    std::initializer_list<std::string> current_tags, global::flag_container flags) {
  insert_random_trap(current_tags, zero_id, flags);
}

void base_mk::insert_random_trap(
    std::initializer_list<std::string> current_tags, uint64_t id, global::flag_container flags) {
  std::vector<trap *> tmp;
  for (auto t : traps) {
    if (t.second.check_tags(current_tags)) tmp.push_back(&t.second);
  }
  if (tmp.size() == 0) throw std::domain_error("No one trap can`t be executed");
  tmp[global::rc.generate_random_number() % tmp.size()]->execute(
      trap_containers[id], flags);
}

}  // namespace mk