// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <mk/base_mk/base_mk.h>

namespace mk {
base_mk::base_mk() {
  file = reinterpret_cast<fs::out_file *>(0);
  loader = reinterpret_cast<ld::base_ld *>(0);
}
base_mk::base_mk(fs::out_file *out_file) {
  file = out_file;
  loader = reinterpret_cast<ld::base_ld *>(0);
}
base_mk::~base_mk() {}
void base_mk::set_file(fs::out_file *out_file) { file = out_file; }
fs::out_file *base_mk::get_file() { return file; }
void base_mk::set_loader(ld::base_ld *current_loader) {
  loader = current_loader;
}
ld::base_ld *base_mk::get_loader() { return loader; }

void base_mk::add_trap(std::string trap_name, std::function<void(std::map<std::string, std::any> &values)> trap_code) {
	traps[trap_name] = trap_code;
	traps_params[trap_name] = std::map<std::string, std::any>();
}

void base_mk::insert_trap(std::string trap_name) {
	traps[trap_name](traps_params[trap_name]);
}
void base_mk::add_param_to_trap(std::string trap_name, std::string param_name, std::any value) {
	traps_params[trap_name][param_name] = value;
}
void base_mk::set_trap_random(std::string trap_name) {
	rand_traps.insert(trap_name);
}

void base_mk::insert_random_trap() {
	std::vector<std::string> tmp;
	std::copy(rand_traps.begin(), rand_traps.end(), std::back_inserter(tmp));
	global::rc.random_shuffle_vector(&tmp);
	traps[tmp.back()](traps_params[tmp.back()]);
}

}  // namespace mk