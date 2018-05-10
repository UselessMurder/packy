#ifndef BASE_MK_H
#define BASE_MK_H

#include <eg/base/base_eg.h>
#include <fs/file.h>
#include <ld/base_ld/base_ld.h>

namespace mk {
class base_mk {
 protected:
  fs::out_file *file;
  ld::base_ld *loader;
  std::map<std::string, std::function<void(std::map<std::string, std::any> &values)>> traps;
  std::map<std::string, std::map<std::string, std::any>> traps_params;
  std::set<std::string> rand_traps;
  void add_trap(std::string trap_name, std::function<void(std::map<std::string, std::any> &values)> trap_code);
  void insert_trap(std::string name);
  void add_param_to_trap(std::string trap_name, std::string param_name, std::any value);
  void set_trap_random(std::string trap_name);
  void insert_random_trap();
  virtual void init_traps() = 0;
 public:
  base_mk();
  base_mk(fs::out_file *out_file);
  virtual ~base_mk();
  void set_file(fs::out_file *out_file);
  fs::out_file *get_file();
  void set_loader(ld::base_ld *current_loader);
  ld::base_ld *get_loader();
  virtual bool ok_machine(ld::machine_types current_machine) = 0;
  virtual bool ok_loader(ld::loader_types current_loader) = 0;
  virtual void make() = 0;
};
}  // namespace mk

#endif