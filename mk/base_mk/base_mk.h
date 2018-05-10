#ifndef BASE_MK_H
#define BASE_MK_H

#include <eg/base/base_eg.h>
#include <fs/file.h>
#include <ld/base_ld/base_ld.h>

namespace mk {


class trap : public global::tag_container {
private:
  std::function<void(eg::key_value_storage &values, global::flag_container flags)> body;
public:
  trap();
  trap(std::function<void(eg::key_value_storage &values, global::flag_container flags)> current_body);
  void set_body(std::function<void(eg::key_value_storage &values, global::flag_container flags)> current_body);
  void execute(eg::key_value_storage &values, global::flag_container flags);
};

class base_mk {
 protected:
  fs::out_file *file;
  ld::base_ld *loader;
  std::map<std::string, trap> traps;
  std::map<uint64_t, eg::key_value_storage> trap_containers;
  std::uint64_t zero_id;
  void add_trap(std::string trap_name,
                std::function<void(eg::key_value_storage &values, global::flag_container flags)> trap_code);
  void add_tags_to_trap(std::string trap_name, std::initializer_list<std::string> current_tags);
  void insert_trap(std::string name, uint64_t id, global::flag_container flags);
  void insert_trap(std::string name, global::flag_container flags);
  std::uint64_t add_container();
  void remove_container(std::uint64_t id);
  template <typename T>
  void add_to_container(uint64_t container_id, std::string name, T value) {
    trap_containers[container_id].set_value(name, value);
  }
  void remove_from_container(uint64_t container_id, std::string name);
  void insert_random_trap(std::initializer_list<std::string> current_tags, global::flag_container flags);
  void insert_random_trap(std::initializer_list<std::string> current_tags, uint64_t id, global::flag_container flags);
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