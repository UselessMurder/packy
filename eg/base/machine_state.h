#ifndef MACHINE_STATE_H
#define MACHINE_STATE_H

#include <initializer_list>
#include <list>
#include <map>
#include <vector>

namespace eg {

class machine_state {
protected:
  std::map<std::string, bool> state;
  std::map<std::string, std::map<std::string, std::string>> sub_registers;
  std::map<std::string, std::vector<std::string>> groups;
  std::map<std::string, std::pair<std::uint32_t, std::list<bool>>> local_stack;
  std::map<std::string, std::pair<std::uint32_t, std::list<std::vector<bool>>>>
      group_stack;

  void set_registers(std::initializer_list<std::string> registers);
  void add_group(std::string group_name, std::vector<std::string> registers);
  void add_sub_registers(
      std::string register_name,
      std::initializer_list<std::pair<std::string, std::string>> half_register);

public:
  machine_state();
  virtual ~machine_state();
  
  void local_save(std::string register_name);
  void local_load(std::string register_name);
  void group_save(std::string group_name);
  void group_load(std::string group_name);
  std::uint32_t get_free_count(std::string group_name);
  void grab_register(std::string register_name);
  void free_register(std::string register_name);
  void grab_group(std::string group_name);
  void free_group(std::string group_name);
  std::string get_free(std::string group_name);
  std::string get_rand(std::string group_name);
  std::string get_sub_register(std::string register_name,
                               std::string half_name);
  bool try_grab_registers(std::map<std::string, std::string> *in,
                          std::map<std::string, std::string> *out);
  void free_registers(std::map<std::string, std::string> *registers);
};

} // namespace eg

#endif