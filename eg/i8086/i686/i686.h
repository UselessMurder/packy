#ifndef I686_H
#define I686_H

#include <eg/i8086/i8086.h>

namespace eg::i8086 {
class i686 : public i8086 {
private:
  std::map<std::string, std::uint8_t> ivg;
  void init_invariants();
  void init_assemblers();
  global::flag_container gg(std::initializer_list<std::string> current_flags);

  void init_crc();
  void init_aes();
  void init_unzip();
  void init_clear();
  void init_becb();
  void init_decb();
  void init_gambling();

public:
  i686();
  ~i686();
  void init_state();

  void copy_fundamental();
  void push_registers(std::initializer_list<std::string> registers);
  void pop_registers(std::initializer_list<std::string> registers);
};
} // namespace eg::i8086

#endif