#ifndef I686_H
#define I686_H

#include <eg/i8086/i8086.h>

namespace eg::i8086 {
class i686 : public i8086 {
private:
  void init_invariants();
  void init_assemblers();

public:
  i686();
  ~i686();
  void init_state();

  void push_registers(std::initializer_list<std::string> registers);
  void pop_registers(std::initializer_list<std::string> registers);
};
} // namespace eg::i8086

#endif