#ifndef I8086_H
#define I8086_H

#include <eg/base/base_eg.h>
#include <initializer_list>

namespace eg::i8086 {
static const char rax[] = "rax";
static const char rcx[] = "rcx";
static const char rdx[] = "rdx";
static const char rbx[] = "rbx";
static const char rsp[] = "rsp";
static const char rbp[] = "rbp";
static const char rsi[] = "rsi";
static const char rdi[] = "rdi";
static const char r8[] = "r8";
static const char r9[] = "r9";
static const char r10[] = "r10";
static const char r11[] = "r11";
static const char r12[] = "r12";
static const char r13[] = "r13";
static const char r14[] = "r14";
static const char r15[] = "r15";
static const char eax[] = "eax";
static const char ecx[] = "ecx";
static const char edx[] = "edx";
static const char ebx[] = "ebx";
static const char esp[] = "esp";
static const char ebp[] = "ebp";
static const char esi[] = "esi";
static const char edi[] = "edi";
static const char r8d[] = "r8d";
static const char r9d[] = "r9d";
static const char r10d[] = "r10d";
static const char r11d[] = "r11d";
static const char r12d[] = "r12d";
static const char r13d[] = "r13d";
static const char r14d[] = "r14d";
static const char r15d[] = "r15d";
static const char ax[] = "ax";
static const char cx[] = "cx";
static const char dx[] = "dx";
static const char bx[] = "bx";
static const char sp[] = "sp";
static const char bp[] = "bp";
static const char si[] = "si";
static const char di[] = "di";
static const char r8w[] = "r8w";
static const char r9w[] = "r9w";
static const char r10w[] = "r10w";
static const char r11w[] = "r11w";
static const char r12w[] = "r12w";
static const char r13w[] = "r13w";
static const char r14w[] = "r14w";
static const char r15w[] = "r15w";
static const char al[] = "al";
static const char cl[] = "cl";
static const char dl[] = "dl";
static const char bl[] = "bl";
static const char spl[] = "spl";
static const char bpl[] = "bpl";
static const char sil[] = "sil";
static const char dil[] = "dil";
static const char r8b[] = "r8w";
static const char r9b[] = "r9w";
static const char r10b[] = "r10b";
static const char r11b[] = "r11b";
static const char r12b[] = "r12b";
static const char r13b[] = "r13b";
static const char r14b[] = "r14b";
static const char r15b[] = "r15b";
static const char ah[] = "ah";
static const char ch[] = "ch";
static const char dh[] = "dh";
static const char bh[] = "bh";
static const char rip[] = "rip";
static const char cs[] = "cs";
static const char ss[] = "ss";
static const char ds[] = "ds";
static const char es[] = "es";
static const char fs[] = "fs";
static const char gs[] = "gs";

class i8086 : public build_root {
public:
  i8086();
  virtual ~i8086();
  virtual void push_registers(std::initializer_list<std::string> registers) = 0;
  virtual void pop_registers(std::initializer_list<std::string> registers) = 0;
};

} // namespace eg::i8086

#endif