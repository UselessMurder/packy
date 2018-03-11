#ifndef BASE_LD_H
#define BASE_LD_H

#include <fs/file.h>
#include <cstdint>

namespace ld {

enum class machine_types : std::uint8_t { none = 0, i386 = 1, amd64 = 2 };

enum class loader_types : std::uint8_t {
  none = 0,
  pe32 = 1,
  pe64 = 2,
  elf = 3
};

class base_ld {
protected:
  std::vector<std::uint8_t> image;
  fs::in_file *file;

public:
  base_ld();
  base_ld(fs::in_file *in_file);
  virtual ~base_ld();
  void set_file(fs::in_file *in_file);
  fs::in_file *get_file();
  virtual bool parse() = 0;
  virtual machine_types get_machine_type() = 0;
  virtual loader_types get_loader_type() = 0;
};
} // namespace ld

#endif