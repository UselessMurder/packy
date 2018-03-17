#ifndef PE32_I386_H
#define PE32_I386_H

#include <eg/i8086/i686/i686.h>
#include <ld/pe/pe32/pe32.h>
#include <mk/base_mk/base_mk.h>
#include <mk/base_mk/compress.h>

namespace mk {
class pe32_i686 : public base_mk {
protected:
  eg::i8086::i686 e;
  lzo_compress cmpr;
  ld::pe::pe32 *get_ld();
  void write_header(std::vector<std::uint8_t> header);
  void write_data(std::vector<std::uint8_t> *data);
  void build_import_stub();
  std::uint32_t build_code(std::vector<std::uint8_t> *stub,
                           std::vector<std::uint8_t> *data);
  // void search_expx_init_code();
  // void get_apix_init_code();
  // void error_exit_init_code();
  // void end_init_code();
  // void find_library_init_code();
  // void load_function_init_code();
  // void restore_image_init_code();

  // std::uint32_t get_KERNEL32_hash();

  // std::uint32_t get_LoadLibrary_hash();
  // std::uint32_t get_GetModuleHandle_hash();
  // std::uint32_t get_GetProcAddress_hash();
  // std::uint32_t get_ExitProcess_hash();
  

public:
  pe32_i686();
  pe32_i686(fs::out_file *out_file);
  ~pe32_i686();
  bool ok_machine(ld::machine_types current_machine);
  bool ok_loader(ld::loader_types current_loader);
  void make();
};
} // namespace mk

#endif