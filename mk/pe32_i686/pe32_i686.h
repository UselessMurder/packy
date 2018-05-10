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
  std::uint32_t tls_rva;
  std::uint32_t export_rva;
  std::pair<uint32_t, uint32_t> resource_directory_params;
  std::pair<uint32_t, uint32_t> reloc_directory_params;
  ld::pe::pe32 *get_ld();
  void write_header(std::vector<std::uint8_t> header);
  void write_data(std::vector<std::uint8_t> *data);

  std::uint32_t build_code(std::vector<std::uint8_t> *stub,
                           std::vector<std::uint8_t> *data);

  void walk_resource(std::vector<uint8_t> &fp, std::vector<uint8_t> &sp,
                     uint64_t id,
                     std::vector<std::pair<uint32_t, uint64_t>> &dofs,
                     uint32_t &dof, uint32_t &sof,
                     ld::pe::resource_container *ct);

  void build_context_forks();

  void search_expx_init_code();
  void get_apix_init_code();
  void error_exit_init_code();
  void end_init_code();
  void find_library_init_code();
  void load_function_init_code();
  void build_import_stub();
  void build_mprotect_stub();
  void build_reloc_stub();
  void build_tls_stub();
  void build_reloc_table();
  void build_resources();
  void build_export();

  std::uint32_t get_KERNEL32_hash();
  std::uint32_t get_LoadLibrary_hash();
  std::uint32_t get_GetModuleHandle_hash();
  std::uint32_t get_GetProcAddress_hash();
  std::uint32_t get_ExitProcess_hash();
  std::uint32_t get_VirtualProtect_hash();
  void init_traps();

 public:
  pe32_i686();
  pe32_i686(fs::out_file *out_file);
  ~pe32_i686();
  bool ok_machine(ld::machine_types current_machine);
  bool ok_loader(ld::loader_types current_loader);
  void make();
};
}  // namespace mk

#endif