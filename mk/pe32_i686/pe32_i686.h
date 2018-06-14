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
  bool api_flag;
  std::uint32_t export_rva;
  std::pair<uint32_t, uint32_t> resource_directory_params;
  std::pair<uint32_t, uint32_t> reloc_directory_params;
  std::pair<uint32_t, uint32_t> tls_directory_params;
  std::pair<uint32_t, uint32_t> import_directory_params;
  std::map<std::string, uint32_t> local_keys;
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
  void clear_exit_init_code();
  void base_exit_init_code();
  void end_init_code();
  void find_library_init_code();
  void load_function_init_code();
  void vista_or_higher_init_code();
  void load_apis(std::map<std::string, std::uint32_t> &requirements,
                 std::string next_name, bool enable);
  void insert_decrypt(std::string memory_name);
  void insert_encrypt(std::string memory_name);
  void detach_debugger(std::string reg_name);
  void set_base();
  void build_import_stub();
  void build_import_directory();
  void build_mprotect_stub();
  void build_reloc_stub();
  void build_tls_stub();
  void build_reloc_table();
  void build_resources();
  void build_export();
  void init_guard_routine();
  void init_forever_crash_loop();

  std::uint32_t get_KERNEL32_hash();
  std::uint32_t get_NTDLL_hash();
  std::uint32_t get_LoadLibrary_hash();
  std::uint32_t get_GetModuleHandle_hash();
  std::uint32_t get_GetProcAddress_hash();
  std::uint32_t get_NtTerminateProcess_hash();
  std::uint32_t get_VirtualProtect_hash();
  std::uint32_t get_GetVersionEx_hash();
  std::uint32_t get_NtQueryInformationProcess_hash();
  std::uint32_t get_GetThreadContext_hash();
  std::uint32_t get_SetThreadContext_hash();
  std::uint32_t get_CreateThread_hash();
  std::uint32_t get_Sleep_hash();
  std::uint32_t get_NtSetInformationThread_hash();
  std::uint32_t get_DbgUiRemoteBreakin_hash();
  void init_traps();

  void init_ectx(eg::key_value_storage &ectx);
  void exception_prologue(eg::key_value_storage &ectx);
  void exception_epilogue(eg::key_value_storage &ectx);
  void insert_except_handler(eg::key_value_storage &ectx);

  bool is_api_configured();

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