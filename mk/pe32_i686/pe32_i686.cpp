// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <cry/crypto.h>
#include <mk/pe32_i686/pe32_i686.h>

#define CHECK_DEBUGGER

namespace mk {
pe32_i686::pe32_i686() : base_mk() {
  tls_directory_params.first = 0;
  tls_directory_params.second = 0;
  import_directory_params.first = 0;
  import_directory_params.second = 0;
  resource_directory_params.first = 0;
  resource_directory_params.second = 0;
  export_rva = 0;
  reloc_directory_params.first = 0;
  reloc_directory_params.second = 0;
  api_flag = false;
  init_traps();
}
pe32_i686::pe32_i686(fs::out_file *out_file) : base_mk(out_file) {
  tls_directory_params.first = 0;
  tls_directory_params.second = 0;
  import_directory_params.first = 0;
  import_directory_params.second = 0;
  resource_directory_params.first = 0;
  resource_directory_params.second = 0;
  export_rva = 0;
  reloc_directory_params.first = 0;
  reloc_directory_params.second = 0;
  api_flag = false;
  init_traps();
}
pe32_i686::~pe32_i686() {}

inline ld::pe::pe32 *pe32_i686::get_ld() {
  return dynamic_cast<ld::pe::pe32 *>(loader);
}
bool pe32_i686::ok_machine(ld::machine_types current_machine) {
  if (ld::machine_types::i386 == current_machine) return true;
  return false;
}
bool pe32_i686::ok_loader(ld::loader_types current_loader) {
  if (ld::loader_types::pe32 == current_loader) return true;
  return false;
}

bool pe32_i686::is_api_configured() { return api_flag; }

std::uint32_t pe32_i686::get_KERNEL32_hash() {
  std::vector<std::uint8_t> kernel32 = {0x4b, 0x45, 0x52, 0x4e, 0x45,
                                        0x4c, 0x33, 0x32, 0x2e, 0x64,
                                        0x6c, 0x6c, 0x0};
  cry::crc32 c;
  c.set(kernel32);
  return c.get();
}

std::uint32_t pe32_i686::get_NTDLL_hash() {
  std::vector<std::uint8_t> ntdll = {0x4e, 0x54, 0x44, 0x4c, 0x4c,
                                     0x2e, 0x64, 0x6c, 0x6c, 0x0};
  cry::crc32 c;
  c.set(ntdll);
  return c.get();
}

std::uint32_t pe32_i686::get_LoadLibrary_hash() {
  std::vector<std::uint8_t> loadlibrary = {0x4c, 0x6f, 0x61, 0x64, 0x4c,
                                           0x69, 0x62, 0x72, 0x61, 0x72,
                                           0x79, 0x41, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(loadlibrary);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_GetModuleHandle_hash() {
  std::vector<std::uint8_t> getmodulehandle = {
      0x47, 0x65, 0x74, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65,
      0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x41, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(getmodulehandle);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_GetProcAddress_hash() {
  std::vector<std::uint8_t> getprocaddr = {0x47, 0x65, 0x74, 0x50, 0x72,
                                           0x6f, 0x63, 0x41, 0x64, 0x64,
                                           0x72, 0x65, 0x73, 0x73, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(getprocaddr);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_NtTerminateProcess_hash() {
  std::vector<std::uint8_t> ntterminateprocess = {
      0x4e, 0x74, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74,
      0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x0};
  std::uint32_t result = get_NTDLL_hash();
  cry::crc32 c;
  c.set(ntterminateprocess);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_VirtualProtect_hash() {
  std::vector<std::uint8_t> virtualprotect = {0x56, 0x69, 0x72, 0x74, 0x75,
                                              0x61, 0x6c, 0x50, 0x72, 0x6f,
                                              0x74, 0x65, 0x63, 0x74, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(virtualprotect);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_GetVersionEx_hash() {
  std::vector<std::uint8_t> getosversionex = {0x47, 0x65, 0x74, 0x56, 0x65,
                                              0x72, 0x73, 0x69, 0x6f, 0x6e,
                                              0x45, 0x78, 0x41, 0x00};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(getosversionex);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_NtQueryInformationProcess_hash() {
  std::vector<std::uint8_t> ntqueryinformationprocess = {
      0x4e, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x49, 0x6e,
      0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e,
      0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x0};
  std::uint32_t result = get_NTDLL_hash();
  cry::crc32 c;
  c.set(ntqueryinformationprocess);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_GetThreadContext_hash() {
  std::vector<std::uint8_t> getthreadcontext = {
      0x47, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64,
      0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(getthreadcontext);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_SetThreadContext_hash() {
  std::vector<std::uint8_t> setthreadcontext = {
      0x53, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64,
      0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(setthreadcontext);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_CreateThread_hash() {
  std::vector<std::uint8_t> createthread = {0x43, 0x72, 0x65, 0x61, 0x74,
                                            0x65, 0x54, 0x68, 0x72, 0x65,
                                            0x61, 0x64, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(createthread);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_NtSetInformationThread_hash() {
  std::vector<std::uint8_t> ntsetinformationthread = {
      0x4e, 0x74, 0x53, 0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,
      0x74, 0x69, 0x6f, 0x6e, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x0};
  std::uint32_t result = get_NTDLL_hash();
  cry::crc32 c;
  c.set(ntsetinformationthread);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_Sleep_hash() {
  std::vector<std::uint8_t> sleep = {0x53, 0x6c, 0x65, 0x65, 0x70, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(sleep);
  result += c.get();
  return result;
}

std::uint32_t pe32_i686::get_DbgUiRemoteBreakin_hash() {
  std::vector<std::uint8_t> dbguiremotebreakin = {
      0x44, 0x62, 0x67, 0x55, 0x69, 0x52, 0x65, 0x6d, 0x6f, 0x74,
      0x65, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x69, 0x6e, 0x0};
  std::uint32_t result = get_NTDLL_hash();
  cry::crc32 c;
  c.set(dbguiremotebreakin);
  result += c.get();
  return result;
}

void pe32_i686::init_traps() {
  // integrity_check
  add_trap("integrity_check",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto seg1 = global::cs.generate_unique_string("usegment");
             auto fctx = global::cs.generate_unique_number("fctx");
             auto tmp_1 = global::cs.generate_unique_string("pr_regs");
             auto tmp_2 = global::cs.generate_unique_string("pr_regs");
             e.f(fl, "store_abs", e.vshd("target"),
                 e.shd(values.get_value<std::string>("target")));
             e.f(fl, "store_vd", e.vshd("count"),
                 e.fszd(values.get_value<std::string>("target")));
             e.f(fl, "store_vb", e.vshd("crc_switch"), std::uint64_t(0));
             e.f(fl, "invoke", e.shd("crc"));
             e.bs(tmp_1, "common", fctx);
             e.bs(tmp_2, "common", fctx);
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "push_rd", e.g(tmp_2));
             e.f(fl, "load_rd", e.g(tmp_2), e.vshd("result"));
             e.f(fl, "mov_rd_vd", e.g(tmp_1),
                 e.c32d(values.get_value<std::string>("target"), {}));
             e.f(fl, "cmp_rd_rd", e.g(tmp_1), e.g(tmp_2));
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::flag_safe);
             e.f(new_fl, "pop_rd", e.g(tmp_2));
             e.f(new_fl, "pop_rd", e.g(tmp_1));
             e.fr(tmp_1);
             e.fr(tmp_2);
             e.f(fl, "branch", "e", e.shd(seg1),
                 e.shd(values.get_value<std::string>("if_error")));
             e.end();
             e.start_segment(seg1);
           });
  add_tags_to_trap("integrity_check", {"all", "unapi"});

  // IsDebbugerPresent
  add_trap("is_debbuger_present",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto seg1 = global::cs.generate_unique_string("usegment");
             auto fctx = global::cs.generate_unique_number("fctx");
             auto tmp = global::cs.generate_unique_string("pr_regs");
             auto fs_ = global::cs.generate_unique_string("pr_regs");
             e.bs(tmp, "common", fctx);
             e.f(fl, "push_rd", e.g(tmp));
             e.f(fl, "mov_rd_vd", e.g(tmp), std::uint64_t(0x30));
             e.bss(fs_, eg::i8086::fs, fctx);
             e.f(fl, "mov_rd_serd", e.g(tmp), e.g(fs_), e.g(tmp));
             e.fr(fs_);
             e.f(fl, "add_rd_vd", e.g(tmp), std::uint64_t(2));
             e.f(fl, "movzx_rd_mb", e.g(tmp), e.g(tmp));
             e.f(fl, "test_rd_rd", e.g(tmp), e.g(tmp));
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::flag_safe);
             e.f(new_fl, "pop_rd", e.g(tmp));
             e.fr(tmp);
             e.f(fl, "branch", "e", e.shd(seg1),
                 e.shd(values.get_value<std::string>("if_error")));
             e.end();
             e.start_segment(seg1);
           });
  add_tags_to_trap("is_debbuger_present",
                   {"all", "undep", "unapi", "without_target"});

  // NtGlobalFlag
  add_trap("nt_global_flag",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto seg1 = global::cs.generate_unique_string("usegment");
             auto fctx = global::cs.generate_unique_number("fctx");
             auto tmp = global::cs.generate_unique_string("pr_regs");
             auto fs_ = global::cs.generate_unique_string("pr_regs");
             e.bs(tmp, "common", fctx);
             e.f(fl, "push_rd", e.g(tmp));
             e.f(fl, "mov_rd_vd", e.g(tmp), std::uint64_t(0x30));
             e.bss(fs_, eg::i8086::fs, fctx);
             e.f(fl, "mov_rd_serd", e.g(tmp), e.g(fs_), e.g(tmp));
             e.fr(fs_);
             e.f(fl, "add_rd_vd", e.g(tmp), std::uint64_t(0x68));
             e.f(fl, "mov_rd_md", e.g(tmp), e.g(tmp));
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::flag_safe);
             e.f(new_fl, "and_rd_vd", e.g(tmp), std::uint64_t(0x70));
             e.f(new_fl, "pop_rd", e.g(tmp));
             e.fr(tmp);
             e.f(fl, "branch", "z", e.shd(seg1),
                 e.shd(values.get_value<std::string>("if_error")));
             e.end();
             e.start_segment(seg1);
           });
  add_tags_to_trap("nt_global_flag",
                   {"all", "undep", "unapi", "without_target"});

  // HeapFlags
  add_trap("heap_flags",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto over = global::cs.generate_unique_string("usegment");
             auto end = global::cs.generate_unique_string("usegment");
             auto compare_2 = global::cs.generate_unique_string("usegment");
             auto compare_1 = global::cs.generate_unique_string("usegment");
             auto large = global::cs.generate_unique_string("usegment");
             auto smaller = global::cs.generate_unique_string("usegment");
             auto fctx = global::cs.generate_unique_number("fctx");
             auto tmp_1 = global::cs.generate_unique_string("pr_regs");
             auto tmp_2 = global::cs.generate_unique_string("pr_regs");
             auto fs_ = global::cs.generate_unique_string("pr_regs");
             auto ebp_ = global::cs.generate_unique_string("pr_regs");
             e.bs(tmp_1, "common", fctx);
             e.bs(tmp_2, "common", fctx);
             e.bss(ebp_, eg::i8086::ebp, fctx);
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "push_rd", e.g(tmp_2));
             e.f(fl, "mov_rd_vd", e.g(tmp_1), std::uint64_t(0x30));
             e.bss(fs_, eg::i8086::fs, fctx);
             e.f(fl, "mov_rd_serd", e.g(tmp_1), e.g(fs_), e.g(tmp_1));
             e.fr(fs_);
             e.f(fl, "add_rd_vd", e.g(tmp_1), std::uint64_t(0x18));
             e.f(fl, "mov_rd_md", e.g(tmp_1), e.g(tmp_1));
             e.f(fl, "mov_rd_rd", e.g(tmp_2), e.g(tmp_1));
             e.f(fl, "test_smb_vb", e.g(ebp_), std::string("-"), e.vshd("os_switch"),
                 std::uint64_t(1));
             e.fr(ebp_);
             e.f(fl, "branch", "nz", e.shd(large), e.shd(smaller));
             e.end();

             e.start_segment(large);
             e.f(fl, "add_rd_vd", e.g(tmp_1), std::uint64_t(0x40));
             e.f(fl, "add_rd_vd", e.g(tmp_2), std::uint64_t(0x44));
             e.f(fl, "jump", e.shd(compare_1));
             e.end();

             e.start_segment(smaller);
             e.f(fl, "add_rd_vd", e.g(tmp_1), std::uint64_t(0xC));
             e.f(fl, "add_rd_vd", e.g(tmp_2), std::uint64_t(0x10));
             e.f(fl, "jump", e.shd(compare_1));
             e.end();

             e.start_segment(compare_1);
             e.f(fl, "mov_rd_md", e.g(tmp_1), e.g(tmp_1));
             e.f(fl, "mov_rd_md", e.g(tmp_2), e.g(tmp_2));
             e.f(fl, "cmp_rd_vd", e.g(tmp_2), std::uint64_t(0));
             e.f(fl, "branch", "ne", e.shd(over), e.shd(compare_2));
             e.end();

             e.start_segment(compare_2);
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::flag_safe);
             e.f(new_fl, "and_rd_vd", e.g(tmp_1), std::uint64_t(0xfffffffd));
             e.f(fl, "branch", "z", e.shd(end), e.shd(over));
             e.end();

             e.start_segment(over);
             e.f(fl, "pop_rd", e.g(tmp_2));
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.f(fl, "jump", e.shd(values.get_value<std::string>("if_error")));
             e.end();

             e.start_segment(end);
             e.f(fl, "pop_rd", e.g(tmp_2));
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.fr(tmp_1);
             e.fr(tmp_2);
           });
  add_tags_to_trap("heap_flags", {"all", "without_target"});

  // TF_check
  add_trap("tf_check",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto over = global::cs.generate_unique_string("usegment");
             auto end = global::cs.generate_unique_string("usegment");
             auto tmp_1 = global::cs.generate_unique_string("pr_regs");
             auto esp_ = global::cs.generate_unique_string("pr_regs");
             auto fs_ = global::cs.generate_unique_string("pr_regs");

             eg::key_value_storage ectx;
             init_ectx(ectx);
             ectx.set_value("fl", fl);
             auto fctx = ectx.get_value<uint64_t>("fctx");

             e.bs(tmp_1, "common", fctx);
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "abs_r", e.g(tmp_1),
                 e.shd(ectx.get_value<std::string>("flag_name")));
             e.f(fl, "mov_mb_vb", e.g(tmp_1), std::uint64_t(1));
             exception_prologue(ectx);

             e.f(fl, "push_fd");
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::stack_safe);
             e.bss(esp_, eg::i8086::esp, fctx);
             e.f(new_fl, "or_md_vd", e.g(esp_), std::uint64_t(0x100));
             e.fr(esp_);
             e.f(fl, "pop_fd");
             e.f(fl, "nop");
             e.f(fl, "jump", e.shd("error_exit"));
             e.end();

             exception_epilogue(ectx);
             e.f(fl, "abs_r", e.g(tmp_1),
                 e.shd(ectx.get_value<std::string>("flag_name")));
             e.f(fl, "cmp_mb_vb", e.g(tmp_1), std::uint64_t(0));
             e.f(fl, "branch", "e", e.shd(end), e.shd(over));
             e.end();

             e.add_data(ectx.get_value<std::string>("flag_name"), 1);

             insert_except_handler(ectx);

             e.start_segment(over);
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.f(fl, "jump", e.shd(values.get_value<std::string>("if_error")));
             e.end();

             e.start_segment(end);
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.fr(tmp_1);
           });
  add_tags_to_trap("tf_check", {"all", "undep", "unapi", "without_target"});

  // remote_debugger_present
  add_trap("remote_debugger_present", [this](eg::key_value_storage &values,
                                             global::flag_container fl) {
    auto fctx = global::cs.generate_unique_number("fctx");
    auto eax_ = global::cs.generate_unique_string("pr_regs");
    auto esp_ = global::cs.generate_unique_string("pr_regs");
    auto ebp_ = global::cs.generate_unique_string("pr_regs");
    auto tmp_1 = global::cs.generate_unique_string("pr_regs");
    auto over = global::cs.generate_unique_string("usegment");
    auto end = global::cs.generate_unique_string("usegment");
    auto check = global::cs.generate_unique_string("usegment");
    e.bss(eax_, eg::i8086::eax, fctx);
    e.bss(esp_, eg::i8086::esp, fctx);
    e.bss(ebp_, eg::i8086::ebp, fctx);
    e.bs(tmp_1, "common", fctx);
    e.f(fl, "push_rd", e.g(tmp_1));
    e.f(fl, "push_rd", e.g(eax_));
    e.f(fl, "push_rd", e.g(eax_));
    auto new_fl = fl;
    new_fl.set_flag(eg::type_flags::stack_safe);
    e.f(new_fl, "mov_rd_rd", e.g(tmp_1), e.g(esp_));
    e.f(fl, "push_rd", e.g(tmp_1));
    e.fr(esp_);
    e.f(fl, "push_vd", std::uint64_t(0x0));
    e.f(fl, "push_vd", std::uint64_t(0x4));
    e.f(fl, "push_rd", e.g(tmp_1));
    e.f(fl, "push_vd", std::uint64_t(0x7));
    e.f(fl, "push_vd", std::uint64_t(0xFFFFFFFF));
    e.f(fl, "call_smd", e.g(ebp_), std::string("-"), e.vshd("NtQueryInformationProcess"));
    e.fr(ebp_);
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.f(fl, "test_rd_rd", e.g(eax_), e.g(eax_));
    e.f(fl, "branch", "nz", e.shd(end), e.shd(check));
    e.end();

    e.start_segment(check);
    e.f(fl, "cmp_md_vd", e.g(tmp_1), std::uint64_t(0));
    e.f(fl, "branch", "e", e.shd(end), e.shd(over));
    e.end();

    e.start_segment(over);
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.f(fl, "jump", e.shd(values.get_value<std::string>("if_error")));
    e.end();

    e.start_segment(end);
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.fr(eax_);
    e.fr(tmp_1);
  });
  add_tags_to_trap("remote_debugger_present", {"all", "without_target"});

  // debug_object_handle
  add_trap("debug_object_handle", [this](eg::key_value_storage &values,
                                         global::flag_container fl) {
    auto fctx = global::cs.generate_unique_number("fctx");
    auto eax_ = global::cs.generate_unique_string("pr_regs");
    auto esp_ = global::cs.generate_unique_string("pr_regs");
    auto ebp_ = global::cs.generate_unique_string("pr_regs");
    auto tmp_1 = global::cs.generate_unique_string("pr_regs");
    auto over = global::cs.generate_unique_string("usegment");
    auto end = global::cs.generate_unique_string("usegment");
    auto check = global::cs.generate_unique_string("usegment");
    e.bss(eax_, eg::i8086::eax, fctx);
    e.bss(esp_, eg::i8086::esp, fctx);
    e.bss(ebp_, eg::i8086::ebp, fctx);
    e.bs(tmp_1, "common", fctx);
    e.f(fl, "push_rd", e.g(tmp_1));
    e.f(fl, "push_rd", e.g(eax_));
    e.f(fl, "push_rd", e.g(eax_));
    auto new_fl = fl;
    new_fl.set_flag(eg::type_flags::stack_safe);
    e.f(new_fl, "mov_rd_rd", e.g(tmp_1), e.g(esp_));
    e.f(fl, "push_rd", e.g(tmp_1));
    e.fr(esp_);
    e.f(fl, "push_vd", std::uint64_t(0x0));
    e.f(fl, "push_vd", std::uint64_t(0x4));
    e.f(fl, "push_rd", e.g(tmp_1));
    e.f(fl, "push_vd", std::uint64_t(0x1E));
    e.f(fl, "push_vd", std::uint64_t(0xFFFFFFFF));
    e.f(fl, "call_smd", e.g(ebp_), std::string("-"), e.vshd("NtQueryInformationProcess"));
    e.fr(ebp_);
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.f(fl, "test_rd_rd", e.g(eax_), e.g(eax_));
    e.f(fl, "branch", "nz", e.shd(end), e.shd(check));
    e.end();

    e.start_segment(check);
    e.f(fl, "cmp_md_vd", e.g(tmp_1), std::uint64_t(0));
    e.f(fl, "branch", "e", e.shd(end), e.shd(over));
    e.end();

    e.start_segment(over);
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.f(fl, "jump", e.shd(values.get_value<std::string>("if_error")));
    e.end();

    e.start_segment(end);
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.fr(eax_);
    e.fr(tmp_1);
  });
  add_tags_to_trap("debug_object_handle", {"all", "without_target"});

  // process_debug_flags
  add_trap("process_debug_flags", [this](eg::key_value_storage &values,
                                         global::flag_container fl) {
    auto fctx = global::cs.generate_unique_number("fctx");
    auto eax_ = global::cs.generate_unique_string("pr_regs");
    auto esp_ = global::cs.generate_unique_string("pr_regs");
    auto ebp_ = global::cs.generate_unique_string("pr_regs");
    auto tmp_1 = global::cs.generate_unique_string("pr_regs");
    auto over = global::cs.generate_unique_string("usegment");
    auto end = global::cs.generate_unique_string("usegment");
    auto check = global::cs.generate_unique_string("usegment");
    e.bss(eax_, eg::i8086::eax, fctx);
    e.bss(esp_, eg::i8086::esp, fctx);
    e.bss(ebp_, eg::i8086::ebp, fctx);
    e.bs(tmp_1, "common", fctx);
    e.f(fl, "push_rd", e.g(tmp_1));
    e.f(fl, "push_rd", e.g(eax_));
    e.f(fl, "push_rd", e.g(eax_));
    auto new_fl = fl;
    new_fl.set_flag(eg::type_flags::stack_safe);
    e.f(new_fl, "mov_rd_rd", e.g(tmp_1), e.g(esp_));
    e.f(fl, "push_rd", e.g(tmp_1));
    e.fr(esp_);
    e.f(fl, "push_vd", std::uint64_t(0x0));
    e.f(fl, "push_vd", std::uint64_t(0x4));
    e.f(fl, "push_rd", e.g(tmp_1));
    e.f(fl, "push_vd", std::uint64_t(0x1F));
    e.f(fl, "push_vd", std::uint64_t(0xFFFFFFFF));
    e.f(fl, "call_smd", e.g(ebp_), std::string("-"), e.vshd("NtQueryInformationProcess"));
    e.fr(ebp_);
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.f(fl, "test_rd_rd", e.g(eax_), e.g(eax_));
    e.f(fl, "branch", "nz", e.shd(end), e.shd(check));
    e.end();

    e.start_segment(check);
    e.f(fl, "cmp_md_vd", e.g(tmp_1), std::uint64_t(0));
    e.f(fl, "branch", "ne", e.shd(end), e.shd(over));
    e.end();

    e.start_segment(over);
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.f(fl, "jump", e.shd(values.get_value<std::string>("if_error")));
    e.end();

    e.start_segment(end);
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(eax_));
    e.f(fl, "pop_rd", e.g(tmp_1));
    e.fr(eax_);
    e.fr(tmp_1);
  });
  add_tags_to_trap("process_debug_flags", {"all", "without_target"});

  // check_thread_ctx
  add_trap("check_thread_ctx",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto fctx = global::cs.generate_unique_number("fctx");
             auto eax_ = global::cs.generate_unique_string("pr_regs");
             auto esp_ = global::cs.generate_unique_string("pr_regs");
             auto ebp_ = global::cs.generate_unique_string("pr_regs");
             auto tmp_1 = global::cs.generate_unique_string("pr_regs");
             auto tmp_2 = global::cs.generate_unique_string("pr_regs");
             auto over = global::cs.generate_unique_string("usegment");
             auto end = global::cs.generate_unique_string("usegment");
             auto check = global::cs.generate_unique_string("usegment");
             e.bss(eax_, eg::i8086::eax, fctx);
             e.bss(esp_, eg::i8086::esp, fctx);
             e.bss(ebp_, eg::i8086::ebp, fctx);
             e.bs(tmp_1, "common", fctx);
             e.bs(tmp_2, "common", fctx);
             e.f(fl, "push_rd", e.g(eax_));
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "push_rd", e.g(tmp_2));
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::stack_safe);
             e.f(new_fl, "sub_rd_vd", e.g(esp_), std::uint64_t(0x2CC));
             e.f(new_fl, "mov_rd_rd", e.g(tmp_1), e.g(esp_));
             e.f(fl, "mov_md_vd", e.g(tmp_1), std::uint64_t(0x10010));
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "push_vd", std::uint64_t(0xFFFFFFFE));
             e.f(fl, "call_smd", e.g(ebp_), std::string("-"), e.vshd("GetThreadContext"));
             e.fr(ebp_);
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.f(fl, "test_rd_rd", e.g(eax_), e.g(eax_));
             e.f(fl, "branch", "z", e.shd(end), e.shd(check));
             e.end();

             e.start_segment(check);
             e.f(fl, "clear_rd", e.g(tmp_2));
             for (uint8_t i = 0; i < 4; i++) {
               e.f(fl, "add_rd_vd", e.g(tmp_1), std::uint64_t(4));
               e.f(fl, "or_rd_md", e.g(tmp_2), e.g(tmp_1));
             }
             e.f(fl, "cmp_rd_vd", e.g(tmp_2), std::uint64_t(0));
             e.f(fl, "branch", "e", e.shd(end), e.shd(over));
             e.end();

             e.start_segment(over);
             e.f(new_fl, "add_rd_vd", e.g(esp_), std::uint64_t(0x2CC));
             e.f(fl, "pop_rd", e.g(tmp_2));
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.f(fl, "pop_rd", e.g(eax_));
             e.f(fl, "jump", e.shd(values.get_value<std::string>("if_error")));
             e.end();

             e.start_segment(end);
             e.f(new_fl, "add_rd_vd", e.g(esp_), std::uint64_t(0x2CC));
             e.fr(esp_);
             e.f(fl, "pop_rd", e.g(tmp_2));
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.f(fl, "pop_rd", e.g(eax_));
             e.fr(eax_);
             e.fr(tmp_1);
             e.fr(tmp_2);
           });
  add_tags_to_trap("check_thread_ctx", {"all", "without_target"});

  // reset_thread_ctx
  add_trap("reset_thread_ctx",
           [this](eg::key_value_storage &values, global::flag_container fl) {
             auto fctx = global::cs.generate_unique_number("fctx");
             auto eax_ = global::cs.generate_unique_string("pr_regs");
             auto esp_ = global::cs.generate_unique_string("pr_regs");
             auto ebp_ = global::cs.generate_unique_string("pr_regs");
             auto tmp_1 = global::cs.generate_unique_string("pr_regs");
             e.bss(eax_, eg::i8086::eax, fctx);
             e.bss(esp_, eg::i8086::esp, fctx);
             e.bss(ebp_, eg::i8086::ebp, fctx);
             e.bs(tmp_1, "common", fctx);
             e.f(fl, "push_rd", e.g(eax_));
             e.f(fl, "push_rd", e.g(tmp_1));
             auto new_fl = fl;
             new_fl.set_flag(eg::type_flags::stack_safe);
             e.f(new_fl, "sub_rd_vd", e.g(esp_), std::uint64_t(0x2CC));
             e.f(new_fl, "mov_rd_rd", e.g(tmp_1), e.g(esp_));
             e.f(fl, "push_rd", e.g(tmp_1));
             e.f(fl, "mov_md_vd", e.g(tmp_1), std::uint64_t(0x10010));
             for (uint8_t i = 0; i < 6; i++) {
               e.f(fl, "add_rd_vd", e.g(tmp_1), std::uint64_t(4));
               e.f(fl, "mov_md_vd", e.g(tmp_1), std::uint64_t(0));
             }
             e.f(fl, "push_vd", std::uint64_t(0xFFFFFFFE));
             e.f(fl, "call_smd", e.g(ebp_), std::string("-"), e.vshd("SetThreadContext"));
             e.fr(ebp_);
             e.f(new_fl, "add_rd_vd", e.g(esp_), std::uint64_t(0x2CC));
             e.fr(esp_);
             e.f(fl, "pop_rd", e.g(tmp_1));
             e.f(fl, "pop_rd", e.g(eax_));
             e.fr(eax_);
             e.fr(tmp_1);
           });
  add_tags_to_trap("reset_thread_ctx", {"all", "without_target"});
}

void pe32_i686::init_ectx(eg::key_value_storage &ectx) {
  ectx.set_value("fctx", global::cs.generate_unique_number("fctx"));
  ectx.set_value("handler_name", global::cs.generate_unique_string("usegment"));
  ectx.set_value("epilogue_name",
                 global::cs.generate_unique_string("usegment"));
  ectx.set_value("flag_name", global::cs.generate_unique_string("udata"));
}

void pe32_i686::exception_prologue(eg::key_value_storage &ectx) {
  auto fl = ectx.get_value<global::flag_container>("fl");
  auto new_fl = fl;
  new_fl.set_flag(eg::type_flags::stack_safe);
  auto tmp_1 = global::cs.generate_unique_string("pr_regs");
  auto tmp_2 = global::cs.generate_unique_string("pr_regs");
  auto esp_ = global::cs.generate_unique_string("pr_regs");
  auto fs_ = global::cs.generate_unique_string("pr_regs");
  auto fctx = ectx.get_value<uint64_t>("fctx");
  e.bs(tmp_1, "common", fctx);
  e.bs(tmp_2, "common", fctx);
  e.bss(esp_, eg::i8086::esp, fctx);
  e.bss(fs_, eg::i8086::fs, fctx);
  e.f(fl, "push_rd", e.g(tmp_1));
  e.f(fl, "push_rd", e.g(tmp_2));
  e.f(fl, "abs_r", e.g(tmp_1),
      e.shd(ectx.get_value<std::string>("handler_name")));
  e.f(fl, "push_rd", e.g(tmp_1));
  e.f(fl, "clear_rd", e.g(tmp_1));
  e.f(fl, "push_serd", e.g(fs_), e.g(tmp_1));
  e.f(new_fl, "mov_serd_rd", e.g(fs_), e.g(tmp_1), e.g(esp_));
  ectx.set_value("tmp_1", tmp_1);
  ectx.set_value("tmp_2", tmp_2);
  e.fr(esp_);
  e.fr(fs_);
}

void pe32_i686::exception_epilogue(eg::key_value_storage &ectx) {
  auto fl = ectx.get_value<global::flag_container>("fl");
  auto new_fl = fl;
  new_fl.set_flag(eg::type_flags::stack_safe);
  auto tmp_2 = ectx.get_value<std::string>("tmp_2");
  auto tmp_1 = ectx.get_value<std::string>("tmp_1");
  auto esp_ = global::cs.generate_unique_string("pr_regs");
  auto fs_ = global::cs.generate_unique_string("pr_regs");
  auto fctx = ectx.get_value<uint64_t>("fctx");
  e.start_segment(ectx.get_value<std::string>("epilogue_name"));
  e.bss(esp_, eg::i8086::esp, fctx);
  e.bss(fs_, eg::i8086::fs, fctx);
  e.f(new_fl, "mov_rd_md", e.g(tmp_1), e.g(esp_));
  e.f(fl, "clear_rd", e.g(tmp_2));
  e.f(fl, "mov_serd_rd", e.g(fs_), e.g(tmp_2), e.g(tmp_1));
  e.fr(fs_);
  e.f(fl, "add_rd_vd", e.g(esp_), std::uint64_t(8));
  e.f(fl, "pop_rd", e.g(tmp_2));
  e.f(fl, "pop_rd", e.g(tmp_1));
  e.fr(tmp_1);
  e.fr(tmp_2);
  e.fr(esp_);
}

void pe32_i686::insert_except_handler(eg::key_value_storage &ectx) {
  auto fctx = global::cs.generate_unique_number("fctx");
  auto esp_ = global::cs.generate_unique_string("pr_regs");
  auto tmp_1 = global::cs.generate_unique_string("pr_regs");
  auto tmp_2 = global::cs.generate_unique_string("pr_regs");
  auto set_and_exit = global::cs.generate_unique_string("usegment");
  auto exit = global::cs.generate_unique_string("usegment");
  e.start_segment(ectx.get_value<std::string>("handler_name"));
  e.group_save("common", fctx);
  e.free_group("common");
  e.grab_group("common");
  e.bs(tmp_2, "common", fctx);
  e.bs(tmp_1, "common", fctx);
  e.bss(esp_, eg::i8086::esp, fctx);
  e.f(e.gg({"fu"}), "push_rd", e.g(tmp_2));
  e.f(e.gg({"fu", "ss"}), "mov_rd_rd", e.g(tmp_2), e.g(esp_));
  e.f(e.gg({"fu"}), "push_rd", e.g(tmp_1));
  e.fr(esp_);

  e.f(e.gg({"fu"}), "add_rd_vd", e.g(tmp_2), std::uint64_t(0x10));
  e.f(e.gg({"fu"}), "mov_rd_md", e.g(tmp_2), e.g(tmp_2));
  e.f(e.gg({"fu"}), "add_rd_vd", e.g(tmp_2), std::uint64_t(0xB8));
  e.f(e.gg({"fu"}), "abs_r", e.g(tmp_1),
      e.shd(ectx.get_value<std::string>("epilogue_name")));
  e.f(e.gg({"fu"}), "mov_md_rd", e.g(tmp_2), e.g(tmp_1));
  e.f(e.gg({"fu"}), "clear_rd", e.g(tmp_1));
  e.f(e.gg({"fu"}), "sub_rd_vd", e.g(tmp_2), std::uint64_t(0xA8));
  e.f(e.gg({"fu"}), "or_rd_md", e.g(tmp_1), e.g(tmp_2));
  for (uint8_t i = 0; i < 3; i++) {
    e.f(e.gg({"fu"}), "sub_rd_vd", e.g(tmp_2), std::uint64_t(4));
    e.f(e.gg({"fu"}), "or_rd_md", e.g(tmp_1), e.g(tmp_2));
  }
  e.f(e.gg({"fu"}), "test_rd_rd", e.g(tmp_1), e.g(tmp_1));
  e.f(e.gg({"fu"}), "branch", "z", e.shd(set_and_exit), e.shd(exit));
  e.end();

  e.start_segment(set_and_exit);
  e.f(e.gg({"fu"}), "abs_r", e.g(tmp_2),
      e.shd(ectx.get_value<std::string>("flag_name")));
  e.f(e.gg({"fu"}), "mov_mb_vb", e.g(tmp_2), std::uint64_t(0));
  e.f(e.gg({"fu"}), "jump", e.shd(exit));
  e.end();

  e.start_segment(exit);
  e.f(e.gg({"fu"}), "pop_rd", e.g(tmp_1));
  e.f(e.gg({"fu"}), "pop_rd", e.g(tmp_2));
  e.fr(tmp_1);
  e.fr(tmp_2);
  e.bss(tmp_2, eg::i8086::eax, fctx);
  e.f(e.gg({"fu"}), "clear_rd", e.g(tmp_2));
  e.fr(tmp_2);
  e.f(e.gg({"fu"}), "ret");
  e.group_load("common", fctx);
  e.end();
}

void pe32_i686::init_forever_crash_loop() {
  std::vector<uint8_t> interrupts(256);
  for (uint16_t i = 0; i < 256; i++) interrupts[i] = i;
  global::rc.random_shuffle_vector(&interrupts);
  e.start_segment("crash_loop");
  for (uint8_t i = 0; i < 5; i++) {
    e.f(e.gg({"fu"}), "int_vb", std::uint64_t(interrupts[i]));
  }
  e.f(e.gg({"fu"}), "jump", e.shd("crash_stub"));
  e.end();
  e.start_segment("crash_stub");
  for (uint8_t i = 0; i < 5; i++) {
    e.f(e.gg({"fu"}), "int_vb", std::uint64_t(interrupts[i]));
  }
  e.f(e.gg({"fu"}), "jump", e.shd("crash_loop"));
  e.end();
}

void pe32_i686::end_init_code() {
  e.start_segment("way_out");
  e.bf("accum", "common");
  e.bf("target", "common");
  e.f("abs_r", e.g("target"),
      e.shd("context_storage_" +
            std::to_string(global::rc.generate_random_number() % 256)));
  for (uint8_t i = 0; i < 8; i++) {
    e.f("mov_rd_md", e.g("accum"), e.g("target"));
    e.f("push_rd", e.g("accum"));
    e.f("add_rd_vd", e.g("target"), std::uint64_t(4));
  }
  e.fr("accum");
  e.fr("target");

  e.grab_group("common");
  e.f("popad");
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "add_rd_vd", e.g("esp_"), e.frszd());
  e.fr("esp_");
  e.f(e.gg({"fu"}), "jump",
      std::uint64_t(get_ld()->get_optional_header()->address_of_entry_point));
  e.free_group("common");
  e.end();
}

void pe32_i686::clear_exit_init_code() {
  e.start_segment("clear_exit");
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0));
  e.f(e.gg({"fu"}), "jump", e.shd("base_exit"));
  e.end();
}

void pe32_i686::error_exit_init_code() {
  e.start_segment("error_not_found");
  e.bf("tmp", "common");
  e.f("load_rd", e.g("tmp"), e.vshd("target"));
  e.f("push_vd", std::uint64_t(0x10));
  e.f("push_vd", std::uint64_t(0));
  e.f("push_rd", e.g("tmp"));
  e.f("push_vd", std::uint64_t(0));
  e.f("abs_r", e.g("tmp"), e.shd("MessageBoxA_str_rva_a"));
  e.f("mov_rd_md", e.g("tmp"), e.g("tmp"));
  e.f("call_rd", e.g("tmp"));
  e.fr("tmp");
  e.f("jump", e.shd("error_exit"));
  e.end();

  e.start_segment("error_exit");
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(1));
  e.f(e.gg({"fu"}), "jump", e.shd("base_exit"));
  e.end();
}

void pe32_i686::base_exit_init_code() {
  e.start_segment("base_exit");
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0xFFFFFFFF));
  e.bf("tmp", "common");
  e.f(e.gg({"fu"}), "abs_r", e.g("tmp"), e.shd("exit_storage"));
  e.f(e.gg({"fu"}), "mov_rd_md", e.g("tmp"), e.g("tmp"));
  e.f(e.gg({"fu"}), "xor_rd_vd", e.g("tmp"), std::uint64_t(local_keys["exit"]));
  e.f(e.gg({"fu"}), "call_rd", e.g("tmp"));
  e.fr("tmp");
  e.f(e.gg({"fu"}), "jump", e.shd("crash_loop"));
  e.end();
}

void pe32_i686::search_expx_init_code() {
  e.start_segment("search_expx");
  e.bf("dll_base", "common");
  e.f("load_rd", e.g("dll_base"), e.vshd("dll_base"));
  e.bf("result", "common");
  e.f("mov_rd_smd", e.g("result"), e.g("dll_base"), std::string("+"), std::uint64_t(0x3C));
  e.bf("va", "common");
  e.f("mov_rd_rd", e.g("va"), e.g("dll_base"));
  e.f("add_rd_rd", e.g("va"), e.g("result"));
  e.f("add_rd_vd", e.g("va"), std::uint64_t(0x78));
  e.f("mov_rd_md", e.g("va"), e.g("va"));
  e.f("test_rd_rd", e.g("va"), e.g("va"));
  e.f("branch", "nz", e.shd("search_expx_0"), e.shd("search_expx_end"));
  e.end();

  e.start_segment("search_expx_0");
  e.f("mov_rd_rd", e.g("result"), e.g("dll_base"));
  e.f("add_rd_rd", e.g("result"), e.g("va"));
  e.f("add_rd_vd", e.g("result"), std::uint64_t(0xC));
  e.f("mov_rd_md", e.g("result"), e.g("result"));
  e.f("add_rd_rd", e.g("result"), e.g("dll_base"));
  e.f("store_vb", e.vshd("crc_switch"), std::uint64_t(1));
  e.f("store_rd", e.vshd("target"), e.g("result"));
  e.push_registers({e.g("dll_base"), e.g("va")});
  e.f("invoke", e.shd("crc"));
  e.pop_registers({e.g("dll_base"), e.g("va")});
  e.f("load_rd", e.g("result"), e.vshd("result"));
  e.f("store_rd", e.vshd("tmp_hash"), e.g("result"));
  e.bf("line", "common");
  e.f("mov_rd_rd", e.g("line"), e.g("dll_base"));
  e.f("add_rd_rd", e.g("line"), e.g("va"));
  e.f("add_rd_vd", e.g("line"), std::uint64_t(0x18));
  e.f("push_vd", std::uint64_t(4));
  e.f("pop_rd", e.g("va"));
  e.f("jump", e.shd("exp_l0_0"));
  e.end();

  e.start_segment("exp_l0_0");
  e.f("mov_rd_md", e.g("result"), e.g("line"));
  e.f("add_rd_vd", e.g("line"), std::uint64_t(4));
  e.f("add_rd_rd", e.g("result"), e.g("dll_base"));
  e.f("push_rd", e.g("result"));
  e.f("dec_rd", e.g("va"));
  e.f("test_rd_rd", e.g("va"), e.g("va"));
  e.f("branch", "nz", e.shd("exp_l0_0"), e.shd("exp_l0_1"));
  e.end();

  e.start_segment("exp_l0_1");
  e.bf("long_data", "common");
  e.bf("short_data", "common");
  e.f("pop_rd", e.g("long_data"));
  e.f("pop_rd", e.g("short_data"));
  e.f("pop_rd", e.g("line"));
  e.f("pop_rd", e.g("va"));
  e.f(e.gg({"fs"}), "sub_rd_rd", e.g("va"), e.g("dll_base"));
  e.f("branch", "z", e.shd("search_expx_end"), e.shd("exp_l3_0"));
  e.end();

  e.start_segment("exp_l3_0");
  e.f("mov_rd_rd", e.g("result"), e.g("short_data"));
  e.f("add_rd_rd", e.g("result"), e.g("va"));
  e.f("add_rd_rd", e.g("result"), e.g("va"));
  e.f("add_rd_rd", e.g("result"), e.g("va"));
  e.f("add_rd_rd", e.g("result"), e.g("va"));
  e.f("sub_rd_vd", e.g("result"), std::uint64_t(4));
  e.f("mov_rd_md", e.g("result"), e.g("result"));
  e.f("add_rd_rd", e.g("result"), e.g("dll_base"));
  e.f("store_rd", e.vshd("target"), e.g("result"));
  e.f("store_vb", e.vshd("crc_switch"), std::uint64_t(1));
  e.push_registers({e.g("short_data"), e.g("va"), e.g("dll_base"), e.g("line"),
                    e.g("long_data")});
  e.f("invoke", e.shd("crc"));
  e.pop_registers({e.g("short_data"), e.g("va"), e.g("dll_base"), e.g("line"),
                   e.g("long_data")});
  e.f("load_rd", e.g("result"), e.vshd("result"));
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("add_rd_smd", e.g("result"), e.g("ebp_"), std::string("-"), e.vshd("tmp_hash"));
  e.f("cmp_rd_smd", e.g("result"), e.g("ebp_"), std::string("-"), e.vshd("hash"));
  e.fr("ebp_");
  e.f("branch", "ne", e.shd("exp_l3_1"), e.shd("exp_l3_2"));
  e.end();

  e.start_segment("exp_l3_1");
  e.f("dec_rd", e.g("va"));
  e.f("test_rd_rd", e.g("va"), e.g("va"));
  e.f("branch", "nz", e.shd("exp_l3_0"), e.shd("search_expx_end"));
  e.end();

  e.start_segment("exp_l3_2");
  e.fr("short_data");
  e.f("dec_rd", e.g("va"));
  e.f("xchg_rd_rd", e.g("result"), e.g("dll_base"));
  e.fr("dll_base");
  e.f("xchg_rd_rd", e.g("result"), e.g("va"));
  e.f("add_rd_rd", e.g("result"), e.g("result"));
  e.f("add_rd_rd", e.g("result"), e.g("long_data"));
  e.fr("long_data");
  e.f("movzx_rd_mw", e.g("result"), e.g("result"));
  e.bf("tmp", "common");
  e.f("mov_rd_rd", e.g("tmp"), e.g("line"));
  e.fr("line");
  e.f("add_rd_rd", e.g("tmp"), e.g("result"));
  e.f("add_rd_rd", e.g("tmp"), e.g("result"));
  e.f("add_rd_rd", e.g("tmp"), e.g("result"));
  e.f("add_rd_rd", e.g("tmp"), e.g("result"));
  e.fr("result");
  e.f("add_rd_md", e.g("va"), e.g("tmp"));
  e.fr("tmp");
  e.f("jump", e.shd("search_expx_end"));
  e.end();

  e.start_segment("search_expx_end");
  e.f("store_rd", e.vshd("func"), e.g("va"));
  e.fr("va");
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::get_apix_init_code() {
  e.start_segment("get_apix");
  e.f("push_vd", std::uint64_t(0x30));
  e.bf("pointer", "common");
  e.f("pop_rd", e.g("pointer"));
  e.bsp("fs_", eg::i8086::fs);
  e.f("mov_rd_serd", e.g("pointer"), e.g("fs_"), e.g("pointer"));
  e.fr("fs_");
  e.f("add_rd_vd", e.g("pointer"), std::uint64_t(0xC));
  e.f("mov_rd_md", e.g("pointer"), e.g("pointer"));
  e.f("add_rd_vd", e.g("pointer"), std::uint64_t(0xC));
  e.bf("flink", "common");
  e.f("mov_rd_md", e.g("flink"), e.g("pointer"));
  e.f("sub_rd_vd", e.g("pointer"), std::uint64_t(0xC));
  e.fr("pointer");
  e.f("jump", e.shd("gapi_l1_0"));
  e.end();

  e.start_segment("gapi_l1_0");
  e.f("add_rd_vd", e.g("flink"), std::uint64_t(0x18));
  e.bf("dll_base", "common");
  e.f("mov_rd_md", e.g("dll_base"), e.g("flink"));
  e.f("sub_rd_vd", e.g("flink"), std::uint64_t(0x18));
  e.f("test_rd_rd", e.g("dll_base"), e.g("dll_base"));
  e.f("branch", "nz", e.shd("gapi_l0_0"), e.shd("gapi_l1_1"));
  e.end();

  e.start_segment("gapi_l0_0");
  e.f("store_rd", e.vshd("dll_base"), e.g("dll_base"));
  e.push_registers({e.g("flink")});
  e.f("invoke", e.shd("search_expx"));
  e.pop_registers({e.g("flink")});
  e.bf("pointer", "common");
  e.f("load_rd", e.g("pointer"), e.vshd("func"));
  e.f("test_rd_rd", e.g("pointer"), e.g("pointer"));
  e.fr("pointer");
  e.f("branch", "nz", e.shd("clear_end"), e.shd("gapi_l0_1"));
  e.end();

  e.start_segment("gapi_l0_1");
  e.f("mov_rd_md", e.g("flink"), e.g("flink"));
  e.f("jump", e.shd("gapi_l1_0"));
  e.end();

  e.start_segment("gapi_l1_1");
  e.fr("dll_base");
  e.fr("flink");
  e.f("store_vd", e.vshd("func"), std::uint64_t(0));
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::find_library_init_code() {
  e.start_segment("find_library");
  e.bsp("eax_", eg::i8086::eax);
  e.bf("lib_name", "common");
  e.f("load_rd", e.g("lib_name"), e.vshd("target"));
  e.f("push_rd", e.g("lib_name"));
  e.f("push_rd", e.g("lib_name"));
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("GetModuleHandle"));
  e.f("pop_rd", e.g("lib_name"));
  e.f("test_rd_rd", e.g("eax_"), e.g("eax_"));
  e.f("branch", "nz", e.shd("dll_found"), e.shd("dll_not_found"));
  e.end();

  e.start_segment("dll_not_found");
  e.f("push_rd", e.g("lib_name"));
  e.fr("lib_name");
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("LoadLibrary"));
  e.fr("ebp_");
  e.f("test_rd_rd", e.g("eax_"), e.g("eax_"));
  e.f("branch", "nz", e.shd("dll_found"), e.shd("error_not_found"));
  e.end();

  e.start_segment("dll_found");
  e.f("store_rd", e.vshd("current_dll"), e.g("eax_"));
  e.fr("eax_");
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::load_function_init_code() {
  e.start_segment("find_function");
  e.bsp("eax_", eg::i8086::eax);
  e.bf("lib_addr", "common");
  e.f("load_rd", e.g("lib_addr"), e.vshd("current_dll"));
  e.bf("func_name", "common");
  e.f("load_rd", e.g("func_name"), e.vshd("target"));
  e.f("push_rd", e.g("func_name"));
  e.fr("func_name");
  e.f("push_rd", e.g("lib_addr"));
  e.fr("lib_addr");
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("GetProcAddr"));
  e.fr("ebp_");
  e.f("test_rd_rd", e.g("eax_"), e.g("eax_"));
  e.f("branch", "nz", e.shd("function_found"), e.shd("error_not_found"));
  e.end();

  e.start_segment("function_found");
  e.f("store_rd", e.vshd("func"), e.g("eax_"));
  e.fr("eax_");
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::vista_or_higher_init_code() {
  e.start_segment("vista_or_higher");
  e.bf("tmp", "common");
  e.bsp("esp_", eg::i8086::esp);
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("sub_rd_vd", e.g("esp_"), std::uint64_t(0x90));
  e.f("push_vd", std::uint64_t(0x94));
  e.f("mov_rd_rd", e.g("tmp"), e.g("esp_"));
  e.f("push_rd", e.g("tmp"));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("GetVersionEx"));
  e.fr("ebp_");
  e.f("pop_rd", e.g("tmp"));
  e.f("pop_rd", e.g("tmp"));
  e.f("add_rd_vd", e.g("esp_"), std::uint64_t(0x8c));
  e.fr("esp_");
  e.f("cmp_rd_vd", e.g("tmp"), std::uint64_t(6));
  e.fr("tmp");
  e.f("branch", "ge", e.shd("set_vista_flag"), e.shd("unset_vista_flag"));
  e.end();

  e.start_segment("set_vista_flag");
  e.f("store_vb", e.vshd("os_switch"), std::uint64_t(1));
  e.f("jump", e.shd("clear_end"));
  e.end();

  e.start_segment("unset_vista_flag");
  e.f("store_vb", e.vshd("os_switch"), std::uint64_t(0));
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::build_import_stub() {
  std::vector<ld::pe::library> *import = get_ld()->get_import();
  std::uint32_t f_counter = 0;
  std::uint32_t l_counter = 0;
  e.start_segment("import");
  if (import->size() != 0)
    e.f("jump", e.shd("import_library_" + std::to_string(l_counter)));
  else
    e.f("jump", e.shd("reloc"));
  e.end();
  std::vector<uint32_t> keys;
  std::uint32_t counter = 0;
  bool lock = false;
  for (uint64_t i = 0; i < import->size(); i++) {
    auto lib = (*import)[i];
    e.bf("iat_base", "common");
    e.start_segment("import_library_" + std::to_string(l_counter));
    l_counter++;
    e.f("abs_r", e.g("iat_base"), std::uint64_t(lib.iat_begin));
    auto dll_alias = global::cs.generate_unique_string("il");
    e.add_top_data(dll_alias, &lib.name);
    e.enable_alter(dll_alias, dll_alias + "key", "dword_ecb");
    e.bf("tmp", "common");
    e.f("abs_r", e.g("tmp"), e.shd(dll_alias));
    e.f("store_rd", e.vshd("target"), e.g("tmp"));
    e.f("store_vd", e.vshd("count"), e.fszd(dll_alias));
    e.f("store_vd", e.vshd("dword_key"), e.kd(dll_alias + "key", 32, 0));
    e.fr("tmp");
    e.push_registers({e.g("iat_base")});
    e.f("invoke", e.shd("alter_d"));
    e.f("invoke", e.shd("find_library"));
    e.f("invoke", e.shd("alter_d"));
    e.pop_registers({e.g("iat_base")});
    if (lib.functions.size() != 0)
      e.f("jump", e.shd("import_function_" + std::to_string(f_counter)));
    else {
      if (i == (import->size() - 1))
        e.f("jump", e.shd("reloc"));
      else
        e.f("jump", e.shd("import_library_" + std::to_string(l_counter)));
    }
    e.end();
    for (uint64_t j = 0; j < lib.functions.size(); j++) {
      auto func = lib.functions[j];
      auto function_alias = global::cs.generate_unique_string("if");
      e.add_top_data(function_alias, &func.first);
      e.enable_alter(function_alias, function_alias + "key", "dword_ecb");
      e.bf("tmp", "common");
      e.start_segment("import_function_" + std::to_string(f_counter));
      f_counter++;
      if (!lock && f_counter > 1 && global::rc.may_be(8)) {
        e.f("push_rd", e.g("iat_base"));
#ifdef CHECK_DEBUGGER
        auto cid = add_container();
        add_to_container(cid, "target",
                         "import_function_" + std::to_string(f_counter - 2));
        add_to_container(cid, "if_error", std::string("error_exit"));
        insert_random_trap({}, cid, 0);
        remove_container(cid);
#endif
        insert_encrypt("import_function_" + std::to_string(f_counter - 2));
        e.f("pop_rd", e.g("iat_base"));
      }
      e.f("abs_r", e.g("tmp"), e.shd(function_alias));
      e.f("store_rd", e.vshd("target"), e.g("tmp"));
      e.f("store_vd", e.vshd("count"), e.fszd(function_alias));
      e.f("store_vd", e.vshd("dword_key"), e.kd(function_alias + "key", 32, 0));
      e.fr("tmp");
      e.push_registers({e.g("iat_base")});
      e.f("invoke", e.shd("alter_d"));
      e.f("invoke", e.shd("find_function"));
      e.f("invoke", e.shd("alter_d"));
      e.pop_registers({e.g("iat_base")});
      e.bf("func_addr", "common");
      e.f("load_rd", e.g("func_addr"), e.vshd("func"));
      if (get_ld()->is_nx_compatible()) {
        keys.push_back(
            static_cast<uint32_t>(global::rc.generate_random_number()));
        e.f("xor_rd_vd", e.g("func_addr"), std::uint64_t(keys.back()));
        e.bf("storage", "common");
        e.f("abs_r", e.g("storage"),
            e.shd("import_storage_" + std::to_string(counter)));
        e.f("mov_md_rd", e.g("storage"), e.g("func_addr"));
        e.fr("storage");
        e.f("abs_r", e.g("func_addr"),
            e.shd("import_guard_" + std::to_string(counter)));
        counter++;
      }
      e.f("mov_md_rd", e.g("iat_base"), e.g("func_addr"));
      e.fr("func_addr");
      e.f("add_rd_vd", e.g("iat_base"), std::uint64_t(4));
      if (j == (lib.functions.size() - 1)) {
        if (i == (import->size() - 1))
          e.f("jump", e.shd("reloc"));
        else
          e.f("jump", e.shd("import_library_" + std::to_string(l_counter)));
      } else {
        if (global::rc.may_be(7)) {
          e.f("push_rd", e.g("iat_base"));
          insert_decrypt("import_function_" + std::to_string(f_counter));
#ifdef CHECK_DEBUGGER
          auto cid = add_container();
          add_to_container(cid, "target",
                           "import_function_" + std::to_string(f_counter));
          add_to_container(cid, "if_error", std::string("error_exit"));
          insert_random_trap({}, cid, 0);
          remove_container(cid);
#endif
          e.f("pop_rd", e.g("iat_base"));
          lock = true;
        } else
          lock = false;
        e.f("jump", e.shd("import_function_" + std::to_string(f_counter)));
      }
      e.end();
    }
    e.fr("iat_base");
  }
  counter = 0;
  if (get_ld()->is_nx_compatible()) {
    e.grab_group("common");
    for (auto key : keys) {
      e.add_data("import_storage_" + std::to_string(counter), 4);
      e.start_segment("import_guard_" + std::to_string(counter));
      e.bs("accum", "common", global::cs.generate_unique_number("fctx"));
      e.bsp("esp_", eg::i8086::esp);
      e.f(e.gg({"fu"}), "push_rd", e.g("accum"));
      e.f(e.gg({"fu"}), "push_rd", e.g("accum"));
      e.f(e.gg({"fu"}), "abs_r", e.g("accum"),
          e.shd("import_storage_" + std::to_string(counter)));
      e.f(e.gg({"fu"}), "mov_rd_md", e.g("accum"), e.g("accum"));
      e.f(e.gg({"fu"}), "xor_rd_vd", e.g("accum"), std::uint64_t(key));
      e.f(e.gg({"fu", "ss"}), "add_rd_vd", e.g("esp_"), std::uint64_t(8));
      e.f(e.gg({"fu", "ss"}), "push_rd", e.g("accum"));
      e.f(e.gg({"fu", "ss"}), "sub_rd_vd", e.g("esp_"), std::uint64_t(4));
      e.f(e.gg({"fu"}), "pop_rd", e.g("accum"));
      e.f(e.gg({"fu"}), "ret");
      e.fr("accum");
      e.fr("esp_");
      e.end();
      counter++;
    }
    e.free_group("common");
  }
}

void pe32_i686::build_reloc_stub() {
  uint64_t r_count = 0;
  e.start_segment("reloc");
  e.bf("D", "common");
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("mov_rd_smd", e.g("D"), e.g("ebp_"), std::string("-"), e.vshd("base"));
  e.f("sub_rd_vd", e.g("D"),
      std::uint64_t(get_ld()->get_optional_header()->image_base));
  auto relocs = get_ld()->get_relocations();
  if (relocs->size() == 0)
    e.f("jump", e.shd("tls_stub"));
  else
    e.f("jump", e.shd("tune_reloc_" + std::to_string(r_count)));
  e.end();
  e.fr("ebp_");
  bool lock = false;
  for (uint64_t i = 0; i < relocs->size(); i++) {
    auto r = (*relocs)[i];
    e.start_segment("tune_reloc_" + std::to_string(r_count));
    r_count++;
    if (!lock && r_count > 1 && global::rc.may_be(6)) {
      e.f("push_rd", e.g("D"));
#ifdef CHECK_DEBUGGER
      auto cid = add_container();
      add_to_container(cid, "target",
                       "tune_reloc_" + std::to_string(r_count - 2));
      add_to_container(cid, "if_error", std::string("error_exit"));
      insert_random_trap({}, cid, 0);
      remove_container(cid);
#endif
      insert_encrypt("tune_reloc_" + std::to_string(r_count - 2));
      e.f("pop_rd", e.g("D"));
    }
    e.bf("tmp", "common");
    e.f("abs_r", e.g("tmp"), std::uint64_t(r));
    e.f("add_md_rd", e.g("tmp"), e.g("D"));
    e.fr("tmp");
    if (i != (relocs->size() - 1)) {
      if (global::rc.may_be(5)) {
        e.f("push_rd", e.g("D"));
        insert_decrypt("tune_reloc_" + std::to_string(r_count));
#ifdef CHECK_DEBUGGER
        auto cid = add_container();
        add_to_container(cid, "target",
                         "tune_reloc_" + std::to_string(r_count));
        add_to_container(cid, "if_error", std::string("error_exit"));
        insert_random_trap({}, cid, 0);
        remove_container(cid);
#endif
        e.f("pop_rd", e.g("D"));
        lock = true;
      } else
        lock = false;
      e.f("jump", e.shd("tune_reloc_" + std::to_string(r_count)));
    } else
      e.f("jump", e.shd("tls_stub"));
    e.end();
  }
  e.fr("D");
}

void pe32_i686::build_import_directory() {
  std::vector<uint8_t> user32dll = {0x55, 0x53, 0x45, 0x52, 0x33, 0x32,
                                    0x2e, 0x44, 0x4c, 0x4c, 0x0,  0x0};

  std::vector<uint8_t> messageboxa = {0x0,  0x0,  0x4d, 0x65, 0x73, 0x73, 0x61,
                                      0x67, 0x65, 0x42, 0x6f, 0x78, 0x41, 0x0};

  e.set_address_alignment("import_directory", 4);

  e.start_segment("import_directory");
  e.add_address("address_of_int_user32_table", "int_user32_table",
                std::uint64_t(0));
  e.add_data("import_timestamp_and_forward_chain_user32", 8);
  e.add_address("rva_user32_dll", "user32_dll_str", std::uint64_t(0));
  e.add_address("address_of_iat_user32_table", "iat_user32_table",
                std::uint64_t(0));
  e.add_data("empty_import_thunk", 20);

  e.end();

  e.add_data("user32_dll_str", &user32dll);

  e.start_segment("int_user32_table");
  e.add_address("MessageBoxA_str_rva_n", "MessageBoxA_str", 0);
  e.add_data("empty_int_record_user32", 4);
  e.end();

  e.start_segment("iat_user32_table");
  e.add_address("MessageBoxA_str_rva_a", "MessageBoxA_str", 0);
  e.add_data("empty_iat_record_user32", 4);
  e.end();

  e.add_data("MessageBoxA_str", &messageboxa);
}

void pe32_i686::build_tls_stub() {
  e.start_segment("tls_directory");
  std::vector<std::uint8_t> tmp;
  std::uint32_t diff = 0;
  if (get_ld()->is_tls_exists()) {
    diff = get_ld()->get_tls_directory()->end_address_of_raw_data -
           get_ld()->get_tls_directory()->start_address_of_raw_data;
    e.add_address("start_address_of_raw_data", "tls_data",
                  get_ld()->get_optional_header()->image_base);
    e.add_address("end_address_of_raw_data", "tls_data",
                  get_ld()->get_optional_header()->image_base + diff);
  } else {
    e.add_data("start_address_of_raw_data", 4);
    e.add_data("end_address_of_raw_data", 4);
  }
  e.add_address("tls_index_addr", "tls_index",
                get_ld()->get_optional_header()->image_base);
  e.add_address("tls_callbacks_addr", "tls_callbacks",
                get_ld()->get_optional_header()->image_base);
  if (get_ld()->is_tls_exists()) {
    global::value_to_vector(
        &tmp, get_ld()->get_tls_directory()->size_of_zero_fill,
        sizeof(get_ld()->get_tls_directory()->size_of_zero_fill));
    e.add_data("size_of_zero_fill", &tmp);
    global::value_to_vector(
        &tmp, get_ld()->get_tls_directory()->characteristics,
        sizeof(get_ld()->get_tls_directory()->characteristics));
    e.add_data("characteristics", &tmp);
  } else {
    e.add_data("size_of_zero_fill", 4);
    e.add_data("characteristics", 4);
  }
  e.end();

  if (get_ld()->is_tls_exists()) {
    tmp.clear();
    get_ld()->get_part_of_image(
        &tmp,
        get_ld()->get_tls_directory()->start_address_of_raw_data -
            get_ld()->get_optional_header()->image_base,
        diff);
    e.add_data("tls_data", &tmp);
  }
  e.add_data("tls_index", 4);

  e.start_segment("tls_callbacks");
  e.add_address("first_line_addr", "first_line",
                get_ld()->get_optional_header()->image_base);
  bool make_callbacks = false;
  if (get_ld()->is_tls_exists()) {
    std::uint32_t call_count = 0;
    std::uint32_t call_seek =
        get_ld()->get_tls_directory()->address_of_call_backs -
        get_ld()->get_optional_header()->image_base;

    while (*(reinterpret_cast<std::uint32_t *>(
               &(*get_ld()->get_image())[call_seek])) != 0) {
      call_count += 4;
      call_seek += 4;
    }
    if (call_count != 0) {
      make_callbacks = true;
      e.add_data("tls_real_callbacks", call_count);
    }
  }
  e.add_data("tls_callbacks_end", 4);
  e.end();

  e.start_segment("tls_stub");
  if (get_ld()->is_tls_exists()) {
    e.bf("src", "common");
    e.bf("dst", "common");
    e.bf("data", "common");
    e.f("abs_r", e.g("src"), e.shd("tls_index"));
    e.f("abs_r", e.g("dst"),
        std::uint64_t(get_ld()->get_tls_directory()->address_of_index -
                      get_ld()->get_optional_header()->image_base));
    e.f("mov_rd_md", e.g("data"), e.g("src"));
    e.f("mov_md_rd", e.g("dst"), e.g("data"));
    e.f("abs_r", e.g("src"), e.shd("tls_index_addr"));
    e.f("mov_md_rd", e.g("src"), e.g("dst"));
    e.f("abs_r", e.g("data"),
        std::uint64_t(get_ld()->get_tls_directory()->address_of_call_backs -
                      get_ld()->get_optional_header()->image_base));
    e.f("add_rd_vd", e.g("src"), std::uint64_t(4));
    e.f("mov_md_rd", e.g("src"), e.g("data"));
    e.f("load_rd", e.g("dst"), e.vshd("base"));
    e.fr("src");
    if (make_callbacks) {
      e.bf("seek", "common");
      e.f("abs_r", e.g("seek"), e.shd("tls_real_callbacks"));
    }
    e.f("jump", e.shd("tls_stub_compare"));
    e.end();

    e.start_segment("tls_stub_compare");
    e.f("cmp_md_vd", e.g("data"), std::uint64_t(0));
    e.f("branch", "nz", e.shd("tls_stub_loop"), e.shd("tls_stub_end"));
    e.end();

    e.start_segment("tls_stub_loop");
    if (make_callbacks)
      e.push_registers({e.g("dst"), e.g("data"), e.g("seek")});
    else
      e.push_registers({e.g("dst"), e.g("data")});
    e.f("push_vd", std::uint64_t(0));
    e.f("push_vd", std::uint64_t(1));
    e.f("push_rd", e.g("dst"));
    e.f("call_md", e.g("data"));
    if (make_callbacks)
      e.pop_registers({e.g("dst"), e.g("data"), e.g("seek")});
    else
      e.pop_registers({e.g("dst"), e.g("data")});
    if (make_callbacks) {
      e.bf("tmp", "common");
      e.f("mov_rd_md", e.g("tmp"), e.g("data"));
      e.f("mov_md_rd", e.g("seek"), e.g("tmp"));
      e.fr("tmp");
    }
    e.f("add_rd_vd", e.g("data"), std::uint64_t(4));
    if (make_callbacks) e.f("add_rd_vd", e.g("seek"), std::uint64_t(4));
    e.f("jump", e.shd("tls_stub_compare"));
    e.end();

    e.start_segment("tls_stub_end");
    e.fr("data");
    e.fr("dst");
    if (make_callbacks) e.fr("seek");
    get_ld()->wipe_tls_directory();
  }
  e.f("jump", e.shd("mprotect"));

  e.end();
}

void pe32_i686::build_reloc_table() {
  e.start_segment("reloc_directory");

  e.add_processed_data("reloc_directory_tables", [](eg::build_root *root,
                                                    eg::dependence_line *dl) {
    std::vector<std::uint8_t> reloc_table;
    if (root->get_state() >= eg::build_states::translating) {
      std::map<std::uint32_t, std::vector<std::uint32_t>> used;
      std::vector<std::uint32_t> need;
      std::uint64_t shift = 0;
      std::function<void(eg::memory_piece * mp)> fn =
          [&shift](eg::memory_piece *mp) { shift = mp->get_shift(); };
      root->get_depended_memory("tls_directory", fn,
                                {eg::dependence_flags::shift});
      for (std::uint32_t i = 0; i <= 12; i += 4)
        need.push_back(static_cast<std::uint32_t>(shift) + i);

      root->get_depended_memory("first_line_addr", fn,
                                {eg::dependence_flags::shift});

      need.push_back(static_cast<std::uint32_t>(shift));

      for (auto addr : need) {
        std::uint32_t tmp = (addr / 4096) * 4096;
        if (used.count(tmp) != 0) {
          used[tmp].push_back(addr - tmp);
        } else {
          used.insert(std::make_pair(tmp, std::vector<uint32_t>()));
          used[tmp].push_back(addr - tmp);
        }
      }

      std::vector<uint8_t> tmpv;
      for (auto table : used) {
        global::value_to_vector(&tmpv, table.first, sizeof(table.first));
        reloc_table.insert(reloc_table.end(), tmpv.begin(), tmpv.end());
        std::uint32_t size =
            sizeof(table.first) + (table.second.size() * 2) + 4;
        if (size % 4 != 0) size += 2;
        global::value_to_vector(&tmpv, size, sizeof(size));
        reloc_table.insert(reloc_table.end(), tmpv.begin(), tmpv.end());
        size = 0;
        for (auto sh : table.second) {
          size++;
          global::value_to_vector(
              &tmpv, std::uint16_t(12288) | static_cast<std::uint16_t>(sh),
              sizeof(std::uint16_t));
          reloc_table.insert(reloc_table.end(), tmpv.begin(), tmpv.end());
        }
        if (size % 2 != 0) {
          global::value_to_vector(&tmpv, std::uint16_t(0),
                                  sizeof(std::uint16_t));
          reloc_table.insert(reloc_table.end(), tmpv.begin(), tmpv.end());
        }
      }
      global::value_to_vector(&tmpv, std::uint64_t(0), sizeof(std::uint64_t));
      reloc_table.insert(reloc_table.end(), tmpv.begin(), tmpv.end());
      dl->set_flag(eg::type_flags::node_cached);
    } else
      reloc_table.resize(6 * 8);
    dl->set_content(&reloc_table);
  });

  e.end();
}

void pe32_i686::walk_resource(std::vector<uint8_t> &fp,
                              std::vector<uint8_t> &sp, uint64_t id,
                              std::vector<std::pair<uint32_t, uint64_t>> &dofs,
                              uint32_t &dof, uint32_t &sof,
                              ld::pe::resource_container *ct) {
  std::vector<uint8_t> tmp;
  ld::pe::resource_diretory &res = ct->directories[id];
  global::value_to_vector(&tmp, res.dir.characteristics, sizeof(uint32_t));
  fp.insert(fp.end(), tmp.begin(), tmp.end());
  global::value_to_vector(&tmp, res.dir.time_data_stamp, sizeof(uint32_t));
  fp.insert(fp.end(), tmp.begin(), tmp.end());
  global::value_to_vector(&tmp, res.dir.major_version, sizeof(uint16_t));
  fp.insert(fp.end(), tmp.begin(), tmp.end());
  global::value_to_vector(&tmp, res.dir.minor_version, sizeof(uint16_t));
  fp.insert(fp.end(), tmp.begin(), tmp.end());
  global::value_to_vector(&tmp, res.dir.number_of_named_entries,
                          sizeof(uint16_t));
  fp.insert(fp.end(), tmp.begin(), tmp.end());
  global::value_to_vector(&tmp, res.dir.number_of_id_entries, sizeof(uint16_t));
  fp.insert(fp.end(), tmp.begin(), tmp.end());
  dof += sizeof(ld::pe::image_resource_directory);
  dof += sizeof(ld::pe::image_resource_directory_entry) * res.entries.size();
  std::vector<std::vector<uint8_t>> temporary_storage;
  for (auto et : res.entries) {
    if (et.str) {
      global::value_to_vector(&tmp, sof | 2147483648, sizeof(uint32_t));
      fp.insert(fp.end(), tmp.begin(), tmp.end());
      sp.insert(sp.end(), et.self_id.begin(), et.self_id.end());
      sof += et.self_id.size();
    } else
      fp.insert(fp.end(), et.self_id.begin(), et.self_id.end());
    if (et.dir) {
      temporary_storage.push_back(std::vector<uint8_t>());
      global::value_to_vector(&tmp, dof | 2147483648, sizeof(uint32_t));
      fp.insert(fp.end(), tmp.begin(), tmp.end());
      walk_resource(temporary_storage.back(), sp, et.child_id, dofs, dof, sof,
                    ct);
    } else {
      dofs.back().second = et.child_id;
      global::value_to_vector(&tmp, dofs.back().first, sizeof(uint32_t));
      fp.insert(fp.end(), tmp.begin(), tmp.end());
      dofs.push_back(std::make_pair(
          dofs.back().first + sizeof(ld::pe::image_resource_data_entry),
          0xFFFFFFFFFFFFFFFF));
    }
  }
  for (auto st : temporary_storage) fp.insert(fp.end(), st.begin(), st.end());
}

void pe32_i686::build_resources() {
  if (get_ld()->is_resources_exists()) {
    ld::pe::resource_container *ct = get_ld()->get_resources();
    std::uint32_t data_entries_offset = 0;
    std::uint32_t strings_offsets = 0;
    for (auto dir : ct->directories) {
      std::uint32_t current_offset = 0;
      current_offset += sizeof(ld::pe::image_resource_directory);
      current_offset += sizeof(ld::pe::image_resource_directory_entry) *
                        dir.second.entries.size();
      strings_offsets += current_offset;
      data_entries_offset += current_offset;
      for (auto et : dir.second.entries) {
        if (et.str) data_entries_offset += et.self_id.size();
      }
    }
    std::vector<std::pair<uint32_t, uint64_t>> offsets;
    offsets.push_back(std::make_pair(data_entries_offset, 0xFFFFFFFFFFFFFFFF));
    std::vector<uint8_t> tmp_1;
    std::vector<uint8_t> tmp_2;
    uint32_t current_offset = 0;
    walk_resource(tmp_1, tmp_2, ct->root_id, offsets, current_offset,
                  strings_offsets, ct);
    tmp_1.insert(tmp_1.end(), tmp_2.begin(), tmp_2.end());
    e.start_segment("resource_diretory");
    e.add_data("resources_dirs", &tmp_1);
    e.add_processed_data(
        "resources_data_entries",
        [offsets, ct](eg::build_root *root, eg::dependence_line *dl) {
          std::vector<std::uint8_t> entries;
          if (root->get_state() >= eg::build_states::translating) {
            std::vector<uint8_t> tmp;
            for (auto of : offsets) {
              if (of.second == 0xFFFFFFFFFFFFFFFF) break;
              std::uint64_t shift = 0;
              std::function<void(eg::memory_piece * mp)> fn =
                  [&shift](eg::memory_piece *mp) { shift = mp->get_shift(); };
              root->get_depended_memory("resource_" + std::to_string(of.second),
                                        fn, {eg::dependence_flags::shift});
              global::value_to_vector(&tmp, static_cast<uint32_t>(shift),
                                      sizeof(uint32_t));
              entries.insert(entries.end(), tmp.begin(), tmp.end());
              global::value_to_vector(&tmp,
                                      ct->resources[of.second].data_entry.size,
                                      sizeof(uint32_t));
              entries.insert(entries.end(), tmp.begin(), tmp.end());
              global::value_to_vector(
                  &tmp, ct->resources[of.second].data_entry.code_page,
                  sizeof(uint32_t));
              entries.insert(entries.end(), tmp.begin(), tmp.end());
              global::value_to_vector(
                  &tmp, ct->resources[of.second].data_entry.reserved,
                  sizeof(uint32_t));
              entries.insert(entries.end(), tmp.begin(), tmp.end());
            }
            dl->set_flag(eg::type_flags::node_cached);
          } else
            entries.resize((offsets.size() - 1) *
                           sizeof(ld::pe::image_resource_data_entry));
          dl->set_content(&entries);
        });

    for (auto of : offsets) {
      if (of.second == 0xFFFFFFFFFFFFFFFF) break;
      e.add_data("resource_" + std::to_string(of.second),
                 (&ct->resources[of.second].data));
    }
    e.end();
  }
}

void pe32_i686::build_export() {
  if (get_ld()->is_exports_exists()) {
    e.add_data("export_image_name", &(get_ld()->get_export()->image_name));

    std::uint32_t export_base =
        get_ld()->get_optional_header()->data_directory[0].virtual_address;

    ld::pe::image_export_directory *ed =
        get_ld()->get_export_directory(export_base);

    auto exp = get_ld()->get_export();

    e.start_segment("export_directory");
    e.add_processed_data("export_table", [ed](eg::build_root *root,
                                              eg::dependence_line *dl) {
      std::vector<std::uint8_t> table;
      if (root->get_state() >= eg::build_states::translating) {
        std::vector<std::uint8_t> tmp;
        global::value_to_vector(&tmp, ed->characteristics, sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        global::value_to_vector(&tmp, ed->time_data_stamp, sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        global::value_to_vector(&tmp, ed->major_version, sizeof(uint16_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        global::value_to_vector(&tmp, ed->minor_version, sizeof(uint16_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        std::uint64_t shift = 0;
        std::function<void(eg::memory_piece * mp)> fn =
            [&shift](eg::memory_piece *mp) { shift = mp->get_shift(); };
        root->get_depended_memory("export_image_name", fn,
                                  {eg::dependence_flags::shift});
        global::value_to_vector(&tmp, static_cast<uint32_t>(shift),
                                sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        global::value_to_vector(&tmp, ed->base, sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        global::value_to_vector(&tmp, ed->number_of_functions,
                                sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        global::value_to_vector(&tmp, ed->number_of_names, sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        root->get_depended_memory("export_funcs", fn,
                                  {eg::dependence_flags::shift});
        global::value_to_vector(&tmp, static_cast<uint32_t>(shift),
                                sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        root->get_depended_memory("export_names", fn,
                                  {eg::dependence_flags::shift});
        global::value_to_vector(&tmp, static_cast<uint32_t>(shift),
                                sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        root->get_depended_memory("export_ords", fn,
                                  {eg::dependence_flags::shift});
        global::value_to_vector(&tmp, static_cast<uint32_t>(shift),
                                sizeof(uint32_t));
        table.insert(table.end(), tmp.begin(), tmp.end());
        dl->set_flag(eg::type_flags::node_cached);
      } else
        table.resize(sizeof(ld::pe::image_export_directory));
      dl->set_content(&table);
    });
    std::map<uint64_t, uint32_t> redirects;
    export_base += sizeof(ld::pe::image_export_directory);
    std::vector<uint8_t> strings;
    for (uint64_t i = 0; i < exp->addresses.size(); i++) {
      std::pair<std::vector<uint8_t>, bool> &current = exp->addresses[i];
      if (current.second) {
        redirects[i] = export_base;
        strings.insert(strings.end(), current.first.begin(),
                       current.first.end());
        export_base += current.first.size();
      }
    }
    e.add_data("export_redirects", &strings);
    e.end();

    e.add_processed_data("export_funcs", [exp, redirects](
                                             eg::build_root *root,
                                             eg::dependence_line *dl) mutable {
      std::vector<std::uint8_t> table;
      if (root->get_state() >= eg::build_states::translating) {
        std::vector<std::uint8_t> tmp;
        std::uint64_t shift = 0;
        std::function<void(eg::memory_piece * mp)> fn =
            [&shift](eg::memory_piece *mp) { shift = mp->get_shift(); };
        root->get_depended_memory("export_directory", fn,
                                  {eg::dependence_flags::shift});
        for (uint64_t i = 0; i < exp->addresses.size(); i++) {
          std::pair<std::vector<uint8_t>, bool> &current = exp->addresses[i];
          if (current.second) {
            global::value_to_vector(&tmp,
                                    static_cast<uint32_t>(shift + redirects[i]),
                                    sizeof(uint32_t));
            table.insert(table.end(), tmp.begin(), tmp.end());
          } else
            table.insert(table.end(), current.first.begin(),
                         current.first.end());
        }
        dl->set_flag(eg::type_flags::node_cached);
      } else
        table.resize(sizeof(uint32_t) * exp->addresses.size());
      dl->set_content(&table);
    });

    strings.clear();
    std::vector<uint8_t> tmp;
    for (std::uint32_t i = 0; i < exp->names.size(); i++) {
      e.add_data("export_name_" + std::to_string(i), &(exp->names[i].first));
      global::value_to_vector(&tmp, exp->names[i].second, sizeof(uint16_t));
      strings.insert(strings.end(), tmp.begin(), tmp.end());
    }
    e.add_data("export_ords", &strings);
    e.add_processed_data(
        "export_names", [exp](eg::build_root *root, eg::dependence_line *dl) {
          std::vector<std::uint8_t> table;
          if (root->get_state() >= eg::build_states::translating) {
            std::vector<std::uint8_t> tmp;
            for (std::uint32_t i = 0; i < exp->names.size(); i++) {
              std::uint64_t shift = 0;
              std::function<void(eg::memory_piece * mp)> fn =
                  [&shift](eg::memory_piece *mp) { shift = mp->get_shift(); };
              root->get_depended_memory("export_name_" + std::to_string(i), fn,
                                        {eg::dependence_flags::shift});
              global::value_to_vector(&tmp, static_cast<uint32_t>(shift),
                                      sizeof(uint32_t));
              table.insert(table.end(), tmp.begin(), tmp.end());
            }
            dl->set_flag(eg::type_flags::node_cached);
          } else
            table.resize(sizeof(uint32_t) * exp->names.size());
          dl->set_content(&table);
        });
  }
}

void pe32_i686::insert_encrypt(std::string memory_name) {
  e.f("store_abs", e.vshd("target"), e.shd(memory_name));
  e.f("store_vd", e.vshd("count"), e.fszd(memory_name));
  e.f("store_vb", e.vshd("byte_key"),
      std::uint64_t(global::rc.generate_random_number() % 256));
  e.f("invoke", e.shd("alter_b"));
}

void pe32_i686::insert_decrypt(std::string memory_name) {
  e.enable_alter(memory_name, memory_name + "_key", "byte_ecb");
  e.f("store_abs", e.vshd("target"), e.shd(memory_name));
  e.f("store_vd", e.vshd("count"), e.fszd(memory_name));
  e.f("store_vb", e.vshd("byte_key"), e.kd(memory_name + "_key", 8, 0));
  e.f("invoke", e.shd("alter_b"));
}

void pe32_i686::build_mprotect_stub() {
  e.start_segment("mprotect");

  insert_decrypt("way_out");

  e.bsp("eax_", eg::i8086::eax);
  e.bsp("ebp_", eg::i8086::ebp);
  e.bf("trash", "common");
  e.f("lea_rd_smd", e.g("trash"), e.g("ebp_"), std::string("-"), e.vshd("trash_ptr"));
  uint32_t s_counter = 0;
  e.f("jump", e.shd("s_right_set_" + std::to_string(s_counter)));
  e.end();

  if (get_ld()->is_nx_compatible()) {
    bool lock = false;
    for (std::uint64_t i = 0; i < get_ld()->get_sections_count(); i++) {
      e.start_segment("s_right_set_" + std::to_string(s_counter));
      s_counter++;
      if (!lock && s_counter > 1 && global::rc.may_be(16)) {
        e.f("push_rd", e.g("trash"));
#ifdef CHECK_DEBUGGER
        auto cid = add_container();
        add_to_container(cid, "target",
                         "s_right_set_" + std::to_string(s_counter - 2));
        add_to_container(cid, "if_error", std::string("error_exit"));
        insert_random_trap({}, cid, 0);
        remove_container(cid);
#endif
        insert_encrypt("s_right_set_" + std::to_string(s_counter - 2));
        e.f("pop_rd", e.g("trash"));
      }
      e.bf("beg", "common");
      e.push_registers({e.g("trash")});
      e.f("push_rd", e.g("trash"));
      e.f("push_vd", std::uint64_t(get_ld()->section_flags_to_memory_flags(
                         get_ld()->get_section_header(i)->characteristics)));
      e.f("push_vd", std::uint64_t(get_ld()->get_section_header(i)->misc));
      e.f("abs_r", e.g("beg"),
          std::uint64_t(get_ld()->get_section_header(i)->virtual_address));
      e.f("push_rd", e.g("beg"));
      e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("VirtualProtect"));
      e.pop_registers({e.g("trash")});
      e.fr("beg");
      if (global::rc.may_be(15)) {
        e.f("push_rd", e.g("trash"));
        insert_decrypt("s_right_set_" + std::to_string(s_counter));
#ifdef CHECK_DEBUGGER
        auto cid = add_container();
        add_to_container(cid, "target",
                         "s_right_set_" + std::to_string(s_counter));
        add_to_container(cid, "if_error", std::string("error_exit"));
        insert_random_trap({}, cid, 0);
        remove_container(cid);
#endif
        e.f("pop_rd", e.g("trash"));
        lock = true;
      } else
        lock = false;
      e.f("jump", e.shd("s_right_set_" + std::to_string(s_counter)));
      e.end();
    }
  }
  e.start_segment("s_right_set_" + std::to_string(s_counter));
  s_counter++;
  e.bf("beg", "common");
  e.f("abs_r", e.g("beg"), get_ld()->get_begin_of_stub());
  e.push_registers({e.g("trash")});
  e.f("push_rd", e.g("trash"));
  e.f("push_vd", std::uint64_t(0x20));
  e.f("push_vd", e.ssd());
  e.f("push_rd", e.g("beg"));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("VirtualProtect"));
  e.pop_registers({e.g("trash")});
  e.fr("beg");
  e.fr("trash");
  e.fr("ebp_");
  e.fr("eax_");
  e.f("jump", e.shd("way_out"));
  e.end();
}

void pe32_i686::build_context_forks() {
  for (std::uint32_t i = 0; i < 256; i++)
    e.add_data("context_storage_" + std::to_string(i), 32);

  auto fctx = global::cs.generate_unique_number("fctx");

  e.start_segment("fork_ctx");
  e.grab_group("unsafe");
  e.bs("tmp", "unsafe", fctx);
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "push_rd", e.g("tmp"));
  e.f(e.gg({"fu"}), "abs_r", e.g("tmp"), e.shd("clear_exit"));
  e.f(e.gg({"fu", "ss"}), "add_rd_vd", e.g("esp_"), std::uint64_t(8));
  e.f(e.gg({"fu", "ss"}), "push_rd", e.g("tmp"));
  e.f(e.gg({"fu", "ss"}), "sub_rd_vd", e.g("esp_"), std::uint64_t(4));
  e.f(e.gg({"fu"}), "pop_rd", e.g("tmp"));
  e.fr("tmp");
  e.fr("esp_");
  e.f(e.gg({"fu"}), "pushad");
  e.free_group("unsafe");

  e.bf("flag_addr", "unsafe");
  e.f(e.gg({"fu"}), "abs_r", e.g("flag_addr"), e.shd("tls_is_called"));
  e.f(e.gg({"fu"}), "cmp_mb_vb", e.g("flag_addr"), std::uint64_t(1));
  e.f(e.gg({"fu"}), "branch", "e", e.shd("begin_forks"), e.shd("call_tls"));
  e.fr("flag_addr");
  e.end();

  e.start_segment("call_tls");
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0));
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0));
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0));
  e.f(e.gg({"fu"}), "invoke", e.shd("first_line"));
  e.f(e.gg({"fu"}), "jump", e.shd("begin_forks"));
  e.end();

  e.start_segment("begin_forks");
  e.bf("src", "unsafe");
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu", "ss"}), "mov_rd_rd", e.g("src"), e.g("esp_"));
  e.fr("esp_");
  e.f(e.gg({"fu"}), "jump", e.shd("store_ctx_0"));
  e.end();

  e.bf("accum", "unsafe");
  e.bf("dst", "unsafe");
  e.bf("fork_target", "unsafe");

  e.start_segment("fork_mv_ctx");
  for (uint32_t i = 0; i < 8; i++) {
    e.f(e.gg({"fu"}), "mov_rd_md", e.g("accum"), e.g("src"));
    e.f(e.gg({"fu"}), "mov_md_rd", e.g("dst"), e.g("accum"));
    if (i != 7) {
      e.f(e.gg({"fu"}), "sub_rd_vd", e.g("src"), uint64_t(4));
      e.f(e.gg({"fu"}), "add_rd_vd", e.g("dst"), uint64_t(4));
    }
  }
  e.f(e.gg({"fu"}), "jmp_rd", e.g("fork_target"));
  e.end();

  for (std::uint32_t i = 0; i < 256; i++) {
    e.start_segment("store_ctx_" + std::to_string(i));
#ifdef CHECK_DEBUGGER
    if (i != 0 && global::rc.may_be(5)) {
      e.f(e.gg({"fu"}), "push_rd", e.g("src"));
      e.f(e.gg({"fu"}), "push_rd", e.g("dst"));
      e.f(e.gg({"fu"}), "push_rd", e.g("fork_target"));
      e.f(e.gg({"fu"}), "push_rd", e.g("accum"));
      auto cid = add_container();
      add_to_container(cid, "target", "store_ctx_" + std::to_string(i - 1));
      add_to_container(cid, "if_error", std::string("error_exit"));
      insert_random_trap({"undep", "unapi"}, cid, e.gg({"fu"}));
      remove_container(cid);
      e.f(e.gg({"fu"}), "pop_rd", e.g("accum"));
      e.f(e.gg({"fu"}), "pop_rd", e.g("fork_target"));
      e.f(e.gg({"fu"}), "pop_rd", e.g("dst"));
      e.f(e.gg({"fu"}), "pop_rd", e.g("src"));
    }
#endif
    e.f(e.gg({"fu"}), "add_rd_vd", e.g("src"), uint64_t(28));
    e.f(e.gg({"fu"}), "abs_r", e.g("dst"),
        e.shd("context_storage_" + std::to_string(i)));
    e.f(e.gg({"fu"}), "abs_r", e.g("fork_target"),
        e.shd("store_ctx_" + std::to_string(i + 1)));
    e.f(e.gg({"fu"}), "jump", e.shd("fork_mv_ctx"));
    e.end();
  }

  e.fr("accum");
  e.fr("dst");
  e.fr("fork_target");
  e.fr("src");

  e.start_segment("store_ctx_256");
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "add_rd_vd", e.g("esp_"), std::uint64_t(32));
  //e.f(e.gg({"fu"}), "jump", e.shd("clear_end"));
  e.f(e.gg({"fu"}), "jump", e.shd("set_base"));
  e.fr("esp_");
  e.end();
}

void pe32_i686::load_apis(std::map<std::string, std::uint32_t> &requirements,
                          std::string next_name, bool enable) {
  bool first = true;

  std::string last_s;

  for (auto r : requirements) {
    bool lock = false;
    auto seg = global::cs.generate_unique_string("usegment");
    e.f("store_vd", e.vshd("hash"), std::uint64_t(r.second));
    e.f("invoke", e.shd("get_apix"));
    e.bf("tmp", "common");
    e.f("load_rd", e.g("tmp"), e.vshd("func"));
    e.f("store_rd", e.vshd(r.first), e.g("tmp"));
    e.fr("tmp");

    if (global::rc.may_be(15)) {
      if (enable) {
#ifdef CHECK_DEBUGGER
        auto cid = add_container();
        add_to_container(cid, "target", seg);
        add_to_container(cid, "if_error", std::string("error_exit"));
        insert_random_trap({"unapi"}, cid, 0);
        remove_container(cid);
#endif
      }
      lock = true;
    }

    e.f("jump", e.shd(seg));
    e.end();

    e.start_segment(seg);

    if (!first && !lock && global::rc.may_be(16)) {
      if (enable) {
#ifdef CHECK_DEBUGGER
        auto cid = add_container();
        add_to_container(cid, "target", last_s);
        add_to_container(cid, "if_error", std::string("error_exit"));
        insert_random_trap({"unapi"}, cid, 0);
        remove_container(cid);
#endif
      }
    }

    last_s = seg;

    if (first) first = false;
  }
  e.f("jump", e.shd(next_name));
  e.end();
}

void pe32_i686::set_base() {
  e.bsp("esp_", eg::i8086::esp);
  e.bsp("ebp_", eg::i8086::ebp);
  e.f(e.gg({"fu"}), "mov_rd_rd", e.g("ebp_"), e.g("esp_"));
  e.f(e.gg({"fu"}), "sub_rd_vd", e.g("esp_"), e.frszd());
  e.fr("esp_");
  e.fr("ebp_");
  e.bf("shift", "common");
  if (global::rc.generate_random_number() % 2 == 0 || get_ld()->is_dll()) {
    auto seg1 = global::cs.generate_unique_string("usegment");
    auto new_fl = e.gg({"fu"});
    new_fl.set_flag(eg::type_flags::ignore_shift);
    e.t(new_fl, "call $+5");
    e.start_segment(seg1);
    e.f(e.gg({"fu"}), "pop_rd", e.g("shift"));
    e.end();
    e.f(e.gg({"fu"}), "sub_rd_vd", e.g("shift"), e.shd(seg1));
  } else {
    e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0x30));
    e.f(e.gg({"fu"}), "pop_rd", e.g("shift"));
    e.bsp("fs_", eg::i8086::fs);
    e.f(e.gg({"fu"}), "mov_rd_serd", e.g("shift"), e.g("fs_"), e.g("shift"));
    e.fr("fs_");
    e.f(e.gg({"fu"}), "mov_rd_smd", e.g("shift"), e.g("shift"), std::string("+"),
        std::uint64_t(0x8));
  }
  e.f(e.gg({"fu"}), "store_rd", e.vshd("base"), e.g("shift"));
  e.fr("shift");
}

void pe32_i686::detach_debugger(std::string reg_name) {
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("push_vd", std::uint64_t(0));
  e.f("push_vd", std::uint64_t(0));
  e.f("push_vd", std::uint64_t(0x11));
  e.f("push_rd", e.g(reg_name));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("NtSetInformationThread"));
  e.fr("ebp_");
}

void pe32_i686::init_guard_routine() {
  e.start_segment("guard_routine");
  e.grab_group("common");
  e.f(e.gg({"fu"}), "pushad");
  e.free_group("common");
  set_base();
  std::map<std::string, uint32_t> g_apis;
  g_apis["NtSetInformationThread"] = get_NtSetInformationThread_hash();
  g_apis["GetVersionEx"] = get_GetVersionEx_hash();
  g_apis["NtQueryInformationProcess"] = get_NtQueryInformationProcess_hash();
  g_apis["GetThreadContext"] = get_GetThreadContext_hash();
  g_apis["SetThreadContext"] = get_SetThreadContext_hash();
  g_apis["Sleep"] = get_Sleep_hash();
  load_apis(g_apis, "hide_guard", false);

  e.start_segment("hide_guard");
  e.f("invoke", e.shd("vista_or_higher"));
  api_flag = true;
#ifdef CHECK_DEBUGGER
  e.bf("tmp", "common");
  e.f("mov_rd_vd", e.g("tmp"), std::uint64_t(0xFFFFFFFE));
  detach_debugger("tmp");
  e.fr("tmp");
#endif
  e.bf("tmp", "common");
  e.f("abs_r", e.g("tmp"), e.shd("ok_guard"));
  e.f("add_mb_vb", e.g("tmp"), std::uint64_t(1));
  e.fr("tmp");
  e.f("jump", e.shd("guard_stub_1"));
  e.end();

  e.start_segment("guard_stub_1");
#ifdef CHECK_DEBUGGER
  auto cid = add_container();
  add_to_container(cid, "if_error", std::string("error_exit"));
  insert_trap("is_debbuger_present", cid, 0);
  insert_trap("nt_global_flag", cid, 0);
  insert_trap("heap_flags", cid, 0);
  insert_trap("remote_debugger_present", cid, 0);
  insert_trap("process_debug_flags", cid, 0);
  insert_trap("debug_object_handle", cid, 0);
  insert_trap("reset_thread_ctx", cid, 0);
  remove_container(cid);
#endif
  e.f("jump", e.shd("guard_stub_2"));
  e.end();

  e.start_segment("guard_stub_2");
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("push_vd", std::uint64_t(500));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("Sleep"));
  e.fr("ebp_");
  e.f("jump", e.shd("guard_stub_1"));
  e.end();

  e.start_segment("guard_end");
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "add_rd_vd", e.g("esp_"), e.frszd());
  e.fr("esp_");
  e.grab_group("common");
  e.f(e.gg({"fu"}), "popad");
  e.f(e.gg({"fu"}), "ret_vw", std::uint64_t(0x4));
  e.free_group("common");
  e.end();
}

std::uint32_t pe32_i686::build_code(std::vector<std::uint8_t> *stub,
                                    std::vector<std::uint8_t> *data) {
  e.set_base(get_ld()->get_begin_of_stub());

  e.init_state();

  e.add_data("image", data);

  e.add_data("tls_is_called", 1);

  e.add_data("exit_storage", 4);

  e.add_data("ok_tls", 1);
  e.add_data("ok_guard", 1);

  local_keys["exit"] =
      static_cast<uint32_t>(global::rc.generate_random_number());

  e.start_frame("example_frame");
  e.copy_fundamental();

  // e.start_segment("entry_point");
  // e.bsp("esp_", eg::i8086::esp);
  // e.bsp("ebp_", eg::i8086::ebp);
  // e.f(e.gg({"fu"}), "mov_rd_rd", e.g("ebp_"), e.g("esp_"));
  // e.f(e.gg({"fu"}), "sub_rd_vd", e.g("esp_"), e.frszd());

  // e.bf("shift", "common");
  // e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0x30));
  // e.f(e.gg({"fu"}), "pop_rd", e.g("shift"));
  // e.bsp("fs_", eg::i8086::fs);
  // e.f(e.gg({"fu"}), "mov_rd_serd", e.g("shift"), e.g("fs_"), e.g("shift"));
  // e.fr("fs_");
  // e.f(e.gg({"fu"}), "add_rd_vd", e.g("shift"), std::uint64_t(0x8));
  // e.f(e.gg({"fu"}), "mov_rd_md", e.g("shift"), e.g("shift"));
  // e.f(e.gg({"fu"}), "store_rd", e.vshd("base"), e.g("shift"));
  // e.fr("shift");

  // e.bf("ptr", "common");
  // e.f("push_vd", std::uint64_t(0x0));
  // e.f("push_vd", std::uint64_t(0x21646c72));
  // e.f("push_vd", std::uint64_t(0x6f77206f));
  // e.f("push_vd", std::uint64_t(0x6c6c6548));
  // e.f("mov_rd_rd", e.g("ptr"), e.g("esp_"));
  // e.f("push_vd", std::uint64_t(0x10));
  // e.f("push_vd", std::uint64_t(0));
  // e.f("push_rd", e.g("ptr"));
  // e.f("push_vd", std::uint64_t(0));
  // e.f("abs_r", e.g("ptr"), e.shd("MessageBoxA_str_rva_a"));
  // e.f("mov_rd_md", e.g("ptr"), e.g("ptr"));
  // e.f("call_rd", e.g("ptr"));
  // e.fr("ptr");

  // e.f("mov_rd_rd", e.g("esp_"), e.g("ebp_"));
  // e.f("ret");
  // e.fr("esp_");
  // e.fr("ebp_");
  // e.end();
  // e.end();

  e.start_frame("general");
  e.copy_fundamental();

  e.add_var("hash", 4);
  e.add_var("tmp_hash", 4);
  e.add_var("dll_base", 4);
  e.add_var("current_dll", 4);
  e.add_var("func", 4);
  e.add_var("trash_ptr", 4);
  e.add_var("os_switch", 1);
  e.add_var("align", 2);
  e.add_var("LoadLibrary", 4);
  e.add_var("GetModuleHandle", 4);
  e.add_var("GetProcAddr", 4);
  e.add_var("VirtualProtect", 4);
  e.add_var("GetVersionEx", 4);
  e.add_var("NtQueryInformationProcess", 4);
  e.add_var("NtSetInformationThread", 4);
  e.add_var("GetThreadContext", 4);
  e.add_var("SetThreadContext", 4);
  e.add_var("DbgUiRemoteBreakin", 4);

  search_expx_init_code();
  get_apix_init_code();
  base_exit_init_code();
  error_exit_init_code();
  clear_exit_init_code();
  end_init_code();
  find_library_init_code();
  load_function_init_code();
  vista_or_higher_init_code();
  build_mprotect_stub();
  build_import_stub();
  build_import_directory();
  build_tls_stub();
  build_reloc_stub();
  build_reloc_table();
  build_resources();
  build_export();
  init_forever_crash_loop();

  build_context_forks();

  e.start_segment("begin");
  e.grab_group("common");
  e.f(e.gg({"fu"}), "jump", e.shd("fork_ctx"));
  //e.f(e.gg({"fu"}), "invoke", e.shd("fork_ctx"));
  //e.f(e.gg({"fu"}), "jump", e.shd("set_base"));
  e.free_group("common");
  e.end();

  e.start_segment("set_base");
  set_base();
#ifdef CHECK_DEBUGGER
  auto cid = add_container();
  add_to_container(cid, "target", std::string("first_line"));
  add_to_container(cid, "if_error", std::string("clear_exit"));
  insert_trap("integrity_check", cid, 0);
  remove_container(cid);
#endif
  e.f("jump", e.shd("load_general_api"));
  e.end();

  e.start_segment("load_general_api");
  std::map<std::string, uint32_t> g_apis;
  g_apis["LoadLibrary"] = get_LoadLibrary_hash();
  g_apis["GetProcAddr"] = get_GetProcAddress_hash();
  g_apis["GetModuleHandle"] = get_GetModuleHandle_hash();
  g_apis["VirtualProtect"] = get_VirtualProtect_hash();
  g_apis["NtQueryInformationProcess"] = get_NtQueryInformationProcess_hash();
  g_apis["GetVersionEx"] = get_GetVersionEx_hash();
  g_apis["GetThreadContext"] = get_GetThreadContext_hash();
  g_apis["SetThreadContext"] = get_SetThreadContext_hash();
  g_apis["NtSetInformationThread"] = get_NtSetInformationThread_hash();
  g_apis["DbgUiRemoteBreakin"] = get_DbgUiRemoteBreakin_hash();
  load_apis(g_apis, "load_general_api_end", true);

  e.start_segment("load_general_api_end");
  e.bf("tmp", "common");
  #ifdef CHECK_DEBUGGER
  e.f("mov_rd_vd", e.g("tmp"), std::uint64_t(0xFFFFFFFE));
  detach_debugger("tmp");
  #endif
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("lea_rd_smd", e.g("tmp"), e.g("ebp_"), std::string("-"), e.vshd("trash_ptr"));
  e.f("push_rd", e.g("tmp"));
  e.f("push_vd", std::uint64_t(0x40));
  e.f("push_vd", std::uint64_t(6));
  e.f("load_rd", e.g("tmp"), e.vshd("DbgUiRemoteBreakin"));
  e.f("push_rd", e.g("tmp"));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("VirtualProtect"));
  e.f("load_rd", e.g("tmp"), e.vshd("DbgUiRemoteBreakin"));
  e.f("mov_mb_vb", e.g("tmp"), std::uint64_t(0x68));
  e.f("inc_rd", e.g("tmp"));
  e.bf("err", "common");
  e.f("abs_r", e.g("err"), e.shd("clear_exit"));
  e.f("mov_md_rd", e.g("tmp"), e.g("err"));
  e.fr("err");
  e.f("add_rd_vd", e.g("tmp"), std::uint64_t(4));
  e.f("mov_mb_vb", e.g("tmp"), std::uint64_t(0xC3));
  e.f("lea_rd_smd", e.g("tmp"), e.g("ebp_"), std::string("-"), e.vshd("trash_ptr"));
  e.f("push_rd", e.g("tmp"));
  e.f("load_rd", e.g("tmp"), e.vshd("trash_ptr"));
  e.f("push_rd", e.g("tmp"));
  e.f("push_vd", std::uint64_t(6));
  e.f("load_rd", e.g("tmp"), e.vshd("DbgUiRemoteBreakin"));
  e.f("push_rd", e.g("tmp"));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("VirtualProtect"));
  e.fr("tmp");
  e.fr("ebp_");
  e.f("invoke", e.shd("vista_or_higher"));
  api_flag = true;
#ifdef CHECK_DEBUGGER
  cid = add_container();
  add_to_container(cid, "target", std::string("first_line_checks"));
  add_to_container(cid, "if_error", std::string("clear_exit"));
  insert_trap("integrity_check", cid, 0);
  remove_container(cid);
#endif
  e.bf("tmp", "common");
  e.f("abs_r", e.g("tmp"), e.shd("ok_tls"));
  e.f("cmp_mb_vb", e.g("tmp"), std::uint64_t(1));
  e.f("branch", "e", e.shd("decrypt_secondary_key"), e.shd("error_exit"));
  e.fr("tmp");
  e.end();

  e.enable_alter("image", "some_key", "aes");
  e.add_key("some_key");
  e.enable_alter("some_key", "secondary_key", "dword_ecb");

  e.start_segment("decrypt_secondary_key");
  insert_decrypt("decrypt_paramount_key");
  e.f("jump", e.shd("decrypt_paramount_key"));
  e.end();

  e.start_segment("decrypt_paramount_key");
  e.f("store_abs", e.vshd("target"), e.shd("some_key"));
  e.f("store_vd", e.vshd("count"), e.fszd("some_key"));
  e.f("store_vd", e.vshd("dword_key"), e.kd("secondary_key", 32, 0));
  e.f("invoke", e.shd("alter_d"));
  e.bf("tmp", "common");
  e.f("abs_r", e.g("tmp"), e.shd("ok_guard"));
  e.f("jump", e.shd("wait_stub_1"));
  e.end();

  e.start_segment("wait_stub_1");
  e.f("cmp_mb_vb", e.g("tmp"), std::uint64_t(1));
  e.f("branch", "e", e.shd("unpack_image"), e.shd("wait_stub_2"));
  e.end();

  e.start_segment("wait_stub_2");
  e.f("jump", e.shd("wait_stub_1"));
  e.fr("tmp");
  e.end();

  e.start_segment("unpack_image");
  e.f("store_abs", e.vshd("target"), e.shd("image"));
  e.f("store_vd", e.vshd("count"), e.fszd("image"));
  e.f("store_abs", e.vshd("key_addr"), e.shd("some_key"));
  e.f("invoke", e.shd("aes_decrypt"));
  e.f("store_abs", e.vshd("target"), e.shd("image"));
  e.f("store_abs", e.vshd("value"), get_ld()->get_real_image_begin());
  e.f("invoke", e.shd("uncompress"));
  e.f("jump", e.shd("import"));
  e.end();

  e.end();

  api_flag = false;

  e.start_frame("support");

  e.copy_fundamental();
  e.copy_var("hash", "general");
  e.copy_var("tmp_hash", "general");
  e.copy_var("dll_base", "general");
  e.copy_var("func", "general");
  e.add_var("align", 3);
  e.add_var("NtTerminateProcess", 4);
  e.add_var("NtSetInformationThread", 4);
  e.add_var("CreateThread", 4);

  e.start_segment("first_line");
  e.grab_group("common");
  e.f(e.gg({"fu"}), "pushad");
  e.free_group("common");
  set_base();
  e.bf("flag_addr", "common");
  e.bf("flag", "base");
  e.f("abs_r", e.g("flag_addr"), e.shd("tls_is_called"));
  e.f("mov_rb_mb", e.g("flag", "lb"), e.g("flag_addr"));
  e.f("test_rb_rb", e.g("flag", "lb"), e.g("flag", "lb"));
  e.f("branch", "nz", e.shd("first_line_end"), e.shd("first_line_apis"));
  e.fr("flag");
  e.end();

  e.start_segment("first_line_apis");
  e.f("mov_mb_vb", e.g("flag_addr"), std::uint64_t(1));
  e.fr("flag_addr");
  std::map<std::string, uint32_t> s_apis;
  s_apis["NtTerminateProcess"] = get_NtTerminateProcess_hash();
  s_apis["CreateThread"] = get_CreateThread_hash();
  s_apis["NtSetInformationThread"] = get_NtSetInformationThread_hash();
  load_apis(s_apis, "first_line_checks", false);

  e.start_segment("first_line_checks");
  e.bf("tmp", "common");
  e.f("load_rd", e.g("tmp"), e.vshd("NtTerminateProcess"));
  e.f("xor_rd_vd", e.g("tmp"), std::uint64_t(local_keys["exit"]));
  e.bf("exit_s", "common");
  e.f("abs_r", e.g("exit_s"), e.shd("exit_storage"));
  e.f("mov_md_rd", e.g("exit_s"), e.g("tmp"));
  e.fr("exit_s");
  e.fr("tmp");

#ifdef CHECK_DEBUGGER
  e.bf("tmp", "common");
  e.f("mov_rd_vd", e.g("tmp"), std::uint64_t(0xFFFFFFFE));
  detach_debugger("tmp");
  e.fr("tmp");
  cid = add_container();
  add_to_container(cid, "target", std::string("begin"));
  add_to_container(cid, "if_error", std::string("error_exit"));
  insert_trap("integrity_check", cid, 0);
  insert_trap("is_debbuger_present", cid, 0);
  insert_trap("nt_global_flag", cid, 0);
  remove_container(cid);
#endif
  insert_decrypt("create_thread");
  e.f("jump", e.shd("create_thread"));
  e.end();

  e.start_segment("create_thread");
  e.bf("tmp", "common");
  e.f("abs_r", e.g("tmp"), e.shd("ok_tls"));
  e.f("mov_mb_vb", e.g("tmp"), std::uint64_t(1));
  e.f("abs_r", e.g("tmp"), e.shd("guard_routine"));
  e.bsp("ebp_", eg::i8086::ebp);
  e.bsp("esp_", eg::i8086::esp);
  e.bf("reminder", "common");
  e.f("mov_rd_rd", e.g("reminder"), e.g("esp_"));
  e.f("and_rd_vd", e.g("reminder"), std::uint64_t(15));
  e.f("sub_rd_rd", e.g("esp_"), e.g("reminder"));
  e.f("push_rd", e.g("reminder"));
  e.f("push_rd", e.g("reminder"));
  e.f("push_vd", std::uint64_t(0));
  e.f("push_vd", std::uint64_t(0));
  e.f("push_vd", std::uint64_t(0));
  e.f("push_rd", e.g("tmp"));
  e.f("push_vd", std::uint64_t(0));
  e.f("push_vd", std::uint64_t(0));
  e.f("call_smd", e.g("ebp_"), std::string("-"), e.vshd("CreateThread"));
  e.f("pop_rd", e.g("reminder"));
  e.f("pop_rd", e.g("reminder"));
  e.f("add_rd_rd", e.g("esp_"), e.g("reminder"));
  e.fr("esp_");
  e.fr("reminder");
  e.fr("ebp_");
  e.fr("tmp");
  e.f("jump", e.shd("first_line_end"));
  e.end();

  e.start_segment("first_line_end");
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "add_rd_vd", e.g("esp_"), e.frszd());
  e.fr("esp_");
  e.grab_group("common");
  e.f(e.gg({"fu"}), "popad");
  e.f(e.gg({"fu"}), "ret_vw", std::uint64_t(0xC));
  e.free_group("common");
  e.end();

  e.end();

  e.start_frame("guard");
  e.copy_fundamental();
  e.copy_var("hash", "general");
  e.copy_var("tmp_hash", "general");
  e.copy_var("dll_base", "general");
  e.copy_var("func", "general");
  e.copy_var("os_switch", "general");
  e.copy_var("align", "general");
  e.add_var("NtSetInformationThread", 4);
  e.add_var("Sleep", 4);
  e.copy_var("GetVersionEx", "general");
  e.add_var("NtQueryInformationProcess", 4);
  e.add_var("GetThreadContext", 4);
  e.add_var("SetThreadContext", 4);

  init_guard_routine();

  e.end();

  e.build(stub);

  import_directory_params.first =
      static_cast<std::uint32_t>(e.get_memory_rva("import_directory"));
  import_directory_params.second =
      static_cast<std::uint32_t>(e.get_memory_payload_size("import_directory"));

  tls_directory_params.first =
      static_cast<std::uint32_t>(e.get_memory_rva("tls_directory"));
  tls_directory_params.second =
      static_cast<std::uint32_t>(e.get_memory_payload_size("tls_directory"));

  reloc_directory_params.first =
      static_cast<std::uint32_t>(e.get_memory_rva("reloc_directory"));
  reloc_directory_params.second =
      static_cast<std::uint32_t>(e.get_memory_payload_size("reloc_directory"));

  if (get_ld()->is_resources_exists()) {
    resource_directory_params.first =
        static_cast<std::uint32_t>(e.get_memory_rva("resource_diretory"));
    resource_directory_params.second = static_cast<std::uint32_t>(
        e.get_memory_payload_size("resource_diretory"));
  }

  if (get_ld()->is_exports_exists()) {
    export_rva =
        static_cast<std::uint32_t>(e.get_memory_rva("export_directory"));
    global::wipe_memory(
        get_ld()->get_image(),
        get_ld()->get_optional_header()->data_directory[0].virtual_address,
        sizeof(ld::pe::image_export_directory));
  }

  return static_cast<std::uint32_t>(e.get_memory_rva("begin"));
}

void pe32_i686::make() {
  file->open();
  std::vector<uint8_t> data = get_ld()->get_protected_data();
  std::vector<uint8_t> stub;
  cmpr.compress(data);
  std::uint32_t begin = build_code(&stub, &data);
  write_header(get_ld()->get_rebuilded_header(
      stub.size(), begin, tls_directory_params, reloc_directory_params,
      resource_directory_params, export_rva, import_directory_params));
  get_ld()->resize_with_file_align(&stub);
  write_data(&stub);
  file->close();
}

void pe32_i686::write_header(std::vector<std::uint8_t> header) {
  file->write_bytes(header);
}

void pe32_i686::write_data(std::vector<std::uint8_t> *data) {
  file->write_bytes(*data);
}
}  // namespace mk