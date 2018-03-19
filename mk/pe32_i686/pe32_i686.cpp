#include <cry/crypto.h>
#include <mk/pe32_i686/pe32_i686.h>

namespace mk {
pe32_i686::pe32_i686() : base_mk() {}
pe32_i686::pe32_i686(fs::out_file *out_file) : base_mk(out_file) {}
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

std::uint32_t pe32_i686::get_KERNEL32_hash() {
  std::vector<std::uint8_t> kernel32 = {0x4b, 0x45, 0x52, 0x4e, 0x45,
                                        0x4c, 0x33, 0x32, 0x2e, 0x64,
                                        0x6c, 0x6c, 0x0};
  cry::crc32 c;
  c.set(kernel32);
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

std::uint32_t pe32_i686::get_ExitProcess_hash() {
  std::vector<std::uint8_t> exitprocess = {0x45, 0x78, 0x69, 0x74, 0x50, 0x72,
                                           0x6f, 0x63, 0x65, 0x73, 0x73, 0x0};
  std::uint32_t result = get_KERNEL32_hash();
  cry::crc32 c;
  c.set(exitprocess);
  result += c.get();
  return result;
}

void pe32_i686::end_init_code() {
  e.start_segment("end");
  e.grab_group("common");
  e.bss("ebp_", eg::i8086::ebp);
  e.bss("esp_", eg::i8086::esp);
  e.f("mov_rd_rd", e.g("esp_"), e.g("ebp_"));
  e.f("pop_rd", e.g("ebp_"));
  e.t("popad");
  e.f(e.gg({"fu"}), "jump",
      std::uint64_t(get_ld()->get_optional_header()->address_of_entry_point));
  e.end();
  e.free_group("common");
  e.fr("ebp_");
  e.fr("esp_");
}

void pe32_i686::error_exit_init_code() {
  e.start_segment("error_exit");
  e.f("push_vd", std::uint64_t(0));
  e.bss("ebp_", eg::i8086::ebp);
  e.f("call_smd", e.g("ebp_"), "-", e.vshd("ExitProcess"));
  e.fr("ebp_");
  e.end();
}

void pe32_i686::search_expx_init_code() {
  e.add_var("tmp_hash", 4);

  e.start_segment("search_expx");
  e.bf("dll_base", "common");
  e.f("load_rd", e.g("dll_base"), e.vshd("dll_base"));
  e.bf("result", "common");
  e.f("mov_rd_smd", e.g("result"), e.g("dll_base"), "+", std::uint64_t(0x3C));
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
  e.f("add_rd_smd", e.g("result"), e.g("ebp_"), "-", e.vshd("tmp_hash"));
  e.f("cmp_rd_smd", e.g("result"), e.g("ebp_"), "-", e.vshd("hash"));
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
  e.f("push_rd", std::uint64_t(0x30));
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
  e.f("store_rd", e.vshd("func"), std::uint64_t(0));
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::find_library_init_code() {
  e.start_segment("find_library");
  e.bsp("eax_", eg::i8086::eax);
  e.bf("lib_name", "common");
  e.f("load_rd", e.g("lib_name"), e.vshd("target"));
  e.f("push_rd", e.g("lib_name"));
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("call_smd", e.g("ebp_"), "-", e.vshd("GetModuleHandle"));
  e.f("test_rd_rd", e.g("eax_"), e.g("eax_"));
  e.f("branch", "nz", e.shd("dll_found"), e.shd("dll_not_found"));
  e.end();

  e.start_segment("dll_not_found");
  e.f("push_rd", e.g("lib_name"));
  e.fr("lib_name");
  e.f("call_smd", e.g("ebp_"), "-", e.vshd("LoadLibrary"));
  e.fr("ebp_");
  e.f("test_rd_rd", e.g("eax_"), e.g("eax_"));
  e.f("branch", "nz", e.shd("dll_found"), e.shd("dll_not_load"));
  e.end();

  e.start_segment("dll_not_load");
  e.f("jump", e.shd("error_exit"));
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
  e.f("call_smd", e.g("ebp_"), "-", e.vshd("GetProcAddr"));
  e.fr("ebp_");
  e.f("test_rd_rd", e.g("eax_"), e.g("eax_"));
  e.f("branch", "nz", e.shd("function_found"), e.shd("function_not_found"));
  e.end();

  e.start_segment("function_not_found");
  e.f("jump", e.shd("error_exit"));
  e.end();

  e.start_segment("function_found");
  e.f("store_rd", e.vshd("func"), e.g("eax_"));
  e.fr("eax_");
  e.f("jump", e.shd("clear_end"));
  e.end();
}

void pe32_i686::build_import_stub() {
  std::vector<ld::pe::library> *import = get_ld()->get_import();
  e.start_segment("import");

  for (auto lib : *import) {
    e.bf("iat_base", "common");
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

    for (auto func : lib.functions) {
      auto function_alias = global::cs.generate_unique_string("if");
      e.add_top_data(function_alias, &func.first);
      e.enable_alter(function_alias, function_alias + "key", "dword_ecb");
      e.bf("tmp", "common");
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
      e.f("mov_md_rd", e.g("iat_base"), e.g("func_addr"));
      e.fr("func_addr");
      e.f("add_rd_vd", e.g("iat_base"), std::uint64_t(4));
    }

    e.fr("iat_base");
  }

  e.f("jump", e.shd("end"));
  e.end();
}

std::uint32_t pe32_i686::build_code(std::vector<std::uint8_t> *stub,
                                    std::vector<std::uint8_t> *data) {
  e.set_base(get_ld()->get_begin_of_stub());
  e.init_state();

  e.add_data("image", data);

  e.start_frame("general");
  e.copy_fundamental();

  e.add_var("hash", 4);
  e.add_var("dll_base", 4);
  e.add_var("current_dll", 4);
  e.add_var("func", 4);
  e.add_var("message_box_switch", 1);
  e.add_var("LoadLibrary", 4);
  e.add_var("GetModuleHandle", 4);
  e.add_var("GetProcAddr", 4);
  e.add_var("ExitProcess", 4);
  e.add_var("MessageBox", 4);

  search_expx_init_code();
  get_apix_init_code();
  error_exit_init_code();
  end_init_code();
  find_library_init_code();
  load_function_init_code();
  build_import_stub();

  e.start_segment("begin");
  e.t("pushad");
  e.bsp("ebp_", eg::i8086::ebp);
  e.f(e.gg({"fu"}), "push_rd", e.g("ebp_"));
  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "mov_rd_rd", e.g("ebp_"), e.g("esp_"));
  e.f(e.gg({"fu"}), "sub_rd_vd", e.g("esp_"), e.frszd());
  e.fr("esp_");
  e.f(e.gg({"fu"}), "push_vd", std::uint64_t(0x30));
  e.bf("shift", "common");
  e.f(e.gg({"fu"}), "pop_rd", e.g("shift"));
  e.bsp("fs_", eg::i8086::fs);
  e.f(e.gg({"fu"}), "mov_rd_serd", e.g("shift"), e.g("fs_"), e.g("shift"));
  e.fr("fs_");
  e.f(e.gg({"fu"}), "mov_rd_smd", e.g("shift"), e.g("shift"), "+",
      std::uint64_t(0x8));
  e.f(e.gg({"fu"}), "store_rd", e.vshd("base"), e.g("shift"));
  e.fr("shift");

  e.f("store_abs", e.vshd("target"), e.shd("image"));
  e.f("store_vd", e.vshd("count"), e.fszd("image"));
  e.f("store_abs", e.vshd("key_addr"), e.shd("some_key"));
  e.f("invoke", e.shd("aes_decrypt"));
  e.f("store_abs", e.vshd("target"), e.shd("image"));
  e.f("store_abs", e.vshd("value"), get_ld()->get_real_image_begin());
  e.f("invoke", e.shd("uncompress"));

  e.f("store_rd", e.vshd("hash"), std::uint64_t(get_LoadLibrary_hash()));
  e.f("invoke", e.shd("get_apix"));
  e.bf("tmp", "common");
  e.f("load_rd", e.g("tmp"), e.vshd("func"));
  e.f("store_rd", e.vshd("LoadLibrary"), e.g("tmp"));
  e.fr("tmp");

  e.f("store_rd", e.vshd("hash"), std::uint64_t(get_GetProcAddress_hash()));
  e.f("invoke", e.shd("get_apix"));
  e.bf("tmp", "common");
  e.f("load_rd", e.g("tmp"), e.vshd("func"));
  e.f("store_rd", e.vshd("GetProcAddr"), e.g("tmp"));
  e.fr("tmp");

  e.f("store_rd", e.vshd("hash"), std::uint64_t(get_GetModuleHandle_hash()));
  e.f("invoke", e.shd("get_apix"));
  e.bf("tmp", "common");
  e.f("load_rd", e.g("tmp"), e.vshd("func"));
  e.f("store_rd", e.vshd("GetModuleHandle"), e.g("tmp"));
  e.fr("tmp");

  e.f("store_rd", e.vshd("hash"), std::uint64_t(get_ExitProcess_hash()));
  e.f("invoke", e.shd("get_apix"));
  e.bf("tmp", "common");
  e.f("load_rd", e.g("tmp"), e.vshd("func"));
  e.f("store_rd", e.vshd("ExitProcess"), e.g("tmp"));
  e.fr("tmp");

  e.f("jump", e.shd("import"));

  e.bsp("esp_", eg::i8086::esp);
  e.f(e.gg({"fu"}), "mov_rd_rd", e.g("esp_"), e.g("ebp_"));
  e.f(e.gg({"fu"}), "pop_rd", e.g("ebp_"));
  e.f(e.gg({"fu"}), "ret");
  e.fr("ebp_");
  e.fr("esp_");

  e.end();

  e.enable_alter("image", "some_key", "aes");
  e.add_key("some_key");

  e.end();

  e.build(stub);

  return static_cast<std::uint32_t>(e.get_entry_point());
}

void pe32_i686::make() {
  file->open();
  std::vector<uint8_t> data = get_ld()->get_protected_data();
  std::vector<uint8_t> stub;
  cmpr.compress(data);
  std::uint32_t begin = build_code(&stub, &data);
  write_header(get_ld()->get_rebuilded_header(stub.size(), begin));
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