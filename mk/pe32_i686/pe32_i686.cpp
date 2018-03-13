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
  if (ld::machine_types::i386 == current_machine)
    return true;
  return false;
}
bool pe32_i686::ok_loader(ld::loader_types current_loader) {
  if (ld::loader_types::pe32 == current_loader)
    return true;
  return false;
}

// std::uint32_t pe32_i686::get_KERNEL32_hash() {
//   std::vector<std::uint8_t> kernel32 = {0x4b, 0x45, 0x52, 0x4e, 0x45,
//                                         0x4c, 0x33, 0x32, 0x2e, 0x64,
//                                         0x6c, 0x6c, 0x0};
//   return crc::crc32(&kernel32);
// }

// std::uint32_t pe32_i686::get_LoadLibrary_hash() {
//   std::vector<std::uint8_t> loadlibrary = {0x4c, 0x6f, 0x61, 0x64, 0x4c,
//                                            0x69, 0x62, 0x72, 0x61, 0x72,
//                                            0x79, 0x41, 0x0};
//   std::uint32_t result = get_KERNEL32_hash();
//   result += crc::crc32(&loadlibrary);
//   return result;
// }

// std::uint32_t pe32_i686::get_GetModuleHandle_hash() {
//   std::vector<std::uint8_t> getmodulehandle = {
//       0x47, 0x65, 0x74, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65,
//       0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x41, 0x0};
//   std::uint32_t result = get_KERNEL32_hash();
//   result += crc::crc32(&getmodulehandle);
//   return result;
// }

// std::uint32_t pe32_i686::get_GetProcAddress_hash() {
//   std::vector<std::uint8_t> getprocaddr = {0x47, 0x65, 0x74, 0x50, 0x72,
//                                            0x6f, 0x63, 0x41, 0x64, 0x64,
//                                            0x72, 0x65, 0x73, 0x73, 0x0};
//   std::uint32_t result = get_KERNEL32_hash();
//   result += crc::crc32(&getprocaddr);
//   return result;
// }

// std::uint32_t pe32_i686::get_ExitProcess_hash() {
//   std::vector<std::uint8_t> exitprocess = {0x45, 0x78, 0x69, 0x74, 0x50,
//   0x72,
//                                            0x6f, 0x63, 0x65, 0x73, 0x73,
//                                            0x0};
//   std::uint32_t result = get_KERNEL32_hash();
//   result += crc::crc32(&exitprocess);
//   return result;
// }

// void pe32_i686::end_init_code() {
//   e.allocate_element("end", "general");
//   auto entry_point = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(entry_point);
//   e.f("abs", entry_point,
//       (*get_ld())->get_optional_header()->address_of_entry_point);
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("func_target"),
//       entry_point);
//   e.get_machine()->free_register(entry_point);
//   e.get_machine()->grab_group("all");
//   e.f("mov_rd_rd", eg::i8086::esp, eg::i8086::ebp);
//   e.f("pop_rd", eg::i8086::ebp);
//   auto r = e.get_machine()->get_rand("common");
//   e.get_machine()->prepare(r);
//   e.t("popad");
//   e.f("push_rd", r);
//   e.f("push_rd", r);
//   e.f("add_rd_vd", eg::i8086::esp, std::uint64_t(4));
//   e.f("mov_rd_mdsh", r, eg::i8086::esp, "-",
//       eg::base_eg::wrapp(
//           eg::base_eg::vshd("func_target"), {32},
//           [](eg::part *p, std::vector<std::uint64_t> *v) -> std::uint64_t {
//             return p->get_value() + (*v)[0];
//           }));
//   e.f("mov_md_rd", eg::i8086::esp, r);
//   e.f("sub_rd_vd", eg::i8086::esp, std::uint64_t(4));
//   e.f("pop_rd", r);
//   e.f("ret");
//   e.get_machine()->local_load(r);
//   e.get_machine()->free_group("all");
// }

// void pe32_i686::error_exit_init_code() {
//   e.allocate_element("error_exit", "general");
//   e.f("push_vd", std::uint64_t(0));
//   e.f("call_mdsh", eg::i8086::ebp, "-", eg::base_eg::vshd("ExitProcess"));
// }

// void pe32_i686::search_expx_init_code() {
//   e.get_chain("general")->add_var("tmp_hash", 4);
//   e.allocate_element("search_expx", "general");
//   auto dll_base = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(dll_base);
//   e.f("mov_rd_mdsh", dll_base, eg::i8086::ebp, "-",
//       eg::base_eg::vshd("dll_base"));
//   auto result = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(result);
//   e.f("mov_rd_mdsh", result, dll_base, "+", std::uint64_t(0x3C));
//   auto va = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(va);
//   e.f("mov_rd_mdrdsh", va, dll_base, "+", result, "+", std::uint64_t(0x78));
//   e.f("test_rd_rd", va, va);
//   e.branch("jnz", "search_expx_0", "exp_l2");

//   e.allocate_element("search_expx_0", "general");
//   e.f("mov_rd_mdrdsh", result, dll_base, "+", va, "+", std::uint64_t(0xC));
//   e.f("add_rd_rd", result, dll_base);
//   e.f("mov_mbsh_vb", eg::i8086::ebp, "-", eg::base_eg::vshd("crc_switch"),
//       std::uint64_t(1));
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("func_target"),
//       result);
//   e.push_registers({dll_base, va});
//   e.invoke("crc");
//   e.pop_registers({dll_base, va});
//   e.f("mov_rd_mdsh", result, eg::i8086::ebp, "-", eg::base_eg::vshd("crc"));
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("tmp_hash"),
//       result);
//   auto line = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(line);
//   e.f("lea_rd_mdrdsh", line, dll_base, "+", va, "+", std::uint64_t(0x18));
//   e.f("push_vd", std::uint64_t(4));
//   e.f("pop_rd", va);
//   e.jump("exp_l0_0");

//   e.allocate_element("exp_l0_0", "general");
//   e.f("mov_rd_md", result, line);
//   e.f("add_rd_vd", line, std::uint64_t(4));
//   e.f("add_rd_rd", result, dll_base);
//   e.f("push_rd", result);
//   e.f("dec_rd", va);
//   e.f("test_rd_rd", va, va);
//   e.branch("jnz", "exp_l0_0", "exp_l0_1");

//   e.allocate_element("exp_l0_1", "general");
//   auto long_data = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(long_data);
//   auto short_data = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(short_data);
//   e.f("pop_rd", long_data);
//   e.f("pop_rd", short_data);
//   e.f("pop_rd", line);
//   e.f("pop_rd", va);
//   e.f("sub_rd_rd", va, dll_base);
//   e.branch("jz", "exp_l2", "exp_l3_0");

//   e.allocate_element("exp_l3_0", "general");
//   e.f("mov_rd_mdshmdsh", result, short_data, "+", std::uint64_t(4), "*", va,
//       "-", std::uint64_t(4));
//   e.f("add_rd_rd", result, dll_base);
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("func_target"),
//       result);
//   e.f("mov_mbsh_vb", eg::i8086::ebp, "-", eg::base_eg::vshd("crc_switch"),
//       std::uint64_t(1));
//   e.push_registers({short_data, va, dll_base, line, long_data});
//   e.invoke("crc");
//   e.pop_registers({short_data, va, dll_base, line, long_data});
//   e.f("mov_rd_mdsh", result, eg::i8086::ebp, "-", eg::base_eg::vshd("crc"));
//   e.f("add_rd_mdsh", result, eg::i8086::ebp, "-",
//       eg::base_eg::vshd("tmp_hash"));
//   e.f("cmp_rd_mdsh", result, eg::i8086::ebp, "-", eg::base_eg::vshd("hash"));
//   e.branch("jne", "exp_l3_1", "exp_l3_2");

//   e.allocate_element("exp_l3_1", "general");
//   e.f("dec_rd", va);
//   e.f("test_rd_rd", va, va);
//   e.branch("jnz", "exp_l3_0", "exp_l2");

//   e.allocate_element("exp_l3_2", "general");
//   e.get_machine()->free_register(short_data);
//   e.f("dec_rd", va);
//   e.f("xchg_rd_rd", result, dll_base);
//   e.f("xchg_rd_rd", result, va);
//   e.f("movzx_rd_mwshrd", result, long_data, "+", std::uint64_t(2), "*",
//   result); e.f("add_rd_mdshrd", va, line, "+", std::uint64_t(4), "*",
//   result); e.get_machine()->free_register(result);
//   e.get_machine()->free_register(dll_base);
//   e.get_machine()->free_register(line);
//   e.get_machine()->free_register(long_data);
//   e.jump("exp_l2");

//   e.allocate_element("exp_l2", "general");
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("func"), va);
//   e.get_machine()->free_register(va);
//   e.f("ret");
// }

// void pe32_i686::get_apix_init_code() {
//   e.allocate_element("get_apix", "general");
//   e.f("push_vd", std::uint64_t(0x30));
//   auto pointer = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(pointer);
//   e.f("pop_rd", pointer);
//   e.f("mov_rd_ssdrsh", pointer, eg::i8086::fs, pointer);
//   e.f("mov_rd_mdsh", pointer, pointer, "+", std::uint64_t(0xC));
//   auto flink = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(flink);
//   e.f("mov_rd_mdsh", flink, pointer, "+", std::uint64_t(0xC));
//   e.jump("gapi_l1_0");

//   e.allocate_element("gapi_l1_0", "general");
//   auto dll_base = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(dll_base);
//   e.f("mov_rd_mdsh", dll_base, flink, "+", std::uint64_t(0x18));
//   e.f("test_rd_rd", dll_base, dll_base);
//   e.branch("jnz", "gapi_l0_0", "gapi_l1_1");

//   e.allocate_element("gapi_l0_0", "general");
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("dll_base"),
//       dll_base);
//   e.push_registers({flink});
//   e.invoke("search_expx");
//   e.pop_registers({flink});
//   e.f("mov_rd_mdsh", pointer, eg::i8086::ebp, "-",
//   eg::base_eg::vshd("func")); e.f("test_rd_rd", pointer, pointer);
//   e.branch("jnz", "clear_end", "gapi_l0_1");

//   e.allocate_element("gapi_l0_1", "general");
//   e.f("mov_rd_md", flink, flink);
//   e.jump("gapi_l1_0");

//   e.allocate_element("gapi_l1_1", "general");
//   e.get_machine()->free_register(pointer);
//   e.get_machine()->free_register(flink);
//   e.get_machine()->free_register(dll_base);
//   e.f("mov_mdsh_vd", eg::i8086::ebp, "-", eg::base_eg::vshd("func"),
//       std::uint64_t(0));
//   e.jump("clear_end");
// }

// void pe32_i686::find_library_init_code() {
//   e.allocate_element("find_library", "general");
//   e.get_machine()->grab_register(eg::i8086::eax);
//   auto lib_name = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(lib_name);
//   e.f("mov_rd_mdsh", lib_name, eg::i8086::ebp, "-",
//       eg::base_eg::vshd("func_target"));
//   e.f("push_rd", lib_name);
//   e.f("call_mdsh", eg::i8086::ebp, "-",
//   eg::base_eg::vshd("GetModuleHandle")); e.f("test_rd_rd", eg::i8086::eax,
//   eg::i8086::eax); e.branch("jnz", "dll_found", "dll_not_found");

//   e.allocate_element("dll_not_found", "general");
//   e.f("push_rd", lib_name);
//   e.f("call_mdsh", eg::i8086::ebp, "-", eg::base_eg::vshd("LoadLibrary"));
//   e.f("test_rd_rd", eg::i8086::eax, eg::i8086::eax);
//   e.branch("jnz", "dll_found", "dll_not_load");

//   e.allocate_element("dll_not_load", "general");
//   e.jump("error_exit");

//   e.allocate_element("dll_found", "general");
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("current_dll"),
//       eg::i8086::eax);
//   e.f("ret");

//   e.get_machine()->free_register(eg::i8086::eax);
//   e.get_machine()->free_register(lib_name);
// }

// void pe32_i686::load_function_init_code() {
//   e.allocate_element("find_function", "general");
//   e.get_machine()->grab_register(eg::i8086::eax);
//   auto lib_addr = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(lib_addr);
//   auto func_name = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(func_name);
//   e.f("mov_rd_mdsh", func_name, eg::i8086::ebp, "-",
//       eg::base_eg::vshd("func_target"));
//   e.f("mov_rd_mdsh", lib_addr, eg::i8086::ebp, "-",
//       eg::base_eg::vshd("current_dll"));
//   e.f("push_rd", func_name);
//   e.f("push_rd", lib_addr);
//   e.f("call_mdsh", eg::i8086::ebp, "-", eg::base_eg::vshd("GetProcAddr"));
//   e.f("test_rd_rd", eg::i8086::eax, eg::i8086::eax);
//   e.branch("jnz", "function_found", "function_not_found");

//   e.allocate_element("function_not_found", "general");
//   e.jump("error_exit");

//   e.allocate_element("function_found", "general");
//   e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("func"),
//       eg::i8086::eax);
//   e.f("ret");

//   e.get_machine()->free_register(eg::i8086::eax);
//   e.get_machine()->free_register(lib_addr);
//   e.get_machine()->free_register(func_name);
// }

// void pe32_i686::build_import_stub() {
//   std::vector<ld::pe::library> *import = (*get_ld())->get_import();
//   e.allocate_element("import", "general");

//   for (auto lib : *import) {
//     auto iat_base = e.get_machine()->get_free("common");
//     e.get_machine()->grab_register(iat_base);
//     e.f("abs", iat_base, lib.iat_begin);
//     auto dll_name_label = "il" + e.generate("il");
//     auto dll_name_glob = e.allocate_global(dll_name_label);
//     dll_name_glob->update_data(&lib.name);
//     e.f("mov_mdsh_abs", eg::i8086::ebp, "-",
//     eg::base_eg::vshd("func_target"),
//         eg::base_eg::shd(dll_name_label));
//     e.push_registers({iat_base});
//     e.invoke("find_library");
//     e.pop_registers({iat_base});

//     for (auto func : lib.functions) {
//       auto function_name_label = "if" + e.generate("if");
//       auto function_name_glob = e.allocate_global(function_name_label);
//       function_name_glob->update_data(&func.first);
//       e.f("mov_mdsh_abs", eg::i8086::ebp, "-",
//       eg::base_eg::vshd("func_target"),
//           eg::base_eg::shd(function_name_label));
//       e.push_registers({iat_base});
//       e.invoke("find_function");
//       e.pop_registers({iat_base});
//       auto func_addr = e.get_machine()->get_free("common");
//       e.get_machine()->grab_register(func_addr);
//       e.f("mov_rd_mdsh", func_addr, eg::i8086::ebp, "-",
//           eg::base_eg::vshd("func"));
//       e.f("mov_md_rd", iat_base, func_addr);
//       e.f("add_rd_vd", iat_base, std::uint64_t(4));
//       e.get_machine()->free_register(func_addr);
//     }
//     e.get_machine()->free_register(iat_base);
//   }

//   e.jump("end");
// }

// void pe32_i686::restore_image_init_code() {
//   e.allocate_element("restore_image", "general");
//   auto accum = e.get_machine()->get_free("base");
//   e.get_machine()->grab_register(accum);
//   auto lb_accum = e.get_sub_lbyte(e.get_sub_word(accum));
//   auto original_pointer = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(original_pointer);
//   auto copy_pointer = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(copy_pointer);
//   auto counter = e.get_machine()->get_free("common");
//   e.get_machine()->grab_register(counter);

//   e.f("abs", original_pointer, (*get_ld())->get_real_image_begin());
//   e.f("abs", copy_pointer, eg::base_eg::shd("data"));
//   e.f("mov_rd_vd", counter, eg::base_eg::szd("data"));
//   e.jump("restore_condition");

//   e.allocate_element("restore_condition", "general");
//   e.f("test_rd_rd", counter, counter);
//   e.branch("jz", "restore_end", "restore_loop");

//   e.allocate_element("restore_loop", "general");
//   e.f("mov_rb_mb", lb_accum, copy_pointer);
//   e.f("mov_mb_rb", original_pointer, lb_accum);
//   e.f("inc_rd", copy_pointer);
//   e.f("inc_rd", original_pointer);
//   e.f("dec_rd", counter);
//   e.jump("restore_condition");

//   e.allocate_element("restore_end", "general");
//   e.jump("import");

//   e.get_machine()->free_register(accum);
//   e.get_machine()->free_register(original_pointer);
//   e.get_machine()->free_register(copy_pointer);
//   e.get_machine()->free_register(counter);
// }

std::uint32_t pe32_i686::build_code(std::vector<std::uint8_t> *stub,
                                    std::vector<std::uint8_t> *data) {
  e.set_base(get_ld()->get_begin_of_stub());
  e.init_state();

  e.start_frame("general");
  e.copy_fundamental();

  e.start_segment("begin");
  e.bsp("ebp_", eg::i8086::ebp);
  e.f("push_rd", e.g("ebp_"));
  e.bsp("esp_", eg::i8086::esp);
  e.f("mov_rd_rd", e.g("ebp_"), e.g("esp_"));
  e.f("sub_rd_vd", e.g("esp_"), e.frszd());
  e.fr("esp_");
  e.f("push_vd", std::uint64_t(0x30));
  e.bf("shift", "common");
  e.f("pop_rd", e.g("shift"));
  e.bsp("fs_", eg::i8086::fs);
  e.f("mov_rd_serd", e.g("shift"), e.g("fs_"), e.g("shift"));
  e.fr("fs_");
  e.f("mov_rd_smd", e.g("shift"), e.g("shift"), "+", std::uint64_t(0x8));
  e.f("mov_smd_rd", e.g("ebp_"), "-", e.vshd("base"), e.g("shift"));
  e.fr("shift");
  e.bf("accum", "common");
  e.f("mov_rd_smd", e.g("accum"), e.g("ebp_"), "-", e.vshd("base"));
  e.f("add_rd_vd", e.g("accum"), e.shd("tmp"));
  e.f("mov_smd_rd", e.g("ebp_"), "-", e.vshd("target"), e.g("accum"));
  e.f("mov_smb_vb", e.g("ebp_"), "-", e.vshd("crc_switch"), std::uint64_t(0));
  e.f("mov_smd_vd", e.g("ebp_"), "-", e.vshd("count"), e.fszd("tmp"));
  e.f("invoke", e.shd("crc"));
  e.f("mov_rd_smd", e.g("accum"), e.g("ebp_"), "-", e.vshd("result"));
  e.f("cmp_rd_vd", e.g("accum"), e.c32d("tmp", {}));
  e.fr("accum");
  e.fr("ebp_");

  std::vector<uint8_t> tmp = {0,1,2,3,4,5};

  e.end();

  e.add_data("tmp", &tmp);

  e.end();

  // e.get_chain("general")->add_var("hash", 4);
  // e.get_chain("general")->add_var("dll_base", 4);
  // e.get_chain("general")->add_var("current_dll", 4);
  // e.get_chain("general")->add_var("func", 4);
  // e.get_chain("general")->add_var("message_box_switch", 1);

  // e.get_chain("general")->add_var("LoadLibrary", 4);
  // e.get_chain("general")->add_var("GetModuleHandle", 4);
  // e.get_chain("general")->add_var("GetProcAddr", 4);
  // e.get_chain("general")->add_var("ExitProcess", 4);
  // e.get_chain("general")->add_var("MessageBox", 4);

  // end_init_code();
  // search_expx_init_code();
  // get_apix_init_code();
  // build_import_stub();
  // find_library_init_code();
  // load_function_init_code();
  // error_exit_init_code();
  // restore_image_init_code();
  // auto glob = e.allocate_global("data");
  // glob->update_data(data);

  // e.allocate_element("begin", "general");
  // e.t("popad");
  // e.f("push_rd", eg::i8086::ebp);
  // e.f("mov_rd_rd", eg::i8086::ebp, eg::i8086::esp);
  // e.f("sub_rd_vd", eg::i8086::esp, eg::base_eg::vsszd());
  // auto ir = e.get_machine()->get_rand("common");
  // e.get_machine()->grab_register(ir);
  // e.f("push_vd", std::uint64_t(0x30));
  // e.f("pop_rd", ir);
  // e.f("mov_rd_ssdrsh", ir, eg::i8086::fs, ir);
  // e.f("mov_rd_mdsh", ir, ir, "+", std::uint64_t(0x8));
  // e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("base"), ir);
  // e.get_machine()->free_register(ir);

  // e.f("mov_mdsh_vd", eg::i8086::ebp, "-", eg::base_eg::vshd("hash"),
  //     std::uint64_t(get_LoadLibrary_hash()));
  // e.invoke("get_apix");

  // auto ll = e.get_machine()->get_free("common");
  // e.get_machine()->grab_register(ll);
  // e.f("mov_rd_mdsh", ll, eg::i8086::ebp, "-", eg::base_eg::vshd("func"));
  // e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("LoadLibrary"),
  // ll); e.get_machine()->free_register(ll);

  // e.f("mov_mdsh_vd", eg::i8086::ebp, "-", eg::base_eg::vshd("hash"),
  //     std::uint64_t(get_GetProcAddress_hash()));
  // e.invoke("get_apix");

  // ll = e.get_machine()->get_free("common");
  // e.get_machine()->grab_register(ll);
  // e.f("mov_rd_mdsh", ll, eg::i8086::ebp, "-", eg::base_eg::vshd("func"));
  // e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("GetProcAddr"),
  // ll); e.get_machine()->free_register(ll);

  // e.f("mov_mdsh_vd", eg::i8086::ebp, "-", eg::base_eg::vshd("hash"),
  //     std::uint64_t(get_GetModuleHandle_hash()));
  // e.invoke("get_apix");

  // ll = e.get_machine()->get_free("common");
  // e.get_machine()->grab_register(ll);
  // e.f("mov_rd_mdsh", ll, eg::i8086::ebp, "-", eg::base_eg::vshd("func"));
  // e.f("mov_mdsh_rd", eg::i8086::ebp, "-",
  // eg::base_eg::vshd("GetModuleHandle"),
  //     ll);
  // e.get_machine()->free_register(ll);

  // e.f("mov_mdsh_vd", eg::i8086::ebp, "-", eg::base_eg::vshd("hash"),
  //     std::uint64_t(get_ExitProcess_hash()));
  // e.invoke("get_apix");

  // ll = e.get_machine()->get_free("common");
  // e.get_machine()->grab_register(ll);
  // e.f("mov_rd_mdsh", ll, eg::i8086::ebp, "-", eg::base_eg::vshd("func"));
  // e.f("mov_mdsh_rd", eg::i8086::ebp, "-", eg::base_eg::vshd("ExitProcess"),
  // ll); e.get_machine()->free_register(ll);

  // e.jump("restore_image");

  // e.align();
  // e.get_data(stub);

  //printf("%s\n", e.to_string().c_str());

  e.build(stub);

  //printf("%s\n", e.to_string().c_str());

  return static_cast<std::uint32_t>(e.get_entry_point());
}

void pe32_i686::make() {
  file->open();
  std::vector<uint8_t> data = get_ld()->get_protected_data();
  std::vector<uint8_t> stub;
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
} // namespace mk