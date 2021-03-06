// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <cry/crypto.h>
#include <eg/i8086/i686/i686.h>

#define PROGRAMMER(code)                    \
  register_programmer(                      \
      [this, iv](global::flag_container fl, \
                 std::map<std::string, part *> *vars) { code })
#define VALIDATOR(code) \
  register_validator([this](std::vector<part *> *vars) -> bool { code })
#define BALANCER(code) \
  register_balancer([this](std::map<std::string, part *> *vars) { code })
#define EG this
#define VARS (*vars)

#define CAST static_cast<global::flag_container>(*iv)

#define GROUP_ALL                              \
  type_flags::stack_safe type_flags::flag_safe \
      type_flags::fundomental_undepended type_flags::debug_unprotected

namespace eg::i8086 {

i686::i686() : i8086() {
  set_value("nop", std::uint8_t(0x90));
  set_value("bitness", std::uint32_t(32));
  set_value("short_branch_limit",
            branch_limit{.forward = 0x81, .reverse = 0x79, .stub = 0x79});

  set_registers(
      {eax, ecx, edx, ebx, esp, ebp, esi, edi, cs, ss, ds, es, fs, gs});
  add_group("all",
            {eax, ecx, edx, ebx, esp, ebp, esi, edi, cs, ss, ds, es, fs, gs});
  add_group("use", {eax, ecx, edx, ebx, esp, ebp, esi, edi});
  add_group("segment", {cs, ss, ds, es, fs, gs});
  add_group("common", {eax, ecx, edx, ebx, esi, edi});
  add_group("unsafe", {eax, ecx, edx, ebx, esi, edi, ebp});
  add_group("base", {eax, ecx, edx, ebx});
  add_sub_registers(eax, {{"w", ax}, {"lb", al}, {"hb", ah}});
  add_sub_registers(ecx, {{"w", cx}, {"lb", cl}, {"hb", ch}});
  add_sub_registers(edx, {{"w", dx}, {"lb", dl}, {"hb", dh}});
  add_sub_registers(ebx, {{"w", bx}, {"lb", bl}, {"hb", bh}});
  add_sub_registers(esp, {{"w", sp}});
  add_sub_registers(ebp, {{"w", bp}});
  add_sub_registers(esi, {{"w", si}});
  add_sub_registers(esi, {{"w", di}});

  ivg = {{"st", type_flags::memory_static},
         {"ss", type_flags::stack_safe},
         {"fs", type_flags::flag_safe},
         {"up", type_flags::debug_unprotected},
         {"fu", type_flags::fundomental_undepended},
         {"rc", type_flags::invariant_recursive},
         {"sh", type_flags::shift_depeneded}};

  init_assemblers();
  init_invariants();
  set_recursion_counter(5);
  get_build_node()->select_node();
}
i686::~i686() {}

int __lib_asm_cb(RLibPlugin *pl, void *user, void *data) {
  RAsmPlugin *hand = (RAsmPlugin *)data;

  for (auto c_asm : node_cast<build_root>(global_root)->assemblers)
    r_asm_add(c_asm.second, hand);
  return true;
}

int __lib_asm_dt(RLibPlugin *pl, void *p, void *u) { return true; }

void i686::init_assemblers() {
  const char *path;

  assemblers["default"] = r_asm_new();
  assemblers["olly"] = r_asm_new();

  r_lib = r_lib_new("radare_plugin");

  r_lib_add_handler(r_lib, R_LIB_TYPE_ASM, "(dis)assembly plugins",
                    &__lib_asm_cb, &__lib_asm_dt, NULL);

  path = r_sys_getenv(R_LIB_ENV);
  if (path && *path) r_lib_opendir(r_lib, path);

  char *homeplugindir = r_str_home(R2_HOME_PLUGINS);
  r_lib_opendir(r_lib, homeplugindir);
  DEFER(free(homeplugindir););
  char *plugindir = r_str_r2_prefix(R2_PLUGINS);
  char *extrasdir = r_str_r2_prefix(R2_EXTRAS);
  char *bindingsdir = r_str_r2_prefix(R2_BINDINGS);
  r_lib_opendir(r_lib, plugindir);
  r_lib_opendir(r_lib, extrasdir);
  r_lib_opendir(r_lib, bindingsdir);
  DEFER(free(plugindir););
  DEFER(free(extrasdir););
  DEFER(free(bindingsdir););

  if (!r_asm_use(assemblers["default"], "x86"))
    throw std::domain_error("Invalid assembler name: x86");
  if (!r_asm_set_bits(assemblers["default"],
                      get_value<std::uint32_t>("bitness")))
    throw std::domain_error("Invalid bintess");

  if (!r_asm_use(assemblers["olly"], "x86.olly"))
    throw std::domain_error("Invalid assembler name: x86.olly");
  if (!r_asm_set_bits(assemblers["olly"], get_value<std::uint32_t>("bitness")))
    throw std::domain_error("Invalid bintess");
}

void i686::init_state() {
  start_frame("fundamental");
  add_var("base", 4);
  add_var("temporary", 4);
  add_var("crc_switch", 1);
  add_var("count", 4);
  add_var("target", 4);
  add_var("result", 4);
  add_var("byte_key", 1);
  add_var("dword_key", 4);
  add_var("key_addr", 4);
  add_var("value", 4);
  add_var("round_number", 1);
  add_var("sub_byte", 1);
  add_var("bus_byte", 1);

  start_segment("clear_end");
  f("ret");
  end();
  init_crc();
  init_aes();
  init_uncompress();
  init_clear();
  init_becb();
  init_decb();
  init_gambling();
  end();
}

void i686::init_crc() {
  start_segment("crc");
  bf("target", "common");
  bsp("ebp_", ebp);
  f("load_rd", g("target"), vshd("target"));
  bf("result", "base");
  bf("accum", "base");
  f("clear_rd", g("result"));
  f("clear_rd", g("accum"));
  f("test_smb_vb", g("ebp_"), std::string("-"), vshd("crc_switch"),
    std::uint64_t(1));
  f("branch", "nz", shd("crc_loop"), shd("crc_set_size"));
  end();

  start_segment("crc_set_size");
  bf("size", "common");
  f("mov_rd_smd", g("size"), g("ebp_"), std::string("-"), vshd("count"));
  f("inc_rd", g("size"));
  f("jump", shd("crc_test_size"));
  end();

  start_segment("crc_test_size");
  f("dec_rd", g("size"));
  f("test_rd_rd", g("size"), g("size"));
  f("branch", "z", shd("crc_end"), shd("crc_loop"));
  end();

  start_segment("crc_loop");
  f("mov_rb_mb", g("accum", "lb"), g("target"));
  f("inc_rd", g("target"));
  f("or_rb_vb", g("accum", "lb"), std::uint64_t(0x20));
  f("xor_rb_rb", g("result", "lb"), g("accum", "lb"));
  f("push_vd", std::uint64_t(8));
  bf("counter", "common");
  f("pop_rd", g("counter"));
  f("jump", shd("crc_shift"));
  end();

  start_segment("crc_shift");
  f(gg({"fs"}), "shr_rd_vb", g("result"), std::uint64_t(1));
  f("branch", "nc", shd("crc_test_counter"), shd("crc_xor"));
  end();

  start_segment("crc_xor");
  f("xor_rd_vd", g("result"), std::uint64_t(0x82F63B78));
  f("jump", shd("crc_test_counter"));
  end();

  start_segment("crc_test_counter");
  f("dec_rd", g("counter"));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("crc_shift"), shd("crc_choose"));
  end();

  start_segment("crc_choose");
  f("test_smb_vb", g("ebp_"), std::string("-"), vshd("crc_switch"),
    std::uint64_t(1));
  f("branch", "z", shd("crc_test_size"), shd("crc_test_zero"));
  end();

  start_segment("crc_test_zero");
  f(gg({"fs"}), "sub_rb_vb", g("accum", "lb"), std::uint64_t(0x20));
  f("branch", "nz", shd("crc_loop"), shd("crc_end"));
  end();

  start_segment("crc_end");
  fr("target");
  fr("counter");
  fr("accum");
  fr("size");
  f("store_rd", vshd("result"), g("result"));
  fr("result");
  fr("ebp_");
  f("ret");
  end();
}

void i686::init_clear() {
  start_segment("clear_memory");
  bf("target", "common");
  f("load_rd", g("target"), vshd("value"));
  bf("counter", "common");
  f("load_rd", g("counter"), vshd("count"));
  f("jump", shd("clear_memory_test"));
  end();

  start_segment("clear_memory_test");
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "z", shd("clear_end"), shd("clear_memory_loop"));
  end();

  start_segment("clear_memory_loop");
  f("mov_mb_vb", g("target"), std::uint64_t(0));
  f("inc_rb", g("target"));
  f("dec_rb", g("counter"));
  f("jump", shd("clear_memory_test"));
  fr("target");
  fr("counter");
  end();
}

void i686::init_aes() {
  std::vector<uint8_t> bytes_inv_s_box = {
      const_inv_s_box, const_inv_s_box + sizeof(const_inv_s_box)};
  std::vector<uint8_t> bytes_s_box = {const_sbox,
                                      const_sbox + sizeof(const_sbox)};
  std::vector<uint8_t> bytes_rcon;
  std::vector<uint32_t> table_rcon = {
      const_rcon, const_rcon + sizeof(const_rcon) / sizeof(const_rcon[0])};
  global::table_to_byte_array(&bytes_rcon, &table_rcon);
  add_data("inv_s_box", &bytes_inv_s_box);
  add_data("s_box", &bytes_s_box);
  add_data("rcon", &bytes_rcon);
  add_data("aes_state", 16);
  add_data("aes_key_space", 240);

  // aes decrypt begin
  start_segment("aes_decrypt");
  bf("counter", "common");
  bf("text", "common");
  f("load_rd", g("counter"), vshd("count"));
  f("load_rd", g("text"), vshd("target"));
  push_registers({g("counter"), g("text")});
  f("invoke", shd("aes_expand_key"));
  pop_registers({g("counter"), g("text")});
  bf("size", "common");
  f("mov_rd_rd", g("size"), g("counter"));
  f("store_rd", vshd("value"), g("text"));
  f("store_rd", vshd("count"), g("counter"));
  push_registers({g("counter"), g("text"), g("size")});
  f("invoke", shd("aes_reverse_bytes"));
  pop_registers({g("counter"), g("text"), g("size")});
  f("jump", shd("aes_decrypt_test"));
  end();

  start_segment("aes_decrypt_test");
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "z", shd("aes_decrypt_end"), shd("aes_decrypt_loop"));
  end();

  start_segment("aes_decrypt_loop");
  bf("ast", "common");
  f("abs_r", g("ast"), shd("aes_state"));
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("text"));
  f("mov_md_rd", g("ast"), g("accum"));
  f("mov_rd_smd", g("accum"), g("text"), std::string("+"), std::uint64_t(4));
  f("mov_smd_rd", g("ast"), std::string("+"), std::uint64_t(4), g("accum"));
  f("mov_rd_smd", g("accum"), g("text"), std::string("+"), std::uint64_t(8));
  f("mov_smd_rd", g("ast"), std::string("+"), std::uint64_t(8), g("accum"));
  f("mov_rd_smd", g("accum"), g("text"), std::string("+"), std::uint64_t(12));
  f("mov_smd_rd", g("ast"), std::string("+"), std::uint64_t(12), g("accum"));
  fr("ast");
  fr("accum");
  push_registers({g("counter"), g("text"), g("size")});
  f("invoke", shd("aes_decrypt_block"));
  pop_registers({g("counter"), g("text"), g("size")});
  bf("ast", "common");
  f("abs_r", g("ast"), shd("aes_state"));
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("ast"));
  f("mov_md_rd", g("text"), g("accum"));
  f("mov_rd_smd", g("accum"), g("ast"), std::string("+"), std::uint64_t(4));
  f("mov_smd_rd", g("text"), std::string("+"), std::uint64_t(4), g("accum"));
  f("mov_rd_smd", g("accum"), g("ast"), std::string("+"), std::uint64_t(8));
  f("mov_smd_rd", g("text"), std::string("+"), std::uint64_t(8), g("accum"));
  f("mov_rd_smd", g("accum"), g("ast"), std::string("+"), std::uint64_t(12));
  f("mov_smd_rd", g("text"), std::string("+"), std::uint64_t(12), g("accum"));
  fr("accum");
  fr("ast");
  f("sub_rd_vd", g("counter"), std::uint64_t(16));
  f("add_rd_vd", g("text"), std::uint64_t(16));
  f("jump", shd("aes_decrypt_test"));
  end();

  start_segment("aes_decrypt_end");
  f("sub_rd_rd", g("text"), g("size"));
  f("store_rd", vshd("value"), g("text"));
  f("store_rd", vshd("count"), g("size"));
  fr("size");
  fr("counter");
  fr("text");
  f("invoke", shd("aes_reverse_bytes"));
  f("jump", shd("clear_end"));
  end();
  // aes decrypt end

  // aes rot_word begin
  start_segment("aes_rot_word");
  bf("accum", "base");
  bf("tmp", "base");
  f("load_rd", g("accum"), vshd("value"));
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("shl_rd_vb", g("accum"), std::uint64_t(8));
  f("shr_rd_vb", g("tmp"), std::uint64_t(24));
  f("mov_rb_rb", g("accum", "lb"), g("tmp", "lb"));
  fr("tmp");
  f("store_rd", vshd("value"), g("accum"));
  fr("accum");
  f("jump", shd("clear_end"));
  end();
  // aes rot_word end

  // aes rconx begin
  start_segment("aes_rconx");
  bf("accum", "base");
  f("clear_rd", g("accum"));
  f("load_rb", g("accum", "lb"), vshd("bus_byte"));
  f("shl_rd_vb", g("accum"), std::uint64_t(2));
  bf("pointer", "common");
  f("abs_r", g("pointer"), shd("rcon"));
  f("add_rd_rd", g("pointer"), g("accum"));
  fr("accum");
  bf("accum", "common");
  f("load_rd", g("accum"), vshd("value"));
  f("xor_rd_md", g("accum"), g("pointer"));
  fr("pointer");
  f("store_rd", vshd("value"), g("accum"));
  fr("accum");
  f("jump", shd("clear_end"));
  end();
  // aes rconx end

  // aes expand_key begin
  start_segment("aes_expand_key");
  bf("tmp", "common");
  f("abs_r", g("tmp"), shd("aes_key_space"));
  f("store_rd", vshd("value"), g("tmp"));
  f("mov_rd_vd", g("tmp"), fszd("aes_key_space"));
  f("store_rd", vshd("count"), g("tmp"));
  f("invoke", shd("clear_memory"));
  fr("tmp");
  bf("key_ptr", "common");
  f("load_rd", g("key_ptr"), vshd("key_addr"));
  bf("key_space", "common");
  f("abs_r", g("key_space"), shd("aes_key_space"));
  bf("counter", "common");
  f("mov_rd_vd", g("counter"), std::uint64_t(8));
  f("jump", shd("aes_expand_key_copy_loop"));
  end();

  start_segment("aes_expand_key_copy_loop");
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("key_ptr"));
  f("mov_md_rd", g("key_space"), g("accum"));
  fr("accum");
  f("add_rd_vd", g("key_ptr"), std::uint64_t(4));
  f("add_rd_vd", g("key_space"), std::uint64_t(4));
  f("dec_rd", g("counter"));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("aes_expand_key_copy_loop"),
    shd("aes_expand_key_begin"));
  fr("counter");
  fr("key_ptr");
  end();

  start_segment("aes_expand_key_begin");
  f("sub_rd_vd", g("key_space"), std::uint64_t(32));
  f("store_rd", vshd("value"), g("key_space"));
  f("mov_rd_vd", g("key_space"), fszd("aes_key_space"));
  f("store_rd", vshd("count"), g("key_space"));
  f("invoke", shd("aes_reverse_bytes"));
  fr("key_space");
  bf("bg_ptr", "common");
  bf("cr_ptr", "common");
  f("abs_r", g("bg_ptr"), shd("aes_key_space"));
  f("mov_rd_rd", g("cr_ptr"), g("bg_ptr"));
  f("add_rd_vd", g("cr_ptr"), std::uint64_t(28));
  bf("counter", "base");
  f("mov_rd_vd", g("counter"), std::uint64_t(8));
  bsp("ebp_", ebp);
  f("mov_smb_vb", g("ebp_"), std::string("-"), vshd("bus_byte"),
    std::uint64_t(0));
  fr("ebp_");
  f("jump", shd("aes_expand_key_expand"));
  end();

  start_segment("aes_expand_key_expand");
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("cr_ptr"));
  f("store_rd", vshd("value"), g("accum"));
  fr("accum");
  f("test_rd_vd", g("counter"), std::uint64_t(7));
  f("branch", "nz", shd("aes_expand_key_next"), shd("aes_expand_key_expand_2"));
  end();

  start_segment("aes_expand_key_expand_2");
  push_registers({g("counter"), g("bg_ptr"), g("cr_ptr")});
  f("invoke", shd("aes_rot_word"));
  f("invoke", shd("aes_sub_word"));
  f("invoke", shd("aes_rconx"));
  pop_registers({g("counter"), g("bg_ptr"), g("cr_ptr")});
  bsp("ebp_", ebp);
  f("add_smb_vb", g("ebp_"), std::string("-"), vshd("bus_byte"),
    std::uint64_t(1));
  fr("ebp_");
  f("jump", shd("aes_expand_key_next"));
  end();

  start_segment("aes_expand_key_next");
  bf("tmp", "base");
  f("mov_rd_rd", g("tmp"), g("counter"));
  f("sub_rd_vd", g("tmp"), std::uint64_t(4));
  f("test_rb_vb", g("tmp", "lb"), std::uint64_t(7));
  fr("tmp");
  f("branch", "nz", shd("aes_expand_key_xor"), shd("aes_expand_key_next_2"));
  end();

  start_segment("aes_expand_key_next_2");
  push_registers({g("counter"), g("bg_ptr"), g("cr_ptr")});
  f("invoke", shd("aes_sub_word"));
  pop_registers({g("counter"), g("bg_ptr"), g("cr_ptr")});
  f("jump", shd("aes_expand_key_xor"));
  end();

  start_segment("aes_expand_key_xor");
  f("add_rd_vd", g("cr_ptr"), std::uint64_t(4));
  bf("accum", "common");
  f("load_rd", g("accum"), vshd("value"));
  f("mov_md_rd", g("cr_ptr"), g("accum"));
  bf("tmp", "common");
  f("mov_rd_rd", g("tmp"), g("counter"));
  f("sub_rd_vd", g("tmp"), std::uint64_t(8));
  f("shl_rd_vb", g("tmp"), std::uint64_t(2));
  f("add_rd_rd", g("bg_ptr"), g("tmp"));
  f("mov_rd_md", g("accum"), g("bg_ptr"));
  f("sub_rd_rd", g("bg_ptr"), g("tmp"));
  fr("tmp");
  f("xor_md_rd", g("cr_ptr"), g("accum"));
  fr("accum");
  f("inc_rd", g("counter"));
  f("cmp_rd_vd", g("counter"), std::uint64_t(60));
  f("branch", "l", shd("aes_expand_key_expand"), shd("clear_end"));
  fr("counter");
  fr("bg_ptr");
  fr("cr_ptr");
  end();
  // aes expand_key end

  // aes sub word begin
  start_segment("aes_sub_word");
  bf("accum", "base");
  f("load_rd", g("accum"), vshd("value"));
  bf("tmp", "base");
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("store_rb", vshd("sub_byte"), g("tmp", "lb"));
  push_registers({g("accum"), g("tmp")});
  f("invoke", shd("aes_substitute_byte"));
  pop_registers({g("accum"), g("tmp")});
  f("load_rb", g("tmp", "lb"), vshd("sub_byte"));
  f("mov_rb_rb", g("accum", "lb"), g("tmp", "lb"));
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("shr_rd_vb", g("tmp"), std::uint64_t(8));
  f("store_rb", vshd("sub_byte"), g("tmp", "lb"));
  push_registers({g("accum"), g("tmp")});
  f("invoke", shd("aes_substitute_byte"));
  pop_registers({g("accum"), g("tmp")});
  f("load_rb", g("tmp", "lb"), vshd("sub_byte"));
  f("mov_rb_rb", g("accum", "hb"), g("tmp", "lb"));
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("shr_rd_vb", g("tmp"), std::uint64_t(16));
  f("store_rb", vshd("sub_byte"), g("tmp", "lb"));
  push_registers({g("accum"), g("tmp")});
  f("invoke", shd("aes_substitute_byte"));
  pop_registers({g("accum"), g("tmp")});
  f("load_rb", g("tmp", "lb"), vshd("sub_byte"));
  f("shl_rd_vb", g("tmp"), std::uint64_t(16));
  f("and_rd_vd", g("tmp"), std::uint64_t(0x00FF0000));
  f("and_rd_vd", g("accum"), std::uint64_t(0xFF00FFFF));
  f("or_rd_rd", g("accum"), g("tmp"));
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("shr_rd_vb", g("tmp"), std::uint64_t(24));
  f("store_rb", vshd("sub_byte"), g("tmp", "lb"));
  push_registers({g("accum"), g("tmp")});
  f("invoke", shd("aes_substitute_byte"));
  pop_registers({g("accum"), g("tmp")});
  f("load_rb", g("tmp", "lb"), vshd("sub_byte"));
  f("shl_rd_vb", g("tmp"), std::uint64_t(24));
  f("and_rd_vd", g("tmp"), std::uint64_t(0xFF000000));
  f("and_rd_vd", g("accum"), std::uint64_t(0x00FFFFFF));
  f("or_rd_rd", g("accum"), g("tmp"));
  fr("tmp");
  f("store_rd", vshd("value"), g("accum"));
  fr("accum");
  f("jump", shd("clear_end"));
  end();
  // aes sub word end

  // aes reverse_bytes begin
  start_segment("aes_reverse_bytes");
  bf("accum", "common");
  f("load_rd", g("accum"), vshd("value"));
  bf("counter", "common");
  f("load_rd", g("counter"), vshd("count"));
  bf("tmp", "common");
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("jump", shd("aes_reverse_bytes_loop"));
  end();

  start_segment("aes_reverse_bytes_loop");
  f("mov_rd_md", g("accum"), g("tmp"));
  f("bswap_rd", g("accum"));
  f("mov_md_rd", g("tmp"), g("accum"));
  f("add_rd_vd", g("tmp"), std::uint64_t(4));
  f("sub_rd_vd", g("counter"), std::uint64_t(4));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "z", shd("clear_end"), shd("aes_reverse_bytes_loop"));
  fr("counter");
  fr("accum");
  fr("tmp");
  end();
  // aes reverse_bytes end

  // aes decrypt_block begin
  start_segment("aes_decrypt_block");
  bf("round", "base");
  f("mov_rb_vb", g("round", "lb"), std::uint64_t(14));
  f("store_rb", vshd("round_number"), g("round", "lb"));
  push_registers({g("round")});
  f("invoke", shd("aes_add_round_key"));
  pop_registers({g("round")});
  f("dec_rb", g("round", "lb"));
  f("jump", shd("aes_decrypt_block_loop"));
  end();

  start_segment("aes_decrypt_block_loop");
  push_registers({g("round")});
  f("invoke", shd("aes_inv_shift_rows"));
  pop_registers({g("round")});
  push_registers({g("round")});
  f("invoke", shd("aes_inv_sub_bytes"));
  pop_registers({g("round")});
  f("store_rb", vshd("round_number"), g("round", "lb"));
  push_registers({g("round")});
  f("invoke", shd("aes_add_round_key"));
  pop_registers({g("round")});
  push_registers({g("round")});
  f("invoke", shd("aes_inv_mix_columns"));
  pop_registers({g("round")});
  f("dec_rb", g("round", "lb"));
  f("cmp_rb_vb", g("round", "lb"), std::uint64_t(1));
  f("branch", "ge", shd("aes_decrypt_block_loop"),
    shd("aes_decrypt_block_end"));
  end();

  start_segment("aes_decrypt_block_end");
  f("store_rb", vshd("round_number"), g("round", "lb"));
  push_registers({g("round")});
  f("invoke", shd("aes_inv_shift_rows"));
  pop_registers({g("round")});
  push_registers({g("round")});
  f("invoke", shd("aes_inv_sub_bytes"));
  pop_registers({g("round")});
  push_registers({g("round")});
  f("invoke", shd("aes_add_round_key"));
  pop_registers({g("round")});
  f("jump", shd("clear_end"));
  fr("round");
  end();
  // aes decrypt_block end

  // aes add_round_key begin
  start_segment("aes_add_round_key");
  bf("key_space", "common");
  f("abs_r", g("key_space"), shd("aes_key_space"));
  bf("rn", "base");
  f("clear_rd", g("rn"));
  f("load_rb", g("rn", "lb"), vshd("round_number"));
  f("shl_rd_vb", g("rn"), std::uint64_t(4));
  f("add_rd_rd", g("key_space"), g("rn"));
  fr("rn");
  bf("ast", "common");
  f("abs_r", g("ast"), shd("aes_state"));
  bf("counter", "common");
  f("push_vd", std::uint64_t(4));
  f("pop_rd", g("counter"));
  f("jump", shd("aes_add_round_key_add"));
  end();

  start_segment("aes_add_round_key_add");
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("key_space"));
  f("xor_md_rd", g("ast"), g("accum"));
  f("add_rd_vd", g("key_space"), std::uint64_t(4));
  f("add_rd_vd", g("ast"), std::uint64_t(4));
  f("dec_rd", g("counter"));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("aes_add_round_key_add"), shd("clear_end"));
  fr("accum");
  fr("counter");
  fr("ast");
  fr("key_space");
  end();
  // aes add_round_key end

  // aes inv_shift_rows begin
  start_segment("aes_inv_shift_rows");
  bf("ast", "common");
  f("abs_r", g("ast"), shd("aes_state"));
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "hb"), g("ast"), std::string("+"),
    std::uint64_t(14));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(10));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(14),
    g("accum", "lb"));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(6));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(10),
    g("accum", "lb"));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(2));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(6),
    g("accum", "lb"));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(2),
    g("accum", "hb"));
  f("mov_rb_smb", g("accum", "hb"), g("ast"), std::string("+"),
    std::uint64_t(1));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(5));
  f("shl_rd_vb", g("accum"), std::uint64_t(16));
  f("mov_rb_smb", g("accum", "hb"), g("ast"), std::string("+"),
    std::uint64_t(9));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(13));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(1),
    g("accum", "hb"));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(5),
    g("accum", "lb"));
  f("shr_rd_vb", g("accum"), std::uint64_t(16));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(9),
    g("accum", "hb"));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(13),
    g("accum", "lb"));
  f("mov_rb_smb", g("accum", "hb"), g("ast"), std::string("+"),
    std::uint64_t(0));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(4));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(0),
    g("accum", "lb"));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(8));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(4),
    g("accum", "lb"));
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(12));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(8),
    g("accum", "lb"));
  f("mov_smb_rb", g("ast"), std::string("+"), std::uint64_t(12),
    g("accum", "hb"));
  f("ret");
  fr("ast");
  fr("accum");
  end();
  // aes inv_shift_rows end

  // aes inv_sub_bytes begin
  start_segment("aes_inv_sub_bytes");
  bf("ast", "common");
  f("abs_r", g("ast"), shd("aes_state"));
  bf("counter", "common");
  f("mov_rd_vd", g("counter"), std::uint64_t(16));
  f("jump", shd("aes_inv_sub_bytes_sub"));
  end();

  start_segment("aes_inv_sub_bytes_sub");
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("ast"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("counter"), g("ast")});
  f("invoke", shd("aes_inv_substitute_byte"));
  pop_registers({g("counter"), g("ast")});
  bf("accum", "base");
  f("load_rb", g("accum", "lb"), vshd("sub_byte"));
  f("mov_mb_rb", g("ast"), g("accum", "lb"));
  fr("accum");
  f("inc_rd", g("ast"));
  f("dec_rd", g("counter"));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("aes_inv_sub_bytes_sub"), shd("clear_end"));
  fr("ast");
  fr("counter");
  end();
  // aes inv_sub_bytes end

  // aes substitute_byte begin
  start_segment("aes_substitute_byte");
  bf("s_box", "common");
  f("abs_r", g("s_box"), shd("s_box"));
  bf("accum", "base");
  f("clear_rd", g("accum"));
  f("load_rb", g("accum", "lb"), vshd("sub_byte"));
  f("and_rd_vd", g("accum"), std::uint64_t(0xff));
  f("add_rd_rd", g("s_box"), g("accum"));
  f("mov_rb_mb", g("accum", "lb"), g("s_box"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  fr("s_box");
  f("jump", shd("clear_end"));
  end();
  // aes substitute_byte end

  // aes inv_substitute_byte begin
  start_segment("aes_inv_substitute_byte");
  bf("s_box", "common");
  f("abs_r", g("s_box"), shd("inv_s_box"));
  bf("accum", "base");
  f("clear_rd", g("accum"));
  f("load_rb", g("accum", "lb"), vshd("sub_byte"));
  f("and_rd_vd", g("accum"), std::uint64_t(0xff));
  f("add_rd_rd", g("s_box"), g("accum"));
  f("mov_rb_mb", g("accum", "lb"), g("s_box"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  fr("s_box");
  f("jump", shd("clear_end"));
  end();
  // aes inv_substitute_byte end

  // aes inv_mix_columns begin
  start_segment("aes_inv_mix_columns");
  bsp("esp_", esp);
  bsp("ebp_", ebp);
  f("sub_rd_vd", g("esp_"), std::uint64_t(16));
  bf("nast", "common");
  f("lea_rd_md", g("nast"), g("esp_"));
  bf("ast", "common");
  f("abs_r", g("ast"), shd("aes_state"));
  bf("counter", "common");
  f("mov_rd_vd", g("counter"), std::uint64_t(4));
  f("jump", shd("aes_inv_mix_columns_mix"));
  end();

  start_segment("aes_inv_mix_columns_mix");
  f("mov_smb_vb", g("ebp_"), std::string("-"), vshd("bus_byte"),
    std::uint64_t(0));
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("ast"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_09"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(1));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0d"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(2));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0b"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(3));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0e"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("tmp", "base");
  f("load_rb", g("tmp", "lb"), vshd("bus_byte"));
  f("mov_smb_rb", g("nast"), std::string("+"), std::uint64_t(3),
    g("tmp", "lb"));
  fr("tmp");
  f("mov_smb_vb", g("ebp_"), std::string("-"), vshd("bus_byte"),
    std::uint64_t(0));
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("ast"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0d"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(1));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0b"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(2));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0e"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(3));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_09"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("tmp", "base");
  f("load_rb", g("tmp", "lb"), vshd("bus_byte"));
  f("mov_smb_rb", g("nast"), std::string("+"), std::uint64_t(2),
    g("tmp", "lb"));
  fr("tmp");
  f("mov_smb_vb", g("ebp_"), std::string("-"), vshd("bus_byte"),
    std::uint64_t(0));
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("ast"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0b"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(1));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0e"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(2));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_09"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(3));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0d"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("tmp", "base");
  f("load_rb", g("tmp", "lb"), vshd("bus_byte"));
  f("mov_smb_rb", g("nast"), std::string("+"), std::uint64_t(1),
    g("tmp", "lb"));
  fr("tmp");
  f("mov_smb_vb", g("ebp_"), std::string("-"), vshd("bus_byte"),
    std::uint64_t(0));
  fr("ebp_");
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("ast"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0e"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(1));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_09"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(2));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0d"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("accum", "base");
  f("mov_rb_smb", g("accum", "lb"), g("ast"), std::string("+"),
    std::uint64_t(3));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  push_registers({g("ast"), g("nast"), g("counter")});
  f("invoke", shd("aes_xtime_0b"));
  pop_registers({g("ast"), g("nast"), g("counter")});
  bf("tmp", "base");
  f("load_rb", g("tmp", "lb"), vshd("bus_byte"));
  f("mov_mb_rb", g("nast"), g("tmp", "lb"));
  fr("tmp");
  f("add_rd_vd", g("ast"), std::uint64_t(4));
  f("add_rd_vd", g("nast"), std::uint64_t(4));
  f("dec_rd", g("counter"));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("aes_inv_mix_columns_mix"),
    shd("aes_inv_mix_columns_excnahge"));
  fr("counter");
  end();

  start_segment("aes_inv_mix_columns_excnahge");
  f("sub_rd_vd", g("ast"), std::uint64_t(16));
  f("sub_rd_vd", g("nast"), std::uint64_t(16));
  bf("counter", "common");
  f("mov_rd_vd", g("counter"), std::uint64_t(4));
  f("jump", shd("aes_inv_mix_columns_copy"));
  end();

  start_segment("aes_inv_mix_columns_copy");
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("nast"));
  f("mov_md_rd", g("ast"), g("accum"));
  f("add_rd_vd", g("ast"), std::uint64_t(4));
  f("add_rd_vd", g("nast"), std::uint64_t(4));
  f("dec_rd", g("counter"));
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "z", shd("aes_inv_mix_columns_end"),
    shd("aes_inv_mix_columns_copy"));
  fr("accum");
  fr("nast");
  fr("ast");
  fr("counter");
  end();

  start_segment("aes_inv_mix_columns_end");
  f("add_rd_vd", g("esp_"), std::uint64_t(16));
  fr("esp_");
  f("jump", shd("clear_end"));
  end();
  // aes aes_inv_mix_columns end

  // aes xtime begin
  start_segment("aes_xtime");
  bf("accum", "base");
  f("clear_rd", g("accum"));
  f("load_rb", g("accum", "lb"), vshd("sub_byte"));
  f("jump", shd("aes_xtime_loop"));
  end();

  start_segment("aes_xtime_loop");
  f("shl_rw_vb", g("accum", "w"), std::uint64_t(0x1));
  f("test_rb_rb", g("accum", "hb"), g("accum", "hb"));
  f("branch", "z", shd("aes_xtime_end"), shd("aes_xtime_xor"));
  end();

  start_segment("aes_xtime_xor");
  f("xor_rb_vb", g("accum", "lb"), std::uint64_t(0x1b));
  f("jump", shd("aes_xtime_end"));
  end();

  start_segment("aes_xtime_end");
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  fr("accum");
  f("jump", shd("clear_end"));
  end();
  // aes xtime end

  // aes xor_func_begin
  start_segment("aes_xor_func");
  bf("accum", "base");
  f("load_rb", g("accum", "lb"), vshd("sub_byte"));
  f("load_rb", g("accum", "hb"), vshd("bus_byte"));
  f("xor_rb_rb", g("accum", "hb"), g("accum", "lb"));
  f("store_rb", vshd("sub_byte"), g("accum", "lb"));
  f("store_rb", vshd("bus_byte"), g("accum", "hb"));
  fr("accum");
  f("jump", shd("clear_end"));
  end();
  // aes xor_func_end

  // aes xtime_09 begin
  start_segment("aes_xtime_09");
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("jump", shd("clear_end"));
  end();
  // aes xtime_09 end

  // aes xtime_0b begin
  start_segment("aes_xtime_0b");
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("jump", shd("clear_end"));
  end();
  // aes xtime_0b end

  // aes xtime_0d begin
  start_segment("aes_xtime_0d");
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("jump", shd("clear_end"));
  end();
  // aes xtime_0d end

  // aes xtime_0e begin
  start_segment("aes_xtime_0e");
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("invoke", shd("aes_xtime"));
  f("invoke", shd("aes_xor_func"));
  f("jump", shd("clear_end"));
  end();
  // aes xtime_0e end
}
void i686::init_uncompress() {
  start_segment("uncompress");
  bf("in", "common");
  bf("out", "common");
  f("load_rd", g("in"), vshd("target"));
  f("load_rd", g("out"), vshd("value"));
  f("jump", shd("uncompress_l0"));
  end();

  start_segment("uncompress_l0");
  bf("accum", "base");
  f("clear_rd", g("accum"));
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("inc_rd", g("in"));
  f("cmp_rb_vb", g("accum", "lb"), std::uint64_t(31));
  f("branch", "a", shd("uncompress_lm2"), shd("uncompress_l0_0"));
  end();

  start_segment("uncompress_l0_0");
  f(gg({"fs"}), "or_rb_rb", g("accum", "lb"), g("accum", "lb"));
  bf("tmp", "base");
  f(gg({"fs"}), "mov_rd_rd", g("tmp"), g("accum"));
  f("branch", "nz", shd("uncompress_l2"), shd("uncompress_l0_1"));
  end();

  start_segment("uncompress_l0_1");
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("inc_rd", g("in"));
  f("or_rb_rb", g("accum", "lb"), g("accum", "lb"));
  f("branch", "nz", shd("uncompress_l0_3"), shd("uncompress_l0_2"));
  end();

  start_segment("uncompress_l0_2");
  f("add_rd_vd", g("tmp"), std::uint64_t(255));
  f("jump", shd("uncompress_l0_1"));
  end();

  start_segment("uncompress_l0_3");
  f("add_rd_rd", g("tmp"), g("accum"));
  f("add_rd_vd", g("tmp"), std::uint64_t(31));
  f("jump", shd("uncompress_l2"));
  end();

  start_segment("uncompress_l2");
  f("mov_rb_rb", g("accum", "lb"), g("tmp", "lb"));
  f("shr_rd_vb", g("tmp"), std::uint64_t(2));
  f("jump", shd("uncompress_l2_test"));
  end();

  start_segment("uncompress_l2_test");
  f("test_rd_rd", g("tmp"), g("tmp"));
  f("branch", "nz", shd("uncompress_l2_loop"), shd("uncompress_l2_0"));
  end();

  start_segment("uncompress_l2_loop");
  bf("dword", "common");
  f("mov_rd_md", g("dword"), g("in"));
  f("mov_md_rd", g("out"), g("dword"));
  fr("dword");
  f("add_rd_vd", g("in"), std::uint64_t(4));
  f("add_rd_vd", g("out"), std::uint64_t(4));
  f("dec_rd", g("tmp"));
  f("jump", shd("uncompress_l2_test"));
  end();

  start_segment("uncompress_l2_0");
  f(gg({"fs"}), "and_rb_vb", g("accum", "lb"), std::uint64_t(3));
  f("branch", "z", shd("uncompress_l2_2"), shd("uncompress_l2_1"));
  end();

  start_segment("uncompress_l2_1");
  bf("dword", "common");
  f("mov_rd_md", g("dword"), g("in"));
  f("add_rd_rd", g("in"), g("accum"));
  f("mov_md_rd", g("out"), g("dword"));
  fr("dword");
  f("add_rd_rd", g("out"), g("accum"));
  f("jump", shd("uncompress_l2_2"));
  end();

  start_segment("uncompress_l2_2");
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("inc_rd", g("in"));
  f("jump", shd("uncompress_lm1"));
  end();

  start_segment("uncompress_lm1");
  f("cmp_rb_vb", g("accum", "lb"), std::uint64_t(31));
  f("branch", "be", shd("uncompress_lm21"), shd("uncompress_lm2"));
  end();

  start_segment("uncompress_lm2");
  f("cmp_rb_vb", g("accum", "lb"), std::uint64_t(223));
  f("branch", "a", shd("uncompress_lm3"), shd("uncompress_lm2_0"));
  end();

  start_segment("uncompress_lm2_0");
  bf("data", "common");
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("shr_rd_vb", g("accum"), std::uint64_t(2));
  f("mov_rd_rd", g("data"), g("out"));
  f("dec_rd", g("data"));
  f("and_rb_vb", g("accum", "lb"), std::uint64_t(7));
  f("shr_rd_vb", g("tmp"), std::uint64_t(5));
  bf("dword", "common");
  f("mov_rd_rd", g("dword"), g("accum"));
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("push_rd", g("tmp"));
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("mov_rd_rd", g("accum"), g("dword"));
  fr("dword");
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("tmp"));
  f("pop_rd", g("tmp"));
  f("inc_rd", g("in"));
  f("jump", shd("uncompress_lm5"));
  end();

  start_segment("uncompress_lm5");
  f("sub_rd_rd", g("data"), g("accum"));
  f("add_rd_vd", g("tmp"), std::uint64_t(2));
  f("xchg_rd_rd", g("in"), g("data"));
  f("cmp_rd_vd", g("tmp"), std::uint64_t(6));
  f("branch", "b", shd("uncompress_lm5_2"), shd("uncompress_lm5_0"));
  end();

  start_segment("uncompress_lm5_0");
  f("cmp_rd_vd", g("accum"), std::uint64_t(4));
  f("branch", "b", shd("uncompress_lm5_2"), shd("uncompress_lm5_1"));
  end();

  start_segment("uncompress_lm5_1");
  f("mov_rb_rb", g("accum", "lb"), g("tmp", "lb"));
  f("shr_rd_vb", g("tmp"), std::uint64_t(2));
  f("jump", shd("uncompress_lm5_test"));
  end();

  start_segment("uncompress_lm5_test");
  f("test_rd_rd", g("tmp"), g("tmp"));
  f("branch", "nz", shd("uncompress_lm5_loop"), shd("uncompress_lm5_loop_end"));
  end();

  start_segment("uncompress_lm5_loop");
  bf("dword", "common");
  f("mov_rd_md", g("dword"), g("in"));
  f("mov_md_rd", g("out"), g("dword"));
  fr("dword");
  f("add_rd_vd", g("in"), std::uint64_t(4));
  f("add_rd_vd", g("out"), std::uint64_t(4));
  f("dec_rd", g("tmp"));
  f("jump", shd("uncompress_lm5_test"));
  end();

  start_segment("uncompress_lm5_loop_end");
  f("and_rb_vb", g("accum", "lb"), std::uint64_t(3));
  f("mov_rb_rb", g("tmp", "lb"), g("accum", "lb"));
  f("jump", shd("uncompress_lm5_2"));
  end();

  start_segment("uncompress_lm5_2");
  f("push_rd", g("accum"));
  f("jump", shd("uncompress_lm5_btest"));
  end();

  start_segment("uncompress_lm5_btest");
  f("test_rd_rd", g("tmp"), g("tmp"));
  f("branch", "nz", shd("uncompress_lm5_bloop"),
    shd("uncompress_lm5_bloop_end"));
  end();

  start_segment("uncompress_lm5_bloop");
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("mov_mb_rb", g("out"), g("accum", "lb"));
  f("inc_rd", g("in"));
  f("inc_rd", g("out"));
  f("dec_rd", g("tmp"));
  f("jump", shd("uncompress_lm5_btest"));
  end();

  start_segment("uncompress_lm5_bloop_end");
  f("pop_rd", g("accum"));
  f("mov_rd_rd", g("in"), g("data"));
  f("jump", shd("uncompress_ln1"));
  end();

  start_segment("uncompress_ln1");
  f("mov_rb_smb", g("tmp", "lb"), g("in"), std::string("-"), std::uint64_t(2));
  f(gg({"fs"}), "and_rd_vd", g("tmp"), std::uint64_t(3));
  f("branch", "z", shd("uncompress_l0"), shd("uncompress_ln1_0"));
  end();

  start_segment("uncompress_ln1_0");
  f("mov_rd_md", g("accum"), g("in"));
  f("add_rd_rd", g("in"), g("tmp"));
  f("mov_md_rd", g("out"), g("accum"));
  f("add_rd_rd", g("out"), g("tmp"));
  f("clear_rd", g("accum"));
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("inc_rd", g("in"));
  f("jump", shd("uncompress_lm1"));
  end();

  start_segment("uncompress_lm21");
  f("shr_rd_vb", g("accum"), std::uint64_t(2));
  f("mov_rd_rd", g("data"), g("out"));
  f("sub_rd_vd", g("data"), std::uint64_t(0x801));
  f("mov_rd_rd", g("tmp"), g("accum"));
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("inc_rd", g("in"));
  bf("dword", "common");
  f("mov_rd_rd", g("dword"), g("accum"));
  f("mov_rd_rd", g("accum"), g("tmp"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  f("add_rd_rd", g("accum"), g("dword"));
  fr("dword");
  f("sub_rd_rd", g("data"), g("accum"));
  f("mov_rd_md", g("accum"), g("data"));
  f("mov_md_rd", g("out"), g("accum"));
  f("add_rd_vd", g("out"), std::uint64_t(3));
  f("jump", shd("uncompress_ln1"));
  end();

  start_segment("uncompress_lm21_0");
  f("mov_rb_mb", g("accum", "lb"), g("in"));
  f("inc_rd", g("in"));
  f("or_rb_rb", g("accum", "lb"), g("accum", "lb"));
  f("branch", "nz", shd("uncompress_lm21_2"), shd("uncompress_lm21_1"));
  end();

  start_segment("uncompress_lm21_1");
  f("add_rd_vd", g("tmp"), std::uint64_t(255));
  f("jump", shd("uncompress_lm21_0"));
  end();

  start_segment("uncompress_lm21_2");
  f("add_rd_rd", g("tmp"), g("accum"));
  f("add_rd_vd", g("tmp"), std::uint64_t(31));
  f("jump", shd("uncompress_lm4"));
  end();

  start_segment("uncompress_lm3");
  f(gg({"fs"}), "and_rb_vb", g("accum", "lb"), std::uint64_t(31));
  f(gg({"fs"}), "mov_rd_rd", g("tmp"), g("accum"));
  f("branch", "z", shd("uncompress_lm21_0"), shd("uncompress_lm4"));
  end();

  start_segment("uncompress_lm4");
  f("mov_rd_rd", g("data"), g("out"));
  f("mov_rw_mw", g("accum", "w"), g("in"));
  f("add_rd_vd", g("in"), std::uint64_t(2));
  f(gg({"fs"}), "shr_rd_vb", g("accum"), std::uint64_t(2));
  f("branch", "nz", shd("uncompress_lm5"), shd("clear_end"));
  fr("in");
  fr("out");
  fr("accum");
  fr("tmp");
  fr("data");
  end();
}

void i686::init_becb() {
  start_segment("alter_b");
  bf("target", "common");
  f("load_rd", g("target"), vshd("target"));
  bf("key", "base");
  f("load_rb", g("key", "lb"), vshd("byte_key"));
  bf("counter", "common");
  f("load_rd", g("counter"), vshd("count"));
  f("jump", shd("alter_b_test"));
  end();

  start_segment("alter_b_test");
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("alter_b_loop"), shd("clear_end"));
  end();

  start_segment("alter_b_loop");
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("target"));
  f("xor_rb_rb", g("accum", "lb"), g("key", "lb"));
  f("mov_mb_rb", g("target"), g("accum", "lb"));
  fr("accum");
  f("dec_rd", g("counter"));
  f("inc_rd", g("target"));
  f("jump", shd("alter_b_test"));
  fr("target");
  fr("key");
  fr("counter");
  end();
}
void i686::init_decb() {
  start_segment("alter_d");
  bf("target", "common");
  f("load_rd", g("target"), vshd("target"));
  bf("key", "common");
  f("load_rd", g("key"), vshd("dword_key"));
  bf("counter", "common");
  f("load_rd", g("counter"), vshd("count"));
  f("jump", shd("alter_d_test"));
  end();

  start_segment("alter_d_test");
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("alter_d_loop"), shd("clear_end"));
  end();

  start_segment("alter_d_loop");
  bf("accum", "common");
  f("mov_rd_md", g("accum"), g("target"));
  f("xor_rd_rd", g("accum"), g("key"));
  f("mov_md_rd", g("target"), g("accum"));
  fr("accum");
  f("add_rd_vd", g("target"), std::uint64_t(4));
  f("sub_rd_vd", g("counter"), std::uint64_t(4));
  f("jump", shd("alter_d_test"));
  fr("target");
  fr("key");
  fr("counter");
  end();
}
void i686::init_gambling() {
  start_segment("gambling");
  bf("target", "common");
  f("load_rd", g("target"), vshd("target"));
  bf("key", "common");
  f("load_rd", g("key"), vshd("key_addr"));
  bf("counter", "common");
  f("load_rd", g("counter"), vshd("count"));
  f("jump", shd("gambling_test"));
  end();

  start_segment("gambling_test");
  f("test_rd_rd", g("counter"), g("counter"));
  f("branch", "nz", shd("gambling_loop"), shd("clear_end"));
  end();

  start_segment("gambling_loop");
  bf("accum", "base");
  f("mov_rb_mb", g("accum", "lb"), g("target"));
  f("mov_rb_mb", g("accum", "hb"), g("key"));
  f("xor_rb_rb", g("accum", "lb"), g("accum", "hb"));
  f("mov_mb_rb", g("target"), g("accum", "lb"));
  fr("accum");
  f("dec_rd", g("counter"));
  f("inc_rd", g("target"));
  f("inc_rd", g("key"));
  f("jump", shd("gambling_test"));
  fr("target");
  fr("key");
  fr("counter");
  end();
}

void i686::copy_fundamental() {
  copy_var("base", "fundamental");
  copy_var("temporary", "fundamental");
  copy_var("crc_switch", "fundamental");
  copy_var("count", "fundamental");
  copy_var("target", "fundamental");
  copy_var("result", "fundamental");
  copy_var("byte_key", "fundamental");
  copy_var("dword_key", "fundamental");
  copy_var("key_addr", "fundamental");
  copy_var("value", "fundamental");
  copy_var("round_number", "fundamental");
  copy_var("sub_byte", "fundamental");
  copy_var("bus_byte", "fundamental");
}

void i686::push_registers(std::initializer_list<std::string> registers) {
  for (auto r : registers) f("push_rd", r);
}

void i686::pop_registers(std::initializer_list<std::string> registers) {
  std::vector<std::string> reflection;
  for (auto r : registers) reflection.push_back(r);
  std::reverse(reflection.begin(), reflection.end());
  for (auto r : reflection) f("pop_rd", r);
}

global::flag_container i686::gg(
    std::initializer_list<std::string> current_flags) {
  global::flag_container current;
  for (auto cf : current_flags) current.set_flag(ivg[cf]);
  return current;
}

void i686::init_invariants() {
  form *cf = reinterpret_cast<eg::form *>(0);
  invariant *iv = reinterpret_cast<eg::invariant *>(0);

  // nop begin

  cf = make_form("nop");
  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "nop"););

  // nop end

  // load begin

  // load_rd begin
  cf = make_form("load_rd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rd_smd", VARS["r"], EG->g(ebp_),
                       std::string("-"), VARS["a"]);
                 EG->fr(ebp_););
  // load_rd end

  // load_rb begin
  cf = make_form("load_rb");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rb_smb", VARS["r"], EG->g(ebp_),
                       std::string("-"), VARS["a"]);
                 EG->fr(ebp_););
  // load_rb end

  // load end

  // store begin

  // store_abs
  cf = make_form("store_abs");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->add_register("r", "common");
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "abs_r", VARS["r"], VARS["a2"]);
                 EG->f(fl, "mov_smd_rd", EG->g(ebp_), std::string("-"),
                       VARS["a1"], VARS["r"]);
                 EG->fr(ebp_););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 auto reg_ = global::cs.generate_unique_string("pr_regs");
                 auto fctx = global::cs.generate_unique_number("fctx");
                 EG->bs(reg_, "common", fctx);
                 EG->f(fl, "push_rd", EG->g(reg_)); EG->bss(ebp_, ebp, fctx);
                 EG->f(fl, "abs_r", EG->g(reg_), VARS["a2"]);
                 EG->f(fl, "mov_smd_rd", EG->g(ebp_), std::string("-"),
                       VARS["a1"], EG->g(reg_));
                 EG->f(fl, "pop_rd", EG->g(reg_)); EG->fr(reg_); EG->fr(ebp_););
  // store_abs

  // store_rd begin
  cf = make_form("store_rd");
  cf->add_argument("a", 32);
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_smd_rd", EG->g(ebp_), std::string("-"),
                       VARS["a"], VARS["r"]);
                 EG->fr(ebp_););
  // store_rd end

  // store_rb begin
  cf = make_form("store_rb");
  cf->add_argument("a", 32);
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_smb_rb", EG->g(ebp_), std::string("-"),
                       VARS["a"], VARS["r"]);
                 EG->fr(ebp_););
  // store_rb end

  // store_vd begin
  cf = make_form("store_vd");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_smd_vd", EG->g(ebp_), std::string("-"),
                       VARS["a1"], VARS["a2"]);
                 EG->fr(ebp_););
  // store_vd end

  // store_vb begin
  cf = make_form("store_vb");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_smb_vb", EG->g(ebp_), std::string("-"),
                       VARS["a1"], VARS["a2"]);
                 EG->fr(ebp_););
  // store_vb end

  // store end

  // jumper begin
  cf = make_form("jumper");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "up", "fu"}));
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "add_rd_vd", EG->g(esp_), std::uint64_t(4));
                 EG->f(fl, "ret"); EG->fr(esp_););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->add_register("r", "common");
  iv->PROGRAMMER(EG->f(fl, "pop_rd", VARS["r"]); EG->f(fl, "ret"););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->add_register("r", "common");
  iv->PROGRAMMER(EG->f(fl, "pop_rd", VARS["r"]); EG->f(fl, "pop_rd", VARS["r"]);
                 EG->f(fl, "jmp_rd", VARS["r"]););
  // jumper end

  // branch begin
  cf = make_form("branch");
  cf->add_argument("f");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu"}));
  iv->PROGRAMMER(auto seg1 = global::cs.generate_unique_string("usegment");
                 auto seg2 = global::cs.generate_unique_string("usegment");
                 EG->f(fl, "jxx_vd", VARS["f"], EG->shd(seg2));
                 EG->f(fl, "jump", EG->shd(seg1)); EG->start_top_segment(seg1);
                 EG->f(fl, "jump", VARS["a2"]); EG->end();
                 EG->start_top_segment(seg2); EG->f(fl, "jump", VARS["a1"]);
                 EG->end(););
  // branch end

  // invoke begin
  cf = make_form("invoke");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(auto seg1 = global::cs.generate_unique_string("usegment");
                 EG->f(fl, "abs_r", VARS["r"], EG->shd(seg1));
                 EG->f(fl, "push_rd", VARS["r"]); EG->f(fl, "jump", VARS["a"]);
                 EG->end(); EG->start_segment(seg1););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(
      auto seg1 = global::cs.generate_unique_string("usegment");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto esp_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->bss(esp_, esp, fctx); EG->bs(reg_, "common", fctx);
      EG->f(fl, "push_rd", EG->g(reg_)); EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "abs_r", EG->g(reg_), EG->shd(seg1));
      auto new_fl = fl;
      new_fl.set_flag(type_flags::stack_safe);
      EG->f(new_fl, "add_rd_vd", EG->g(esp_), std::uint64_t(8));
      EG->f(new_fl, "push_rd", EG->g(reg_));
      EG->f(new_fl, "sub_rd_vd", EG->g(esp_), std::uint64_t(4)); EG->fr(esp_);
      EG->f(fl, "pop_rd", EG->g(reg_));
      EG->fr(reg_); 
      EG->f(fl, "jump", VARS["a"]); 
      EG->end();
      EG->start_segment(seg1););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "call_vd", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
                 EG->f(fl, "call_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
      EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
      auto new_fl = fl;
      new_fl.set_flag(type_flags::fundomental_undepended);
      EG->f(new_fl, "store_rd", EG->vshd("temporary"), VARS["r"]); 
      EG->f(new_fl, "call_smd", EG->g(ebp_), std::string("-"), EG->vshd("temporary"));
      EG->fr(ebp_); 
      );

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->bs(reg_, "common", fctx); EG->f(fl, "push_rd", EG->g(reg_));
      EG->bss(ebp_, ebp, fctx); EG->f(fl, "abs_r", EG->g(reg_), VARS["a"]);
      
      auto new_fl = fl;
      new_fl.set_flag(type_flags::fundomental_undepended);
      EG->f(new_fl, "store_rd", EG->vshd("temporary"), EG->g(reg_));
      EG->f(new_fl, "pop_rd", EG->g(reg_)); EG->fr(reg_); 
      EG->f(new_fl, "call_smd", EG->g(ebp_), std::string("-"), EG->vshd("temporary"));
      EG->fr(ebp_);
      );
  // invoke end

  // jump begin
  cf = make_form("jump");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(
      auto seg1 = global::cs.generate_unique_string("usegment");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto esp_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->start_top_segment(seg1); EG->f(fl, "jumper"); EG->end();
      EG->bss(esp_, esp, fctx); EG->bs(reg_, "common", fctx);
      EG->f(fl, "push_rd", EG->g(reg_)); EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "abs_r", EG->g(reg_), VARS["a"]);
      auto new_fl = fl;
      new_fl.set_flag(type_flags::stack_safe);
      EG->f(new_fl, "add_rd_vd", EG->g(esp_), std::uint64_t(8));
      EG->f(new_fl, "push_rd", EG->g(reg_));
      EG->f(new_fl, "sub_rd_vd", EG->g(esp_), std::uint64_t(4)); 
      EG->f(fl, "pop_rd", EG->g(reg_));
      EG->fr(esp_); EG->fr(reg_); EG->f(fl, "invoke", EG->shd(seg1)););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(auto seg1 = global::cs.generate_unique_string("usegment");
                 EG->start_top_segment(seg1); EG->f(fl, "jumper"); EG->end();
                 EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
                 EG->f(fl, "push_rd", VARS["r"]);
                 EG->f(fl, "invoke", EG->shd(seg1)););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
                 EG->f(fl, "jmp_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "jmp_vd", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
                 EG->f(fl, "jmp_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
                 EG->f(fl, "push_rd", VARS["r"]); EG->f(fl, "ret"););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc", "fu"}));
  iv->PROGRAMMER(
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto esp_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->bs(reg_, "common", fctx); EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "push_rd", EG->g(reg_)); EG->bss(esp_, esp, fctx);
      EG->f(fl, "abs_r", EG->g(reg_), VARS["a"]);
      auto new_fl = fl;
      new_fl.set_flag(type_flags::stack_safe);
      EG->f(new_fl, "add_rd_vd", EG->g(esp_), std::uint64_t(8));
      EG->f(new_fl, "push_rd", EG->g(reg_));
      EG->f(new_fl, "sub_rd_vd", EG->g(esp_), std::uint64_t(4));
      EG->fr(esp_);
      EG->f(fl, "pop_rd", EG->g(reg_)); EG->fr(reg_); EG->f(fl, "ret"););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
      EG->f(fl, "abs_r", VARS["r"], VARS["a"]);
      auto new_fl = fl;
      new_fl.set_flag(type_flags::fundomental_undepended);
      EG->f(new_fl, "store_rd", EG->vshd("temporary"), VARS["r"]); 
      EG->f(new_fl, "jmp_smd", EG->g(ebp_), std::string("-"), EG->vshd("temporary"));
      EG->fr(ebp_); 
      );

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->bs(reg_, "common", fctx); EG->f(fl, "push_rd", EG->g(reg_));
      EG->bss(ebp_, ebp, fctx); EG->f(fl, "abs_r", EG->g(reg_), VARS["a"]);
      auto new_fl = fl;
      new_fl.set_flag(type_flags::fundomental_undepended);
      EG->f(new_fl, "store_rd", EG->vshd("temporary"), EG->g(reg_));
      EG->f(new_fl, "pop_rd", EG->g(reg_)); EG->fr(reg_); 
      EG->f(new_fl, "jmp_smd", EG->g(ebp_), std::string("-"), EG->vshd("temporary"));
      EG->fr(ebp_);
      );
  // jump end

  // abs begin

  // abs_r begin
  cf = make_form("abs_r");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu"}));
  iv->PROGRAMMER(auto seg1 = global::cs.generate_unique_string("usegment");
                 auto new_fl = CAST; new_fl.set_flag(type_flags::ignore_shift);
                 EG->t(new_fl, "call $+5"); start_segment(seg1);
                 EG->f(fl, "pop_rd", VARS["r"]); end();
                 EG->f(fl, "sub_rd_vd", VARS["r"], EG->shd(seg1));
                 EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rd_smd", VARS["r"], EG->g(ebp_),
                       std::string("-"), EG->vshd("base"));
                 EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]); EG->fr(ebp_););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(fl, "add_rd_smd", VARS["r"], EG->g(ebp_),
                       std::string("-"), EG->vshd("base"));
                 EG->fr(ebp_););
  // abs_r end

  // abs end

  // not begin
  // not_rd begin
  cf = make_form("not_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "not ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "xor_rd_vd", VARS["r"], std::uint64_t(0xFFFFFFFF)););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r"]);
                 EG->f(fl, "mov_rd_vd", VARS["r"], std::uint64_t(0xFFFFFFFF));
                 EG->f(fl, "sub_rd_rd", VARS["r"], VARS["rt"]););
  // not_rd end
  // not end

  // clear begin

  // clear_rd begin
  cf = make_form("clear_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "xor_rd_rd", VARS["r"], VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r"], std::uint64_t(0)););

  iv = make_invariant(cf);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"st", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["r1"], VARS["r"]);
                 EG->f(fl, "not_rd", VARS["r1"]);
                 EG->f(fl, "and_rd_rd", VARS["r"], VARS["r1"]););
  // clear_rd end

  // clear end

  // pusha begin
  // pushad begin
  cf = make_form("pushad");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "pushad"););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu", "rc"}));
  iv->PROGRAMMER(
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->group_save("unsafe", fctx); EG->free_group("unsafe");
      EG->grab_group("unsafe"); EG->f("push_rd", std::string(eax));
      EG->f("push_rd", std::string(ecx)); EG->f("push_rd", std::string(edx));
      EG->f("push_rd", std::string(ebx)); EG->f("push_rd", std::string(eax));
      EG->f("push_rd", std::string(ebp)); EG->f("push_rd", std::string(esi));
      EG->f("push_rd", std::string(edi)); EG->group_load("unsafe", fctx););
  // pushad end
  // pusha end

  // push begin

  // push_rd begin
  cf = make_form("push_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "push ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[0]) == esp) return false;
      return true;);
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "sub_rd_vd", g(esp_), std::uint64_t(4));
                 EG->f(fl, "mov_md_rd", g(esp_), VARS["r"]); EG->fr(esp_););
  // push_rd end

  // push_fd begin
  cf = make_form("push_fd");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "pushfd"););
  // push_fd end

  // push_vd begin
  cf = make_form("push_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "push ", VARS["a"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "sub_rd_vd", g(esp_), std::uint64_t(4));
                 EG->f(fl, "mov_md_vd", g(esp_), VARS["a"]); EG->fr(esp_););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(fl, "push_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "up", "fu", "rc"}));
  iv->PROGRAMMER(
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto esp_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->bs(reg_, "common", fctx); EG->bss(esp_, esp, fctx);
      EG->f(fl, "push_rd", EG->g(reg_)); EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "mov_rd_vd", EG->g(reg_), VARS["a"]);
      auto new_fl = fl;
      new_fl.set_flag(type_flags::stack_safe);
      EG->f(new_fl, "add_rd_vd", EG->g(esp_), std::uint64_t(8));
      EG->f(new_fl, "push_rd", EG->g(reg_));
      EG->f(new_fl, "sub_rd_vd", EG->g(esp_), std::uint64_t(4));
      EG->f(fl, "pop_rd", EG->g(reg_));
      EG->fr(reg_); EG->fr(esp_););
  // push_vd end

  // push_serd begin
  cf = make_form("push_serd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "push DWORD [", VARS["r1"], ":", VARS["r2"], "]"););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[1]) == esp) return false;
      return true;);
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "sub_rd_vd", g(esp_), std::uint64_t(4));
                 EG->f(fl, "mov_rd_serd", VARS["rt"], VARS["r1"], VARS["r2"]);
                 EG->f(fl, "mov_md_rd", g(esp_), VARS["rt"]); EG->fr(esp_););
  // push_serd end

  // push_md begin
  cf = make_form("push_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "push DWORD [", VARS["r"], "]"););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[0]) == esp) return false;
      return true;);
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "sub_rd_vd", g(esp_), std::uint64_t(4));
                 EG->f(fl, "mov_rd_md", VARS["rt"], VARS["r"]);
                 EG->f(fl, "mov_md_rd", g(esp_), VARS["rt"]); EG->fr(esp_););
  // push_md end

  // push end

  // popa begin
  // popad begin
  cf = make_form("popad");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "popa"););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu", "rc"}));
  iv->PROGRAMMER(
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->group_save("unsafe", fctx); EG->free_group("unsafe");
      EG->grab_group("unsafe"); EG->f("pop_rd", std::string(edi));
      EG->f("pop_rd", std::string(esi)); EG->f("pop_rd", std::string(ebp));
      EG->f("add_rd_vd", std::string(esp), std::uint64_t(4));
      EG->f("pop_rd", std::string(ebx)); EG->f("pop_rd", std::string(edx));
      EG->f("pop_rd", std::string(ecx)); EG->f("pop_rd", std::string(eax));
      EG->group_load("unsafe", fctx););
  // popad end
  // popa end

  // pop begin

  // pop_rd begin
  cf = make_form("pop_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "pop ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[0]) == esp) return false;
      return true;);
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rd_md", VARS["r"], g(esp_));
                 EG->f(fl, "add_rd_vd", g(esp_), std::uint64_t(4));
                 EG->fr(esp_););
  // pop_rd end

  // pop_fd begin
  cf = make_form("pop_fd");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "popfd"););
  // pop_fd end

  // pop_serd begin
  cf = make_form("pop_serd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "pop DWORD [", VARS["r1"], ":", VARS["r2"], "]"););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[1]) == esp) return false;
      return true;);
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rd_md", VARS["rt"], g(esp_));
                 EG->f(fl, "add_rd_vd", g(esp_), std::uint64_t(4));
                 EG->fr(esp_);
                 EG->f(fl, "mov_serd_rd", VARS["r1"], VARS["r2"], VARS["rt"]););
  // pop_serd end

  // pop_md begin
  cf = make_form("pop_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "pop DWORD [", VARS["r"], "]"););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[0]) == esp) return false;
      return true;);
  iv->PROGRAMMER(auto esp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(esp_, esp, global::cs.generate_unique_number("fctx"));
                 EG->f(fl, "mov_rd_md", VARS["rt"], g(esp_));
                 EG->f(fl, "add_rd_vd", g(esp_), std::uint64_t(4));
                 EG->fr(esp_); EG->f(fl, "mov_md_rd", VARS["r"], VARS["rt"]););
  // pop_md end

  // pop end

  // int begin

  // int_vb begin
  cf = make_form("int_vb");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "int ", VARS["a"]););
  // int_vb end

  // int end

  // mov begin

  // mov_rd_rd begin
  cf = make_form("mov_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "clear_rd", VARS["r1"]);
                 EG->f(fl, "add_rd_rd", VARS["r1"], VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
                 EG->f(fl, "mov_rd_rd", VARS["r1"], VARS["rt"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[0]) == esp ||
          get_part_value<std::string>((*vars)[1]) == esp) return false;
      return true;);
  iv->PROGRAMMER(EG->f(fl, "push_rd", VARS["r2"]);
                 EG->f(fl, "pop_rd", VARS["r1"]););
  // mov_rd_rd end

  // mov_rd_vd begin
  cf = make_form("mov_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "clear_rd", VARS["r"]);
                 EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if (get_part_value<std::string>((*vars)[0]) == esp) return false;
      return true;);
  iv->PROGRAMMER(EG->f(fl, "push_vd", VARS["a"]);
                 EG->f(fl, "pop_rd", VARS["r"]););
  // mov_rd_vd end

  // mov_rd_md begin
  cf = make_form("mov_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(EG->f(fl, "clear_rd", VARS["r1"]);
                 EG->f(fl, "add_rd_md", VARS["r1"], VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu", "rc"}));
  // iv->VALIDATOR(
  //     if (get_part_value<std::string>((*vars)[1]) == esp) return false;
  //     return true;);
  iv->PROGRAMMER(EG->f(fl, "push_md", VARS["r2"]);
                 EG->f(fl, "pop_rd", VARS["r1"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "mov ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // mov_rd_md end

  // mov_rw_mw begin
  cf = make_form("mov_rw_mw");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ", WORD [", VARS["r2"], "]"););
  // mov_rw_mw end

  // mov_rd_smd begin
  cf = make_form("mov_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(
      EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(fl, "add_rd_vd", VARS["rt"], VARS["a"]);
      else EG->f(fl, "sub_rd_vd", VARS["rt"], VARS["a"]);
      EG->f(fl, "mov_rd_md", VARS["r1"], VARS["rt"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(
      auto new_fl = fl; if (get_part_value<std::string>(VARS["r2"]) == esp)
                            new_fl.set_flag(type_flags::stack_safe);
      if (get_part_value<std::string>(VARS["r2"]) == ebp)
          new_fl.set_flag(type_flags::fundomental_undepended);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(new_fl, "add_rd_vd", VARS["r2"], VARS["a"]);
      else EG->f(new_fl, "sub_rd_vd", VARS["r2"], VARS["a"]);
      EG->f(new_fl, "mov_rd_md", VARS["r1"], VARS["r2"]);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(new_fl, "sub_rd_vd", VARS["r2"], VARS["a"]);
      else EG->f(new_fl, "add_rd_vd", VARS["r2"], VARS["a"]););
  // mov_rd_smd end

  // mov_md_rd begin
  cf = make_form("mov_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "mov DWORD [", VARS["r1"], "],", VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_md_vd", VARS["r1"], std::uint64_t(0));
                 EG->f(fl, "add_md_rd", VARS["r1"], VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu", "rc"}));
  // iv->VALIDATOR(
  //     if (get_part_value<std::string>((*vars)[0]) == esp) return false;
  //     return true;);
  iv->PROGRAMMER(EG->f(fl, "push_rd", VARS["r2"]);
                 EG->f(fl, "pop_md", VARS["r1"]););
  // mov_md_rd end

  // mov_mw_rw begin
  cf = make_form("mov_mw_rw");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov WORD [", VARS["r1"], "],", VARS["r2"]););
  // mov_mw_rw end

  // mov_smd_rd begin
  cf = make_form("mov_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(
      EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r1"]);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(fl, "add_rd_vd", VARS["rt"], VARS["a"]);
      else EG->f(fl, "sub_rd_vd", VARS["rt"], VARS["a"]);
      EG->f(fl, "mov_md_rd", VARS["rt"], VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(
      auto new_fl = fl; if (get_part_value<std::string>(VARS["r1"]) == esp)
                            new_fl.set_flag(type_flags::stack_safe);
      if (get_part_value<std::string>(VARS["r1"]) == ebp)
          new_fl.set_flag(type_flags::fundomental_undepended);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(new_fl, "add_rd_vd", VARS["r1"], VARS["a"]);
      else EG->f(new_fl, "sub_rd_vd", VARS["r1"], VARS["a"]);
      EG->f(new_fl, "mov_md_rd", VARS["r1"], VARS["r2"]);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(new_fl, "sub_rd_vd", VARS["r1"], VARS["a"]);
      else EG->f(new_fl, "add_rd_vd", VARS["r1"], VARS["a"]););
  // mov_smd_rd end

  // mov_md_vd begin
  cf = make_form("mov_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "mov DWORD [", VARS["r"], "],", VARS["a"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "push_vd", VARS["a"]);
                 EG->f(fl, "pop_md", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_md_vd", VARS["r"], std::uint64_t(0));
                 EG->f(fl, "add_md_vd", VARS["r"], VARS["a"]););
  // mov_md_vd end

  // mov_smd_vd begin
  cf = make_form("mov_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(
      EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r"]);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(fl, "add_rd_vd", VARS["rt"], VARS["a1"]);
      else EG->f(fl, "sub_rd_vd", VARS["rt"], VARS["a1"]);
      EG->f(fl, "mov_md_vd", VARS["rt"], VARS["a2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(
      auto new_fl = fl; if (get_part_value<std::string>(VARS["r"]) == esp)
                            new_fl.set_flag(type_flags::stack_safe);
      if (get_part_value<std::string>(VARS["r"]) == ebp)
          new_fl.set_flag(type_flags::fundomental_undepended);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(new_fl, "add_rd_vd", VARS["r"], VARS["a1"]);
      else EG->f(new_fl, "sub_rd_vd", VARS["r"], VARS["a1"]);
      EG->f(new_fl, "mov_md_vd", VARS["r"], VARS["a2"]);
      if (get_part_value<std::string>(VARS["sign"]) == std::string("+"))
          EG->f(new_fl, "sub_rd_vd", VARS["r"], VARS["a1"]);
      else EG->f(new_fl, "add_rd_vd", VARS["r"], VARS["a1"]););
  // mov_smd_vd end

  // mov_rd_serd begin
  cf = make_form("mov_rd_serd");
  cf->add_argument("r1");
  cf->add_argument("sr");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "mov ", VARS["r1"], ", DWORD [",
                        VARS["sr"], ":", VARS["r2"], "]"););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[2])) return false;
                return true;);
  iv->PROGRAMMER(EG->f(fl, "clear_rd", VARS["r1"]);
                 EG->f(fl, "add_rd_serd", VARS["r1"], VARS["sr"], VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu", "rc"}));
  // iv->VALIDATOR(
  //     if (get_part_value<std::string>((*vars)[1]) == esp) return false;
  //     return true;);
  iv->PROGRAMMER(EG->f(fl, "push_serd", VARS["sr"], VARS["r2"]);
                 EG->f(fl, "pop_rd", VARS["r1"]););
  // mov_rd_serd end

  // mov_serd_rd begin
  cf = make_form("mov_serd_rd");
  cf->add_argument("sr");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "mov DWORD [", VARS["sr"], ":",
                        VARS["r1"], "], ", VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(
      EG->f(fl, "mov_serd_vd", VARS["sr"], VARS["r1"], std::uint64_t(0));
      EG->f(fl, "add_serd_rd", VARS["sr"], VARS["r1"], VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "up", "fu", "rc"}));
  // iv->VALIDATOR(
  //     if (get_part_value<std::string>((*vars)[0]) == esp) return false;
  //     return true;);
  iv->PROGRAMMER(EG->f(fl, "push_rd", VARS["r2"]);
                 EG->f(fl, "pop_serd", VARS["sr"], VARS["r1"]););
  // mov_serd_rd end

  // mov_serd_vd begin
  cf = make_form("mov_serd_vd");
  cf->add_argument("sr");
  cf->add_argument("r1");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "mov DWORD [", VARS["sr"], ":",
                        VARS["r1"], "], ", VARS["a"]););
  // mov_serd_vd end

  // mov_rb_rb begin
  cf = make_form("mov_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ",", VARS["r2"]););
  // mov_rb_rb end

  // mov_rb_vb begin
  cf = make_form("mov_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r"], ",", VARS["a"]););
  // mov_rb_vb end

  // mov_rb_mb begin
  cf = make_form("mov_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // mov_rb_mb end

  // mov_rb_smb begin
  cf = make_form("mov_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // mov_rb_smb end

  // mov_mb_rb begin
  cf = make_form("mov_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov BYTE [", VARS["r1"], "],", VARS["r2"]););
  // mov_mb_rb end

  // mov_smb_rb begin
  cf = make_form("mov_smb_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // mov_smb_rb end

  // mov_mb_vb begin
  cf = make_form("mov_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov BYTE [", VARS["r"], "],", VARS["a"]););
  // mov_mb_vb end

  // mov_smb_vb begin
  cf = make_form("mov_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // mov_smb_vb end

  // mov end

  // movzx begin

  // movzx_rd_rb begin
  cf = make_form("movzx_rd_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "movzx ", VARS["r1"], ",", VARS["r2"]););
  // movzx_rd_rb end

  // movzx_rd_mw begin
  cf = make_form("movzx_rd_mw");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "movzx ", VARS["r1"], ", WORD [", VARS["r2"], "]"););
  // movzx_rd_mw end

  // movzx_rd_mb begin
  cf = make_form("movzx_rd_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "movzx ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // movzx_rd_mb end

  // movzx_rd_smb begin
  cf = make_form("movzx_rd_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "movzx ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // movzx_rd_smb end

  // movzx end

  // call begin

  // call_vd begin
  cf = make_form("call_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu", "sh"}));
  iv->PROGRAMMER(EG->t(CAST, "call ", VARS["a"]););
  // call_vd end

  // call_rd begin
  cf = make_form("call_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "call ", VARS["r"]););

  iv = make_invariant(cf);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"fu", "rc"}));
  iv->PROGRAMMER(
      auto seg1 = global::cs.generate_unique_string("usegment");
      auto esp_ = global::cs.generate_unique_string("pr_regs");
      auto fctx = global::cs.generate_unique_number("fctx");
      EG->bss(esp_, esp, fctx); auto new_fl = fl;
      new_fl.set_flag(type_flags::stack_safe); EG->f(fl, "push_rd", VARS["r"]);
      EG->f(fl, "push_rd", VARS["r"]);
      EG->f(fl, "abs_r", VARS["r1"], EG->shd(seg1));
      EG->f(new_fl, "add_rd_vd", EG->g(esp_), std::uint64_t(8));
      EG->f(new_fl, "push_rd", VARS["r1"]);
      EG->f(new_fl, "sub_rd_vd", EG->g(esp_), std::uint64_t(4)); EG->fr(esp_);
      EG->f(fl, "ret"); EG->end(); EG->start_segment(seg1););
  // call_rd end

  // call_md begin
  cf = make_form("call_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "call DWORD [", VARS["r"], "]"););
  // call_md end

  // call_smd begin
  cf = make_form("call_smd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "call DWORD [", VARS["r"], VARS["sign"], VARS["a"], "]"););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r"]);
                 if (get_part_value<std::string>(VARS["sign"]) == "+")
                     EG->f(fl, "add_rd_vd", VARS["rt"], VARS["a"]);
                 else EG->f(fl, "sub_rd_vd", VARS["rt"], VARS["a"]);
                 EG->f(fl, "call_md", VARS["rt"]););
  // call_smd end

  // call end

  // jmp begin

  // jmp_vd begin
  cf = make_form("jmp_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu", "sh"}));
  iv->PROGRAMMER(EG->t(CAST, "jmp ", VARS["a"]););
  // jmp_vd end

  // jmp_rd begin
  cf = make_form("jmp_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "jmp ", VARS["r"]););
  // jmp_rd end

  // jmp_md begin
  cf = make_form("jmp_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "jmp [", VARS["r"], "]"););
  // jmp_md end

  // jmp_smd begin
  cf = make_form("jmp_smd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "jmp [", VARS["r"], VARS["sign"], VARS["a"], "]"););
  // jmp_smd end

  // jmp end

  // jxx begin

  // jxx_vd end
  cf = make_form("jxx_vd");
  cf->add_argument("f");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu", "sh"}));
  iv->PROGRAMMER(EG->t(CAST, "j", VARS["f"], " ", VARS["a"]););
  // jxx_vd end

  // jxx end

  // ret begin
  cf = make_form("ret");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ret"););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->f("pop_rd", VARS["r"]); EG->f("jmp_rd", VARS["r"]););
  // ret end

  // ret_vw
  cf = make_form("ret_vw");
  cf->add_argument("a", 16);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ret ", VARS["a"]););
  // ret_vw end

  // bswap begin

  // bswap_rd begin

  cf = make_form("bswap_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "bswap ", VARS["r"]););
  // bswap_rd end

  // bswap end

  // add begin

  // add_rd_rd begin
  cf = make_form("add_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
                 EG->f(fl, "not_rd", VARS["rt"]);
                 EG->f(fl, "inc_rd", VARS["rt"]);
                 EG->f(fl, "sub_rd_rd", VARS["r1"], VARS["rt"]););
  // add_rd_rd end

  // add_rd_vd begin
  cf = make_form("add_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "add ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t tmp = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               tmp = ~tmp; tmp++;
               set_part_value(VARS["a1"], static_cast<uint64_t>(tmp)););
  iv->PROGRAMMER(EG->f(fl, "sub_rd_vd", VARS["r"], VARS["a1"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 32);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(
      uint32_t a =
          static_cast<uint32_t>(get_part_value<std::uint64_t>(VARS["a"]));
      uint32_t b = static_cast<uint32_t>(global::rc.generate_random_number());
      a = a + b; set_part_value(VARS["a1"], static_cast<uint64_t>(a));
      set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "add_rd_vd", VARS["r"], VARS["a1"]);
                 if (get_part_value<std::string>(VARS["r"]) == esp)
                     fl.set_flag(type_flags::stack_safe);
                 EG->f(fl, "sub_rd_vd", VARS["r"], VARS["a2"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 32);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(
      uint32_t a =
          static_cast<uint32_t>(get_part_value<std::uint64_t>(VARS["a"]));
      uint32_t b = static_cast<uint32_t>(global::rc.generate_random_number());
      a = a ^ b; set_part_value(VARS["a1"], static_cast<uint64_t>(a));
      set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r1"], VARS["a1"]);
                 EG->f(fl, "xor_rd_vd", VARS["r1"], VARS["a2"]);
                 EG->f(fl, "add_rd_rd", VARS["r"], VARS["r1"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 8);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t a = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               uint8_t b = static_cast<uint8_t>(
                   global::rc.generate_random_number() % 254 + 1);
               a = global::rotl32(a, b);
               set_part_value(VARS["a1"], static_cast<uint64_t>(a));
               set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r1"], VARS["a1"]);
                 EG->f(fl, "ror_rd_vb", VARS["r1"], VARS["a2"]);
                 EG->f(fl, "add_rd_rd", VARS["r"], VARS["r1"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 8);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t a = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               uint8_t b = static_cast<uint8_t>(
                   global::rc.generate_random_number() % 254 + 1);
               a = global::rotr32(a, b);
               set_part_value(VARS["a1"], static_cast<uint64_t>(a));
               set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r1"], VARS["a1"]);
                 EG->f(fl, "rol_rd_vb", VARS["r1"], VARS["a2"]);
                 EG->f(fl, "add_rd_rd", VARS["r"], VARS["r1"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->VALIDATOR(
      if ((*vars)[1]->check_flag(type_flags::dependence) ||
          (*vars)[1]->check_flag(type_flags::will_balanced)) return false;
      if (get_part_value<std::uint64_t>((*vars)[1]) > 50) return false;
      return true;);
  iv->PROGRAMMER(for (std::uint64_t i = 0;
                      i < get_part_value<std::uint64_t>(VARS["a"]); i++)
                     EG->f(fl, "inc_rd", VARS["r"]););
  // add_rd_vd end

  // add_rd_md begin
  cf = make_form("add_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "add ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // add_rd_md end

  // add_rd_smd begin
  cf = make_form("add_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "add ", VARS["r1"], ", DWORD [",
                        VARS["r2"], VARS["sign"], VARS["a"], "]"););
  // add_rd_smd end

  // add_rd_serd begin
  cf = make_form("add_rd_serd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("r3");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "add ", VARS["r1"], ", DWORD [",
                        VARS["r2"], ":", VARS["r3"], "]"););
  // add_rd_serd end

  // add_md_rd begin
  cf = make_form("add_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "add DWORD [", VARS["r1"], "],", VARS["r2"]););
  // add_md_rd end

  // add_smd_rd begin
  cf = make_form("add_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // add_smd_rd end

  // add_serd_rd begin
  cf = make_form("add_serd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("r3");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "add DWORD [", VARS["r1"], ":",
                        VARS["r2"], "],", VARS["r3"]););
  // add_serd_rd end

  // add_md_vd begin
  cf = make_form("add_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "add DWORD [", VARS["r"], "],", VARS["a"]););
  // add_md_vd end

  // add_smd_vd begin
  cf = make_form("add_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "add DWORD [", VARS["r"], VARS["sign"],
                        VARS["a1"], "],", VARS["a2"]););
  // add_smd_vd end

  // add_rb_rb begin
  cf = make_form("add_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r1"], ",", VARS["r2"]););
  // add_rb_rb end

  // add_rb_vb begin
  cf = make_form("add_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r"], ",", VARS["a"]););
  // add_rb_vb end

  // add_rb_mb begin
  cf = make_form("add_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // add_rb_mb end

  // add_rb_smb begin
  cf = make_form("add_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // add_rb_smb end

  // add_mb_rb begin
  cf = make_form("add_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add BYTE [", VARS["r1"], "],", VARS["r2"]););
  // add_mb_rb end

  // add_smb_rb begin
  cf = make_form("add_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // add_smb_rb end

  // add_mb_vb begin
  cf = make_form("add_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add BYTE [", VARS["r"], "],", VARS["a"]););
  // add_mb_vb end

  // add_smb_vb begin
  cf = make_form("add_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // add_smb_vb end

  // add end

  // sub begin

  // sub_rd_rd begin
  cf = make_form("sub_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
                 EG->f(fl, "not_rd", VARS["rt"]);
                 EG->f(fl, "inc_rd", VARS["rt"]);
                 EG->f(fl, "add_rd_rd", VARS["r1"], VARS["rt"]););
  // sub_rd_rd end

  // sub_rd_vd begin
  cf = make_form("sub_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "sub ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t tmp = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               tmp = ~tmp; tmp++;
               set_part_value(VARS["a1"], static_cast<uint64_t>(tmp)););
  iv->PROGRAMMER(EG->f(fl, "add_rd_vd", VARS["r"], VARS["a1"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 32);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(
      uint32_t a =
          static_cast<uint32_t>(get_part_value<std::uint64_t>(VARS["a"]));
      uint32_t b = static_cast<uint32_t>(global::rc.generate_random_number());
      a = a - b; set_part_value(VARS["a1"], static_cast<uint64_t>(a));
      set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "sub_rd_vd", VARS["r"], VARS["a1"]);
                 if (get_part_value<std::string>(VARS["r"]) == esp)
                     fl.set_flag(type_flags::stack_safe);
                 EG->f(fl, "sub_rd_vd", VARS["r"], VARS["a2"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 32);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(
      uint32_t a =
          static_cast<uint32_t>(get_part_value<std::uint64_t>(VARS["a"]));
      uint32_t b = static_cast<uint32_t>(global::rc.generate_random_number());
      a = a ^ b; set_part_value(VARS["a1"], static_cast<uint64_t>(a));
      set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r1"], VARS["a1"]);
                 EG->f(fl, "xor_rd_vd", VARS["r1"], VARS["a2"]);
                 EG->f(fl, "sub_rd_rd", VARS["r"], VARS["r1"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 8);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t a = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               uint8_t b = static_cast<uint8_t>(
                   global::rc.generate_random_number() % 254 + 1);
               a = global::rotl32(a, b);
               set_part_value(VARS["a1"], static_cast<uint64_t>(a));
               set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r1"], VARS["a1"]);
                 EG->f(fl, "ror_rd_vb", VARS["r1"], VARS["a2"]);
                 EG->f(fl, "sub_rd_rd", VARS["r"], VARS["r1"]););

  iv = make_invariant(cf);
  iv->add_variable("a1", 32);
  iv->add_variable("a2", 8);
  iv->add_register("r1", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t a = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               uint8_t b = static_cast<uint8_t>(
                   global::rc.generate_random_number() % 254 + 1);
               a = global::rotr32(a, b);
               set_part_value(VARS["a1"], static_cast<uint64_t>(a));
               set_part_value(VARS["a2"], static_cast<uint64_t>(b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_vd", VARS["r1"], VARS["a1"]);
                 EG->f(fl, "rol_rd_vb", VARS["r1"], VARS["a2"]);
                 EG->f(fl, "sub_rd_rd", VARS["r"], VARS["r1"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fu", "rc"}));
  iv->VALIDATOR(
      if ((*vars)[1]->check_flag(type_flags::dependence) ||
          (*vars)[1]->check_flag(type_flags::will_balanced)) return false;
      if (get_part_value<std::uint64_t>((*vars)[1]) > 50) return false;
      return true;);
  iv->PROGRAMMER(for (std::uint64_t i = 0;
                      i < get_part_value<std::uint64_t>(VARS["a"]); i++)
                     EG->f(fl, "dec_rd", VARS["r"]););
  // sub_rd_vd end

  // sub_rd_md begin
  cf = make_form("sub_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "sub ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // sub_rd_md end

  // sub_rd_smd begin
  cf = make_form("sub_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "sub ", VARS["r1"], ", DWORD [",
                        VARS["r2"], VARS["sign"], VARS["a"], "]"););
  // sub_rd_smd end

  // sub_md_rd begin
  cf = make_form("sub_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub DWORD [", VARS["r1"], "],", VARS["r2"]););
  // sub_md_rd end

  // sub_smd_rd begin
  cf = make_form("sub_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // sub_smd_rd end

  // sub_md_vd begin
  cf = make_form("sub_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub DWORD [", VARS["r"], "],", VARS["a"]););
  // sub_md_vd end

  // sub_smd_vd begin
  cf = make_form("sub_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // sub_smd_vd end

  // sub_rb_rb begin
  cf = make_form("sub_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r1"], ",", VARS["r2"]););
  // sub_rb_rb end

  // sub_rb_vb begin
  cf = make_form("sub_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r"], ",", VARS["a"]););
  // sub_rb_vb end

  // sub_rb_mb begin
  cf = make_form("sub_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // sub_rb_mb end

  // sub_rb_smb begin
  cf = make_form("sub_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // sub_rb_smb end

  // sub_mb_rb begin
  cf = make_form("sub_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub BYTE [", VARS["r1"], "],", VARS["r2"]););
  // sub_mb_rb end

  // sub_smb_rb begin
  cf = make_form("sub_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // sub_smb_rb end

  // sub_mb_vb begin
  cf = make_form("sub_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub BYTE [", VARS["r"], "],", VARS["a"]););
  // sub_mb_vb end

  // sub_smb_vb begin
  cf = make_form("sub_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // sub_smb_vb end

  // sub end

  // xor begin

  // xor_rd_rd begin
  cf = make_form("xor_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "xor ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(auto new_fl = fl;
                 if (get_part_value<std::string>(VARS["r1"]) == esp)
                     new_fl.set_flag(type_flags::stack_safe);
                 if (get_part_value<std::string>(VARS["r1"]) == ebp)
                     new_fl.set_flag(type_flags::fundomental_undepended);
                 EG->f(new_fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
                 EG->f(new_fl, "not_rd", VARS["rt"]);
                 EG->f(new_fl, "and_rd_rd", VARS["rt"], VARS["r1"]);
                 EG->f(new_fl, "not_rd", VARS["r1"]);
                 EG->f(new_fl, "and_rd_rd", VARS["r1"], VARS["r2"]);
                 EG->f(new_fl, "or_rd_rd", VARS["r1"], VARS["rt"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(auto new_fl = fl;
                 if (get_part_value<std::string>(VARS["r1"]) == esp)
                     new_fl.set_flag(type_flags::stack_safe);
                 if (get_part_value<std::string>(VARS["r1"]) == ebp)
                     new_fl.set_flag(type_flags::fundomental_undepended);
                 EG->f(new_fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
                 EG->f(new_fl, "or_rd_rd", VARS["rt"], VARS["r1"]);
                 EG->f(new_fl, "and_rd_rd", VARS["r1"], VARS["r2"]);
                 EG->f(new_fl, "not_rd", VARS["r1"]);
                 EG->f(new_fl, "and_rd_rd", VARS["r1"], VARS["rt"]););
  // xor_rd_rd end

  // xor_rd_vd begin
  cf = make_form("xor_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "xor ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_variable("b", 32);
  iv->add_variable("nb", 32);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t b = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               set_part_value(VARS["b"], static_cast<uint64_t>(b));
               set_part_value(VARS["nb"], static_cast<uint64_t>(~b)););
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r"]);
                 EG->f(fl, "and_rd_vd", VARS["rt"], VARS["nb"]);
                 if (get_part_value<std::string>(VARS["r"]) == esp)
                     fl.set_flag(type_flags::stack_safe);
                 EG->f(fl, "not_rd", VARS["r"]);
                 EG->f(fl, "and_rd_vd", VARS["r"], VARS["b"]);
                 EG->f(fl, "or_rd_rd", VARS["r"], VARS["rt"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->PROGRAMMER(auto new_fl = fl;
                 if (get_part_value<std::string>(VARS["r"]) == esp)
                     new_fl.set_flag(type_flags::stack_safe);
                 if (get_part_value<std::string>(VARS["r"]) == ebp)
                     new_fl.set_flag(type_flags::fundomental_undepended);
                 EG->f(new_fl, "mov_rd_vd", VARS["rt"], VARS["a"]);
                 EG->f(new_fl, "or_rd_rd", VARS["rt"], VARS["r"]);
                 EG->f(new_fl, "and_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(new_fl, "not_rd", VARS["r"]);
                 EG->f(new_fl, "and_rd_rd", VARS["r"], VARS["rt"]););
  // xor_rd_vd end

  // xor_rd_md begin
  cf = make_form("xor_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "xor ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // xor_rd_md end

  // xor_rd_smd begin
  cf = make_form("xor_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "xor ", VARS["r1"], ", DWORD [",
                        VARS["r2"], VARS["sign"], VARS["a"], "]"););
  // xor_rd_smd end

  // xor_md_rd begin
  cf = make_form("xor_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor DWORD [", VARS["r1"], "],", VARS["r2"]););
  // xor_md_rd end

  // xor_smd_rd begin
  cf = make_form("xor_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // xor_smd_rd end

  // xor_md_vd begin
  cf = make_form("xor_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor DWORD [", VARS["r"], "],", VARS["a"]););
  // xor_md_vd end

  // xor_smd_vd begin
  cf = make_form("xor_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // xor_smd_vd end

  // xor_rb_rb begin
  cf = make_form("xor_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r1"], ",", VARS["r2"]););
  // xor_rb_rb end

  // xor_rb_vb begin
  cf = make_form("xor_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r"], ",", VARS["a"]););
  // xor_rb_vb end

  // xor_rb_mb begin
  cf = make_form("xor_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // xor_rb_mb end

  // xor_rb_smb begin
  cf = make_form("xor_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // xor_rb_smb end

  // xor_mb_rb begin
  cf = make_form("xor_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor BYTE [", VARS["r1"], "],", VARS["r2"]););
  // xor_mb_rb end

  // xor_smb_rb begin
  cf = make_form("xor_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // xor_smb_rb end

  // xor_mb_vb begin
  cf = make_form("xor_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor BYTE [", VARS["r"], "],", VARS["a"]););
  // xor_mb_vb end

  // xor_smb_vb begin
  cf = make_form("xor_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // xor_smb_vb end

  // xor end

  // or begin

  // or_rd_rd begin
  cf = make_form("or_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->add_register("rt", "common");
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(
      auto new_fl = fl; if (get_part_value<std::string>(VARS["r1"]) == esp)
                            new_fl.set_flag(type_flags::stack_safe);
      if (get_part_value<std::string>(VARS["r1"]) == ebp)
          new_fl.set_flag(type_flags::fundomental_undepended);
      EG->f(new_fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
      EG->f(new_fl, "not_rd", VARS["rt"]); EG->f(new_fl, "not_rd", VARS["r1"]);
      EG->f(new_fl, "and_rd_rd", VARS["r1"], VARS["rt"]);
      EG->f(new_fl, "not_rd", VARS["r1"]););
  // or_rd_rd end

  // or_rd_vd begin
  cf = make_form("or_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "or ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_variable("nb", 32);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t b = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               set_part_value(VARS["nb"], static_cast<uint64_t>(~b)););
  iv->PROGRAMMER(if (get_part_value<std::string>(VARS["r"]) == esp)
                     fl.set_flag(type_flags::stack_safe);
                 EG->f(fl, "not_rd", VARS["r"]);
                 EG->f(fl, "and_rd_vd", VARS["r"], VARS["nb"]);
                 EG->f(fl, "not_rd", VARS["r"]););
  // or_rd_vd end

  // or_rd_md begin
  cf = make_form("or_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // or_rd_md end

  // or_rd_smd begin
  cf = make_form("or_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // or_rd_smd end

  // or_md_rd begin
  cf = make_form("or_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or DWORD [", VARS["r1"], "],", VARS["r2"]););
  // or_md_rd end

  // or_smd_rd begin
  cf = make_form("or_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // or_smd_rd end

  // or_md_vd begin
  cf = make_form("or_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or DWORD [", VARS["r"], "],", VARS["a"]););
  // or_md_vd end

  // or_smd_vd begin
  cf = make_form("or_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // or_smd_vd end

  // or_rb_rb begin
  cf = make_form("or_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r1"], ",", VARS["r2"]););
  // or_rb_rb end

  // or_rb_vb begin
  cf = make_form("or_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r"], ",", VARS["a"]););
  // or_rb_vb end

  // or_rb_mb begin
  cf = make_form("or_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // or_rb_mb end

  // or_rb_smb begin
  cf = make_form("or_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // or_rb_smb end

  // or_mb_rb begin
  cf = make_form("or_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or BYTE [", VARS["r1"], "],", VARS["r2"]););
  // or_mb_rb end

  // or_smb_rb begin
  cf = make_form("or_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // or_smb_rb end

  // or_mb_vb begin
  cf = make_form("or_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or BYTE [", VARS["r"], "],", VARS["a"]););
  // or_mb_vb end

  // or_smb_vb begin
  cf = make_form("or_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // or_smb_vb end

  // or end

  // and begin

  // and_rd_rd begin
  cf = make_form("and_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fu", "rc"}));
  iv->add_register("rt", "common");
  iv->VALIDATOR(if (get_part_value<std::string>((*vars)[0]) ==
                    get_part_value<std::string>((*vars)[1])) return false;
                return true;);
  iv->PROGRAMMER(
      auto new_fl = fl; if (get_part_value<std::string>(VARS["r1"]) == esp)
                            new_fl.set_flag(type_flags::stack_safe);
      if (get_part_value<std::string>(VARS["r1"]) == ebp)
          new_fl.set_flag(type_flags::fundomental_undepended);
      EG->f(new_fl, "mov_rd_rd", VARS["rt"], VARS["r2"]);
      EG->f(new_fl, "not_rd", VARS["rt"]); EG->f(new_fl, "not_rd", VARS["r1"]);
      EG->f(new_fl, "or_rd_rd", VARS["r1"], VARS["rt"]);
      EG->f(new_fl, "not_rd", VARS["r1"]););
  // and_rd_rd end

  // and_rd_vd begin
  cf = make_form("and_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "and ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_variable("nb", 32);
  iv->copy_flags(gg({"ss", "up", "fu", "rc"}));
  iv->BALANCER(uint32_t b = static_cast<uint32_t>(
                   get_part_value<std::uint64_t>(VARS["a"]));
               set_part_value(VARS["nb"], static_cast<uint64_t>(~b)););
  iv->PROGRAMMER(if (get_part_value<std::string>(VARS["r"]) == esp)
                     fl.set_flag(type_flags::stack_safe);
                 EG->f(fl, "not_rd", VARS["r"]);
                 EG->f(fl, "or_rd_vd", VARS["r"], VARS["nb"]);
                 EG->f(fl, "not_rd", VARS["r"]););
  // and_rd_vd end

  // and_rd_md begin
  cf = make_form("and_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "and ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // and_rd_md end

  // and_rd_smd begin
  cf = make_form("and_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // and_rd_smd end

  // and_md_rd begin
  cf = make_form("and_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and DWORD [", VARS["r1"], "],", VARS["r2"]););
  // and_md_rd end

  // and_smd_rd begin
  cf = make_form("and_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // and_smd_rd end

  // and_md_vd begin
  cf = make_form("and_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and DWORD [", VARS["r"], "],", VARS["a"]););
  // and_md_vd end

  // and_smd_vd begin
  cf = make_form("and_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // and_smd_vd end

  // and_rb_rb begin
  cf = make_form("and_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r1"], ",", VARS["r2"]););
  // and_rb_rb end

  // and_rb_vb begin
  cf = make_form("and_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r"], ",", VARS["a"]););
  // and_rb_vb end

  // and_rb_mb begin
  cf = make_form("and_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // and_rb_mb end

  // and_rb_smb begin
  cf = make_form("and_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // and_rb_smb end

  // and_mb_rb begin
  cf = make_form("and_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and BYTE [", VARS["r1"], "],", VARS["r2"]););
  // and_mb_rb end

  // and_smb_rb begin
  cf = make_form("and_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // and_smb_rb end

  // and_mb_vb begin
  cf = make_form("and_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and BYTE [", VARS["r"], "],", VARS["a"]););
  // and_mb_vb end

  // and_smb_vb begin
  cf = make_form("and_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // and_smb_vb end

  // and end

  // inc begin

  // inc_rd begin
  cf = make_form("inc_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "inc ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "add_rd_vd", VARS["r"], std::uint64_t(1)););
  // inc_rd end

  // inc_md begin
  cf = make_form("inc_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "inc DWORD [", VARS["r"], "]"););
  // inc_md end

  // inc_rb begin
  cf = make_form("inc_rb");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "inc ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "add_rb_vb", VARS["r"], std::uint64_t(1)););
  // inc_rb end

  // inc end

  // dec begin

  // dec_rd begin
  cf = make_form("dec_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "dec ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "sub_rd_vd", VARS["r"], std::uint64_t(1)););
  // dec_rd end

  // dec_md begin
  cf = make_form("dec_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "dec DWORD [", VARS["r"], "]"););
  // dec_md end

  // dec_rb begin
  cf = make_form("dec_rb");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "dec ", VARS["r"]););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu", "rc"}));
  iv->PROGRAMMER(EG->f(fl, "sub_rb_vb", VARS["r"], std::uint64_t(1)););
  // dec_rb end

  // dec end

  // xchg begin

  // xchg_rd_rd begin
  cf = make_form("xchg_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg ", VARS["r1"], ",", VARS["r2"]););
  // xchg_rd_rd end

  // xchg_rd_md begin
  cf = make_form("xchg_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "xchg ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // xchg_rd_md end

  // xchg_rd_smd begin
  cf = make_form("xchg_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // xchg_rd_smd end

  // xchg_md_rd begin
  cf = make_form("xchg_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg DWORD [", VARS["r1"], "],", VARS["r2"]););
  // xchg_md_rd end

  // xchg_smd_rd begin
  cf = make_form("xchg_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg DWORD [", VARS["r1"], VARS["sign"],
                       VARS["a"], "]", ",", VARS["r2"]););
  // xchg_smd_rd end

  // xchg_rb_rb begin
  cf = make_form("xchg_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg ", VARS["r1"], ",", VARS["r2"]););
  // xchg_rb_rb end

  // xchg_rb_mb begin
  cf = make_form("xchg_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "xchg ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // xchg_rb_mb end

  // xchg_rb_smb begin
  cf = make_form("xchg_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // xchg_rb_smb end

  // xchg_mb_rb begin
  cf = make_form("xchg_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg BYTE [", VARS["r1"], "],", VARS["r2"]););
  // xchg_mb_rb end

  // xchg_smb_rb begin
  cf = make_form("xchg_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xchg BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // xchg_smb_rb end

  // xchg end

  // lea begin

  // lea rd_md begin
  cf = make_form("lea_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "lea ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // lea rd_md end

  // lea rd_smd begin
  cf = make_form("lea_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "lea ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // lea rd_smd end

  // lea rb_mb begin
  cf = make_form("lea_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "lea ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // lea rb_mb end

  // lea rb_smb begin
  cf = make_form("lea_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "lea ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // lea rb_smb end

  // lea end

  // cmp begin

  // cmp_rd_rd begin
  cf = make_form("cmp_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r1"]);
                 fl.set_flag(type_flags::flag_safe);
                 EG->f(fl, "sub_rd_rd", VARS["rt"], VARS["r1"]););
  // cmp_rd_rd end

  // cmp_rd_vd begin
  cf = make_form("cmp_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r"]);
                 fl.set_flag(type_flags::flag_safe);
                 EG->f(fl, "sub_rd_vd", VARS["rt"], VARS["a"]););
  // cmp_rd_vd end

  // cmp_rd_md begin
  cf = make_form("cmp_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "cmp ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // cmp_rd_md end

  // cmp_rd_smd begin
  cf = make_form("cmp_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "cmp ", VARS["r1"], ", DWORD [",
                        VARS["r2"], VARS["sign"], VARS["a"], "]"););
  // cmp_rd_smd end

  // cmp_md_rd begin
  cf = make_form("cmp_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp DWORD [", VARS["r1"], "],", VARS["r2"]););
  // cmp_md_rd end

  // cmp_smd_rd begin
  cf = make_form("cmp_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // cmp_smd_rd end

  // cmp_md_vd begin
  cf = make_form("cmp_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp DWORD [", VARS["r"], "],", VARS["a"]););
  // cmp_md_vd end

  // cmp_smd_vd begin
  cf = make_form("cmp_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // cmp_smd_vd end

  // cmp_rb_rb begin
  cf = make_form("cmp_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r1"], ",", VARS["r2"]););
  // cmp_rb_rb end

  // cmp_rb_vb begin
  cf = make_form("cmp_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r"], ",", VARS["a"]););
  // cmp_rb_vb end

  // cmp_rb_mb begin
  cf = make_form("cmp_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // cmp_rb_mb end

  // cmp_rb_smb begin
  cf = make_form("cmp_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // cmp_rb_smb end

  // cmp_mb_rb begin
  cf = make_form("cmp_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp BYTE [", VARS["r1"], "],", VARS["r2"]););
  // cmp_mb_rb end

  // cmp_smb_rb begin
  cf = make_form("cmp_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // cmp_smb_rb end

  // cmp_mb_vb begin
  cf = make_form("cmp_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp BYTE [", VARS["r"], "],", VARS["a"]););
  // cmp_mb_vb end

  // cmp_smb_vb begin
  cf = make_form("cmp_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // cmp_smb_vb end

  // cmp end

  // test begin

  // test_rd_rd begin
  cf = make_form("test_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r1"], ",", VARS["r2"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r1"]);
                 fl.set_flag(type_flags::flag_safe);
                 EG->f(fl, "and_rd_rd", VARS["rt"], VARS["r2"]););
  // test_rd_rd end

  // test_rd_vd begin
  cf = make_form("test_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r"], ",", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("rt", "common");
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "mov_rd_rd", VARS["rt"], VARS["r"]);
                 fl.set_flag(type_flags::flag_safe);
                 EG->f(fl, "and_rd_vd", VARS["rt"], VARS["a"]););
  // test_rd_vd end

  // test_rd_md begin
  cf = make_form("test_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "test ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // test_rd_md end

  // test_rd_smd begin
  cf = make_form("test_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // test_rd_smd end

  // test_md_rd begin
  cf = make_form("test_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test DWORD [", VARS["r1"], "],", VARS["r2"]););
  // test_md_rd end

  // test_smd_rd begin
  cf = make_form("test_smd_rd");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test DWORD [", VARS["r1"], VARS["sign"],
                       VARS["a"], "]", ",", VARS["r2"]););
  // test_smd_rd end

  // test_md_vd begin
  cf = make_form("test_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "test DWORD [", VARS["r"], "],", VARS["a"]););
  // test_md_vd end

  // test_smd_vd begin
  cf = make_form("test_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "test DWORD [", VARS["r"], VARS["sign"],
                        VARS["a1"], "],", VARS["a2"]););
  // test_smd_vd end

  // test_rb_rb begin
  cf = make_form("test_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r1"], ",", VARS["r2"]););
  // test_rb_rb end

  // test_rb_vb begin
  cf = make_form("test_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "test ", VARS["r"], ",", VARS["a"]););
  // test_rb_vb end

  // test_rb_mb begin
  cf = make_form("test_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "test ", VARS["r1"], ", BYTE [", VARS["r2"], "]"););
  // test_rb_mb end

  // test_rb_smb begin
  cf = make_form("test_rb_smb");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r1"], ", BYTE [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // test_rb_smb end

  // test_mb_rb begin
  cf = make_form("test_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test BYTE [", VARS["r1"], "],", VARS["r2"]););
  // test_mb_rb end

  // test_smb_rb begin
  cf = make_form("test_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "]", ",", VARS["r2"]););
  // test_smb_rb end

  // test_mb_vb begin
  cf = make_form("test_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->ta(CAST, "olly", "test BYTE [", VARS["r"], "],", VARS["a"]););
  // test_mb_vb end

  // test_smb_vb begin
  cf = make_form("test_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "test BYTE [", VARS["r"], VARS["sign"],
                        VARS["a1"], "],", VARS["a2"]););
  // test_smb_vb end

  // test end

  // shl begin

  // shl_rd_rb begin
  cf = make_form("shl_rd_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl ", VARS["r1"], ",", VARS["r2"]););
  // shl_rd_rb end

  // shl_rb_rb begin
  cf = make_form("shl_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl ", VARS["r1"], ",", VARS["r2"]););
  // shl_rb_rb end

  // shl_rd_vb begin
  cf = make_form("shl_rd_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl ", VARS["r"], ",", VARS["a"]););
  // shl_rd_vb end

  // shl_rw_vb begin
  cf = make_form("shl_rw_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "olly", "shl ", VARS["r"], ",", VARS["a"]););
  // shl_rw_vb end

  // shl_rb_vb begin
  cf = make_form("shl_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl ", VARS["r"], ",", VARS["a"]););
  // shl_rb_vb end

  // shl_md_rb begin
  cf = make_form("shl_md_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl DWORD [", VARS["r1"], "],", VARS["r2"]););
  // shl_md_rb end

  // shl_mb_rb begin
  cf = make_form("shl_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl BYTE [", VARS["r1"], "],", VARS["r2"]););
  // shl_mb_rb end

  // shl_smd_rb begin
  cf = make_form("shl_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // shl_smd_rb end

  // shl_smb_rb begin
  cf = make_form("shl_smb_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // shl_smb_rb end

  // shl_smd_vb begin
  cf = make_form("shl_smd_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // shl_smd_vb end

  // shl_smb_vb begin
  cf = make_form("shl_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // shl_smb_vb end

  // shl_md_vb begin
  cf = make_form("shl_md_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl DWORD [", VARS["r"], "],", VARS["a"]););
  // shl_md_vb end

  // shl_mb_vb begin
  cf = make_form("shl_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl BYTE [", VARS["r"], "],", VARS["a"]););
  // shl_mb_vb end

  // shl end

  // shr begin

  // shr_rd_rb begin
  cf = make_form("shr_rd_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r1"], ",", VARS["r2"]););
  // shr_rd_rb end

  // shr_rb_rb begin
  cf = make_form("shr_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r1"], ",", VARS["r2"]););
  // shr_rb_rb end

  // shr_rd_vb begin
  cf = make_form("shr_rd_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r"], ",", VARS["a"]););
  // shr_rd_vb end

  // shr_rb_vb begin
  cf = make_form("shr_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r"], ",", VARS["a"]););
  // shr_rb_vb end

  // shr_md_rb begin
  cf = make_form("shr_md_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r1"], "],", VARS["r2"]););
  // shr_md_rb end

  // shr_mb_rb begin
  cf = make_form("shr_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r1"], "],", VARS["r2"]););
  // shr_mb_rb end

  // shr_smd_rb begin
  cf = make_form("shr_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // shr_smd_rb end

  // shr_smb_rb begin
  cf = make_form("shr_smb_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // shr_smb_rb end

  // shr_smd_vb begin
  cf = make_form("shr_smd_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // shr_smd_vb end

  // shr_smb_vb begin
  cf = make_form("shr_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // shr_smb_vb end

  // shr_md_vb begin
  cf = make_form("shr_md_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r"], "],", VARS["a"]););
  // shr_md_vb end

  // shr_mb_vb begin
  cf = make_form("shr_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r"], "],", VARS["a"]););
  // shr_mb_vb end

  // shr end

  // rol begin

  // rol_rd_rb begin
  cf = make_form("rol_rd_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol ", VARS["r1"], ",", VARS["r2"]););
  // rol_rd_rb end

  // rol_rb_rb begin
  cf = make_form("rol_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol ", VARS["r1"], ",", VARS["r2"]););
  // rol_rb_rb end

  // rol_rd_vb begin
  cf = make_form("rol_rd_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol ", VARS["r"], ",", VARS["a"]););
  // rol_rd_vb end

  // rol_rb_vb begin
  cf = make_form("rol_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol ", VARS["r"], ",", VARS["a"]););
  // rol_rb_vb end

  // rol_md_rb begin
  cf = make_form("rol_md_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol DWORD [", VARS["r1"], "],", VARS["r2"]););
  // rol_md_rb end

  // rol_mb_rb begin
  cf = make_form("rol_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol BYTE [", VARS["r1"], "],", VARS["r2"]););
  // rol_mb_rb end

  // rol_smd_rb begin
  cf = make_form("rol_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // rol_smd_rb end

  // rol_smb_rb begin
  cf = make_form("rol_smb_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // rol_smb_rb end

  // rol_smd_vb begin
  cf = make_form("rol_smd_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // rol_smd_vb end

  // rol_smb_vb begin
  cf = make_form("rol_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // rol_smb_vb end

  // rol_md_vb begin
  cf = make_form("rol_md_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol DWORD [", VARS["r"], "],", VARS["a"]););
  // rol_md_vb end

  // rol_mb_vb begin
  cf = make_form("rol_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "rol BYTE [", VARS["r"], "],", VARS["a"]););
  // rol_mb_vb end

  // rol end

  // ror begin

  // ror_rd_rb begin
  cf = make_form("ror_rd_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror ", VARS["r1"], ",", VARS["r2"]););
  // ror_rd_rb end

  // ror_rb_rb begin
  cf = make_form("ror_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror ", VARS["r1"], ",", VARS["r2"]););
  // ror_rb_rb end

  // ror_rd_vb begin
  cf = make_form("ror_rd_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror ", VARS["r"], ",", VARS["a"]););
  // ror_rd_vb end

  // ror_rb_vb begin
  cf = make_form("ror_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror ", VARS["r"], ",", VARS["a"]););
  // ror_rb_vb end

  // ror_md_rb begin
  cf = make_form("ror_md_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror DWORD [", VARS["r1"], "],", VARS["r2"]););
  // ror_md_rb end

  // ror_mb_rb begin
  cf = make_form("ror_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror BYTE [", VARS["r1"], "],", VARS["r2"]););
  // ror_mb_rb end

  // ror_smd_rb begin
  cf = make_form("ror_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // ror_smd_rb end

  // ror_smb_rb begin
  cf = make_form("ror_smb_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
                       "],", VARS["r2"]););
  // ror_smb_rb end

  // ror_smd_vb begin
  cf = make_form("ror_smd_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // ror_smd_vb end

  // ror_smb_vb begin
  cf = make_form("ror_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // ror_smb_vb end

  // ror_md_vb begin
  cf = make_form("ror_md_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror DWORD [", VARS["r"], "],", VARS["a"]););
  // ror_md_vb end

  // ror_mb_vb begin
  cf = make_form("ror_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ror BYTE [", VARS["r"], "],", VARS["a"]););
  // ror_mb_vb end

  // ror end
}

}  // namespace eg::i8086