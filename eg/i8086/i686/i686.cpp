#include <eg/i8086/i686/i686.h>

#define PROGRAMMER(code)                                                       \
  register_programmer(                                                         \
      [this, iv](global::flag_container fl,                                    \
                 std::map<std::string, part *> *vars) { code })
#define VALIDATOR(code)                                                        \
  register_validator([this](std::vector<part *> *vars) -> bool { code })
#define BALANCER(code)                                                         \
  register_balancer([this](std::map<std::string, part *> *vars) { code })
#define EG this
#define VARS (*vars)

#define CAST static_cast<global::flag_container>(*iv)

#define GROUP_ALL                                                              \
  type_flags::stack_safe type_flags::flag_safe                                 \
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
         {"rc", type_flags::invariant_recursive}};

  init_assemblers();
  init_invariants();
  set_recursion_counter(5);
  get_build_node()->select_node();
}
i686::~i686() {}

void i686::init_assemblers() {
  RAsm *a = 0;
  a = r_asm_new();
  if (!r_asm_use(a, "x86"))
    throw std::domain_error("Invalid assemler name");
  if (!r_asm_set_bits(a, get_value<std::uint32_t>("bitness")))
    throw std::domain_error("Invalid bintess");
  assemblers["default"] = a;

  a = r_asm_new();
  if (!r_asm_use(a, "x86.as"))
    throw std::domain_error("Invalid assemler name");
  if (!r_asm_set_bits(a, get_value<std::uint32_t>("bitness")))
    throw std::domain_error("Invalid bintess");
  assemblers["gas"] = a;

  a = r_asm_new();
  if (!r_asm_use(a, "x86.nasm"))
    throw std::domain_error("Invalid assemler name");
  if (!r_asm_set_bits(a, get_value<std::uint32_t>("bitness")))
    throw std::domain_error("Invalid bintess");
  assemblers["nasm"] = a;
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
  init_crc();
  init_aes();
  init_unzip();
  init_becb();
  init_decb();
  init_gambling();
  end();
}

void i686::init_crc() {
  start_segment("crc");
  bf("target", "common");
  bss("ebp_", ebp);
  f("mov_rd_smd", g("target"), g("ebp_"), "-", vshd("target"));
  bf("result", "base");
  bf("accum", "base");
  f("clear_rd", g("result"));
  f("clear_rd", g("accum"));
  f("test_smb_vb", g("ebp_"), "-", vshd("crc_switch"), std::uint64_t(1));
  f("branch", "nz", shd("crc_loop"), shd("crc_set_size"));
  end();

  start_segment("crc_set_size");
  bf("size", "common");
  f("mov_rd_smd", g("size"), g("ebp_"), "-", vshd("count"));
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
  f("test_smb_vb", g("ebp_"), "-", vshd("crc_switch"), std::uint64_t(1));
  f("branch", "z", shd("crc_test_size"), shd("crc_test_zero"));
  end();

  start_segment("crc_test_zero");
  f(gg({"fs"}), "sub_rb_vb", g("accum", "lb"), std::uint64_t(20));
  f("branch", "nz", shd("crc_loop"), shd("crc_end"));
  end();

  start_segment("crc_end");
  fr("target");
  fr("counter");
  fr("accum");
  fr("size");
  f("mov_smd_rd", g("ebp_"), "-", vshd("result"), g("result"));
  fr("result");
  fr("ebp_");
  f("ret");
  end();
}
void i686::init_aes() {}
void i686::init_unzip() {}
void i686::init_becb() {}
void i686::init_decb() {}
void i686::init_gambling() {}

void i686::copy_fundamental(std::string frame_name) {
  copy_var("base", "fundamental");
  copy_var("temporary", "fundamental");
  copy_var("crc_switch", "fundamental");
  copy_var("count", "fundamental");
  copy_var("target", "fundamental");
  copy_var("result", "fundamental");
  copy_var("byte_key", "fundamental");
  copy_var("dword_key", "fundamental");
  copy_var("key_addr", "fundamental");
}

void i686::push_registers(std::initializer_list<std::string> registers) {
  for (auto r : registers)
    f("push_rd", r);
}

void i686::pop_registers(std::initializer_list<std::string> registers) {
  std::vector<std::string> reflection;
  for (auto r : registers)
    reflection.push_back(r);
  std::reverse(reflection.begin(), reflection.end());
  for (auto r : reflection)
    f("pop_rd", r);
}

global::flag_container
i686::gg(std::initializer_list<std::string> current_flags) {
  global::flag_container current;
  for (auto cf : current_flags)
    current.set_flag(ivg[cf]);
  return current;
}

void i686::init_invariants() {
  form *cf = reinterpret_cast<eg::form *>(0);
  invariant *iv = reinterpret_cast<eg::invariant *>(0);

  // branch begin
  cf = make_form("branch");
  cf->add_argument("f");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(auto seg1 = global::cs.generate_unique_string("usegment");
                 auto seg2 = global::cs.generate_unique_string("usegment");
                 EG->f(fl, "jxx_vd", VARS["f"], EG->shd(seg2));
                 EG->start_segment(seg1); EG->f(fl, "jump", VARS["a2"]);
                 EG->end(); EG->start_segment(seg2);
                 EG->f(fl, "jump", VARS["a1"]); EG->end(););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up"}));
  iv->PROGRAMMER(auto seg1 = global::cs.generate_unique_string("usegment");
                 auto seg2 = global::cs.generate_unique_string("usegment");
                 EG->f(fl, "jxx_vd", VARS["f"], EG->shd(seg2));
                 EG->f(fl, "jump", EG->shd(seg1));
                 EG->start_segment(seg1, "fundamental");
                 EG->f(fl, "jump", VARS["a2"]); EG->end();
                 EG->start_segment(seg2, "fundamental");
                 EG->f(fl, "jump", VARS["a1"]); EG->end(););
  // branch end

  // invoke begin
  cf = make_form("invoke");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "call_vd", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp); EG->f(fl, "mov_rd_smd", VARS["r"],
                                           EG->g(ebp_), "-", EG->vshd("base"));
                 EG->fr(ebp_); EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(fl, "call_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      EG->bss(ebp_, ebp);
      EG->f(fl, "mov_rd_smd", VARS["r"], EG->g(ebp_), "-", EG->vshd("base"));
      EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]);
      fl.set_flag(type_flags::fundomental_undepended); EG->f(
          fl, "mov_smd_rd", EG->g(ebp_), "-", EG->vshd("temporary"), VARS["r"]);
      EG->f(fl, "call_smd", EG->g(ebp_), "-", EG->vshd("temporary"));
      EG->fr(ebp_); fl.unset_flag(type_flags::fundomental_undepended););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      EG->bs(reg_, "common"); EG->f(fl, "push_rd", EG->g(reg_)); EG->bss(ebp_, ebp);
      EG->f(fl, "mov_rd_smd", EG->g(reg_), EG->g(ebp_), "-", EG->vshd("base"));
      EG->f(fl, "add_rd_vd", EG->g(reg_), VARS["a"]);
      fl.set_flag(type_flags::fundomental_undepended);
      EG->f(fl, "mov_smd_rd", EG->g(ebp_), "-", EG->vshd("temporary"),
            EG->g(reg_));
      EG->f(fl, "pop_rd", EG->g(reg_)); EG->fr(reg_);
      EG->f(fl, "call_smd", EG->g(ebp_), "-", EG->vshd("temporary"));
      fl.unset_flag(type_flags::fundomental_undepended); EG->fr(ebp_););
  // invoke end

  // jump begin
  cf = make_form("jump");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "jmp_vd", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp); EG->f(fl, "mov_rd_smd", VARS["r"],
                                           EG->g(ebp_), "-", EG->vshd("base"));
                 EG->fr(ebp_); EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(fl, "jmp_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(auto ebp_ = global::cs.generate_unique_string("pr_regs");
                 EG->bss(ebp_, ebp); EG->f(fl, "mov_rd_smd", VARS["r"],
                                           EG->g(ebp_), "-", EG->vshd("base"));
                 EG->fr(ebp_); EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(fl, "push_rd", VARS["r"]); EG->f(fl, "ret"););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      auto esp_ = global::cs.generate_unique_string("pr_regs");
      EG->bs(reg_, "common"); EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "push_rd", EG->g(reg_)); EG->bss(esp_, esp);
      fl.set_flag(type_flags::stack_safe);
      EG->f(fl, "add_rd_vd", EG->g(esp_), std::uint64_t(8)); EG->bss(ebp_, ebp);
      EG->f(fl, "mov_rd_smd", EG->g(reg_), EG->g(ebp_), "-", EG->vshd("base"));
      EG->fr(ebp_); EG->f(fl, "add_rd_vd", EG->g(reg_), VARS["a"]);
      EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "sub_rd_vd", EG->g(esp_), std::uint64_t(4)); EG->fr(esp_);
      EG->f(fl, "pop_rd", EG->g(reg_)); EG->fr(reg_);
      fl.unset_flag(type_flags::stack_safe); EG->f(fl, "ret"););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->copy_flags(gg({"ss", "rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      EG->bss(ebp_, ebp);
      EG->f(fl, "mov_rd_smd", VARS["r"], EG->g(ebp_), "-", EG->vshd("base"));
      EG->f(fl, "add_rd_vd", VARS["r"], VARS["a"]);
      fl.set_flag(type_flags::fundomental_undepended);
      EG->f(fl, "mov_smd_rd", EG->g(ebp_), "-", EG->vshd("target"), VARS["r"]);
      EG->f(fl, "jmp_smd", EG->g(ebp_), "-", EG->vshd("target")); EG->fr(ebp_);
      fl.unset_flag(type_flags::fundomental_undepended););

  iv = make_invariant(cf);
  iv->copy_flags(gg({"rc"}));
  iv->PROGRAMMER(
      auto ebp_ = global::cs.generate_unique_string("pr_regs");
      auto reg_ = global::cs.generate_unique_string("pr_regs");
      EG->bs(reg_, "common"); EG->f(fl, "push_rd", EG->g(reg_)); EG->bss(ebp_, ebp);
      EG->f(fl, "mov_rd_smd", EG->g(reg_), EG->g(ebp_), "-", EG->vshd("base"));
      EG->f(fl, "add_rd_vd", EG->g(reg_), VARS["a"]);
      fl.set_flag(type_flags::fundomental_undepended); EG->f(
          fl, "mov_smd_rd", EG->g(ebp_), "-", EG->vshd("target"), EG->g(reg_));
      EG->f(fl, "pop_rd", EG->g(reg_)); EG->fr(reg_);
      EG->f(fl, "jmp_smd", EG->g(ebp_), "-", EG->vshd("target"));
      fl.unset_flag(type_flags::fundomental_undepended); EG->fr(ebp_););
  // jump end

  // clear begin

  // clear_rd begin
  cf = make_form("clear_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->f(fl, "xor_rd_rd", VARS["r"], VARS["r"]););
  // clear_rd end

  // clear end

  // push begin

  // push_rd begin
  cf = make_form("push_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "push ", VARS["r"]););
  // push_rd end

  // push_vd begin
  cf = make_form("push_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "push ", VARS["a"]););

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
      EG->bs(reg_, "common"); EG->bss(esp_, esp);
      EG->f(fl, "push_rd", EG->g(reg_)); EG->f(fl, "push_rd", EG->g(reg_));
      EG->f(fl, "mov_rd_vd", EG->g(reg_), VARS["a"]);
      fl.set_flag(type_flags::stack_safe);
      EG->t(CAST, "add ", EG->g(esp_), ",8"); EG->f(fl, "push_rd", EG->g(reg_));
      EG->t(CAST, "sub ", EG->g(esp_), ",4"); EG->f(fl, "pop_rd", EG->g(reg_));
      fl.unset_flag(type_flags::stack_safe); EG->fr(reg_); EG->fr(esp_););
  // push_vd end

  // push end

  // pop begin

  // pop_rd begin
  cf = make_form("pop_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "pop ", VARS["r"]););
  // pop_rd end

  // pop end

  // mov begin

  // mov_rd_rd begin
  cf = make_form("mov_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r1"], ",", VARS["r2"]););
  // mov_rd_rd end

  // mov_rd_vd begin
  cf = make_form("mov_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov ", VARS["r"], ",", VARS["a"]););
  // mov_rd_vd end

  // mov_rd_md begin
  cf = make_form("mov_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "mov ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // mov_rd_md end

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
  // mov_rd_smd end

  // mov_md_rd begin
  cf = make_form("mov_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov DWORD [", VARS["r1"], "],", VARS["r2"]););
  // mov_md_rd end

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
  // mov_smd_rd end

  // mov_md_vd begin
  cf = make_form("mov_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "mov DWORD [", VARS["r"], "],", VARS["a"]););
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
  // mov_smd_vd end

  // mov_rd_serd begin
  cf = make_form("mov_rd_serd");
  cf->add_argument("r1");
  cf->add_argument("sr");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "mov ", VARS["r1"], ", DWORD [",
                        VARS["sr"], ":", VARS["r2"], "]"););
  // mov_rd_serd end

  // mov_serd_rd begin
  cf = make_form("mov_serd_rd");
  cf->add_argument("sr");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "mov DWORD [", VARS["sr"], ":",
                        VARS["r1"], "], ", VARS["r2"]););
  // mov_serd_rd end

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
  cf = make_form("mov_smd_rb");
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
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "movzx ", VARS["r1"], ",", VARS["r2"]););
  // movzx_rd_rb end

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
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "call DWORD ", VARS["a"]););
  // call_vd end

  // call_rd begin
  cf = make_form("call_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "call ", VARS["r"]););
  // call_rd end

  // call_md begin
  cf = make_form("call_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "call DWORD [", VARS["r"], "]"););
  // call_md end

  // call_smd begin
  cf = make_form("call_smd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "call DWORD [", VARS["r"], VARS["sign"],
                        VARS["a"], "]"););
  // call_smd end

  // call end

  // jmp begin

  // jmp_vd begin
  cf = make_form("jmp_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "jmp NEAR ", VARS["a"]););
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
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "jmp DWORD [", VARS["r"], "]"););
  // jmp_md end

  // jmp_smd begin
  cf = make_form("jmp_smd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "jmp DWORD [", VARS["r"], VARS["sign"],
                        VARS["a"], "]"););
  // jmp_smd end

  // jmp end

  // jxx begin

  // jxx_vd end
  cf = make_form("jxx_vd");
  cf->add_argument("f");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "j", VARS["f"], " NEAR ", VARS["a"]););
  // jxx_vd end

  // jxx end

  // ret begin
  cf = make_form("ret");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "ret"););
  // ret end

  // add begin

  // add_rd_rd begin
  cf = make_form("add_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r1"], ",", VARS["r2"]););
  // add_rd_rd end

  // add_rd_vd begin
  cf = make_form("add_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r"], ",", VARS["a"]););
  // add_rd_vd end

  // add_rd_md begin
  cf = make_form("add_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "add ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // add_rd_md end

  // add_rd_smd begin
  cf = make_form("add_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
  // add_rd_smd end

  // add_md_rd begin
  cf = make_form("add_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add DWORD [", VARS["r1"], "],", VARS["r2"]););
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

  // add_md_vd begin
  cf = make_form("add_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add DWORD [", VARS["r"], "],", VARS["a"]););
  // add_md_vd end

  // add_smd_vd begin
  cf = make_form("add_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "add DWORD [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
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
  // sub_rd_rd end

  // sub_rd_vd begin
  cf = make_form("sub_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r"], ",", VARS["a"]););
  // sub_rd_vd end

  // sub_rd_md begin
  cf = make_form("sub_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "sub ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // sub_rd_md end

  // sub_rd_smd begin
  cf = make_form("sub_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "sub ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
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
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r1"], ",", VARS["r2"]););
  // xor_rd_rd end

  // xor_rd_vd begin
  cf = make_form("xor_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r"], ",", VARS["a"]););
  // xor_rd_vd end

  // xor_rd_md begin
  cf = make_form("xor_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(
      EG->t(CAST, "xor ", VARS["r1"], ", DWORD [", VARS["r2"], "]"););
  // xor_rd_md end

  // xor_rd_smd begin
  cf = make_form("xor_rd_smd");
  cf->add_argument("r1");
  cf->add_argument("r2");
  cf->add_argument("sign");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "xor ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
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
  // or_rd_rd end

  // or_rd_vd begin
  cf = make_form("or_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "or ", VARS["r"], ",", VARS["a"]););
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
  // and_rd_rd end

  // and_rd_vd begin
  cf = make_form("and_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "and ", VARS["r"], ",", VARS["a"]););
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

  // inc_rd end

  // inc_rb begin

  cf = make_form("inc_rb");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "inc ", VARS["r"]););

  // inc_rb end

  // inc end

  // dec begin

  // dec_rd begin

  cf = make_form("dec_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "dec ", VARS["r"]););

  // dec_rd end

  // dec_rb begin

  cf = make_form("dec_rb");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "dec ", VARS["r"]););

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
  // cmp_rd_rd end

  // cmp_rd_vd begin
  cf = make_form("cmp_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r"], ",", VARS["a"]););
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
  iv->PROGRAMMER(EG->t(CAST, "cmp ", VARS["r1"], ", DWORD [", VARS["r2"],
                       VARS["sign"], VARS["a"], "]"););
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
  // test_rd_rd end

  // test_rd_vd begin
  cf = make_form("test_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::stack_safe);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r"], ",", VARS["a"]););
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
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "test DWORD [", VARS["r"], "],", VARS["a"]););
  // test_md_vd end

  // test_smd_vd begin
  cf = make_form("test_smd_vd");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 32);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "test DWORD [", VARS["r"], VARS["sign"],
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
  iv->PROGRAMMER(EG->t(CAST, "test ", VARS["r"], ",", VARS["a"]););
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
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "test BYTE [", VARS["r"], "],", VARS["a"]););
  // test_mb_vb end

  // test_smb_vb begin
  cf = make_form("test_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->ta(CAST, "nasm", "test BYTE [", VARS["r"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // test_smb_vb end

  // test end

  // shl begin

  // shl_rd_rb begin
  cf = make_form("shl_rd_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r1"], ",", VARS["r2"]););
  // shl_rd_rb end

  // shl_rb_rb begin
  cf = make_form("shl_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r1"], ",", VARS["r2"]););
  // shl_rb_rb end

  // shl_rd_vb begin
  cf = make_form("shl_rd_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r1"], ",", VARS["a"]););
  // shl_rd_vb end

  // shl_rb_vb begin
  cf = make_form("shl_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr ", VARS["r1"], ",", VARS["a"]););
  // shl_rb_vb end

  // shl_md_rb begin
  cf = make_form("shl_md_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r1"], "],", VARS["r2"]););
  // shl_md_rb end

  // shl_mb_rb begin
  cf = make_form("shl_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"st", "fs", "ss", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r1"], "],", VARS["r2"]););
  // shl_mb_rb end

  // shl_smd_rb begin
  cf = make_form("shl_smd_rb");
  cf->add_argument("r1");
  cf->add_argument("sign");
  cf->add_argument("a", 32);
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r1"], VARS["sign"], VARS["a"],
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
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r1"], VARS["sign"], VARS["a"],
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
  iv->PROGRAMMER(EG->t(CAST, "shr DWORD [", VARS["r1"], VARS["sign"],
                       VARS["a1"], "],", VARS["a2"]););
  // shl_smd_vb end

  // shl_smb_vb begin
  cf = make_form("shl_smb_vb");
  cf->add_argument("r");
  cf->add_argument("sign");
  cf->add_argument("a1", 32);
  cf->add_argument("a2", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shr BYTE [", VARS["r1"], VARS["sign"], VARS["a1"],
                       "],", VARS["a2"]););
  // shl_smb_vb end

  // shl_md_vb begin
  cf = make_form("shl_md_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl DWORD [", VARS["r1"], "],", VARS["a"]););
  // shl_md_vb end

  // shl_mb_vb begin
  cf = make_form("shl_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->copy_flags(gg({"ss", "fs", "up", "fu"}));
  iv->PROGRAMMER(EG->t(CAST, "shl BYTE [", VARS["r1"], "],", VARS["a"]););
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
  iv->set_flag(type_flags::stack_safe);
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
  iv->PROGRAMMER(EG->t(CAST, "ror DWORD [", VARS["r1"], "],", VARS["a"]););
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

} // namespace eg::i8086