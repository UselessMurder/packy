#include <eg/i8086/i686/i686.h>

#define PROGRAMMER(code)                                                       \
  register_programmer([this, iv](std::map<std::string, part *> *vars) { code })
#define VALIDATOR(code)                                                        \
  register_validator([this](std::vector<part *> *vars) -> bool { code })
#define BALANCER(code)                                                         \
  register_balancer([this](std::map<std::string, part *> *vars) { code })
#define EG this
#define VARS (*vars)

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

  init_assemblers();
  init_invariants();
  init_state();

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

void i686::init_state() {}

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

void i686::init_invariants() {
  eg::form *cf = reinterpret_cast<eg::form *>(0);
  eg::invariant *iv = reinterpret_cast<eg::invariant *>(0);

  // push begin

  // push_rd begin
  cf = make_form("push_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "push ", VARS["r"]););
  // push_rd end

  // push_vd begin
  cf = make_form("push_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->PROGRAMMER(EG->t("push ", VARS["a"]););

  iv = make_invariant(cf);
  iv->add_register("r", "common");
  iv->set_flag(type_flags::invariant_recursive);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->f(*iv, "mov_rd_vd", VARS["r"], VARS["a"]);
                 EG->f(*iv, "push_rd", VARS["r"]););

  iv = make_invariant(cf);
  iv->set_flag(type_flags::invariant_recursive);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      auto num1 = global::cs.generate_unique_string("pr_regs");
      auto num2 = global::cs.generate_unique_string("pr_regs");
      EG->bs(num1, "common"); EG->bsp(num2, esp);
      EG->f(*iv, "push_rd", EG->g(num1)); EG->f(*iv, "push_rd", EG->g(num1));
      EG->f(*iv, "mov_rd_vd", EG->g(num1), VARS["a"]);
      EG->t({type_flags::memory_static}, "add ", EG->g(num2), ",8");
      EG->f(*iv, "push_rd", EG->g(num1));
      EG->t({type_flags::memory_static}, "sub ", EG->g(num2), ",4");
      EG->f(*iv, "pop_rd", EG->g(num1)); EG->fr(num1); EG->fr(num2););
  // push_vd end

  // push end

  // pop begin

  // pop_rd begin
  cf = make_form("pop_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "pop ", VARS["r"]););
  // pop_rd end

  // pop end

  // mov begin

  // mov_rd_rd begin
  cf = make_form("mov_rd_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      EG->t({type_flags::memory_static}, "mov ", VARS["r1"], ",", VARS["r2"]););
  // mov_rd_rd end

  // mov_rd_vd begin
  cf = make_form("mov_rd_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      EG->t({type_flags::memory_static}, "mov ", VARS["r"], ",", VARS["a"]););
  // mov_rd_vd end

  // mov_rd_md begin
  cf = make_form("mov_rd_md");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "mov ", VARS["r1"],
                       ", DWORD [", VARS["r2"], "]"););
  // mov_rd_md end

  // mov_md_rb begin
  cf = make_form("mov_md_rd");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "mov DWORD [", VARS["r1"],
                       "],", VARS["r2"]););
  // mov_md_rb end

  // mov_md_vd begin
  cf = make_form("mov_md_vd");
  cf->add_argument("r");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "mov DWORD [", VARS["r"],
                       "],", VARS["a"]););
  // mov_md_vd end

  // mov_rb_rb begin
  cf = make_form("mov_rb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      EG->t({type_flags::memory_static}, "mov ", VARS["r1"], ",", VARS["r2"]););
  // mov_rb_rb end

  // mov_rb_vb begin
  cf = make_form("mov_rb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      EG->t({type_flags::memory_static}, "mov ", VARS["r"], ",", VARS["a"]););
  // mov_rb_vb end

  // mov_rb_mb begin
  cf = make_form("mov_rb_mb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "mov ", VARS["r1"],
                       ", BYTE [", VARS["r2"], "]"););
  // mov_rb_mb end

  // mov_mb_rb begin
  cf = make_form("mov_mb_rb");
  cf->add_argument("r1");
  cf->add_argument("r2");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "mov BYTE [", VARS["r1"],
                       "],", VARS["r2"]););
  // mov_mb_rb end

  // mov_mb_vb begin
  cf = make_form("mov_mb_vb");
  cf->add_argument("r");
  cf->add_argument("a", 8);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "mov BYTE [", VARS["r"],
                       "],", VARS["a"]););
  // mov_mb_vb end

  // mov end

  // movzx begin

  // movzx end

  // call begin

  // call_vd begin
  cf = make_form("call_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      EG->ta({type_flags::memory_static}, "nasm", "call DWORD ", VARS["a"]););
  // call_vd end

  // call_rd begin
  cf = make_form("call_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "call ", VARS["r"]););
  // call_rd end

  // call_md begin
  cf = make_form("call_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->ta({type_flags::memory_static}, "nasm", "call DWORD [",
                        VARS["r"], "]"););
  // call_md end

  // call end

  // jmp begin

  // jmp_vd begin
  cf = make_form("jmp_vd");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(
      EG->ta({type_flags::memory_static}, "nasm", "jmp NEAR ", VARS["a"]););
  // jmp_vd end

  // jmp_rd begin
  cf = make_form("jmp_rd");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->t({type_flags::memory_static}, "jmp ", VARS["r"]););
  // jmp_rd end

  // jmp_md begin
  cf = make_form("jmp_md");
  cf->add_argument("r");

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->ta({type_flags::memory_static}, "nasm", "jmp DWORD [",
                        VARS["r"], "]"););
  // jmp_md end

  // jmp end

  // jxx begin

  // jxx_vd end
  cf = make_form("jxx_vd");
  cf->add_argument("f");
  cf->add_argument("a", 32);

  iv = make_invariant(cf);
  iv->set_flag(type_flags::memory_static);
  iv->PROGRAMMER(EG->ta({type_flags::memory_static}, "nasm", "j", VARS["f"],
                        " NEAR ", VARS["a"]););
  // jxx_vd end

  // jxx end

  // add begin

  // add end

  // sub begin

  // sub end

  // xor begin

  // xor end

  // or begin

  // or end

  // and begin

  // and end

  // inc begin

  // inc end

  // dec begin

  // dec end

  // echg begin

  // echg end

  // lea begin

  // lea end

  // cmp begin

  // cmp end

  // test begin

  // test end
}

} // namespace eg::i8086