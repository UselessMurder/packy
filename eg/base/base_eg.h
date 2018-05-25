#ifndef BASE_EG_H
#define BASE_EG_H

#include <eg/base/binding.h>
#include <eg/base/form.h>
#include <eg/base/frame.h>
#include <eg/base/machine_state.h>
#include <r_asm.h>
#include <r_lib.h>

namespace eg {

class crypto_storage {
 protected:
  std::map<std::string, crypto_alghorithm *> algs;
  std::map<std::string, std::pair<std::string, std::vector<std::uint8_t>>> keys;
  std::map<std::string, std::string> enabled_pieces;
  std::map<std::string, std::uint64_t> aligns;

  virtual void keyring() = 0;
  void prepare_key(memory_piece *piece, std::string key_name);

  std::pair<bool, std::uint64_t> has_crypto_align(std::string piece_name);

 public:
  crypto_storage();
  virtual ~crypto_storage();

  void add_algorithm(std::string name, crypto_alghorithm *current_alg);
  void enable_alter(std::string piece_name, std::string key_name,
                    std::string alg_name);

  void alter_memory(std::string piece_name, std::vector<std::uint8_t> *data);
  void get_key(std::string key_name, std::vector<std::uint8_t> *key);
  std::uint64_t get_key_size(std::string key_name);
  std::string get_key_type(std::string key_name);
};

namespace sin {

class context : public global::flag_container {
 private:
  std::string form_name;
  std::string assembly_name;
  std::vector<part *> args;
  node *trash_node;

  template <typename T>
  void parse(T t) {
    args.push_back(create_simple_part<T>(trash_node, t));
  };
  template <typename A, typename... B>
  void parse(A head, B... tail) {
    parse(head);
    parse(tail...);
  }

 public:
  context() {
    assembly_name = "default";
    trash_node = reinterpret_cast<node *>(0);
  }
  template <typename... Args>
  context(node *trash, Args... args) {
    trash_node = trash;
    parse(args...);
    assembly_name = "default";
  }
  ~context() {}
  void set_form_name(std::string current_form_name) {
    form_name = current_form_name;
  }
  void set_assembly_name(std::string current_assembly_name) {
    assembly_name = current_assembly_name;
  }
  std::string &get_form_name() { return form_name; }
  std::string &get_assembly_name() { return assembly_name; }
  std::vector<part *> &get_args() { return args; }
};

template <>
inline void context::parse<part *>(part *p) {
  args.push_back(p);
};

class stub {
 protected:
  virtual void apply_user_input(context *context) = 0;

 public:
  stub() {}
  virtual ~stub() {}
  virtual node *get_trash_node() = 0;

  template <typename... Args>
  void t(global::flag_container instruction_flags, Args... args) {
    context ctx(get_trash_node(), args...);
    ctx.move_flags(instruction_flags);
    apply_user_input(&ctx);
  }
  template <typename... Args>
  void t(Args... args) {
    context ctx(get_trash_node(), args...);
    apply_user_input(&ctx);
  }
  template <typename... Args>
  void ta(global::flag_container instruction_flags, std::string asm_name,
          Args... args) {
    context ctx(get_trash_node(), args...);
    ctx.move_flags(instruction_flags);
    ctx.set_assembly_name(asm_name);
    apply_user_input(&ctx);
  }
  template <typename... Args>
  void ta(std::string asm_name, Args... args) {
    context ctx(get_trash_node(), args...);
    ctx.set_assembly_name(asm_name);
    apply_user_input(&ctx);
  }
  template <typename... Args>
  void f(global::flag_container instruction_flags, std::string name,
         Args... args) {
    context ctx(get_trash_node(), args...);
    ctx.move_flags(instruction_flags);
    ctx.set_form_name(name);
    apply_user_input(&ctx);
  }
  void f(global::flag_container instruction_flags, std::string name) {
    context ctx;
    ctx.move_flags(instruction_flags);
    ctx.set_form_name(name);
    apply_user_input(&ctx);
  }
  template <typename... Args>
  void f(std::string name, Args... args) {
    context ctx(get_trash_node(), args...);
    ctx.set_form_name(name);
    apply_user_input(&ctx);
  }
  void f(std::string name) {
    context ctx;
    ctx.set_form_name(name);
    apply_user_input(&ctx);
  }
};

}  // namespace sin

struct branch_limit {
  std::uint64_t forward;
  std::uint64_t reverse;
  std::uint64_t stub;
};

class build_branch : public node, public printable_object {
 public:
  build_branch(node *parent);
  ~build_branch();
  std::string to_string();
};

class trash_branch : public node {
private:
  std::unordered_map<uint64_t, node *> childs_cache;
public:
  trash_branch(node *parent);
  ~trash_branch();
  void grab_node(node *child_node);
  void free_node(node *child_node);
};

class build_root : public node,
                   public loop_guard,
                   public key_value_storage,
                   public crypto_storage,
                   public machine_state,
                   public recursion_counter,
                   public sin::stub,
                   public printable_object {
 protected:
  build_states self_state;
  std::vector<memory_piece *> build_sequence;
  RLib *r_lib;
  std::uint64_t base;
  std::uint64_t stub_size;
  std::map<std::string, std::pair<std::string, uint64_t>> fake_registers;
  std::map<uint64_t, std::set<std::string>> fake_contexts;

  #ifdef USE_CACHE
  std::map<std::string, form *> form_cache;
  #endif

  virtual void init_assemblers() = 0;
  virtual void init_invariants() = 0;
  void init_cryptography();

  void apply_user_input(sin::context *ctx);

  void duplicate_guard(std::string current_name);

  void aligning();
  void taging();
  void keyring();
  void locating();
  void translating(std::vector<uint8_t> *stub);

  form *make_form(std::string form_name);

  invariant *make_invariant(form *blank);

 public:

  std::map<std::string, RAsm *> assemblers;

  build_root();
  virtual ~build_root();

  build_states get_state();

  std::uint64_t assembly(std::vector<std::uint8_t> *code,
                         std::string instruction, std::string assembler_name,
                         std::uint64_t shift);
  void apply_alters(std::vector<uint8_t> *content, std::string piece_name);

  bool validate_bitness(std::uint64_t value, std::uint32_t bitness);
  bool validate_bitness_by_bintess_of_current_machine(std::uint64_t value);
  std::uint64_t get_stub_with_bitness(std::uint32_t bitness);
  std::uint64_t get_stub_with_bitness_of_current_machine();
  std::uint32_t size_to_bitness(std::uint32_t size);
  std::uint32_t bitness_to_size(std::uint32_t bitness);

  node *get_trash_node();
  node *get_build_node();
  node *get_morph_node();

  void set_base(std::uint64_t current_base);
  std::uint64_t get_base();

  void get_depended_memory(std::string memory_name,
                           std::function<void(memory_piece *mp)> &getter,
                           global::flag_container flags);

  void end();

  void start_frame(std::string frame_name);
  void start_segment(std::string segment_name);
  void start_top_segment(std::string segment_name);
  void start_segment(std::string segment_name, std::string frame_name);
  void fix_segment(std::string segment_name);

  void add_var(std::string var_name, std::uint64_t var_size);
  void copy_var(std::string var_name, std::string frame_name);

  void add_top_data(std::string data_name, std::vector<uint8_t> *data_content);
  void add_data(std::string data_name, std::vector<uint8_t> *data_content);
  void add_data(std::string data_name, std::uint64_t data_size);
  void add_key(std::string key_name);
  void add_address(std::string addr_name, std::string memory_name,
                   std::uint64_t base);
  void add_processed_data(
      std::string addr_name,
      std::function<void(build_root *, dependence_line *)> processor);

  part *ssd();
  part *wr(part *target_part, std::vector<std::uint64_t> values,
           std::function<std::uint64_t(part_wrapper *p)> current_wrapper);
  part *dd(std::string begin_name, std::string end_name);
  part *ddls(std::string begin_name, std::string end_name,
             std::string limit_name, bool direction);
  part *vshd(std::string var_name);
  part *vszd(std::string var_name);
  part *frszd();
  part *shd(std::string memory_name);
  part *fszd(std::string memory_name);
  part *pszd(std::string memory_name);
  part *kd(std::string key_name, std::uint32_t bitness, std::uint32_t index);
  part *c32d(std::string memory_name, global::flag_container flags);
  part *c64d(std::string memory_name, global::flag_container flags);

  std::string to_string();

  void bf(std::string r_name, std::string g_name);
  void bs(std::string r_name, std::string g_name, uint64_t ctx);

  void bsp(std::string rf_name, std::string rr_name);
  void bss(std::string rf_name, std::string rr_name, uint64_t ctx);

  std::string g(std::string r_name);
  std::string g(std::string r_name, std::string half_name);
  void fr(std::string r_name);

  void dump_fakes();

  void build(std::vector<uint8_t> *stub);

  virtual void copy_fundamental() = 0;

  std::uint64_t get_memory_rva(std::string memory_name);
  std::uint64_t get_memory_payload_size(std::string memory_name);
};

}  // namespace eg

#endif