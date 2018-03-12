#include <cry/crypto.h>
#include <eg/base/base_eg.h>

#define LOOP_STUB                                                              \
  global::named_defer ignore_defer;                                            \
  auto parent = find_node_by_flag<memory_piece>(p, type_flags::memory_code, \
                                                {bypass_flags::parents});      \
  if (parent->check_flag(type_flags::memory_static)) {                         \
    parent->set_flag(type_flags::ignore);                                      \
    ignore_defer.set_defer(                                                    \
        [parent]() { parent->unset_flag(type_flags::ignore); });               \
  }                                                                            \
  this->join("parts", p->get_object_id());                                     \
  DEFER(this->leave("parts", p->get_object_id()););

namespace eg {
crypto_storage::crypto_storage() {}

crypto_storage::~crypto_storage() {
  for (auto a : algs)
    delete a.second;
}

void crypto_storage::add_algorithm(std::string name,
                                   crypto_alghorithm *current_alg) {
  if (algs.count(name) > 0)
    throw std::invalid_argument("Algorithm with some name: " + name +
                                " already exists!");
  algs[name] = current_alg;
}

std::pair<bool, std::uint64_t>
crypto_storage::has_crypto_align(std::string piece_name) {
  if (piece_name.empty())
    return std::make_pair(false, 1);

  if (aligns.count(piece_name) < 1)
    return std::make_pair(false, 1);

  return std::make_pair(true, aligns[piece_name]);
}

void crypto_storage::enable_alter(std::string piece_name, std::string key_name,
                                  std::string alg_name) {
  if (enabled_pieces.count(piece_name) > 0)
    throw std::invalid_argument(
        "Encryption for piece with name: " + piece_name + " already enabled");

  if (keys.count(key_name) > 0)
    throw std::invalid_argument("Key with same name: " + key_name +
                                " already exists");

  if (algs.count(alg_name) < 1)
    throw std::invalid_argument("Algorithm with name: " + alg_name +
                                " is not exists");

  if (algs[alg_name]->check_flag(crypto_flags::block_chiper))
    aligns[piece_name] = algs[alg_name]->get_align();

  enabled_pieces[piece_name] = key_name;

  keys[key_name] = std::make_pair(alg_name, std::vector<uint8_t>());
}

void crypto_storage::prepare_key(memory_piece *piece, std::string key_name) {
  std::pair<std::string, std::vector<uint8_t>> &key = keys[key_name];
  crypto_alghorithm *alg = algs[key.first];

  std::map<std::string, std::uint64_t> parameters;

  if (alg->check_flag(crypto_flags::variable_length_key)) {
    if ((!piece->check_flag(type_flags::memory_static)) && (!piece->check_flag(type_flags::fixed)))
      throw std::domain_error(
          "Cant`t generate key for non static piece with id: " +
          std::to_string(piece->get_object_id()));
    parameters["data-size"] = piece->get_full_size();
  }

  alg->generate_key(&key.second, &parameters);
}

void crypto_storage::alter_memory(std::string piece_name,
                                  std::vector<std::uint8_t> *data) {
  if (enabled_pieces.count(piece_name) < 1)
    return;

  std::pair<std::string, std::vector<uint8_t>> &key =
      keys[enabled_pieces[piece_name]];

  algs[key.first]->alter(data, &key.second);
}

void crypto_storage::get_key(std::string key_name,
                             std::vector<std::uint8_t> *key) {
  if (keys.count(key_name) < 1)
    throw std::invalid_argument("Key with name: " + key_name +
                                " is not exists");

  std::pair<std::string, std::vector<uint8_t>> &current_key = keys[key_name];

  key->clear();
  key->insert(key->end(), current_key.second.begin(), current_key.second.end());
}

std::uint64_t crypto_storage::get_key_size(std::string key_name) {
  if (keys.count(key_name) < 1)
    throw std::invalid_argument("Key with name: " + key_name +
                                " is not exists");
  return static_cast<std::uint64_t>(keys[key_name].second.size());
}

std::string crypto_storage::get_key_type(std::string key_name) {
  if (keys.count(key_name) < 1)
    throw std::invalid_argument("Key with name: " + key_name +
                                " is not exists");
  return keys[key_name].first;
}

build_branch::build_branch(node *parent) : node(parent) {}
build_branch::~build_branch() {}
std::string build_branch::to_string() {
  std::stringstream ss;
  for (auto ch : childs)
    if (ch->check_flag(type_flags::build_memory) ||
        ch->check_flag(type_flags::build_frame))
      ss << node_cast<printable_object>(ch)->to_string();
  return ss.str();
}

build_root::build_root()
    : node(reinterpret_cast<node *>(0)), loop_guard(), key_value_storage(),
      crypto_storage(), machine_state(), recursion_counter(), sin::stub() {

  set_flag(type_flags::build_root);
  base = 0;
  self_state = build_states::programming;
  node *build_node = new build_branch(this);
  build_node->set_flag(type_flags::build_branch);
  node *morph_node = new node(this);
  morph_node->set_flag(type_flags::morph_branch);
  node *trash_node = new node(this);
  trash_node->set_flag(type_flags::trash_branch);

  init_cryptography();
}
build_root::~build_root() {
  for (auto a : assemblers)
    r_asm_free(a.second);
}

void build_root::init_cryptography() {
  // one byte ecb
  crypto_alghorithm *alg = new crypto_alghorithm();
  add_algorithm("one_byte_ecb", alg);
  alg->set_alghorithm(
      [](std::vector<std::uint8_t> *data, std::vector<std::uint8_t> *key) {
        cry::ecb alg(1);
        alg.encrypt(data, key);
      });
  alg->set_generator([](std::vector<std::uint8_t> *key,
                        std::map<std::string, std::uint64_t> *parameters) {
    cry::ecb alg(1);
    alg.generate_key(key);
  });
  // dword ecb
  alg = new crypto_alghorithm();
  add_algorithm("dword_ecb", alg);
  alg->set_flag(crypto_flags::block_chiper);
  alg->set_align(4);
  alg->set_alghorithm(
      [](std::vector<std::uint8_t> *data, std::vector<std::uint8_t> *key) {
        cry::ecb alg(4);
        alg.encrypt(data, key);
      });
  alg->set_generator([](std::vector<std::uint8_t> *key,
                        std::map<std::string, std::uint64_t> *parameters) {
    cry::ecb alg(4);
    alg.generate_key(key);
  });
  // gambling
  alg = new crypto_alghorithm();
  add_algorithm("gambling", alg);
  alg->set_flag(crypto_flags::variable_length_key);
  alg->set_alghorithm(
      [](std::vector<std::uint8_t> *data, std::vector<std::uint8_t> *key) {
        cry::gambling alg;
        alg.encrypt(data, key);
      });
  alg->set_generator([](std::vector<std::uint8_t> *key,
                        std::map<std::string, std::uint64_t> *parameters) {
    cry::gambling alg;
    alg.generate_key(key, (*parameters)["data-size"]);
  });
}

build_states build_root::get_state() { return self_state; }

std::uint64_t build_root::assembly(std::vector<std::uint8_t> *code,
                                   std::string instruction,
                                   std::string assembler_name,
                                   std::uint64_t shift) {
  if (assemblers.count(assembler_name) == 0)
    throw std::invalid_argument("Cant`t find assembler with name: " +
                                assembler_name);
  RAsmCode *acode;
  r_asm_set_pc(assemblers[assembler_name], shift);
  std::uint64_t size = 0;
  if (!(acode = r_asm_rasm_assemble(assemblers[assembler_name],
                                    instruction.c_str(), false)))
    throw std::invalid_argument(
        "Cant`t assembly instruction: " + instruction +
        ", using assembler with name: " + assembler_name);
  DEFER(r_asm_code_free(acode););
  if (!acode->len)
    throw std::domain_error("Length of assembled code: " + instruction +
                            " is zero");
  size = static_cast<std::uint64_t>(acode->len);
  for (std::int32_t i = 0; i < acode->len; i++)
    code->push_back(acode->buf[i]);
  return size;
}

void build_root::apply_alters(std::vector<uint8_t> *content,
                              std::string piece_name) {
  alter_memory(piece_name, content);
}

void build_root::apply_user_input(sin::context *ctx) {
  node *current =
        find_node_by_flag<node>(this, type_flags::node_current,
                                {bypass_flags::self, bypass_flags::childs});

  if(!current->check_flag(type_flags::memory_group))
    throw std::domain_error("Cant`t arrange code outside the group");

  if (ctx->get_form_name().empty()) {
    code_line *current_line = new code_line(current);
    current_line->copy_flags(*ctx);
    current_line->set_assembly(ctx->get_assembly_name());
    for (auto p : ctx->get_args())
      current_line->append_part(p);
    return;
  }
  bool appled = false;


  form *current_form =
      find_node_by_name<form>(get_morph_node(), ctx->get_form_name(),
                              {bypass_flags::self, bypass_flags::childs});
  std::vector<invariant *> invariants;
  current_form->get_invariants(&invariants);
  global::rc.random_shuffle_vector(&invariants);
  for (auto iv : invariants) {
    if (iv->is_match(*ctx) && iv->try_execute(*ctx, &ctx->get_args())) {
      appled = true;
      break;
    }
  }
  if (!appled)
    throw std::domain_error(
        "No one invariant not be executed in form with name: " +
        ctx->get_form_name());
}

bool build_root::validate_bitness(std::uint64_t value, std::uint32_t bitness) {
  switch (bitness) {
  case 8:
    if (value > 0xFF)
      return false;
  case 16:
    if (value > 0xFFFF)
      return false;
  case 32:
    if (value > 0xFFFFFFFF)
      return false;
  }
  return true;
}

bool build_root::validate_bitness_by_bintess_of_current_machine(
    std::uint64_t value) {
  return validate_bitness(value, get_value<std::uint32_t>("bitness"));
}

std::uint64_t build_root::get_stub_with_bitness(std::uint32_t bitness) {
  switch (bitness) {
  case 8:
    return build_stub8;
  case 16:
    return build_stub16;
  case 32:
    return build_stub32;
  case 64:
    return build_stub64;
  }
  return 0;
}

std::uint64_t build_root::get_stub_with_bitness_of_current_machine() {
  return get_stub_with_bitness(get_value<std::uint32_t>("bitness"));
}

std::uint32_t build_root::size_to_bitness(std::uint32_t size) {
  return size * 8;
}

std::uint32_t build_root::bitness_to_size(std::uint32_t bitness) {
  return bitness / 8;
}

node *build_root::get_trash_node() { return childs[2]; }
node *build_root::get_build_node() { return childs[0]; }
node *build_root::get_morph_node() { return childs[1]; }

void build_root::set_base(std::uint64_t current_base) { base = current_base; }
std::uint64_t build_root::get_base() { return base; }

void build_root::build(std::vector<uint8_t> *stub) {
  if (self_state != build_states::programming)
    throw std::domain_error("Cant`t build code, because it already builded");

  get_build_node()->unselect_node();

  aligning();

  taging();

  keyring();

  locating();

  translating(stub);

  self_state = build_states::done;
}

void build_root::aligning() {
  self_state = build_states::aligning;

  get_build_node()->run_functor(
      [this](node *n, std::uint64_t ctx) -> bool {
        if (n->check_flag(type_flags::build_memory)) {
          auto ok = this->has_crypto_align(n->get_name());
          if (ok.first)
            node_cast<memory_piece>(n)->set_align(ok.second);
        }
        return false;
      },
      {bypass_flags::childs}, global::cs.generate_unique_number("ctx"));
}

void build_root::taging() {
  self_state = build_states::taging;

  get_build_node()->run_functor(
      [this](node *n, std::uint64_t ctx) -> bool {
        if (n->check_flag(type_flags::memory_group))
          node_cast<group>(n)->check_static();
        return false;
      },
      {bypass_flags::childs}, global::cs.generate_unique_number("ctx"));
}

void build_root::keyring() {
  self_state = build_states::keyring;

  get_build_node()->run_functor(
      [](node *n, std::uint64_t ctx) -> bool {
        if (n->check_flag(type_flags::build_frame))
          node_cast<frame>(n)->fix_vars();
        return false;
      },
      {bypass_flags::childs}, global::cs.generate_unique_number("ctx"));
  
  for (auto ep : enabled_pieces) {
    auto mp = find_node_by_name<memory_piece>(get_build_node(), ep.first,
                                              {bypass_flags::childs});
    prepare_key(mp, ep.second);
  }
}

void build_root::locating() {
  self_state = build_states::locating;
  get_build_node()->run_functor(
      [this](node *n, std::uint64_t ctx) -> bool {
        if (n->check_flag(type_flags::memory_top))
          this->build_sequence.push_back(node_cast<memory_piece>(n));
        return false;
      },
      {bypass_flags::childs}, global::cs.generate_unique_number("ctx"));
  global::rc.random_shuffle_vector(&build_sequence);
  std::uint64_t current_shift = base;
  for (auto mp : build_sequence) {
    mp->set_shift(current_shift);
    current_shift += mp->get_full_size();
  }
}

void build_root::translating(std::vector<uint8_t> *stub) {
  self_state = build_states::translating;

  for (auto mp : build_sequence) {
    std::uint64_t shift_val = mp->get_shift();
    mp->run_functor(
        [&shift_val](node *n, std::uint64_t ctx) -> bool {
          if (n->check_flag(type_flags::build_memory)) {
            auto mp = node_cast<memory_piece>(n);
            if (mp->is_recall(ctx)) {
              shift_val += mp->get_full_size() - mp->get_payload_size();
              return false;
            }
            mp->set_shift(shift_val);
            if (n->check_flag(type_flags::memory_group))
              n->bind_recall(ctx);
            else
              shift_val += mp->get_full_size();
          }
          return false;
        },
        {bypass_flags::childs}, global::cs.generate_unique_number("ctx"));
  }

  for (auto mp : build_sequence) {
    mp->get_content(stub,
                    {properties_flags::get_root, properties_flags::alter_self,
                     properties_flags::alter_childs});
  }
}

void build_root::get_depended_memory(
    std::string memory_name, std::function<void(memory_piece *mp)> getter,
    global::flag_container flags) {

  for (auto mp : build_sequence) {
    memory_piece *target = reinterpret_cast<memory_piece *>(0);
    if (mp->run_functor(
            [&memory_name, &target](node *n, std::uint64_t ctx) -> bool {
              if (n->check_flag(type_flags::build_memory) &&
                  n->get_name() == memory_name) {
                target = node_cast<memory_piece>(n);
                return true;
              }
              return false;
            },
            {bypass_flags::self, bypass_flags::childs},
            global::cs.generate_unique_number("ctx"))) {

      if ((target->get_state() >= self_state) ||

          ((target->check_flag(type_flags::fixed) ||
            target->check_flag(type_flags::memory_static)) &&
           flags.check_flag(dependence_flags::full_size)) ||

          (target->check_flag(type_flags::memory_static) &&
           flags.check_flag(dependence_flags::payload_size)) ||

          (target->check_flag(type_flags::memory_top) &&
           flags.check_flag(dependence_flags::shift))) {
        getter(target);
        return;
      }

      std::uint64_t shift_val = mp->get_shift();
      auto ok = std::make_pair<std::uint64_t, std::uint64_t>(0, 0);
      mp->run_functor(
          [&memory_name, &getter, &shift_val, &ok,
           &flags](node *n, std::uint64_t ctx) -> bool {
            if (n->check_flag(type_flags::build_memory)) {
              bool finally = false;
              auto mp = node_cast<memory_piece>(n);
              if (mp->is_recall(ctx)) {
                shift_val += mp->get_full_size() - mp->get_payload_size();
                if (ok.first == n->get_object_id() && ok.second == ctx)
                  finally = true;
              } else {
                mp->set_shift(shift_val);
                if (n->get_name() == memory_name) {
                  ok.first = n->get_object_id();
                  ok.second = ctx;
                }
                if (n->check_flag(type_flags::memory_group)) {
                  n->bind_recall(ctx);
                  if ((ok.first == n->get_object_id() && ok.second == ctx) &&
                      flags.check_flag(dependence_flags::shift))
                    finally = true;
                } else {
                  shift_val += mp->get_full_size();
                  if (ok.first == n->get_object_id() && ok.second == ctx)
                    finally = true;
                }
              }
              if (finally) {
                getter(mp);
                return true;
              }
            }
            return false;
          },
          {bypass_flags::self, bypass_flags::childs},
          global::cs.generate_unique_number("ctx"));
      return;
    }
  }
  throw std::invalid_argument(
      "Cant`t get depended memory, because can`t find memory with name: " +
      memory_name);
}

void build_root::duplicate_guard(std::string current_name) {
  bool ok = run_functor(
      [&current_name](node *current_node, std::uint64_t ctx) -> bool {
        if (current_node->get_name() == current_name)
          return true;
        return false;
      },
      {bypass_flags::childs}, global::cs.generate_unique_number("ctx"));
  if (ok)
    throw std::domain_error("Name: " + current_name + " already exists!");
}

form *build_root::make_form(std::string form_name) {
  duplicate_guard(form_name);
  form *cf = new form(get_morph_node());
  cf->set_name(form_name);
  return cf;
}

invariant *build_root::make_invariant(form *blank) {
  invariant *iv = new invariant(blank);
  return iv;
}

void build_root::end() { unselect_node(); }

void build_root::start_frame(std::string frame_name) {
  duplicate_guard(frame_name);
  frame *current_frame = new frame(get_build_node());
  current_frame->set_name(frame_name);
  current_frame->select_node();
}

void build_root::add_var(std::string var_name, std::uint64_t var_size) {
  node *current_node =
      find_node_by_flag<node>(get_build_node(), type_flags::node_current,
                              {bypass_flags::self, bypass_flags::childs});
  if (current_node->check_flag(type_flags::build_frame))
    node_cast<frame>(current_node)->add_var(var_name, var_size);
  else
    find_node_by_flag<frame>(current_node, type_flags::build_frame,
                             {bypass_flags::parents})
        ->add_var(var_name, var_size);
}

void build_root::copy_var(std::string var_name, std::string frame_name) {
  node *current_node =
      find_node_by_flag<node>(get_build_node(), type_flags::node_current,
                              {bypass_flags::self, bypass_flags::childs});
  if (current_node->check_flag(type_flags::build_frame))
    node_cast<frame>(current_node)->add_dependence(var_name, frame_name);
  else
    find_node_by_flag<frame>(current_node, type_flags::build_frame,
                             {bypass_flags::parents})
        ->add_dependence(var_name, frame_name);
}

void build_root::start_segment(std::string segment_name) {
  duplicate_guard(segment_name);
  node *current_node =
      find_node_by_flag<node>(get_build_node(), type_flags::node_current,
                              {bypass_flags::self, bypass_flags::childs});
  group *current_group = new group(current_node);

  if (current_node->check_flag(type_flags::build_branch))
    throw std::domain_error("Cant`t allocate segment with name: " +
                            segment_name + " in non frame node");

  if (current_node->check_flag(type_flags::build_frame)) {
    current_group->set_flag(type_flags::fixed);
    current_group->set_flag(type_flags::memory_top);
  } else
    current_group->set_flag(type_flags::align_code);
  current_group->set_name(segment_name);
  current_group->select_node();
}

void build_root::start_segment(std::string segment_name,
                               std::string frame_name) {
  duplicate_guard(segment_name);
  frame *fr = find_node_by_name<frame>(
      get_build_node(), frame_name, {bypass_flags::childs});
  group *current_group = new group(fr);
  current_group->set_flag(type_flags::fixed);
  current_group->set_flag(type_flags::memory_top);
  current_group->set_name(segment_name);
  current_group->select_node();
}

void build_root::fix_segment(std::string segment_name) {
  memory_piece *mp = find_node_by_name<memory_piece>(
      get_build_node(), segment_name, {bypass_flags::childs});
  if(!mp->check_flag(type_flags::memory_group))
    throw std::domain_error("Name: " + segment_name + " is not name of segment");
  mp->set_flag(type_flags::fixed);
}

void build_root::add_data(std::string data_name,
                          std::vector<uint8_t> *data_content) {
  duplicate_guard(data_name);
  node *current_node =
      find_node_by_flag<node>(get_build_node(), type_flags::node_current,
                              {bypass_flags::self, bypass_flags::childs});
  data_line *current_data = new data_line(current_node);
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    current_data->set_flag(type_flags::memory_top);
  current_data->set_name(data_name);
  current_data->set_content(data_content);
}

void build_root::add_key(std::string key_name) {
  node *current_node =
      find_node_by_flag<node>(get_build_node(), type_flags::node_current,
                              {bypass_flags::self, bypass_flags::childs});
  dependence_line *dl = new dependence_line(current_node, {key_name});
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    dl->set_flag(type_flags::memory_top);
  dl->set_name(key_name);
  dl->set_resolver([this, dl]() {
    std::vector<uint8_t> key;
    this->get_key(dl->get_name_by_index(0), &key);
    dl->set_content(&key);
  });
}

std::string build_root::to_string() {
  return node_cast<build_branch>(get_build_node())->to_string();
}

std::uint64_t build_root::get_entry_point() {
  std::uint64_t shift = 0;
  get_depended_memory("begin",
                      [&shift](memory_piece *mp) { shift = mp->get_shift(); },
                      {dependence_flags::shift});
  return shift;
}

part *
build_root::wr(part *target_part, std::vector<std::uint64_t> values,
               std::function<std::uint64_t(part_wrapper *p)> current_wrapper) {
  part_wrapper *pw = new part_wrapper(get_trash_node(), target_part, values);
  pw->set_wrapper(current_wrapper);
  return pw;
}

part *build_root::dd(std::string begin_name, std::string end_name) {
  cached_dependence *p =
      new cached_dependence(get_trash_node(), {begin_name, end_name});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      LOOP_STUB
      std::uint64_t begin = 0, end = 0;
      this->get_depended_memory(
          p->get_name_by_index(0),
          [&begin](memory_piece *mp) { begin = mp->get_shift(); },
          {dependence_flags::shift});
      this->get_depended_memory(
          p->get_name_by_index(1),
          [&end](memory_piece *mp) { end = mp->get_shift(); },
          {dependence_flags::shift});
      if (begin < end)
        p->set_cached_value(end - begin);
      else
        p->set_cached_value(begin - end);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::ddls(std::string begin_name, std::string end_name,
                       std::string limit_name, bool direction) {
  auto limit = get_value<branch_limit>(limit_name);
  part_wrapper *pw =
      new part_wrapper(get_trash_node(), dd(begin_name, end_name),
                       {limit.forward, limit.reverse, limit.stub});
  pw->set_wrapper([this, direction](part_wrapper *p) -> std::uint64_t {
    if (this->get_state() >= build_states::translating) {
      std::uint64_t val = get_part_value<std::uint64_t>(p->get_wrapped());
      if (direction) {
        if (val > p->get_value_by_index(0))
          throw std::domain_error("Branch overflow detected!");
      } else {
        if (val > p->get_value_by_index(1))
          throw std::domain_error("Branch overflow detected!");
      }
      return val;
    }
    return p->get_value_by_index(2);
  });
  return pw;
}

part *build_root::vshd(std::string var_name) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {var_name});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      p->set_cached_value(find_node_by_flag<frame>(p, type_flags::build_frame,
                                                   {bypass_flags::parents})
                              ->get_var(p->get_name_by_index(0))
                              ->shift);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::vszd(std::string var_name) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {var_name});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      p->set_cached_value(find_node_by_flag<frame>(p, type_flags::build_frame,
                                                   {bypass_flags::parents})
                              ->get_var(p->get_name_by_index(0))
                              ->size);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::frszd() {
  cached_dependence *p = new cached_dependence(get_trash_node(), {});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      p->set_cached_value(find_node_by_flag<frame>(p, type_flags::build_frame,
                                                   {bypass_flags::parents})
                              ->get_frame_size());
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::shd(std::string memory_name) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {memory_name});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      LOOP_STUB
      std::uint64_t shift = 0;
      this->get_depended_memory(
          p->get_name_by_index(0),
          [&shift](memory_piece *mp) { shift = mp->get_shift(); },
          {dependence_flags::shift});
      p->set_cached_value(shift);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::fszd(std::string memory_name) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {memory_name});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      LOOP_STUB
      std::uint64_t full_size = 0;
      this->get_depended_memory(
          p->get_name_by_index(0),
          [&full_size](memory_piece *mp) { full_size = mp->get_full_size(); },
          {dependence_flags::full_size});
      p->set_cached_value(full_size);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::pszd(std::string memory_name) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {memory_name});
  p->set_resolver([this](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      LOOP_STUB
      std::uint64_t payload_size = 0;
      this->get_depended_memory(p->get_name_by_index(0),
                                [&payload_size](memory_piece *mp) {
                                  payload_size = mp->get_payload_size();
                                },
                                {dependence_flags::payload_size});
      p->set_cached_value(payload_size);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

union i64_i8 {
  std::uint64_t val;
  std::uint8_t vals[8];
};

part *build_root::kd(std::string key_name, std::uint32_t bitness,
                     std::uint32_t index) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {key_name});
  p->set_resolver([this, bitness, index](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      std::vector<uint8_t> key;
      this->get_key(p->get_name_by_index(0), &key);
      std::uint32_t size = this->bitness_to_size(bitness);
      if ((index * size) - ((size * index) + size) >
          this->bitness_to_size(this->get_value<std::uint32_t>("bitness")))
        throw std::invalid_argument("Bitness is too hight for register size");
      if (key.size() < (size * index) + size)
        throw std::invalid_argument(
            "Key with name: " + p->get_name_by_index(0) + " is less than " +
            std::to_string((size * index) + size));
      i64_i8 result;
      result.val = 0;
      for (std::uint32_t i = index * size, j = 0; i < (size * index) + size;
           i++, j++)
        result.vals[j] = key[i];
      p->set_cached_value(result.val);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness(bitness);
  });
  return p;
}

part *build_root::c32d(std::string memory_name, global::flag_container flags) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {memory_name});
  p->set_resolver([this, flags](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      LOOP_STUB
      std::uint64_t crc32 = 0;
      this->get_depended_memory(p->get_name_by_index(0),
                                [&crc32, &flags](memory_piece *mp) {
                                  std::vector<uint8_t> data;
                                  mp->get_content(&data, flags);
                                  crc32 = static_cast<std::uint64_t>(
                                      cry::crc32(data).get());
                                },
                                {dependence_flags::content});
      p->set_cached_value(crc32);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

part *build_root::c64d(std::string memory_name, global::flag_container flags) {
  cached_dependence *p = new cached_dependence(get_trash_node(), {memory_name});
  p->set_resolver([this, flags](part *cp) -> std::uint64_t {
    auto p = node_cast<cached_dependence>(cp);
    if (p->check_flag(type_flags::node_cached))
      return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      LOOP_STUB
      std::uint64_t crc64 = 0;
      this->get_depended_memory(p->get_name_by_index(0),
                                [&crc64, &flags](memory_piece *mp) {
                                  std::vector<uint8_t> data;
                                  mp->get_content(&data, flags);
                                  crc64 = cry::crc64(data).get();
                                },
                                {dependence_flags::content});
      p->set_cached_value(crc64);
      return p->get_cached_value();
    }
    return this->get_stub_with_bitness_of_current_machine();
  });
  return p;
}

void build_root::bf(std::string r_name, std::string g_name) {
  if (fake_registers.count(r_name) > 0)
    throw std::invalid_argument("Fake register name: " + r_name +
                                " already binded");

  fake_registers[r_name] =
      std::make_pair<std::string, bool>(get_free(g_name), false);
  grab_register(fake_registers[r_name].first);
}
void build_root::bs(std::string r_name, std::string g_name) {
  if (fake_registers.count(r_name) > 0)
    throw std::invalid_argument("Fake register name: " + r_name +
                                " already binded");

  fake_registers[r_name] =
      std::make_pair<std::string, bool>(get_rand(g_name), true);
  local_save(fake_registers[r_name].first);
  free_register(fake_registers[r_name].first);
  grab_register(fake_registers[r_name].first);
}

void build_root::bsp(std::string rf_name, std::string rr_name) {
  if (fake_registers.count(rf_name) > 0)
    throw std::invalid_argument("Fake register name: " + rf_name +
                                " already binded");
  fake_registers[rf_name] =
      std::make_pair<std::string, bool>(std::string(rr_name), false);
  grab_register(rr_name);
}

void build_root::bss(std::string rf_name, std::string rr_name) {
  if (fake_registers.count(rf_name) > 0)
    throw std::invalid_argument("Fake register name: " + rf_name +
                                " already binded");

  fake_registers[rf_name] =
      std::make_pair<std::string, bool>(std::string(rr_name), true);
  local_save(rr_name);
  free_register(rr_name);
  grab_register(rr_name);
}

std::string build_root::g(std::string r_name) {
  if (fake_registers.count(r_name) < 1)
    throw std::invalid_argument("Fake register name: " + r_name +
                                " is not binded");
  return fake_registers[r_name].first;
}

std::string build_root::g(std::string r_name, std::string half_name) {
  if (fake_registers.count(r_name) < 1)
    throw std::invalid_argument("Fake register name: " + r_name +
                                " is not binded");
  return get_sub_register(fake_registers[r_name].first, half_name);
}

void build_root::fr(std::string r_name) {
  if (fake_registers.count(r_name) < 1)
    throw std::invalid_argument("Fake register name: " + r_name +
                                " is not binded");
  if (fake_registers[r_name].second)
    local_load(fake_registers[r_name].first);
  else
    free_register(fake_registers[r_name].first);
  fake_registers.erase(r_name);
}

} // namespace eg
