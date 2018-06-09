// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <cry/crypto.h>
#include <eg/base/base_eg.h>

#define PART_LOOP_STUB                                                      \
  global::named_defer ignore_defer;                                         \
  auto parent = find_node_by_flag<memory_piece>(p, type_flags::memory_code, \
                                                {bypass_flags::parents});   \
  if (parent->check_flag(type_flags::memory_static)) {                      \
    parent->set_flag(type_flags::ignore);                                   \
    ignore_defer.set_defer(                                                 \
        [parent]() { parent->unset_flag(type_flags::ignore); });            \
  }                                                                         \
  this->join("parts", p->get_object_id());                                  \
  DEFER(this->leave("parts", p->get_object_id()););

namespace eg {
crypto_storage::crypto_storage() {}

crypto_storage::~crypto_storage() {
  for (auto a : algs) delete a.second;
}

void crypto_storage::add_algorithm(std::string name,
                                   crypto_alghorithm *current_alg) {
  if (algs.count(name) > 0)
    throw std::invalid_argument("Algorithm with some name: " + name +
                                " already exists!");
  algs[name] = current_alg;
}

std::pair<bool, std::uint64_t> crypto_storage::has_crypto_align(
    std::string piece_name) {
  if (piece_name.empty()) return std::make_pair(false, 1);

  if (aligns.count(piece_name) < 1) return std::make_pair(false, 1);

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
    if ((!piece->check_flag(type_flags::memory_static)) &&
        (!piece->check_flag(type_flags::fixed)))
      throw std::domain_error(
          "Cant`t generate key for non static piece with id: " +
          std::to_string(piece->get_object_id()));
    parameters["data-size"] = piece->get_full_size();
  }

  alg->generate_key(&key.second, &parameters);
}

void crypto_storage::alter_memory(std::string piece_name,
                                  std::vector<std::uint8_t> *data) {
  if (enabled_pieces.count(piece_name) < 1) return;

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

trash_branch::trash_branch(node *parent) : node(parent) {};
trash_branch::~trash_branch() {};
void trash_branch::grab_node(node *child_node) {
  childs_cache[child_node->get_object_id()] = child_node;
}
void trash_branch::free_node(node *child_node) {
  childs_cache.erase(child_node->get_object_id());
}

build_root::build_root()
    : node(reinterpret_cast<node *>(0)),
      loop_guard(),
      key_value_storage(),
      crypto_storage(),
      machine_state(),
      recursion_counter(),
      sin::stub() {
#ifdef USE_CACHE
  global_root = this;
#endif

  r_lib = NULL;
  set_flag(type_flags::build_root);
  base = 0;
  self_state = build_states::programming;
  node *build_node = new build_branch(this);
  build_node->set_flag(type_flags::build_branch);
  node *morph_node = new node(this);
  morph_node->set_flag(type_flags::morph_branch);
  node *trash_node = new trash_branch(this);
  trash_node->set_flag(type_flags::trash_branch);
  stub_size = 0;
  init_cryptography();
}
build_root::~build_root() {
#ifdef USE_CACHE
  global_root = NULL;
#endif
  for (auto a : assemblers) r_asm_free(a.second);
  global_name_cache.cleanup();
  if (r_lib != 0) r_lib_free(r_lib);
}

void build_root::init_cryptography() {
  // one byte ecb
  crypto_alghorithm *alg = new crypto_alghorithm();
  add_algorithm("byte_ecb", alg);
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
  // aes
  alg = new crypto_alghorithm();
  add_algorithm("aes", alg);
  alg->set_flag(crypto_flags::block_chiper);
  alg->set_align(16);
  alg->set_alghorithm(
      [](std::vector<std::uint8_t> *data, std::vector<std::uint8_t> *key) {
        cry::aes alg;
        alg.encrypt(data, key);
      });
  alg->set_generator([](std::vector<std::uint8_t> *key,
                        std::map<std::string, std::uint64_t> *parameters) {
    cry::aes alg;
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
        "Can`t assembly instruction: " + instruction +
        ", using assembler with name: " + assembler_name);
  DEFER(r_asm_code_free(acode););
  if (!acode->len)
    throw std::domain_error("Length of assembled code: " + instruction +
                            " is zero");
  size = static_cast<std::uint64_t>(acode->len);
  for (std::int32_t i = 0; i < acode->len; i++) code->push_back(acode->buf[i]);

  return size;
}

void build_root::apply_alters(std::vector<uint8_t> *content,
                              std::string piece_name) {
  alter_memory(piece_name, content);
}

void build_root::apply_user_input(sin::context *ctx) {
  if (ctx->get_form_name().empty()) {
    node *current = get_current_node<node>(get_build_node());

    if (!current->check_flag(type_flags::memory_group))
      throw std::domain_error("Cant`t arrange code outside the group");

    code_line *current_line = new code_line(current);
    current_line->copy_flags(*ctx);
    current_line->set_assembly(ctx->get_assembly_name());
    for (auto p : ctx->get_args()) current_line->append_part(p);
    return;
  }
  bool appled = true;

  form *current_form = static_cast<form *>(0);

#ifdef USE_CACHE
#ifdef NODE_DEBUG
  if (form_cache.count(ctx->get_form_name()) < 1)
    appled = false;
  else
#endif
    current_form = form_cache[ctx->get_form_name()];
#elif
  for (auto ch : *(get_morph_node()->get_childs())) {
    if (std::strcmp(ctx->get_form_name().data(), ch->get_name().data()) == 0) {
      current_form = node_cast<form>(ch);
      appled = true;
      break;
    }
  }
#endif

  if (!appled)
    throw std::domain_error("Invalid form name: " + ctx->get_form_name());

  appled = false;

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
      if (value > 0xFF) return false;
    case 16:
      if (value > 0xFFFF) return false;
    case 32:
      if (value > 0xFFFFFFFF) return false;
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

  printf("%s\n", "programming done");

  aligning();

  printf("%s\n", "aligning done");

  taging();

  printf("%s\n", "taging done");

  keyring();

  printf("%s\n", "keyring done");

  locating();

  printf("%s\n", "locating done");

  translating(stub);

  printf("%s\n", "translating done");

  self_state = build_states::done;
}

void build_root::aligning() {
  self_state = build_states::aligning;

  std::function<bool(node *, std::uint64_t)> fn =
      [this](node *n, std::uint64_t ctx) -> bool {
    if (n->check_flag(type_flags::build_memory)) {
      auto ok = this->has_crypto_align(n->get_name());
      if (ok.first) node_cast<memory_piece>(n)->set_align(ok.second);
    }
    return false;
  };

  get_build_node()->run_functor(fn, {bypass_flags::childs},
                                global::cs.generate_unique_number("ctx"));
}

void build_root::taging() {
  self_state = build_states::taging;

  std::function<bool(node *, std::uint64_t)> fn =
      [](node *n, std::uint64_t ctx) -> bool {
    if (n->check_flag(type_flags::memory_group))
      node_cast<group>(n)->check_static();
    return false;
  };

  get_build_node()->run_functor(fn, {bypass_flags::childs},
                                global::cs.generate_unique_number("ctx"));
}

void build_root::keyring() {
  self_state = build_states::keyring;

  std::function<bool(node *, std::uint64_t)> fn =
      [](node *n, std::uint64_t ctx) -> bool {
    if (n->check_flag(type_flags::build_frame)) node_cast<frame>(n)->fix_vars();
    return false;
  };

  get_build_node()->run_functor(fn, {bypass_flags::childs},
                                global::cs.generate_unique_number("ctx"));

  for (auto ep : enabled_pieces) {
    auto mp = find_node_by_name<memory_piece>(get_build_node(), ep.first,
                                              {bypass_flags::childs});
    prepare_key(mp, ep.second);
  }
}

void build_root::locating() {
  self_state = build_states::locating;

  std::function<bool(node *, std::uint64_t)> fn =
      [this](node *n, std::uint64_t ctx) -> bool {
    if (n->check_flag(type_flags::memory_top))
      this->build_sequence.push_back(node_cast<memory_piece>(n));
    return false;
  };

  get_build_node()->run_functor(fn, {bypass_flags::childs},
                                global::cs.generate_unique_number("ctx"));

  global::rc.random_shuffle_vector(&build_sequence);
  std::uint64_t current_shift = base;

  std::vector<std::pair<uint64_t, memory_piece *>> stubs;

  for (uint64_t i = 0; i < build_sequence.size(); i++) {
    if(address_alignment.count(build_sequence[i]->get_name()) > 0) {
      auto aa = address_alignment[build_sequence[i]->get_name()];
      if(current_shift % aa != 0) {
        align_stub *stub_mp = new align_stub(get_trash_node());
        stub_mp->set_size(aa - current_shift % aa);
        stub_mp->set_shift(current_shift);
        current_shift += stub_mp->get_full_size();
        stubs.push_back(std::make_pair(i + stubs.size(), stub_mp));
      }
    }
    build_sequence[i]->set_shift(current_shift);
    current_shift += build_sequence[i]->get_full_size();
  }

  for(auto st : stubs)
    build_sequence.insert(build_sequence.begin() + st.first, st.second);

  stub_size = current_shift - base;
}

void build_root::translating(std::vector<uint8_t> *stub) {
  self_state = build_states::translating;
  for (auto mp : build_sequence) {
    if (mp->check_flag(type_flags::memory_group) &&
        mp->check_flag(type_flags::full_processed))
      continue;
    std::uint64_t shift_val = mp->get_shift();
    std::function<bool(node *, std::uint64_t)> fn =
        [&shift_val](node *n, std::uint64_t ctx) -> bool {
      if (n->check_flag(type_flags::build_memory)) {
        auto mp = node_cast<memory_piece>(n);
        if (mp->is_recall(ctx)) {
          shift_val += mp->get_full_size() - mp->get_payload_size();
          mp->set_flag(type_flags::full_processed);
          return false;
        }
        mp->set_shift(shift_val);

        if(mp->check_flag(type_flags::need_balance)) {
          global::flag_container tflags;
          tflags.set_flag(dependence_flags::content);
          node_cast<activation_group>(mp)->activate(tflags);
        }

        if (n->check_flag(type_flags::memory_group))
          n->bind_recall(ctx);
        else
          shift_val += mp->get_full_size();
      }
      return false;
    };
    mp->run_functor(fn, {bypass_flags::self, bypass_flags::childs},
                    global::cs.generate_unique_number("ctx"));
  }

  for (auto mp : build_sequence) {
    mp->get_content(stub,
                    {properties_flags::get_root, properties_flags::alter_self,
                     properties_flags::alter_childs});
  }
}

void build_root::get_depended_memory(
    std::string memory_name, std::function<void(memory_piece *mp)> &getter,
    global::flag_container flags) {

  memory_piece *target = find_node_by_name<memory_piece>(
      get_build_node(), memory_name, {bypass_flags::childs});

  memory_piece *mp = reinterpret_cast<memory_piece *>(0);

  if (target->check_flag(type_flags::memory_top))
    mp = target;
  else
    mp = find_node_by_flag<memory_piece>(target, type_flags::memory_top,
                                         {bypass_flags::parents});

  if (!target->check_flag(type_flags::memory_group) ||
      target->check_flag(type_flags::full_processed)) {
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
  }

  std::uint64_t shift_val = mp->get_shift();
  auto ok = std::make_pair<std::uint64_t, std::uint64_t>(0, 0);

  std::function<bool(node *, std::uint64_t)> fn =
      [&memory_name, &getter, &shift_val, &ok, &flags](
          node *n, std::uint64_t ctx) -> bool {
    if (n->check_flag(type_flags::build_memory)) {
      bool finally = false;
      auto mp = node_cast<memory_piece>(n);
      if (mp->is_recall(ctx)) {
        shift_val += mp->get_full_size() - mp->get_payload_size();
        mp->set_flag(type_flags::full_processed);
        if (ok.first == n->get_object_id() && ok.second == ctx) finally = true;
      } else {
        mp->set_shift(shift_val);

        if(mp->check_flag(type_flags::need_balance))
          node_cast<activation_group>(mp)->activate(flags);

        if ((std::strcmp(memory_name.data(), n->get_name().data()) == 0)) {
          ok.first = n->get_object_id();
          ok.second = ctx;
        }
        if (n->check_flag(type_flags::memory_group)) {
          if ((ok.first == n->get_object_id() && ok.second == ctx) &&
              flags.check_flag(dependence_flags::shift))
            finally = true;
          else
            n->bind_recall(ctx);
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
  };

  mp->run_functor(fn, {bypass_flags::self, bypass_flags::childs},
                  global::cs.generate_unique_number("ctx"));
}

void build_root::duplicate_guard(std::string current_name) {
#ifdef NODE_DEBUG

  std::function<bool(node *, std::uint64_t)> fn =
      [&current_name](node *current_node, std::uint64_t ctx) -> bool {
    if (current_node->get_name() == current_name) return true;
    return false;
  };

  bool ok = run_functor(fn, {bypass_flags::childs},
                        global::cs.generate_unique_number("ctx"));
  if (ok) throw std::domain_error("Name: " + current_name + " already exists!");
#endif
}

void build_root::set_address_alignment(std::string memory_name, uint64_t value) {
    address_alignment[memory_name] = value;
}

form *build_root::make_form(std::string form_name) {
  duplicate_guard(form_name);
  form *cf = new form(get_morph_node());
  cf->set_name(form_name);
#ifdef USE_CACHE
  form_cache[form_name] = cf;
#endif
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
  node *current_node = get_current_node<node>(get_build_node());
  if (current_node->check_flag(type_flags::build_frame))
    node_cast<frame>(current_node)->add_var(var_name, var_size);
  else
    find_node_by_flag<frame>(current_node, type_flags::build_frame,
                             {bypass_flags::parents})
        ->add_var(var_name, var_size);
}

void build_root::copy_var(std::string var_name, std::string frame_name) {
  node *current_node = get_current_node<node>(get_build_node());
  if (current_node->check_flag(type_flags::build_frame))
    node_cast<frame>(current_node)->add_dependence(var_name, frame_name);
  else
    find_node_by_flag<frame>(current_node, type_flags::build_frame,
                             {bypass_flags::parents})
        ->add_dependence(var_name, frame_name);
}

void build_root::start_segment(std::string segment_name) {
  duplicate_guard(segment_name);
  node *current_node = get_current_node<node>(get_build_node());
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

void build_root::start_top_segment(std::string segment_name) {
  duplicate_guard(segment_name);
  node *current_node = get_current_node<node>(get_build_node());
  group *current_group = reinterpret_cast<group *>(0);
  if (!current_node->check_flag(type_flags::build_frame)) {
    current_node = find_node_by_flag<node>(
        current_node, type_flags::build_frame, {bypass_flags::parents});
  }
  current_group = new group(current_node);
  current_group->set_flag(type_flags::fixed);
  current_group->set_flag(type_flags::memory_top);
  current_group->set_name(segment_name);
  current_group->select_node();
}

void build_root::start_segment(std::string segment_name,
                               std::string frame_name) {
  duplicate_guard(segment_name);
  frame *fr = find_node_by_name<frame>(get_build_node(), frame_name,
                                       {bypass_flags::childs});
  group *current_group = new group(fr);
  current_group->set_flag(type_flags::fixed);
  current_group->set_flag(type_flags::memory_top);
  current_group->set_name(segment_name);
  current_group->select_node();
}

void build_root::fix_segment(std::string segment_name) {
  memory_piece *mp = find_node_by_name<memory_piece>(
      get_build_node(), segment_name, {bypass_flags::childs});
  if (!mp->check_flag(type_flags::memory_group))
    throw std::domain_error("Name: " + segment_name +
                            " is not name of segment");
  mp->set_flag(type_flags::fixed);
}

void build_root::add_top_data(std::string data_name,
                              std::vector<uint8_t> *data_content) {
  duplicate_guard(data_name);
  node *current_node = get_current_node<node>(get_build_node());
  data_line *current_data = reinterpret_cast<data_line *>(0);
  if (!current_node->check_flag(type_flags::build_frame)) {
    current_node = find_node_by_flag<node>(
        current_node, type_flags::build_frame, {bypass_flags::parents});
  }
  current_data = new data_line(current_node);
  current_data->set_flag(type_flags::memory_top);
  current_data->set_name(data_name);
  current_data->set_content(data_content);
}

void build_root::add_data(std::string data_name,
                          std::vector<uint8_t> *data_content) {
  duplicate_guard(data_name);
  node *current_node = get_current_node<node>(get_build_node());
  data_line *current_data = new data_line(current_node);
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    current_data->set_flag(type_flags::memory_top);
  current_data->set_name(data_name);
  current_data->set_content(data_content);
}

void build_root::add_data(std::string data_name, std::uint64_t data_size) {
  duplicate_guard(data_name);
  node *current_node = get_current_node<node>(get_build_node());
  data_line *current_data = new data_line(current_node);
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    current_data->set_flag(type_flags::memory_top);
  current_data->set_name(data_name);
  current_data->resize(data_size);
}

void build_root::add_key(std::string key_name) {
  duplicate_guard(key_name);
  node *current_node = get_current_node<node>(get_build_node());
  dependence_line *dl = new dependence_line(current_node, {key_name});
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    dl->set_flag(type_flags::memory_top);
  dl->set_name(key_name);
  dl->set_resolver([this, dl]() {
    std::vector<uint8_t> key;
    this->get_key(dl->get_name_by_index(0), &key);
    dl->set_content(&key);
    dl->set_flag(type_flags::node_cached);
  });
}

void build_root::add_address(std::string addr_name, std::string memory_name,
                             std::uint64_t base) {
  duplicate_guard(addr_name);
  node *current_node = get_current_node<node>(get_build_node());
  dependence_line *dl = new dependence_line(current_node, {memory_name});
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    dl->set_flag(type_flags::memory_top);
  dl->set_name(addr_name);
  dl->set_resolver([this, dl, base]() {
    dl->set_flag(type_flags::ignore);
    DEFER(dl->unset_flag(type_flags::ignore););
    std::vector<uint8_t> address;
    if (this->get_state() >= build_states::translating) {
      std::uint64_t shift = 0;
      std::function<void(memory_piece * mp)> fn = [&shift](memory_piece *mp) {
        shift = mp->get_shift();
      };
      this->get_depended_memory(dl->get_name_by_index(0), fn,
                                {dependence_flags::shift});
      shift += base;
      global::value_to_vector<std::uint64_t>(
          &address, shift, this->get_value<std::uint32_t>("bitness") / 8);
      dl->set_flag(type_flags::node_cached);
    } else
      address.resize(this->get_value<std::uint32_t>("bitness") / 8);
    dl->set_content(&address);
  });
}

void build_root::add_processed_data(
    std::string data_name,
    std::function<void(build_root *, dependence_line *)> processor) {
  duplicate_guard(data_name);
  node *current_node = get_current_node<node>(get_build_node());
  dependence_line *dl = new dependence_line(current_node, {});
  if (current_node->check_flag(type_flags::build_frame) ||
      current_node->check_flag(type_flags::build_branch))
    dl->set_flag(type_flags::memory_top);
  dl->set_name(data_name);
  dl->set_resolver([this, dl, processor]() {
    dl->set_flag(type_flags::ignore);
    DEFER(dl->unset_flag(type_flags::ignore););
    processor(this, dl);
  });
}

std::string build_root::to_string() {
  return node_cast<build_branch>(get_build_node())->to_string();
}

std::uint64_t build_root::get_memory_rva(std::string name) {
  std::uint64_t shift = 0;
  std::function<void(memory_piece * mp)> fn = [&shift](memory_piece *mp) {
    shift = mp->get_shift();
  };
  get_depended_memory(name, fn, {dependence_flags::shift});
  return shift;
}

std::uint64_t build_root::get_memory_payload_size(std::string memory_name) {
  std::uint64_t size = 0;
  std::function<void(memory_piece * mp)> fn = [&size](memory_piece *mp) {
    size = mp->get_payload_size();
  };
  get_depended_memory(memory_name, fn, {dependence_flags::shift});
  return size;
}

part *build_root::ssd() {
  dependence_part *p = new dependence_part(get_trash_node());
  p->set_resolver(
      [this](part *cp) -> std::uint64_t { return this->stub_size; });
  return p;
}

part *build_root::wr(
    part *target_part, std::vector<std::uint64_t> values,
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      PART_LOOP_STUB
      std::uint64_t begin = 0, end = 0;
      std::function<void(memory_piece * mp)> fn = [&begin](memory_piece *mp) {
        begin = mp->get_shift();
      };
      this->get_depended_memory(p->get_name_by_index(0), fn,
                                {dependence_flags::shift});
      fn = [&end](memory_piece *mp) { end = mp->get_shift(); };
      this->get_depended_memory(p->get_name_by_index(1), fn,
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      PART_LOOP_STUB
      std::uint64_t shift = 0;
      std::function<void(memory_piece * mp)> fn = [&shift](memory_piece *mp) {
        shift = mp->get_shift();
        if (shift == 0) printf("%s\n", "shit");
      };
      this->get_depended_memory(p->get_name_by_index(0), fn,
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      PART_LOOP_STUB
      std::uint64_t full_size = 0;
      std::function<void(memory_piece * mp)> fn =
          [&full_size](memory_piece *mp) { full_size = mp->get_full_size(); };
      this->get_depended_memory(p->get_name_by_index(0), fn,
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      PART_LOOP_STUB
      std::uint64_t payload_size = 0;
      std::function<void(memory_piece * mp)> fn =
          [&payload_size](memory_piece *mp) {
            payload_size = mp->get_payload_size();
          };
      this->get_depended_memory(p->get_name_by_index(0), fn,
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      std::vector<uint8_t> key;
      this->get_key(p->get_name_by_index(0), &key);
      std::uint32_t size = this->bitness_to_size(bitness);
      if (size >
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      PART_LOOP_STUB
      std::uint64_t crc32 = 0;
      std::function<void(memory_piece * mp)> fn = [&crc32,
                                                   &flags](memory_piece *mp) {
        std::vector<uint8_t> data;
        mp->get_content(&data, flags);
        crc32 = static_cast<std::uint64_t>(cry::crc32(data).get());
      };
      this->get_depended_memory(p->get_name_by_index(0), fn,
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
    if (p->check_flag(type_flags::node_cached)) return p->get_cached_value();
    if (this->get_state() >= build_states::translating) {
      PART_LOOP_STUB
      std::uint64_t crc64 = 0;

      std::function<void(memory_piece * mp)> fn = [&crc64,
                                                   &flags](memory_piece *mp) {
        std::vector<uint8_t> data;
        mp->get_content(&data, flags);
        crc64 = cry::crc64(data).get();
      };

      this->get_depended_memory(p->get_name_by_index(0), fn,
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
      std::pair<std::string, uint64_t>(get_free(g_name), 0xFFFFFFFFFFFFFFFF);
  grab_register(fake_registers[r_name].first);
}

void build_root::bs(std::string r_name, std::string g_name, uint64_t ctx) {
  if (fake_registers.count(r_name) > 0)
    throw std::invalid_argument("Fake register name: " + r_name +
                                " already binded");

  if (fake_contexts.count(ctx) < 1)
    fake_registers[r_name] =
        std::pair<std::string, uint64_t>(get_rand(g_name), ctx);
  else
    fake_registers[r_name] = std::pair<std::string, uint64_t>(
        get_rand(g_name, fake_contexts[ctx]), ctx);

  fake_contexts[ctx].insert(fake_registers[r_name].first);
  local_save(fake_registers[r_name].first, ctx);
  free_register(fake_registers[r_name].first);
  grab_register(fake_registers[r_name].first);
}

void build_root::bsp(std::string rf_name, std::string rr_name) {
  if (fake_registers.count(rf_name) > 0)
    throw std::invalid_argument("Fake register name: " + rf_name +
                                " already binded");
  fake_registers[rf_name] =
      std::pair<std::string, uint64_t>(rr_name, 0xFFFFFFFFFFFFFFFF);
  grab_register(rr_name);
}

void build_root::bss(std::string rf_name, std::string rr_name, uint64_t ctx) {
  if (fake_registers.count(rf_name) > 0)
    throw std::invalid_argument("Fake register name: " + rf_name +
                                " already binded");

  if (fake_contexts.count(ctx) < 1) {
    if (fake_contexts[ctx].find(rr_name) != fake_contexts[ctx].end())
      throw std::invalid_argument(
          "Register with name: " + rr_name +
          "already exists in context: " + std::to_string(ctx));
  }

  fake_registers[rf_name] = std::pair<std::string, uint64_t>(rr_name, ctx);
  fake_contexts[ctx].insert(rr_name);
  local_save(rr_name, ctx);
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
  std::pair<std::string, uint64_t> &fake = fake_registers[r_name];

  if (fake.second != 0xFFFFFFFFFFFFFFFF) {
    local_load(fake.first, fake.second);
    fake_contexts[fake.second].erase(fake.first);
    if (fake_contexts[fake.second].size() == 0)
      fake_contexts.erase(fake.second);
  } else
    free_register(fake.first);
  fake_registers.erase(r_name);
}

void build_root::dump_fakes() {
  for (auto fake : fake_registers)
    printf("%s %s\n", fake.first.c_str(), fake.second.first.c_str());
}

}  // namespace eg
