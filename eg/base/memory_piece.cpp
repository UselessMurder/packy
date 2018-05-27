// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <eg/base/base_eg.h>

namespace eg {
memory_piece::memory_piece(node *parent) : node(parent) {
  shift = 0;
  size = 0;
  overhead = 0;
  align_value = 1;
  self_state = build_states::programming;
  set_flag(type_flags::build_memory);
}

memory_piece::~memory_piece() {}

void memory_piece::set_align(std::uint64_t current_align) {
  align_value = current_align;
}

void memory_piece::set_shift(std::uint64_t current_shift) {
  shift = current_shift;
}

std::uint64_t memory_piece::get_shift() { return shift; }

std::uint64_t memory_piece::get_full_size() { return size + overhead; }

std::uint64_t memory_piece::get_payload_size() { return size; }

build_states memory_piece::get_state() { return self_state; }

align_stub::align_stub(node *parent) : memory_piece(parent) {}
align_stub::~align_stub() {}
void align_stub::set_size(uint64_t new_size) { size = new_size; }
void align_stub::get_content(std::vector<std::uint8_t> *content,
                             global::flag_container flags) {
  for (uint64_t i = 0; i < size; i++)
    content->push_back(
        static_cast<uint8_t>(global::rc.generate_random_number()));
}

std::string align_stub::to_string() {
  std::stringstream ss;
  ss << "stub:" << shift << "@" << size << "(" << get_object_id() << "):\n";
  return ss.str();
}

group::group(node *parent) : memory_piece(parent) {
  set_flag(type_flags::memory_group);
}

group::~group() {}

std::uint64_t group::get_full_size() {
  resize_decorator(0);
  return size + overhead;
}
std::uint64_t group::get_payload_size() {
  resize_decorator(1);
  return size;
}

void group::resize_decorator(std::uint8_t build_code) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  resize(root);
}

void group::resize(node *root) {
  build_root *br = dynamic_cast<build_root *>(root);

  if (br == reinterpret_cast<build_root *>(0))
    throw std::domain_error("Invalid root pointer");

  if (br->get_state() > self_state) {
    std::uint64_t current_size = 0;

    for (auto ch : childs) {
      if (ch->check_flag(type_flags::build_memory))
        current_size += node_cast<memory_piece>(ch)->get_full_size();
    }

    if (br->get_state() > build_states::locating && size < current_size &&
        check_flag(type_flags::fixed)) {
      printf("%s\n", name.c_str());
      printf("%ld %ld %ld \n", size, overhead, current_size);
      printf("%s\n", this->to_string().c_str());
      throw std::domain_error("Size more wan align size, id: " +
                              std::to_string(get_object_id()));
    }

    if (br->get_state() > build_states::locating &&
        (current_size != size + overhead) && check_flag(type_flags::fixed)) {
      overhead = size - current_size;
      size = current_size;
    } else
      size = current_size;

    if (align_value != 1) global::align(size, overhead, align_value);

    self_state = br->get_state();
  }
}

void group::check_static() {
  if (check_flag(type_flags::group_taged)) return;

  if (align_value == 1) {
    std::function<bool(node *, std::uint64_t)> fn =
        [](node *current_node, std::uint64_t ctx) -> bool {
      if (current_node->check_flag(type_flags::memory_group))
        node_cast<group>(current_node)->check_static();

      if (!current_node->check_flag(type_flags::memory_static) &&
          current_node->check_flag(type_flags::build_memory))
        return true;
      return false;
    };

    bool ok = run_functor(fn, {bypass_flags::childs},
                          global::cs.generate_unique_number("ctx"));

    if (!ok) set_flag(type_flags::memory_static);
  }

  set_flag(type_flags::group_taged);
}

void group::get_content(std::vector<std::uint8_t> *content,
                        global::flag_container flags) {
  resize_decorator(2);

  std::vector<uint8_t> tmp;

  global::flag_container child_flags = flags;

  if (child_flags.check_flag(properties_flags::get_root))
    child_flags.unset_flag(properties_flags::get_root);

  if (check_flag(type_flags::group_random)) {
    if (check_flag(type_flags::group_sequence_constructed)) {
      for (auto ch : childs) {
        if (ch->check_flag(type_flags::build_memory))
          sequence.push_back(node_cast<memory_piece>(ch));
      }
      global::rc.random_shuffle_vector(&sequence);
      set_flag(type_flags::group_sequence_constructed);
    }
    for (auto mp : sequence) {
      mp->get_content(&tmp, child_flags);
    }
  } else {
    for (auto ch : childs) {
      if (ch->check_flag(type_flags::build_memory))
        node_cast<memory_piece>(ch)->get_content(&tmp, child_flags);
    }
  }

#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  if (overhead != 0) {
    if (overhead > overhead_content.size()) {
      std::uint64_t diff = overhead - overhead_content.size();
      if (!check_flag(type_flags::align_code))
        for (std::uint64_t i = 0; i < diff; i++)
          overhead_content.push_back(
              static_cast<std::uint8_t>(global::rc.generate_random_number()));
      else
        for (std::uint64_t i = 0; i < diff; i++)
          overhead_content.push_back(root->get_value<std::uint8_t>("nop"));
    } else if (overhead < overhead_content.size()) {
      overhead_content.resize(overhead);
    }
    tmp.insert(tmp.end(), overhead_content.begin(), overhead_content.end());
  }

  if ((flags.check_flag(properties_flags::alter_self) &&
       flags.check_flag(properties_flags::get_root)) ||
      (!flags.check_flag(properties_flags::get_root) &&
       flags.check_flag(properties_flags::alter_childs))) {
    root->apply_alters(&tmp, name);
  }

  if ((tmp.size() != size + overhead) && check_flag(type_flags::fixed))
    throw std::domain_error("Some shit happen!");

  content->insert(content->end(), tmp.begin(), tmp.end());
}

std::string group::to_string() {
  std::stringstream ss;

  ss << "group:" << shift << "@" << name << "(" << get_object_id() << "):\n";

  for (auto ch : childs) {
    if (ch->check_flag(type_flags::build_memory))
      ss << node_cast<memory_piece>(ch)->to_string();
  }

  return ss.str();
}

activation_group::activation_group(node *parent, invariant *second_parent)
    : group(parent) {
  adoptive_parent = second_parent;
  set_flag(type_flags::memory_code);
}
activation_group::~activation_group() {}

void activation_group::set_shift(std::uint64_t current_shift) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  run_balancer(root);
}

void activation_group::resize_decorator(std::uint8_t build_code) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  if (check_flag(type_flags::ignore)) {
    if (build_code == 2)
      throw std::domain_error("Cant`t ignore content request!");
    if (root->get_state() >= build_states::translating) return;
  }

  run_balancer(root);
  resize(root);
}

void activation_group::run_balancer(node *root) {
  if (node_cast<build_root>(root)->get_state() == build_states::translating) {
    if (!check_flag(type_flags::balanced)) {
      form *f = find_node_by_flag<form>(adoptive_parent, type_flags::build_form,
                                        {bypass_flags::parents});
      f->validate_arguments(&variables);
      if (!balancer) return;
      balancer(&variables);
      adoptive_parent->validate_variables(&variables);
      set_flag(type_flags::balanced);
    }
  }
}

void activation_group::set_variables(
    std::map<std::string, part *> *current_variables) {
  variables = (*current_variables);
}

void activation_group::set_balancer(
    std::function<void(std::map<std::string, part *> *)> current_balancer) {
  balancer = current_balancer;
}

code_line::code_line(node *parent) : memory_piece(parent) {
  set_flag(type_flags::memory_code);
}
code_line::~code_line() {}

void code_line::set_assembly(std::string current_assembly_name) {
  assembler_name = current_assembly_name;
}

void code_line::rebuild(std::uint8_t build_code) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif
  if (self_state < root->get_state()) {
    if (check_flag(type_flags::ignore)) {
      if (build_code == 2)
        throw std::domain_error("Cant`t ignore content request!");
      if (root->get_state() >= build_states::translating) return;
    }

    std::stringstream ss;
    code.clear();

    bool simple = true;

    for (auto ch : childs)
      if (ch->check_flag(type_flags::build_part)) {
        ss << node_cast<part>(ch)->to_string();
        if (ch->check_flag(type_flags::dependence) ||
            ch->check_flag(type_flags::will_balanced))
          simple = false;
      }

    if (check_flag(type_flags::do_not_use_shift))
      root->assembly(&code, ss.str(), assembler_name, 0);
    else
      root->assembly(&code, ss.str(), assembler_name, shift);
    size = code.size();
    if (align_value != 1) global::align(size, overhead, align_value);

    if (!simple || check_flag(type_flags::use_shift))
      self_state = root->get_state();
    else
      self_state = build_states::done;
  }
}

std::uint64_t code_line::get_full_size() {
  rebuild(0);
  return size + overhead;
}

std::uint64_t code_line::get_payload_size() {
  rebuild(1);
  return size;
}

void code_line::append_part(part *current_part) {
  current_part->set_parent(this);
}

void code_line::get_content(std::vector<std::uint8_t> *content,
                            global::flag_container flags) {
  rebuild(2);
  std::vector<std::uint8_t> tmp;
  tmp.insert(tmp.end(), code.begin(), code.end());

#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  if (overhead != 0) {
    for (std::uint64_t i = 0; i < overhead; i++)
      tmp.push_back(root->get_value<std::uint8_t>("nop"));
  }

  if ((flags.check_flag(properties_flags::alter_self) &&
       flags.check_flag(properties_flags::get_root)) ||
      (!flags.check_flag(properties_flags::get_root) &&
       flags.check_flag(properties_flags::alter_childs))) {
    root->apply_alters(&tmp, name);
  }

  content->insert(content->end(), tmp.begin(), tmp.end());
}

std::string code_line::to_string() {
  std::stringstream ss;
  ss << "code:" << shift << "@" << name << "("
     << std::to_string(get_object_id()) << ")"
     << ": ";
  for (auto ch : childs) {
    if (ch->check_flag(type_flags::build_part))
      ss << node_cast<part>(ch)->to_string() << "("
         << std::to_string(ch->get_object_id()) << ")";
  }
  ss << "; " << assembler_name << "\n";
  return ss.str();
}

data_line::data_line(node *parent) : memory_piece(parent) {
  set_flag(type_flags::memory_data);
  set_flag(type_flags::memory_static);
}

data_line::~data_line() {}

void data_line::prepare(std::uint8_t build_code) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  if (self_state < root->get_state()) {
    size = data.size();
    if (align_value != 1) global::align(size, overhead, align_value);
    self_state = root->get_state();
  }
}

std::uint64_t data_line::get_full_size() {
  prepare(0);
  return size + overhead;
}
std::uint64_t data_line::get_payload_size() {
  prepare(1);
  return size;
}
void data_line::set_content(std::vector<std::uint8_t> *content) {
  data.clear();
  data.insert(data.end(), content->begin(), content->end());
}

void data_line::resize(std::uint64_t current_size) {
  data.resize(current_size, 0);
}

void data_line::get_content(std::vector<std::uint8_t> *content,
                            global::flag_container flags) {
  prepare(2);

  std::vector<std::uint8_t> tmp;

  tmp.insert(tmp.end(), data.begin(), data.end());

#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  if (overhead != 0) {
    if (overhead > overhead_content.size()) {
      std::uint64_t diff = overhead - overhead_content.size();
      for (std::uint64_t i = 0; i < diff; i++)
        overhead_content.push_back(
            static_cast<std::uint8_t>(global::rc.generate_random_number()));
    } else if (overhead < overhead_content.size())
      overhead_content.resize(overhead);
    tmp.insert(tmp.end(), overhead_content.begin(), overhead_content.end());
  }

  if ((flags.check_flag(properties_flags::alter_self) &&
       flags.check_flag(properties_flags::get_root)) ||
      (!flags.check_flag(properties_flags::get_root) &&
       flags.check_flag(properties_flags::alter_childs))) {
    root->apply_alters(&tmp, name);
  }

  content->insert(content->end(), tmp.begin(), tmp.end());
}

std::string data_line::to_string() {
  std::stringstream ss;

  ss << "data:" << shift << "@" << name << "("
     << std::to_string(get_object_id()) << ")"
     << ": ";

  for (auto b : data) ss << std::hex << std::uint32_t(b);
  ss << "\n";
  return ss.str();
}

dependence_line::dependence_line(node *parent, std::vector<std::string> names)
    : data_line(parent), string_container(names) {
  set_flag(type_flags::dependence);
}

void dependence_line::prepare(std::uint8_t build_code) {
#ifdef USE_CACHE
  build_root *root = node_cast<build_root>(global_root);
#elif
  build_root *root = find_node_by_flag<build_root>(this, type_flags::build_root,
                                                   {bypass_flags::parents});
#endif

  if (check_flag(type_flags::ignore)) {
    if (build_code == 2)
      throw std::domain_error("Cant`t ignore content request!");
    if (root->get_state() >= build_states::translating) return;
  }

  if (!check_flag(type_flags::node_cached)) {
    if (!resolver)
      throw std::domain_error("Resolver for dependence line with id: " +
                              std::to_string(get_object_id()) + " is not set!");
    resolver();
  }

  if (self_state < root->get_state()) {
    size = data.size();
    if (align_value != 1) global::align(size, overhead, align_value);
    self_state = root->get_state();
  }
}

dependence_line::~dependence_line() {}

void dependence_line::set_resolver(std::function<void()> current_resolver) {
  resolver = current_resolver;
}

}  // namespace eg
