#ifndef MEMORY_PIECE
#define MEMORY_PIECE

#include <eg/base/binding.h>
#include <eg/base/invariant.h>
#include <cstdint>
#include <string>
#include <vector>

namespace eg {
class memory_piece : public node, public printable_object {
   protected:
    std::uint64_t shift;
    std::uint64_t size;
    std::uint64_t overhead;
    std::uint64_t align_value;
    build_states self_state;

   public:
    memory_piece(node *parent);
    virtual ~memory_piece();
    virtual void set_align(std::uint64_t current_align);
    virtual void set_shift(std::uint64_t current_shift);
    virtual std::uint64_t get_shift();
    virtual std::uint64_t get_full_size();
    virtual std::uint64_t get_payload_size();
    build_states get_state();
    virtual void get_content(std::vector<std::uint8_t> *content, global::flag_container flags) = 0;
    virtual std::string to_string() = 0;
};

class align_stub : public memory_piece {
public:
    align_stub(node *parent);
    virtual ~align_stub();
    void set_size(uint64_t new_size);
    void get_content(std::vector<std::uint8_t> *content, global::flag_container flags);
    std::string to_string();
};

class group : public memory_piece {
   protected:
    void resize(node *root);
    virtual void resize_decorator(std::uint8_t build_code);
    std::vector<memory_piece *> sequence;
    std::vector<std::uint8_t> overhead_content;

   public:
    group(node *parent);
    virtual ~group();
    std::uint64_t get_full_size();
    std::uint64_t get_payload_size();
    void check_static();
    void get_content(std::vector<std::uint8_t> *content, global::flag_container flags);
    std::string to_string();
};

class activation_group : public group {
   private:
    std::map<std::string, part *> variables;
    std::function<void(std::map<std::string, part *> *)> balancer;
    invariant *adoptive_parent;
    void run_balancer(node *root);

   public:
    activation_group(node *parent, invariant *adoptive_parent);
    ~activation_group();
    void activate(global::flag_container flags);
    void set_variables(std::map<std::string, part *> *current_variables);
    void set_balancer(std::function<void(std::map<std::string, part *> *)> current_balancer);
};

class code_line : public memory_piece {
   private:
    std::vector<uint8_t> code;
    std::string assembler_name;
    void rebuild(std::uint8_t build_code);

   public:
    code_line(node *parent);
    ~code_line();
    std::uint64_t get_full_size();
    std::uint64_t get_payload_size();
    void set_assembly(std::string current_assembly_name);
    void append_part(part *current_part);
    void get_content(std::vector<std::uint8_t> *content, global::flag_container flags);
    std::string to_string();
};

class data_line : public memory_piece {
   protected:
    std::vector<std::uint8_t> data;
    std::vector<std::uint8_t> overhead_content;
    virtual void prepare(std::uint8_t build_code);

   public:
    data_line(node *parent);
    ~data_line();
    std::uint64_t get_full_size();
    std::uint64_t get_payload_size();
    void set_content(std::vector<std::uint8_t> *content);
    void resize(std::uint64_t current_size);
    void get_content(std::vector<std::uint8_t> *content, global::flag_container flags);
    std::string to_string();
};

class dependence_line : public data_line, public string_container {
   private:
    std::function<void()> resolver;
    void prepare(std::uint8_t build_code);

   public:
    dependence_line(node *parent, std::vector<std::string> names);
    ~dependence_line();
    void set_resolver(std::function<void()> current_resolver);
};

}  // namespace eg

#endif