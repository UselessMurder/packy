#ifndef FRAME_H
#define FRAME_H

#include <eg/base/binding.h>
#include <map>
#include <string>
#include <vector>
#include <eg/base/memory_piece.h>

namespace eg {

struct var {
    std::uint64_t size;
    std::uint64_t shift;
};

class frame : public node, public printable_object {
   private:
    std::uint64_t size;
    std::map<std::string, var> vars;
    std::map<std::string, std::string> fixed;
    void get_voids(std::vector<var> *voids);
    void fill(var space, std::vector<std::string> *values);

   public:
    frame(node *parent);
    ~frame();
    void add_var(std::string var_name, std::uint64_t size);
    void add_dependence(std::string var_name, std::string frame_name);
    void fix_vars();
    var *get_var(std::string var_name);
    std::uint64_t get_frame_size();
    std::string to_string();
};

}  // namespace eg

#endif