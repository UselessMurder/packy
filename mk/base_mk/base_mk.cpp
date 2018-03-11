#include <mk/base_mk/base_mk.h>

namespace mk {
base_mk::base_mk() {}
base_mk::base_mk(fs::out_file *out_file) { file = out_file; }
base_mk::~base_mk() {}
void base_mk::set_file(fs::out_file *out_file) { file = out_file; }
fs::out_file *base_mk::get_file() { return file; }
void base_mk::set_loader(ld::base_ld *current_loader) {
  loader = current_loader;
}
ld::base_ld *base_mk::get_loader() { return loader; }
} // namespace mk