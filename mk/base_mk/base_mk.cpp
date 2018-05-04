// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <mk/base_mk/base_mk.h>

namespace mk {
base_mk::base_mk() {
  file = reinterpret_cast<fs::out_file *>(0);
  loader = reinterpret_cast<ld::base_ld *>(0);
}
base_mk::base_mk(fs::out_file *out_file) {
  file = out_file;
  loader = reinterpret_cast<ld::base_ld *>(0);
}
base_mk::~base_mk() {}
void base_mk::set_file(fs::out_file *out_file) { file = out_file; }
fs::out_file *base_mk::get_file() { return file; }
void base_mk::set_loader(ld::base_ld *current_loader) {
  loader = current_loader;
}
ld::base_ld *base_mk::get_loader() { return loader; }
}  // namespace mk