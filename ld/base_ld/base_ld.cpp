// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <ld/base_ld/base_ld.h>

namespace ld {
base_ld::base_ld() { file = 0; }
base_ld::base_ld(fs::in_file *in_file) { file = in_file; }
base_ld::~base_ld() {}
void base_ld::set_file(fs::in_file *in_file) { file = in_file; }
fs::in_file *base_ld::get_file() { return file; }
} // namespace ld