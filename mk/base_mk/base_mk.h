#ifndef BASE_MK_H
#define BASE_MK_H

#include <eg/base/base_eg.h>
#include <fs/file.h>
#include <ld/base_ld/base_ld.h>

namespace mk {
class base_mk {
 protected:
  fs::out_file *file;
  ld::base_ld *loader;

 public:
  base_mk();
  base_mk(fs::out_file *out_file);
  virtual ~base_mk();
  void set_file(fs::out_file *out_file);
  fs::out_file *get_file();
  void set_loader(ld::base_ld *current_loader);
  ld::base_ld *get_loader();
  virtual bool ok_machine(ld::machine_types current_machine) = 0;
  virtual bool ok_loader(ld::loader_types current_loader) = 0;
  virtual void make() = 0;
};
}  // namespace mk

#endif