#include <ld/base_ld/base_ld.h>
#include <ld/pe/pe32/pe32.h>
#include <mk/base_mk/base_mk.h>
#include <mk/pe32_i686/pe32_i686.h>
#include <packy/packy.h>
#include <stdexcept>

packy::packy() { reason = ""; }
packy::packy(boost::filesystem::path input_path,
             boost::filesystem::path output_path) {
  src.set_path(input_path);
  dest.set_path(output_path);
  reason = "";
}
packy::~packy() {}

bool packy::pack() {
  bool result = false;
  try {
    if (!fs::base_file::is_exist(src.get_path()))
      reason = "File not exist!";
    else {
      std::vector<ld::base_ld *> lds;
      std::vector<mk::base_mk *> mks;
      DEFER(for (auto l : lds) delete l;);
      DEFER(for (auto m : mks) delete m;);
      lds.push_back(new ld::pe::pe32(&src));
      mks.push_back(new mk::pe32_i686(&dest));
      for (std::uint32_t i = 0; i < lds.size(); i++) {
        if (lds[i]->parse()) {
          for (std::uint32_t j = 0; j < mks.size(); j++) {
            if (mks[j]->ok_machine(lds[i]->get_machine_type()) &&
                mks[j]->ok_loader(lds[i]->get_loader_type())) {
              mks[j]->set_loader(lds[i]);
              mks[j]->make();
              result = true;
            }
          }
        }
      }
      if (!result)
        reason = "Unsupported image!";
    }
  } catch (std::exception &ec) {
    reason = ec.what();
  } catch (...) {
    reason = "Something was wrong!";
  }
  close();
  return result;
}

std::string packy::why() { return reason; }

void packy::close() {
  src.close();
  dest.close();
}