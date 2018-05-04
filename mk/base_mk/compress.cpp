// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <cstring>
#include <global/global_entities.h>
#include <lzo/lzo1f.h>
#include <lzo/lzoconf.h>
#include <mk/base_mk/compress.h>
#include <stdexcept>

namespace mk {
bool lzo_inited = false;

void check_status() {
  if (!lzo_inited) {
    lzo_inited = true;
    if (lzo_init() != LZO_E_OK)
      throw std::domain_error("Cant`t init lzo compress");
  }
}

lzo_compress::lzo_compress() {
  check_status();
  wrkmem = static_cast<lzo_voidp>(malloc(LZO1F_MEM_COMPRESS));
}

lzo_compress::~lzo_compress() { free(wrkmem); }

void lzo_compress::compress(std::vector<uint8_t> &data) {
  lzo_bytep in = static_cast<lzo_bytep>(std::malloc(data.size()));
  DEFER(std::free(in););
  lzo_bytep out = static_cast<lzo_bytep>(
      std::malloc(data.size() + (data.size() / (16 + 64 + 3))));
  DEFER(std::free(out););
  std::memcpy(in, &data[0], data.size());

  lzo_uint new_len = data.size() + (data.size() / (16 + 64 + 3)); 

  if (lzo1f_1_compress(in, data.size(), out, &new_len, wrkmem) != LZO_E_OK)
  	throw std::domain_error("Cant`t compess data via lzo");

  if(new_len >= data.size())
  	throw std::domain_error("Incompressible data");
  data.clear();

  for(lzo_uint i = 0; i < new_len; i++)
  	data.push_back(out[i]);
}

} // namespace mk