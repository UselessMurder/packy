#ifndef PE32_H
#define PE32_H

#include <ld/pe/base_pe/base_pe.h>

namespace ld::pe {

class pe32 : public base_pe {
 private:
  std::uint64_t optional_header;
  bool read_optional_header_from_file();
  void read_thuncks(
      std::uint32_t begin,
      std::vector<std::pair<std::vector<uint8_t>, bool>> &functions);
  void wipe_thuncks(std::uint32_t begin);
  bool is_valid_nt_magic();
  void make_first_section_header(std::vector<std::uint8_t> &header);
  void make_second_section_header(std::vector<uint8_t> &header,
                                  std::uint32_t size);
  void continue_parsing();

 public:
  pe32();
  pe32(fs::in_file *in_file);
  ~pe32();
  image_optional_header32 *get_optional_header();
  image_tls_directory32 *get_tls_directory();
  void wipe_tls_directory();
  machine_types get_machine_type();
  loader_types get_loader_type();
  std::vector<uint8_t> get_rebuilded_header(
      std::uint32_t stub_size, std::uint32_t code_begin, std::uint32_t tls_rva,
      std::pair<std::uint32_t, std::uint32_t> reloc_directory);
  std::vector<uint8_t> get_protected_data();
  std::uint64_t get_real_image_begin();
  std::uint64_t get_real_image_size();
  std::uint64_t get_begin_of_stub();
  std::uint64_t get_sections_vs();
  std::uint64_t get_image_vs();
  void resize_with_file_align(std::vector<uint8_t> *data);
  void resize_with_section_align(std::vector<uint8_t> *data);
  bool is_tls_exists();
  std::uint32_t get_tls_rva();
  void get_part_of_image(std::vector<uint8_t> *part, std::uint32_t rva,
                         std::uint32_t size);
};
}  // namespace ld::pe

#endif