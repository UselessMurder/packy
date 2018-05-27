#ifndef BASE_PE_H
#define BASE_PE_H

#include <global/global_entities.h>
#include <ld/base_ld/base_ld.h>

namespace ld::pe {

struct image_dos_header {
  std::uint16_t e_magic;
  std::uint16_t e_cblp;
  std::uint16_t e_cp;
  std::uint16_t e_crlc;
  std::uint16_t e_cparhdr;
  std::uint16_t e_minalloc;
  std::uint16_t e_maxalloc;
  std::uint16_t e_ss;
  std::uint16_t e_sp;
  std::uint16_t e_csum;
  std::uint16_t e_ip;
  std::uint16_t e_cs;
  std::uint16_t e_lfarlc;
  std::uint16_t e_ovno;
  std::uint16_t e_res[4];
  std::uint16_t e_oemid;
  std::uint16_t e_oeminfo;
  std::uint16_t e_res2[10];
  std::uint32_t e_lfanew;
};

struct image_file_header {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};

struct image_data_directory {
  std::uint32_t virtual_address;
  std::uint32_t size;
};

struct image_optional_header32 {
  std::uint16_t magic;
  std::uint8_t major_linker_version;
  std::uint8_t minor_linker_version;
  std::uint32_t size_of_code;
  std::uint32_t size_of_initialized_data;
  std::uint32_t size_of_uninitialized_data;
  std::uint32_t address_of_entry_point;
  std::uint32_t base_of_code;
  std::uint32_t base_of_data;
  std::uint32_t image_base;
  std::uint32_t section_alignment;
  std::uint32_t file_alignment;
  std::uint16_t major_operating_system_version;
  std::uint16_t minor_operating_system_version;
  std::uint16_t major_image_version;
  std::uint16_t minor_image_version;
  std::uint16_t major_subsystem_version;
  std::uint16_t minor_subsystem_version;
  std::uint32_t win_32_version_value;
  std::uint32_t size_of_image;
  std::uint32_t size_of_headers;
  std::uint32_t check_sum;
  std::uint16_t subsystem;
  std::uint16_t dll_characteristics;
  std::uint32_t size_of_stack_reserve;
  std::uint32_t size_of_stack_commit;
  std::uint32_t size_of_heap_reserve;
  std::uint32_t size_of_heap_commit;
  std::uint32_t loader_flags;
  std::uint32_t number_of_rva_and_sizes;
  image_data_directory data_directory[16];
};

struct image_optional_header64 {
  std::uint16_t magic;
  std::uint8_t major_linker_version;
  std::uint8_t minor_linker_version;
  std::uint32_t size_of_code;
  std::uint32_t size_of_initialized_data;
  std::uint32_t size_of_uninitialized_data;
  std::uint32_t address_of_entry_point;
  std::uint32_t base_of_code;
  std::uint64_t image_base;
  std::uint32_t section_alignment;
  std::uint32_t file_alignment;
  std::uint16_t major_operating_system_version;
  std::uint16_t minor_operating_system_version;
  std::uint16_t major_image_version;
  std::uint16_t minor_image_version;
  std::uint16_t major_subsystem_version;
  std::uint16_t minor_subsystem_version;
  std::uint32_t win_32_version_value;
  std::uint32_t size_of_image;
  std::uint32_t size_of_headers;
  std::uint32_t check_sum;
  std::uint16_t subsystem;
  std::uint16_t dll_characteristics;
  std::uint64_t size_of_stack_reserve;
  std::uint64_t size_of_stack_commit;
  std::uint64_t size_of_heap_reserve;
  std::uint64_t size_of_heap_commit;
  std::uint32_t loader_flags;
  std::uint32_t number_of_rva_and_sizes;
  image_data_directory data_directory[16];
};

struct image_section_header {
  std::uint8_t name[8];
  std::uint32_t misc;
  std::uint32_t virtual_address;
  std::uint32_t size_of_raw_data;
  std::uint32_t pointer_to_raw_data;
  std::uint32_t pointer_to_relocations;
  std::uint32_t pointer_to_linenumbers;
  std::uint16_t number_of_relocations;
  std::uint16_t number_of_linenumbers;
  std::uint32_t characteristics;
};

struct image_import_descriptor {
  std::uint32_t original_first_thunk;
  std::uint32_t time_data_stamp;
  std::uint32_t forwarder_chain;
  std::uint32_t name;
  std::uint32_t first_thunk;
};

struct image_base_relocation {
  std::uint32_t virtual_address;
  std::uint32_t size_of_block;
};

struct image_tls_directory32 {
  std::uint32_t start_address_of_raw_data;
  std::uint32_t end_address_of_raw_data;
  std::uint32_t address_of_index;
  std::uint32_t address_of_call_backs;
  std::uint32_t size_of_zero_fill;
  std::uint32_t characteristics;
};

struct image_resource_directory {
  std::uint32_t characteristics;
  std::uint32_t time_data_stamp;
  std::uint16_t major_version;
  std::uint16_t minor_version;
  std::uint16_t number_of_named_entries;
  std::uint16_t number_of_id_entries;
};

struct image_resource_directory_entry {
  std::uint32_t id;
  std::uint32_t offset;
};

struct image_resource_data_entry {
  std::uint32_t offset_to_data;
  std::uint32_t size;
  std::uint32_t code_page;
  std::uint32_t reserved;
};

struct image_export_directory {
  std::uint32_t characteristics;
  std::uint32_t time_data_stamp;
  std::uint16_t major_version;
  std::uint16_t minor_version;
  std::uint32_t name;
  std::uint32_t base;
  std::uint32_t number_of_functions;
  std::uint32_t number_of_names;
  std::uint32_t address_of_functions;
  std::uint32_t address_of_names;
  std::uint32_t address_of_name_ordinals;
};

struct resource_entry {
  image_resource_directory_entry entry;
  bool str, dir;
  std::vector<uint8_t> self_id;
  std::uint64_t child_id;
};

struct resource_diretory {
  image_resource_directory dir;
  std::vector<resource_entry> entries;
};

struct resource_data {
  image_resource_data_entry data_entry;
  std::vector<uint8_t> data;
};

struct resource_container {
  std::uint64_t root_id;
  std::map<uint64_t, resource_diretory> directories;
  std::map<uint64_t, resource_data> resources;
};

struct library {
  std::vector<std::uint8_t> name;
  std::uint32_t iat_begin;
  std::vector<std::pair<std::vector<std::uint8_t>, bool>> functions;
};

struct export_container {
  std::vector<uint8_t> image_name;
  std::vector<std::pair<std::vector<uint8_t>, uint16_t>> names;
  std::vector<std::pair<std::vector<uint8_t>, bool>> addresses;
};

class base_pe : public base_ld {
 protected:
  std::uint64_t dos_header;
  std::uint64_t dos_stub;
  std::uint64_t nt_signature;
  std::uint64_t file_header;
  std::vector<std::uint64_t> section_headers;
  std::vector<library> import;
  std::vector<std::uint32_t> relocations;
  resource_container resources;
  export_container exports;

  bool read_dos_header_from_file();
  bool read_dos_stub_from_file();
  bool read_nt_signature_from_file();
  bool read_file_header_from_file();
  virtual bool read_optional_header_from_file() = 0;
  virtual void continue_parsing() = 0;

  void read_section_headers_from_file(std::uint64_t shift);
  void read_sections_from_file(std::uint64_t shift, std::uint32_t align,
                               std::uint32_t sections_begin);
  void parse_import(image_data_directory *directories);

  virtual void read_thuncks(
      std::uint32_t begin,
      std::vector<std::pair<std::vector<uint8_t>, bool>> &functions) = 0;

  void parse_relocations(image_data_directory *directories);
  void parse_resources();
  void parse_next_resource_level(std::uint32_t depth, std::uint32_t rva,
                                 std::uint64_t id);
  void parse_exports(image_data_directory *directories);

  virtual void wipe_thuncks(std::uint32_t begin) = 0;

  bool is_valid_mz();
  bool is_valid_pe();
  virtual bool is_valid_nt_magic() = 0;

  void is_valid_sections_size(std::uint64_t size_of_headers);
  void is_valid_data_directories(std::uint32_t count,
                                 image_data_directory *directories);

  std::uint64_t rva_to_file_position(std::uint32_t rva);
  bool search_rva_in_sections(std::uint32_t rva, std::uint32_t &index);

 public:
  base_pe();
  base_pe(fs::in_file *in_file);
  virtual ~base_pe();
  bool parse();
  image_dos_header *get_dos_header();
  image_file_header *get_file_header();
  image_section_header *get_section_header(std::uint64_t index);
  std::uint32_t section_flags_to_memory_flags(std::uint32_t section_flags);
  std::uint64_t get_sections_count();
  image_import_descriptor *get_import_descriptor(std::uint32_t rva);
  image_base_relocation *get_base_relocation(std::uint32_t rva);
  image_resource_directory *get_resource_directory(std::uint32_t rva);
  image_resource_data_entry *get_resource_data_entry(std::uint32_t rva);
  image_resource_directory_entry *get_resource_directory_entry(
      std::uint32_t rva);
  image_export_directory *get_export_directory(std::uint32_t rva);
  virtual std::uint32_t get_resource_rva() = 0;
  virtual std::uint32_t get_resource_size() = 0;
  virtual void resize_with_file_align(std::vector<uint8_t> *data) = 0;
  virtual void resize_with_section_align(std::vector<uint8_t> *data) = 0;
  virtual std::vector<uint8_t> get_rebuilded_header(
      std::uint32_t stub_size, std::uint32_t code_begin,
      std::pair<std::uint32_t, std::uint32_t> tls_directory,
      std::pair<std::uint32_t, std::uint32_t> reloc_directory,
      std::pair<std::uint32_t, std::uint32_t> resource_directory,
      std::uint32_t export_rva,
      std::pair<std::uint32_t, std::uint32_t> import_directory) = 0;
  virtual std::vector<uint8_t> get_protected_data() = 0;
  virtual std::vector<uint8_t> *get_image() = 0;
  virtual std::uint64_t get_real_image_begin() = 0;
  virtual std::uint64_t get_begin_of_stub() = 0;
  std::vector<library> *get_import();
  resource_container *get_resources();
  std::vector<std::uint32_t> *get_relocations();
  export_container *get_export();
  virtual bool is_tls_exists() = 0;
  virtual bool is_resources_exists() = 0;
  virtual bool is_reloc_exists() = 0;
  virtual bool is_exports_exists() = 0;
  virtual bool is_nx_compatible() = 0;
  bool is_dll();
  void read_unicode_string_from_image(std::uint32_t rva,
                                      std::vector<uint8_t> &string);
  void read_ascii_string_from_image(std::uint32_t rva,
                                    std::vector<uint8_t> &string);
  void wipe_unicode_string(std::uint32_t rva);
  void wipe_ascii_string(std::uint32_t rva);
  virtual void get_part_of_image(std::vector<uint8_t> *part, std::uint32_t rva,
                                 std::uint32_t size) = 0;
};
}  // namespace ld::pe

#endif