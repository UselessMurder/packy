// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <ld/pe/base_pe/base_pe.h>
#include <stdio.h>
#include <chrono>
#include <cstdlib>

namespace ld::pe {

base_pe::base_pe() : base_ld() {
  dos_header = 0;
  file_header = 0;
  nt_signature = 0;
}

base_pe::base_pe(fs::in_file *in_file) : base_ld(in_file) {
  dos_header = 0;
  file_header = 0;
  nt_signature = 0;
}

base_pe::~base_pe() {}

image_dos_header *base_pe::get_dos_header() {
  return reinterpret_cast<image_dos_header *>(&image[dos_header]);
}

image_file_header *base_pe::get_file_header() {
  return reinterpret_cast<image_file_header *>(&image[file_header]);
}

image_section_header *base_pe::get_section_header(std::uint64_t index) {
  return reinterpret_cast<image_section_header *>(
      &image[section_headers[index]]);
}

image_import_descriptor *base_pe::get_import_descriptor(std::uint32_t rva) {
  return reinterpret_cast<image_import_descriptor *>(&image[rva]);
}

image_base_relocation *base_pe::get_base_relocation(std::uint32_t rva) {
  return reinterpret_cast<image_base_relocation *>(&image[rva]);
}

image_resource_directory *base_pe::get_resource_directory(std::uint32_t rva) {
  return reinterpret_cast<image_resource_directory *>(&image[rva]);
}
image_resource_data_entry *base_pe::get_resource_data_entry(std::uint32_t rva) {
  return reinterpret_cast<image_resource_data_entry *>(&image[rva]);
}
image_resource_directory_entry *base_pe::get_resource_directory_entry(
    std::uint32_t rva) {
  return reinterpret_cast<image_resource_directory_entry *>(&image[rva]);
}

image_export_directory *base_pe::get_export_directory(std::uint32_t rva) {
  return reinterpret_cast<image_export_directory *>(&image[rva]);
}

std::vector<library> *base_pe::get_import() { return &import; }

bool base_pe::parse() {
  bool result = true;
  file->open();
  result = read_dos_header_from_file();
  if (result) result = is_valid_mz();
  if (result) result = read_dos_stub_from_file();
  if (result) result = read_nt_signature_from_file();
  if (result) result = is_valid_pe();
  if (result) result = read_file_header_from_file();
  if (result) result = read_optional_header_from_file();
  if (result) result = is_valid_nt_magic();
  if (result) continue_parsing();
  file->close();
  return result;
}

bool base_pe::read_dos_header_from_file() {
  if (file->get_file_size() < sizeof(image_dos_header)) return false;
  file->set_position(0);
  file->read_bytes(image, sizeof(image_dos_header));
  dos_header = 0;
  return true;
}

bool base_pe::read_dos_stub_from_file() {
  if (file->get_file_size() < get_dos_header()->e_lfanew) return false;
  file->set_position(sizeof(image_dos_header));
  std::vector<std::uint8_t> content;
  file->read_bytes(content,
                   get_dos_header()->e_lfanew - sizeof(image_dos_header));
  image.insert(image.end(), content.begin(), content.end());
  dos_stub = get_dos_header()->e_lfanew - sizeof(image_dos_header);
  return true;
}

bool base_pe::read_nt_signature_from_file() {
  if (file->get_file_size() < get_dos_header()->e_lfanew + 4) return false;
  file->set_position(get_dos_header()->e_lfanew);
  std::vector<std::uint8_t> content;
  file->read_bytes(content, 4);
  image.insert(image.end(), content.begin(), content.end());
  nt_signature = get_dos_header()->e_lfanew;
  return true;
}

bool base_pe::read_file_header_from_file() {
  if (file->get_file_size() <
      get_dos_header()->e_lfanew + 4 + sizeof(image_file_header))
    return false;
  std::vector<std::uint8_t> content;
  file->set_position(get_dos_header()->e_lfanew + 4);
  file->read_bytes(content, sizeof(image_file_header));
  image.insert(image.end(), content.begin(), content.end());
  file_header = get_dos_header()->e_lfanew + 4;
  return true;
}

void base_pe::read_section_headers_from_file(std::uint64_t shift) {
  if (get_file_header()->number_of_sections <= 0)
    throw std::domain_error("Image is not contain sections");

  if (file->get_file_size() <
      get_dos_header()->e_lfanew + 4 + sizeof(image_file_header) + shift +
          sizeof(image_section_header) * get_file_header()->number_of_sections)
    throw std::domain_error("Size of image is less than total sections size");

  std::vector<std::uint8_t> content;
  file->set_position(get_dos_header()->e_lfanew + 4 +
                     sizeof(image_file_header) + shift);
  file->read_bytes(content, get_file_header()->number_of_sections *
                                sizeof(image_section_header));
  section_headers.resize(get_file_header()->number_of_sections);
  for (std::uint32_t i = 0; i < get_file_header()->number_of_sections; i++) {
    section_headers[i] = image.size();
    image.insert(image.end(),
                 content.begin() + i * sizeof(image_section_header),
                 content.begin() + i * sizeof(image_section_header) +
                     sizeof(image_section_header));
  }
}

void base_pe::read_sections_from_file(std::uint64_t shift, std::uint32_t align,
                                      std::uint32_t sections_begin) {
  uint64_t pos =
      get_dos_header()->e_lfanew + 4 + sizeof(image_file_header) + shift +
      sizeof(image_section_header) * get_file_header()->number_of_sections;
  file->set_position(pos);
  std::vector<std::uint8_t> content;
  file->read_bytes(content, sections_begin - pos);
  image.insert(image.end(), content.begin(), content.end());
  image.resize(get_section_header(0)->virtual_address);
  for (std::uint32_t i = 0; i < section_headers.size(); i++) {
    file->set_position(get_section_header(i)->pointer_to_raw_data);
    if (get_section_header(i)->size_of_raw_data != 0)
      file->read_bytes(content, get_section_header(i)->size_of_raw_data);
    else
      content.clear();
    std::uint64_t size = get_section_header(i)->misc;
    std::uint64_t overhead = 0;
    global::align(size, overhead, align);
    content.resize(size + overhead);
    image.insert(std::end(image), std::begin(content), std::end(content));
  }
}

void base_pe::parse_import(image_data_directory *directories) {
  if (directories[1].size == 0) return;
  std::uint32_t begin = directories[1].virtual_address;
  for (std::uint32_t i = 0;
       i * sizeof(image_import_descriptor) < directories[1].size; i++) {
    if (get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->name == 0)
      return;
    library lib;
    read_ascii_string_from_image(
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->name,
        lib.name);
    wipe_ascii_string(
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->name);
    lib.iat_begin =
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->first_thunk;
    read_thuncks(
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->original_first_thunk,
        lib.functions);
    wipe_thuncks(
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->original_first_thunk);
    global::wipe_memory(&image, begin + i * sizeof(image_import_descriptor),
                        sizeof(image_import_descriptor));
    import.push_back(lib);
  }
}

void base_pe::parse_relocations(image_data_directory *directories) {
  if (directories[5].size == 0) return;
  std::uint32_t tmp = 0;
  for (std::uint32_t i = directories[5].virtual_address;
       i - directories[5].virtual_address < directories[5].size; i += tmp) {
    if (get_base_relocation(i)->size_of_block == 0 &&
        get_base_relocation(i)->virtual_address == 0)
      return;
    std::uint32_t beg = i + sizeof(image_base_relocation);
    std::uint32_t count = (get_base_relocation(i)->size_of_block -
                           sizeof(image_base_relocation)) /
                          2;
    while (count) {
      std::uint16_t descriptor = *((std::uint16_t *)&image[beg]);
      if (((descriptor & 61440) >> 12) == 3 ||
          ((descriptor & 61440) >> 12) == 10) {
        relocations.push_back(get_base_relocation(i)->virtual_address +
                              (descriptor & 4095));
      }
      count--;
      beg += 2;
    }
    tmp = get_base_relocation(i)->size_of_block;
    global::wipe_memory(&image, i, get_base_relocation(i)->size_of_block);
  }
}

void base_pe::parse_resources() {
  if (is_resources_exists()) {
    resources.root_id = global::cs.generate_unique_number("res");
    parse_next_resource_level(0, get_resource_rva(), resources.root_id);
  }
}

void base_pe::parse_next_resource_level(std::uint32_t depth, std::uint32_t rva,
                                        std::uint64_t id) {
  depth++;
  if (depth != 4) {
    resources.directories[id] = {.dir = (*get_resource_directory(rva)),
                                 .entries = std::vector<resource_entry>()};
    std::uint32_t count = get_resource_directory(rva)->number_of_named_entries +
                          get_resource_directory(rva)->number_of_id_entries;
    if (get_resource_directory(rva)->number_of_named_entries != 0 &&
        get_resource_directory(rva)->number_of_id_entries != 0)
      count--;
    global::wipe_memory(&image, rva, sizeof(image_resource_directory));
    std::uint32_t pointer = rva + sizeof(image_resource_directory);
    for (std::uint32_t i = 0; i < count; i++) {
      std::uint64_t current_id = global::cs.generate_unique_number("res");
      std::vector<uint8_t> self_id;
      bool dir = false, str = false;
      if (get_resource_directory_entry(pointer)->id & 2147483648) str = true;
      if (get_resource_directory_entry(pointer)->offset & 2147483648)
        dir = true;
      if (str) {
        std::uint32_t offset =
            get_resource_directory_entry(pointer)->id & (~2147483648);
        read_unicode_string_from_image(get_resource_rva() + offset, self_id);
        wipe_unicode_string(get_resource_rva() + offset);
      } else
        global::value_to_vector(&self_id,
                                get_resource_directory_entry(pointer)->id,
                                sizeof(std::uint32_t));
      resources.directories[id].entries.push_back(
          {.entry = (*get_resource_directory_entry(pointer)),
           .str = str,
           .dir = dir,
           .self_id = self_id,
           .child_id = current_id});
      std::uint32_t offset = get_resource_directory_entry(pointer)->offset;
      if (dir) offset &= ~2147483648;
      parse_next_resource_level(depth, get_resource_rva() + offset, current_id);
      global::wipe_memory(&image, pointer,
                          sizeof(image_resource_directory_entry));
      pointer += sizeof(image_resource_directory_entry);
    }
  } else {
    resources.resources[id] = {.data_entry = (*get_resource_data_entry(rva)),
                               .data = std::vector<std::uint8_t>()};
    get_part_of_image(&resources.resources[id].data,
                      get_resource_data_entry(rva)->offset_to_data,
                      get_resource_data_entry(rva)->size);
    global::wipe_memory(&image, get_resource_data_entry(rva)->offset_to_data,
                        get_resource_data_entry(rva)->size);
    global::wipe_memory(&image, rva, sizeof(image_resource_data_entry));
  }
}

void base_pe::parse_exports(image_data_directory *directories) {
  if (is_exports_exists()) {
    std::uint32_t lu = directories[0].virtual_address;
    std::uint32_t ld = lu + directories[0].size;

    read_ascii_string_from_image(get_export_directory(lu)->name,
                                 exports.image_name);
    wipe_ascii_string(get_export_directory(lu)->name);

    for (std::uint32_t i = 0,
                       pointer = get_export_directory(lu)->address_of_functions;
         i < get_export_directory(lu)->number_of_functions; i++, pointer += 4) {
      std::uint32_t val = *((uint32_t *)(&image[pointer]));
      if (val == 0) {
        exports.addresses.push_back(
            std::make_pair(std::vector<uint8_t>(4, 0), false));
      } else {
        std::vector<uint8_t> tmp;
        if (val < ld && val >= lu) {
          read_ascii_string_from_image(val, tmp);
          wipe_ascii_string(val);
          exports.addresses.push_back(std::make_pair(tmp, true));
        }
        global::value_to_vector(&tmp, val, sizeof(uint32_t));
        exports.addresses.push_back(std::make_pair(tmp, false));
      }
      global::wipe_memory(&image, val, sizeof(uint32_t));
    }
    for (std::uint32_t
             i = 0,
             name_rva = get_export_directory(lu)->address_of_names,
             ord_rva = get_export_directory(lu)->address_of_name_ordinals;
         i < get_export_directory(lu)->number_of_names;
         i++, name_rva += 4, ord_rva += 2) {
      exports.names.push_back(
          std::make_pair(std::vector<uint8_t>(),
                         std::uint16_t(*((uint16_t *)(&image[ord_rva])))));
      read_ascii_string_from_image(*((uint32_t *)(&image[name_rva])), exports.names.back().first);
      wipe_ascii_string(*((uint32_t *)(&image[name_rva])));
      global::wipe_memory(&image, *((uint32_t *)(&image[name_rva])), sizeof(uint32_t));
      global::wipe_memory(&image, *((uint32_t *)(&image[name_rva])), sizeof(uint16_t));
    }
  }
}

void base_pe::is_valid_sections_size(std::uint64_t size_of_headers) {
  std::uint64_t temporary_size = 0;
  temporary_size += size_of_headers;
  for (std::uint32_t i = 0; i < section_headers.size(); i++)
    temporary_size += get_section_header(i)->size_of_raw_data;
  if (temporary_size > file->get_file_size())
    throw std::domain_error("Sections is truncated!");
}

bool base_pe::is_valid_mz() {
  std::uint8_t image_dos_signature[2] = {0x4D, 0x5A};
  for (std::uint8_t i = 0; i < 2; i++) {
    if (image_dos_signature[i] != image[dos_header + i]) return false;
  }
  return true;
}

bool base_pe::is_valid_pe() {
  std::uint8_t image_nt_signature[4] = {0x50, 0x45, 0x0, 0x0};
  for (std::uint8_t i = 0; i < 4; i++) {
    if (image[nt_signature + i] != image_nt_signature[i]) return false;
  }
  return true;
}

void base_pe::is_valid_data_directories(std::uint32_t count,
                                        image_data_directory *directories) {
  if (count != 16) throw std::domain_error("Data directories count is invalid");
  for (std::uint32_t i = 0; i < count; i++) {
    if (directories[i].size == 0) continue;
    std::uint64_t position =
        rva_to_file_position(directories[i].virtual_address);
    if (position + directories[i].size > file->get_file_size())
      throw std::domain_error("Data directory location is outsize of the file");
  }
}

std::uint64_t base_pe::rva_to_file_position(std::uint32_t rva) {
  std::uint32_t index = 0;
  if (!search_rva_in_sections(rva, index))
    return (std::uint64_t)rva;
  else
    return get_section_header(index)->pointer_to_raw_data +
           (rva - get_section_header(index)->virtual_address);
  return 0;
}

bool base_pe::search_rva_in_sections(std::uint32_t rva, std::uint32_t &index) {
  for (std::uint32_t i = 0; i < section_headers.size(); i++) {
    if (rva >= get_section_header(i)->virtual_address &&
        rva < get_section_header(i)->virtual_address +
                  get_section_header(i)->misc) {
      index = i;
      return true;
    }
  }
  return false;
}

void base_pe::read_ascii_string_from_image(std::uint32_t rva,
                                           std::vector<uint8_t> &string) {
  string.clear();
  for (std::uint32_t i = rva; i < image.size(); i++) {
    string.push_back(image[i]);
    if (image[i] == 0) {
      return;
    }
  }
  throw std::domain_error("Size of string is more than size of file");
}

union unicode_char {
  std::uint16_t unicode;
  std::uint8_t byte[2];
};

void base_pe::read_unicode_string_from_image(std::uint32_t rva,
                                             std::vector<uint8_t> &string) {
  string.clear();
  for (std::uint32_t i = rva; (i < image.size()) && (i + 1 < image.size());
       i += 2) {
    unicode_char ch;
    ch.byte[0] = image[i];
    ch.byte[1] = image[i + 1];
    string.push_back(image[i]);
    string.push_back(image[i + 1]);
    if (ch.unicode == 0) {
      if (string.size() % 2 != 0)
        throw std::domain_error("Incorrect unicode string!");
      return;
    }
  }
  throw std::domain_error("Size of string is more than size of file");
}

void base_pe::wipe_ascii_string(std::uint32_t rva) {
  for (std::uint32_t i = rva; i < image.size(); i++) {
    if (image[i] == 0) {
      return;
    }
    image[i] = 0;
  }
  throw std::domain_error("Size of string is more than size of file");
}

void base_pe::wipe_unicode_string(std::uint32_t rva) {
  for (std::uint32_t i = rva; (i < image.size()) && (i + 1 < image.size());
       i += 2) {
    unicode_char ch;
    ch.byte[0] = image[i];
    ch.byte[1] = image[i + 1];
    if (ch.unicode == 0) {
      return;
    }
    image[i] = 0;
    image[i + 1] = 0;
  }
  throw std::domain_error("Size of string is more than size of file");
}

std::uint64_t base_pe::get_sections_count() { return section_headers.size(); }

std::uint32_t base_pe::section_flags_to_memory_flags(
    std::uint32_t section_flags) {
  global::tag_container tmp;
  if (section_flags & 0x20000000) tmp.add_tag("x");
  if (section_flags & 0x40000000) tmp.add_tag("r");
  if (section_flags & 0x80000000) tmp.add_tag("w");
  if (tmp.check_tags({"r", "w", "x"})) return 0x40;
  if (tmp.check_tags({"r", "x"})) return 0x20;
  if (tmp.check_tags({"r", "w"})) return 0x04;
  if (tmp.check_tag("r")) return 0x02;
  if (tmp.check_tag("x")) return 0x10;
  return 0x0;
}

bool base_pe::is_dll() {
  if(get_file_header()->characteristics & 0x2000)
    return true;
  return false;
}

std::vector<std::uint32_t> *base_pe::get_relocations() { return &relocations; }

resource_container *base_pe::get_resources() { return &resources; }

export_container *base_pe::get_export() { return &exports; }

}  // namespace ld::pe